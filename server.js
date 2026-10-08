/**
 * Coursatk API — pure backend
 * - Unwraps Stream-Weave playback key (same as player.js)
 * - Decrypts AES-128 HLS segments server-side
 * - Serves plain TS segments + key-free playlist
 * No HTML. CORS open for separate frontend.
 */
import express from "express";
import cors from "cors";
import compression from "compression";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(cors({ origin: true, credentials: false }));
app.use(express.json({ limit: "256kb" }));
app.use(compression());

const PORT = Number(process.env.PORT || 3000);
const API_BASE = process.env.COURSATK_API_BASE || "https://api.coursatk.online/api/v1";
const AUTH_TOKEN = process.env.COURSATK_TOKEN || "";
const YEAR_ID = Number(process.env.COURSATK_YEAR_ID || 4);
const STREAM_HOSTS = (process.env.STREAM_HOSTS ||
  "api.coursatk.online,stream-weave.com,floravon.online,c-cdn.online")
  .split(",").map(s => s.trim()).filter(Boolean);

const STREAM_ORIGIN = process.env.STREAM_ORIGIN || "https://coursatk.online";
const STREAM_REFERER = process.env.STREAM_REFERER || "https://coursatk.online/";
const STREAM_X_REQUESTED_WITH =
  process.env.STREAM_X_REQUESTED_WITH || "com.mycompany.app.soulbrowser";
const STREAM_USER_AGENT = process.env.STREAM_USER_AGENT || "";

const SESSION_TTL_MS = 15 * 60 * 1000;
const MAX_PROXY_BYTES = 12 * 1024 * 1024;
const PLAYER_JS_URL =
  process.env.PLAYER_JS_URL || "https://player.stream-weave.com/assets/player.js?v=1.1.1";

if (!AUTH_TOKEN) {
  console.warn("[Coursatk] COURSATK_TOKEN missing — set Railway variable");
}

let decryptPlaybackKeyFn = null;

async function loadDecryptionUtils() {
  const cachePath = path.join(__dirname, "player.stream-weave.cache.js");
  let source = null;
  try {
    if (fs.existsSync(cachePath)) source = fs.readFileSync(cachePath, "utf8");
  } catch {}

  if (!source) {
    console.log("[Coursatk] fetching player.js …");
    const r = await fetch(PLAYER_JS_URL, {
      headers: { "User-Agent": "Mozilla/5.0", Accept: "*/*" }
    });
    if (!r.ok) throw new Error(`player.js HTTP ${r.status}`);
    source = await r.text();
    try { fs.writeFileSync(cachePath, source); } catch {}
  } else {
    console.log("[Coursatk] player.js cache hit");
  }

  const { webcrypto } = crypto;
  const sandbox = {
    window: {}, self: {}, globalThis: {}, global: {},
    console: { log() {}, warn() {}, error() {}, info() {} },
    crypto: webcrypto,
    TextEncoder, TextDecoder, Uint8Array, ArrayBuffer,
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    btoa: (s) => Buffer.from(s, "binary").toString("base64"),
    setTimeout, clearTimeout, setInterval, clearInterval,
    Promise, Error, Object, Array, String, Number, Boolean, Math, JSON, Date,
    Map, Set, WeakMap, Symbol, Proxy, Reflect,
    document: {
      createElement: () => ({ style: {}, setAttribute() {}, appendChild() {}, remove() {} }),
      head: { appendChild() {} }, body: { appendChild() {} },
      querySelector: () => null, addEventListener() {}
    },
    navigator: { userAgent: "Node" },
    location: { href: "https://coursatk.online/" },
    HTMLElement: class {}, HTMLVideoElement: class {}, MediaSource: class {},
    URL: { createObjectURL: () => "blob:x", revokeObjectURL() {} },
    Blob: class { constructor(p) { this.p = p; } },
    fetch: async () => ({ ok: false }),
    XMLHttpRequest: class { open() {} send() {} setRequestHeader() {} }
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.global = sandbox;

  vm.runInNewContext(source, sandbox, { timeout: 8000 });
  const du = sandbox.DecryptionUtils;
  if (!du?.decryptPlaybackKey) {
    throw new Error("DecryptionUtils.decryptPlaybackKey not found");
  }
  decryptPlaybackKeyFn = du.decryptPlaybackKey.bind(du);
  console.log("[Coursatk] DecryptionUtils ready");
}

async function unwrapKey(wrappedBuf, videoId) {
  if (!decryptPlaybackKeyFn) throw new Error("crypto not loaded");
  const wrapped = Buffer.isBuffer(wrappedBuf)
    ? new Uint8Array(wrappedBuf)
    : new Uint8Array(wrappedBuf);

  if (wrapped.byteLength === 16) return Buffer.from(wrapped);

  const result = await decryptPlaybackKeyFn(wrapped, String(videoId));
  const key = result?.key;
  if (!key) throw new Error("empty key from decryptPlaybackKey");

  const aes = Buffer.isBuffer(key)
    ? key
    : key instanceof ArrayBuffer
      ? Buffer.from(key)
      : Buffer.from(key.buffer || key, key.byteOffset || 0, key.byteLength || key.length);

  if (aes.length !== 16) throw new Error(`AES key length ${aes.length}`);
  return aes;
}

function decryptSegment(encrypted, key, iv) {
  const decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

function parseIvHex(hex) {
  const h = String(hex || "").replace(/^0x/i, "").trim();
  if (!/^[0-9a-fA-F]{32}$/.test(h)) return null;
  return Buffer.from(h, "hex");
}

function ivFromMediaSequence(seq) {
  const iv = Buffer.alloc(16, 0);
  iv.writeUInt32BE(Number(seq) >>> 0, 12);
  return iv;
}

const sessions = new Map();

function authHeaders(extra = {}) {
  return {
    Authorization: `Bearer ${AUTH_TOKEN}`,
    Accept: "application/json",
    ...extra
  };
}

function jsonError(res, status, message) {
  return res.status(status).json({ success: false, message });
}

function allowedStreamUrl(raw, session = null) {
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:") return false;
    const sessionHosts = session?.allowedHosts || new Set();
    const sessionHost = session?.streamUrl
      ? new URL(session.streamUrl).hostname
      : "";
    return (
      STREAM_HOSTS.some(h => u.hostname === h || u.hostname.endsWith("." + h)) ||
      (sessionHost && (u.hostname === sessionHost || u.hostname.endsWith("." + sessionHost))) ||
      [...sessionHosts].some(h => u.hostname === h || u.hostname.endsWith("." + h))
    );
  } catch {
    return false;
  }
}

function absoluteUrl(raw, base) {
  return new URL(raw, base).href;
}

async function upstreamJson(apiPath, options = {}) {
  if (!AUTH_TOKEN) throw new Error("COURSATK_TOKEN غير مضبوط");
  const r = await fetch(`${API_BASE}${apiPath}`, {
    ...options,
    headers: authHeaders(options.headers || {})
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch {
    throw new Error(`Upstream non-JSON (${r.status})`);
  }
  if (!r.ok) throw new Error(data?.message || `Upstream HTTP ${r.status}`);
  return data;
}

function newSession(data) {
  const id = crypto.randomUUID();
  sessions.set(id, {
    id,
    videoId: String(data.video_id),
    token: data.token,
    streamUrl: data.stream_url,
    createdAt: Date.now(),
    plainKey: null,
    defaultIv: null,
    variantUrl: null,
    allowedHosts: new Set([new URL(data.stream_url).hostname])
  });
  return id;
}

function getSession(id) {
  const s = sessions.get(id);
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_TTL_MS) {
    sessions.delete(id);
    return null;
  }
  return s;
}

async function streamFetch(session, url, extra = {}, clientHeaders = null) {
  if (!allowedStreamUrl(url, session)) {
    throw new Error(`Stream URL غير مسموح: ${url}`);
  }
  const ch = clientHeaders || {};
  const headers = {
    Authorization: `Bearer ${session.token}`,
    Accept: "*/*",
    "Cache-Control": "no-cache",
    Origin: STREAM_ORIGIN,
    Referer: STREAM_REFERER,
    "X-Requested-With": STREAM_X_REQUESTED_WITH,
    "User-Agent":
      ch["user-agent"] ||
      STREAM_USER_AGENT ||
      "Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 Chrome/153.0.0.0 Mobile Safari/537.36"
  };
  for (const name of [
    "sec-ch-ua-platform", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-language"
  ]) {
    if (ch[name]) headers[name] = ch[name];
  }
  for (const [k, v] of Object.entries(extra || {})) {
    if (v != null && v !== "") headers[k] = v;
  }
  return fetch(url, { headers, cache: "no-store" });
}

app.get("/api/config", (_req, res) => {
  res.json({
    success: true,
    yearId: YEAR_ID,
    cryptoReady: Boolean(decryptPlaybackKeyFn),
    decryptSegments: true
  });
});

app.get("/api/subjects", async (_req, res) => {
  try { res.json(await upstreamJson(`/user/subjects/${YEAR_ID}`)); }
  catch (e) { jsonError(res, 502, e.message); }
});

app.get("/api/subjects/:id", async (req, res) => {
  try {
    res.json(await upstreamJson(`/user/subjects/${encodeURIComponent(req.params.id)}`));
  } catch (e) { jsonError(res, 502, e.message); }
});

app.get("/api/subjects/:id/teachers", async (req, res) => {
  try {
    res.json(await upstreamJson(`/user/subjects/${encodeURIComponent(req.params.id)}/teachers`));
  } catch (e) { jsonError(res, 502, e.message); }
});

app.get("/api/teachers/:id/chapters", async (req, res) => {
  try {
    res.json(await upstreamJson(`/user/teachers/${encodeURIComponent(req.params.id)}/chapters`));
  } catch (e) { jsonError(res, 502, e.message); }
});

app.get("/api/chapters/:id/lectures", async (req, res) => {
  try {
    res.json(await upstreamJson(`/user/chapters/${encodeURIComponent(req.params.id)}/lectures`));
  } catch (e) { jsonError(res, 502, e.message); }
});

app.get("/api/lectures/:id/content", async (req, res) => {
  try {
    res.json(await upstreamJson(`/user/lectures/${encodeURIComponent(req.params.id)}/content`));
  } catch (e) { jsonError(res, 502, e.message); }
});

app.post("/api/play/:videoId", async (req, res) => {
  try {
    const data = await upstreamJson(
      `/video/${encodeURIComponent(req.params.videoId)}/stream-weave/play`,
      { method: "POST", headers: { Accept: "application/json" } }
    );
    if (!data?.success || !data?.data?.token || !data?.data?.stream_url || !data?.data?.video_id) {
      throw new Error("Playback response ناقص");
    }
    const sessionId = newSession(data.data);
    res.json({
      success: true,
      data: {
        session: sessionId,
        video_id: data.data.video_id,
        manifest_url: `/api/stream/manifest/${sessionId}`
      }
    });
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

app.get("/user/subjects/:id", async (req, res) => {
  try { res.json(await upstreamJson(`/user/subjects/${encodeURIComponent(req.params.id)}`)); }
  catch (e) { jsonError(res, 502, e.message); }
});
app.get("/user/subjects/:id/teachers", async (req, res) => {
  try { res.json(await upstreamJson(`/user/subjects/${encodeURIComponent(req.params.id)}/teachers`)); }
  catch (e) { jsonError(res, 502, e.message); }
});
app.get("/user/teachers/:id/chapters", async (req, res) => {
  try { res.json(await upstreamJson(`/user/teachers/${encodeURIComponent(req.params.id)}/chapters`)); }
  catch (e) { jsonError(res, 502, e.message); }
});
app.get("/user/chapters/:id/lectures", async (req, res) => {
  try { res.json(await upstreamJson(`/user/chapters/${encodeURIComponent(req.params.id)}/lectures`)); }
  catch (e) { jsonError(res, 502, e.message); }
});
app.get("/user/lectures/:id/content", async (req, res) => {
  try { res.json(await upstreamJson(`/user/lectures/${encodeURIComponent(req.params.id)}/content`)); }
  catch (e) { jsonError(res, 502, e.message); }
});

app.get("/api/stream/manifest/:sessionId", async (req, res) => {
  const session = getSession(req.params.sessionId);
  if (!session) return jsonError(res, 404, "جلسة التشغيل منتهية");

  try {
    const master = await streamFetch(session, session.streamUrl, {}, req.headers);
    if (!master.ok) throw new Error(`Stream master HTTP ${master.status}`);
    const masterText = await master.text();
    const lines = masterText.split(/\r?\n/);

    let variant = null;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].trim().startsWith("#EXT-X-STREAM-INF")) {
        const next = lines[i + 1]?.trim();
        if (next && !next.startsWith("#")) {
          variant = absoluteUrl(next, session.streamUrl);
          break;
        }
      }
    }

    if (variant) {
      const variantRes = await streamFetch(session, variant, {}, req.headers);
      if (!variantRes.ok) throw new Error(`Variant HTTP ${variantRes.status}`);
      const variantText = await variantRes.text();
      session.variantUrl = variant;
      return rewritePlaylist(req.params.sessionId, session, variantText, variant, res, req.headers);
    }

    session.variantUrl = session.streamUrl;
    return rewritePlaylist(
      req.params.sessionId, session, masterText, session.streamUrl, res, req.headers
    );
  } catch (e) {
    console.error("[manifest]", e.message);
    jsonError(res, 502, e.message);
  }
});

async function rewritePlaylist(sessionId, session, text, baseUrl, res, clientHeaders) {
  try { session.allowedHosts.add(new URL(baseUrl).hostname); } catch {}

  const lines = text.split(/\r?\n/);
  const out = [];
  let mediaSeq = 0;
  let currentIv = null;
  let keyFetched = false;

  for (const raw of lines) {
    const t = raw.trim();
    if (t.startsWith("#EXT-X-MEDIA-SEQUENCE:")) {
      mediaSeq = Number(t.split(":")[1]) || 0;
    }
  }

  let segIndex = 0;

  for (const raw of lines) {
    const line = raw.trim();

    if (line.startsWith("#EXT-X-KEY:")) {
      const uri = line.match(/URI="([^"]+)"/)?.[1];
      const ivHex = line.match(/IV=(0x[0-9a-fA-F]+|[0-9a-fA-F]{32})/i)?.[1];
      if (ivHex) currentIv = parseIvHex(ivHex);

      if (uri && !keyFetched) {
        const keyUrl = absoluteUrl(uri, baseUrl);
        try { session.allowedHosts.add(new URL(keyUrl).hostname); } catch {}
        const keyRes = await streamFetch(session, keyUrl, {}, clientHeaders);
        if (!keyRes.ok) throw new Error(`Key HTTP ${keyRes.status}`);
        const wrapped = Buffer.from(await keyRes.arrayBuffer());
        console.log(`[key] wrapped=${wrapped.length} videoId=${session.videoId}`);
        session.plainKey = await unwrapKey(wrapped, session.videoId);
        session.defaultIv = currentIv;
        keyFetched = true;
        console.log(`[key] AES-128 ready, iv=${currentIv ? currentIv.toString("hex") : "seq"}`);
      }
      continue;
    }

    if (line && !line.startsWith("#")) {
      const segmentUrl = absoluteUrl(line, baseUrl);
      try { session.allowedHosts.add(new URL(segmentUrl).hostname); } catch {}

      const seq = mediaSeq + segIndex;
      const iv = currentIv || ivFromMediaSequence(seq);
      const payload = JSON.stringify({
        u: segmentUrl,
        iv: iv.toString("hex"),
        s: seq
      });
      const encoded = Buffer.from(payload, "utf8").toString("base64url");
      out.push(`/api/stream/segment/${sessionId}/${encoded}`);
      segIndex++;
      continue;
    }

    out.push(raw);
  }

  if (!session.plainKey) {
    throw new Error("لم يتم تجهيز مفتاح التشفير");
  }

  res.set({
    "Content-Type": "application/vnd.apple.mpegurl",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*"
  });
  res.send(out.join("\n"));
}

app.get("/api/stream/segment/:sessionId/:encoded", async (req, res) => {
  const session = getSession(req.params.sessionId);
  if (!session) return jsonError(res, 404, "جلسة التشغيل منتهية");
  if (!session.plainKey) return jsonError(res, 404, "مفتاح التشغيل غير متاح");

  let meta;
  try {
    meta = JSON.parse(Buffer.from(req.params.encoded, "base64url").toString("utf8"));
  } catch {
    return jsonError(res, 400, "segment meta غير صالح");
  }

  const url = meta?.u;
  if (!url || !allowedStreamUrl(url, session)) {
    return jsonError(res, 403, "رابط segment غير مسموح");
  }

  const iv = parseIvHex(meta.iv) || session.defaultIv || ivFromMediaSequence(meta.s || 0);

  try {
    const upstream = await streamFetch(session, url, {
      Range: req.headers.range || undefined
    }, req.headers);

    if (!upstream.ok && upstream.status !== 206) {
      throw new Error(`Segment HTTP ${upstream.status}`);
    }

    const encrypted = Buffer.from(await upstream.arrayBuffer());
    if (encrypted.length > MAX_PROXY_BYTES) {
      return jsonError(res, 413, "المقطع أكبر من الحد");
    }

    let plain;
    try {
      plain = decryptSegment(encrypted, session.plainKey, iv);
    } catch (decErr) {
      console.error("[decrypt]", decErr.message, "len", encrypted.length);
      plain = encrypted;
    }

    res.status(200);
    res.set({
      "Content-Type": "video/mp2t",
      "Content-Length": String(plain.length),
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
      "Accept-Ranges": "bytes"
    });
    res.send(plain);
  } catch (e) {
    console.error("[segment]", e.message);
    if (!res.headersSent) jsonError(res, 502, e.message);
    else res.end();
  }
});

app.get("/api/stream/key/:sessionId", (req, res) => {
  const session = getSession(req.params.sessionId);
  if (!session?.plainKey) return jsonError(res, 404, "مفتاح التشغيل غير متاح");
  res.set({
    "Content-Type": "application/octet-stream",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Content-Length": String(session.plainKey.length)
  });
  res.send(session.plainKey);
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "coursatk-api",
    mode: "backend-only",
    decryptSegments: true,
    tokenConfigured: Boolean(AUTH_TOKEN),
    cryptoReady: Boolean(decryptPlaybackKeyFn),
    sessions: sessions.size,
    now: new Date().toISOString()
  });
});

app.use((req, res) => {
  jsonError(res, 404, `Not found: ${req.method} ${req.path}`);
});

setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [id, s] of sessions) {
    if (s.createdAt < cutoff) sessions.delete(id);
  }
}, 60_000).unref();

await loadDecryptionUtils();
app.listen(PORT, () => {
  console.log(`[Coursatk API] :${PORT}  backend-only · segment decrypt ON`);
});
