/**
 * Coursatk Railway proxy — server-side AES key unwrap
 * Matches the working userscript (v6): decryptPlaybackKey(wrapped, video_id)
 * then serve the plain 16-byte AES-128 key to HLS.js / native HLS.
 */
import express from "express";
import cors from "cors";
import compression from "compression";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(cors());
app.use(express.json({ limit: "256kb" }));
app.use(compression());

const PORT = Number(process.env.PORT || 3000);
const API_BASE = process.env.COURSATK_API_BASE || "https://api.coursatk.online/api/v1";
const AUTH_TOKEN = process.env.COURSATK_TOKEN || "";
const YEAR_ID = Number(process.env.COURSATK_YEAR_ID || 4);
const STREAM_HOSTS = (process.env.STREAM_HOSTS || "api.coursatk.online,stream-weave.com")
  .split(",").map(s => s.trim()).filter(Boolean);

const STREAM_ORIGIN = process.env.STREAM_ORIGIN || "https://coursatk.online";
const STREAM_REFERER = process.env.STREAM_REFERER || "https://coursatk.online/";
const STREAM_X_REQUESTED_WITH = process.env.STREAM_X_REQUESTED_WITH || "com.mycompany.app.soulbrowser";
const STREAM_USER_AGENT = process.env.STREAM_USER_AGENT || "";

const SESSION_TTL_MS = 10 * 60 * 1000;
const MAX_PROXY_BYTES = 8 * 1024 * 1024;
const PLAYER_JS_URL = process.env.PLAYER_JS_URL || "https://player.stream-weave.com/assets/player.js?v=1.1.1";

if (!AUTH_TOKEN) {
  console.warn("[Coursatk] COURSATK_TOKEN is missing. Set it in Railway Variables.");
}

// ---------------------------------------------------------------------------
// Load Stream-Weave DecryptionUtils once (same crypto the userscript uses)
// ---------------------------------------------------------------------------
let decryptPlaybackKey = null;

async function loadDecryptionUtils() {
  let source;
  const cachePath = path.join(__dirname, "player.stream-weave.cache.js");
  try {
    if (fs.existsSync(cachePath)) {
      source = fs.readFileSync(cachePath, "utf8");
      console.log("[Coursatk] loaded player.js from cache");
    }
  } catch {}

  if (!source) {
    console.log("[Coursatk] fetching player.js …");
    const r = await fetch(PLAYER_JS_URL, {
      headers: { "User-Agent": "Mozilla/5.0", Accept: "*/*" }
    });
    if (!r.ok) throw new Error(`player.js HTTP ${r.status}`);
    source = await r.text();
    try { fs.writeFileSync(cachePath, source); } catch {}
  }

  const { webcrypto } = crypto;
  const sandbox = {
    window: {},
    self: {},
    globalThis: {},
    global: {},
    console: { log() {}, warn() {}, error() {}, info() {} },
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    ArrayBuffer,
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    btoa: (s) => Buffer.from(s, "binary").toString("base64"),
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    Promise,
    Error,
    Object, Array, String, Number, Boolean, Math, JSON, Date,
    Map, Set, WeakMap, Symbol, Proxy, Reflect,
    document: {
      createElement: () => ({ style: {}, setAttribute() {}, appendChild() {}, remove() {} }),
      head: { appendChild() {} },
      body: { appendChild() {} },
      querySelector: () => null,
      addEventListener() {}
    },
    navigator: { userAgent: "Node" },
    location: { href: "https://coursatk.online/" },
    HTMLElement: class {},
    HTMLVideoElement: class {},
    MediaSource: class {},
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
  if (!du || typeof du.decryptPlaybackKey !== "function") {
    throw new Error("DecryptionUtils.decryptPlaybackKey not found in player.js");
  }

  // Bind so `this` is correct if the method uses it
  decryptPlaybackKey = du.decryptPlaybackKey.bind(du);
  console.log("[Coursatk] DecryptionUtils ready (server-side key unwrap)");
}

async function unwrapKey(wrappedBuf, videoId) {
  if (!decryptPlaybackKey) throw new Error("crypto not loaded");
  const wrapped = wrappedBuf instanceof Uint8Array ? wrappedBuf : new Uint8Array(wrappedBuf);

  // Already plain AES-128
  if (wrapped.byteLength === 16) {
    return Buffer.from(wrapped);
  }

  const result = await decryptPlaybackKey(wrapped, String(videoId));
  const key = result?.key;
  if (!key) throw new Error("decryptPlaybackKey returned empty key");

  const aes = key instanceof ArrayBuffer
    ? Buffer.from(key)
    : Buffer.from(key.buffer || key, key.byteOffset || 0, key.byteLength || key.length);

  if (aes.length !== 16) {
    throw new Error(`AES key length ${aes.length} (expected 16)`);
  }
  return aes;
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
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
    const sessionHost = session?.streamUrl ? new URL(session.streamUrl).hostname : "";
    return STREAM_HOSTS.some(h =>
      u.hostname === h || u.hostname.endsWith("." + h)
    ) || (sessionHost && (
      u.hostname === sessionHost || u.hostname.endsWith("." + sessionHost)
    )) || [...sessionHosts].some(h =>
      u.hostname === h || u.hostname.endsWith("." + h)
    );
  } catch {
    return false;
  }
}

function absoluteUrl(raw, base) {
  return new URL(raw, base).href;
}

async function upstreamJson(path, options = {}) {
  if (!AUTH_TOKEN) throw new Error("COURSATK_TOKEN غير مضبوط في Railway");
  const r = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: authHeaders(options.headers || {})
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch {
    throw new Error(`Upstream returned non-JSON (${r.status})`);
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
    plainKey: null,       // decrypted 16-byte AES key
    keyUrl: null,
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
    "User-Agent": ch["user-agent"] || STREAM_USER_AGENT ||
      "Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 Chrome/153.0.0.0 Mobile Safari/537.36"
  };

  for (const name of [
    "sec-ch-ua-platform", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-language"
  ]) {
    if (ch[name]) headers[name] = ch[name];
  }

  for (const [name, value] of Object.entries(extra || {})) {
    if (value !== undefined && value !== null && value !== "") headers[name] = value;
  }

  return fetch(url, { headers, cache: "no-store" });
}

// ---------------- API mirror ----------------

app.get("/api/config", (_req, res) => {
  res.json({ success: true, yearId: YEAR_ID, cryptoReady: Boolean(decryptPlaybackKey) });
});

app.get("/api/subjects", async (_req, res) => {
  try { res.json(await upstreamJson(`/user/subjects/${YEAR_ID}`)); }
  catch (e) { jsonError(res, 502, e.message); }
});

app.get("/api/subjects/:id", async (req, res) => {
  try {
    const id = encodeURIComponent(req.params.id);
    res.json(await upstreamJson(`/user/subjects/${id}`));
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

app.get("/api/subjects/:id/teachers", async (req, res) => {
  try { res.json(await upstreamJson(`/user/subjects/${encodeURIComponent(req.params.id)}/teachers`)); }
  catch (e) { jsonError(res, 502, e.message); }
});

app.get("/api/teachers/:id/chapters", async (req, res) => {
  try { res.json(await upstreamJson(`/user/teachers/${encodeURIComponent(req.params.id)}/chapters`)); }
  catch (e) { jsonError(res, 502, e.message); }
});

app.get("/api/chapters/:id/lectures", async (req, res) => {
  try { res.json(await upstreamJson(`/user/chapters/${encodeURIComponent(req.params.id)}/lectures`)); }
  catch (e) { jsonError(res, 502, e.message); }
});

app.get("/api/lectures/:id/content", async (req, res) => {
  try { res.json(await upstreamJson(`/user/lectures/${encodeURIComponent(req.params.id)}/content`)); }
  catch (e) { jsonError(res, 502, e.message); }
});

app.post("/api/play/:videoId", async (req, res) => {
  try {
    const data = await upstreamJson(`/video/${encodeURIComponent(req.params.videoId)}/stream-weave/play`, {
      method: "POST",
      headers: { Accept: "application/json" }
    });

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

// ---------------- Legacy API aliases ----------------
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

// ---------------- HLS proxy (key unwrapped server-side) ----------------

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
    return rewritePlaylist(req.params.sessionId, session, masterText, session.streamUrl, res, req.headers);
  } catch (e) {
    console.error("[manifest]", e.message);
    jsonError(res, 502, e.message);
  }
});

async function rewritePlaylist(sessionId, session, text, baseUrl, res, clientHeaders = null) {
  try { session.allowedHosts.add(new URL(baseUrl).hostname); } catch {}
  const lines = text.split(/\r?\n/);
  const out = [];

  for (const raw of lines) {
    const line = raw.trim();

    if (line.startsWith("#EXT-X-KEY:")) {
      const uri = line.match(/URI="([^"]+)"/)?.[1];
      if (uri) {
        session.keyUrl = absoluteUrl(uri, baseUrl);
        try { session.allowedHosts.add(new URL(session.keyUrl).hostname); } catch {}

        // Fetch wrapped key + decrypt with the same video_id the userscript uses
        const keyRes = await streamFetch(session, session.keyUrl, {}, clientHeaders);
        if (!keyRes.ok) throw new Error(`Key HTTP ${keyRes.status}`);
        const wrapped = Buffer.from(await keyRes.arrayBuffer());

        console.log(`[key] wrapped ${wrapped.length} bytes, videoId=${session.videoId}`);
        session.plainKey = await unwrapKey(wrapped, session.videoId);
        console.log(`[key] unwrapped AES-128 (${session.plainKey.length} bytes)`);

        // Point playlist at our endpoint that serves the *plain* key
        const rewritten = line.replace(
          /URI="[^"]+"/,
          `URI="/api/stream/key/${sessionId}"`
        );
        out.push(rewritten);
        continue;
      }
    }

    if (line && !line.startsWith("#")) {
      const segmentUrl = absoluteUrl(line, baseUrl);
      try { session.allowedHosts.add(new URL(segmentUrl).hostname); } catch {}
      const encoded = Buffer.from(segmentUrl, "utf8").toString("base64url");
      out.push(`/api/stream/segment/${sessionId}/${encoded}`);
      continue;
    }

    out.push(raw);
  }

  res.set({
    "Content-Type": "application/vnd.apple.mpegurl",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*"
  });
  res.send(out.join("\n"));
}

// Serve the *plain* 16-byte AES key (already decrypted server-side)
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

app.get("/api/stream/segment/:sessionId/:encodedUrl", async (req, res) => {
  const session = getSession(req.params.sessionId);
  if (!session) return jsonError(res, 404, "جلسة التشغيل منتهية");

  let url;
  try { url = Buffer.from(req.params.encodedUrl, "base64url").toString("utf8"); }
  catch { return jsonError(res, 400, "رابط segment غير صالح"); }

  if (!allowedStreamUrl(url, session)) return jsonError(res, 403, "رابط segment غير مسموح");

  try {
    const upstream = await streamFetch(session, url, {
      Range: req.headers.range || undefined
    }, req.headers);

    if (!upstream.ok && upstream.status !== 206) {
      const upstreamType = upstream.headers.get("content-type") || "";
      let detail = `Segment HTTP ${upstream.status}`;
      if (upstream.status === 403) {
        detail += ` (CDN رفض الطلب؛ Origin/Referer/X-Requested-With/User-Agent تم تمريرها)`;
        if (upstreamType.includes("text/html")) detail += " [HTML response]";
      }
      throw new Error(detail);
    }

    const contentType = upstream.headers.get("content-type") || "video/mp2t";
    const contentLength = Number(upstream.headers.get("content-length") || 0);
    if (contentLength > MAX_PROXY_BYTES) {
      return jsonError(res, 413, "المقطع أكبر من الحد المسموح للـproxy");
    }

    res.status(upstream.status);
    res.set({
      "Content-Type": contentType,
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
      "Accept-Ranges": "bytes"
    });

    for (const h of ["content-range", "content-length"]) {
      const v = upstream.headers.get(h);
      if (v) res.set(h, v);
    }

    if (!upstream.body) return res.end();

    const reader = upstream.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(Buffer.from(value));
      }
    } finally {
      try { reader.releaseLock(); } catch {}
    }
    res.end();
  } catch (e) {
    if (!res.headersSent) jsonError(res, 502, e.message);
    else res.end();
  }
});

// ---------------- Health ----------------

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "coursatk-railway-server",
    tokenConfigured: Boolean(AUTH_TOKEN),
    cryptoReady: Boolean(decryptPlaybackKey),
    sessions: sessions.size,
    now: new Date().toISOString()
  });
});

setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [id, s] of sessions) {
    if (s.createdAt < cutoff) sessions.delete(id);
  }
}, 60_000).unref();

// ---------------- Frontend (no client-side key crypto needed) ----------------

const INDEX_HTML = "<!doctype html>\n<html lang=\"ar\" dir=\"rtl\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover,maximum-scale=1\">\n<meta name=\"theme-color\" content=\"#0a0b0f\">\n<title>Coursatk</title>\n<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n<link href=\"https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap\" rel=\"stylesheet\">\n<style>\n:root{\n  --bg:#07080c; --card:#12141c; --card2:#181b26; --line:rgba(255,255,255,.07);\n  --txt:#eef0f6; --muted:#8b93a7; --green:#22c55e; --green2:#16a34a;\n  --orange:#f59e0b; --blue:#38bdf8; --danger:#ef4444; --radius:18px;\n  --shadow:0 18px 50px rgba(0,0,0,.45);\n}\n*{box-sizing:border-box}\nhtml,body{margin:0;min-height:100%;background:var(--bg);color:var(--txt);font-family:Cairo,system-ui,sans-serif;-webkit-tap-highlight-color:transparent}\nbody{overflow-x:hidden}\n.bg-glow{position:fixed;inset:0;pointer-events:none;z-index:0;background:\n  radial-gradient(900px 500px at 80% -10%,rgba(34,197,94,.12),transparent 55%),\n  radial-gradient(700px 400px at 10% 20%,rgba(56,189,248,.08),transparent 50%),\n  linear-gradient(180deg,#0b0d14,#07080c 40%)}\n#app{position:relative;z-index:1;min-height:100vh;padding:18px 14px 110px;max-width:1100px;margin:0 auto}\n\n/* Hero */\n.hero{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px;animation:rise .5s ease both}\n.hero-card{flex:1;padding:16px 18px;border-radius:22px;background:linear-gradient(145deg,rgba(24,28,40,.95),rgba(12,14,20,.98));border:1px solid var(--line);box-shadow:var(--shadow)}\n.hero-title{font-size:22px;font-weight:800;letter-spacing:-.3px}\n.hero-sub{margin-top:4px;color:var(--muted);font-size:12px}\n.badge{display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:5px 10px;border-radius:999px;background:rgba(34,197,94,.12);color:#86efac;font-size:11px;font-weight:600}\n.badge i{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green);animation:pulse 1.8s infinite}\n\n/* Search */\n.search-wrap{margin:14px 0 8px;position:relative;animation:rise .55s ease both}\n.search-wrap input{width:100%;border:1px solid var(--line);background:rgba(255,255,255,.04);color:var(--txt);border-radius:14px;padding:13px 44px 13px 14px;font:600 14px Cairo;outline:none;transition:.2s}\n.search-wrap input:focus{border-color:rgba(34,197,94,.45);background:rgba(255,255,255,.06);box-shadow:0 0 0 3px rgba(34,197,94,.12)}\n.search-wrap .ico{position:absolute;left:14px;top:50%;transform:translateY(-50%);opacity:.5;font-size:15px}\n\n/* Breadcrumb */\n.crumbs{display:flex;align-items:center;gap:6px;overflow-x:auto;padding:6px 2px 12px;scrollbar-width:none;animation:rise .45s ease both}\n.crumbs::-webkit-scrollbar{display:none}\n.crumb{white-space:nowrap;padding:6px 11px;border-radius:999px;font-size:11px;color:var(--muted);background:rgba(255,255,255,.04);border:1px solid transparent}\n.crumb.link{cursor:pointer}\n.crumb.link:hover{color:#bbf7d0;border-color:rgba(34,197,94,.25)}\n.crumb.cur{color:#86efac;background:rgba(34,197,94,.12);font-weight:700}\n.sep{color:#3a4155;font-size:11px}\n\n/* Section */\n.section{display:flex;align-items:center;justify-content:space-between;margin:8px 2px 12px}\n.section h2{margin:0;font-size:13px;font-weight:800;color:var(--muted);letter-spacing:.4px;text-transform:uppercase}\n.section span{font-size:11px;color:#6b7280}\n\n/* Grid cards */\n.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}\n@media(min-width:640px){.grid{grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:14px}}\n.card{position:relative;border-radius:var(--radius);overflow:hidden;background:var(--card);border:1px solid var(--line);cursor:pointer;transition:transform .22s cubic-bezier(.2,.8,.2,1),box-shadow .22s,border-color .22s;animation:cardIn .45s ease both;box-shadow:0 8px 24px rgba(0,0,0,.25)}\n.card:hover{transform:translateY(-4px);border-color:rgba(34,197,94,.28);box-shadow:0 16px 40px rgba(0,0,0,.4)}\n.card:active{transform:scale(.98)}\n.card-media{position:relative;aspect-ratio:16/10;background:#0d1018;overflow:hidden}\n.card-media img{width:100%;height:100%;object-fit:cover;display:block;transition:transform .45s ease}\n.card:hover .card-media img{transform:scale(1.06)}\n.card-media .ph{width:100%;height:100%;display:grid;place-items:center;font-size:34px;background:linear-gradient(135deg,#1a1f2e,#0e121b);color:#4b5563}\n.card-media .overlay{position:absolute;inset:0;background:linear-gradient(180deg,transparent 40%,rgba(0,0,0,.75))}\n.card-body{padding:11px 12px 13px}\n.card-title{font-size:13px;font-weight:700;line-height:1.35;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;min-height:2.7em}\n.card-meta{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}\n.chip{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:8px;font-size:10px;font-weight:600;background:rgba(255,255,255,.06);color:#aeb6c8}\n.chip.g{background:rgba(34,197,94,.15);color:#86efac}\n.chip.o{background:rgba(245,158,11,.15);color:#fcd34d}\n.chip.b{background:rgba(56,189,248,.14);color:#7dd3fc}\n.progress-bar{position:absolute;left:0;right:0;bottom:0;height:3px;background:rgba(255,255,255,.08)}\n.progress-bar > i{display:block;height:100%;background:linear-gradient(90deg,var(--green),#4ade80);border-radius:0 2px 2px 0}\n\n/* List cards (videos) */\n.list{display:flex;flex-direction:column;gap:10px}\n.vcard{display:flex;gap:12px;align-items:center;padding:10px;border-radius:16px;background:var(--card);border:1px solid var(--line);cursor:pointer;transition:.2s;animation:cardIn .4s ease both}\n.vcard:hover{border-color:rgba(34,197,94,.3);background:var(--card2);transform:translateX(-2px)}\n.vcard.accent{border-color:rgba(34,197,94,.25)}\n.vthumb{position:relative;width:88px;height:58px;border-radius:12px;overflow:hidden;flex-shrink:0;background:#0d1018}\n.vthumb img{width:100%;height:100%;object-fit:cover}\n.vthumb .ph{width:100%;height:100%;display:grid;place-items:center;font-size:22px;background:linear-gradient(135deg,#1a2030,#0c1018)}\n.vthumb .play{position:absolute;inset:0;display:grid;place-items:center;background:rgba(0,0,0,.25);color:#fff;font-size:16px;opacity:0;transition:.2s}\n.vcard:hover .play{opacity:1}\n.vbody{flex:1;min-width:0}\n.vtitle{font-size:13px;font-weight:700;line-height:1.35;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}\n.vmeta{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}\n.vact{flex-shrink:0}\n.btn{border:0;border-radius:12px;padding:9px 12px;font:700 12px Cairo;cursor:pointer;transition:.2s;display:inline-flex;align-items:center;gap:5px}\n.btn:active{transform:scale(.96)}\n.btn-p{background:linear-gradient(135deg,var(--green),var(--green2));color:#fff;box-shadow:0 6px 18px rgba(34,197,94,.28)}\n.btn-p:hover{filter:brightness(1.08)}\n.btn-s{background:rgba(255,255,255,.07);color:#d1d5db}\n.btn:disabled{opacity:.5;cursor:not-allowed}\n\n/* States */\n.state{text-align:center;padding:50px 20px;color:var(--muted);animation:rise .4s ease}\n.state .ico{font-size:42px;margin-bottom:8px;opacity:.7}\n.state h3{margin:0 0 6px;color:#c5cad8;font-size:16px}\n.state p{margin:0 auto;max-width:280px;font-size:12px;line-height:1.6}\n.skel{border-radius:var(--radius);height:170px;background:linear-gradient(90deg,rgba(255,255,255,.03),rgba(255,255,255,.07),rgba(255,255,255,.03));background-size:200% 100%;animation:shimmer 1.3s infinite}\n.skel.row{height:78px;margin-bottom:10px}\n\n/* FAB */\n#fab{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);z-index:50;display:flex;gap:8px;padding:8px;border-radius:999px;background:rgba(12,14,20,.88);border:1px solid var(--line);backdrop-filter:blur(16px);box-shadow:0 12px 40px rgba(0,0,0,.5)}\n#fab button{width:46px;height:46px;border-radius:50%;border:0;background:rgba(255,255,255,.06);color:#fff;font-size:18px;cursor:pointer}\n#fab button.main{width:54px;height:54px;background:linear-gradient(135deg,var(--green),var(--green2));box-shadow:0 8px 24px rgba(34,197,94,.4)}\n#fab button:active{transform:scale(.92)}\n\n/* Toast */\n.toast{position:fixed;top:18px;left:50%;transform:translateX(-50%) translateY(-120%);z-index:200;background:rgba(18,20,28,.96);border:1px solid var(--line);color:#fff;padding:12px 16px;border-radius:14px;font-size:13px;font-weight:600;box-shadow:var(--shadow);transition:transform .35s cubic-bezier(.32,.72,0,1);max-width:90vw}\n.toast.show{transform:translateX(-50%) translateY(0)}\n\n/* Player overlay */\n#player{position:fixed;inset:0;z-index:100;background:rgba(0,0,0,.92);display:none;align-items:center;justify-content:center;padding:0;backdrop-filter:blur(8px);animation:fadeIn .25s ease}\n#player.open{display:flex}\n.pshell{width:100%;max-width:1100px;height:100%;max-height:100vh;display:flex;flex-direction:column;background:#000;overflow:hidden}\n@media(min-width:800px){.pshell{height:auto;max-height:94vh;border-radius:18px;box-shadow:0 30px 80px rgba(0,0,0,.7);margin:16px}}\n.phead{display:flex;align-items:center;gap:10px;padding:10px 12px;background:#0a0a0a;flex-shrink:0}\n.ptitle{flex:1;min-width:0;font-size:14px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n.pbtn{width:40px;height:40px;border:0;border-radius:12px;background:#1a1a1a;color:#fff;cursor:pointer;font-size:15px}\n.pvideo-wrap{position:relative;flex:1;min-height:0;background:#000;display:flex;align-items:center;justify-content:center}\n@media(min-width:800px){.pvideo-wrap{aspect-ratio:16/9;flex:0 1 auto}}\n.pvideo{width:100%;height:100%;object-fit:contain;background:#000;display:block}\n.pstart{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;background:#000;z-index:4}\n.bigplay{width:88px;height:88px;border:0;border-radius:50%;background:rgba(255,255,255,.12);color:#fff;font-size:36px;cursor:pointer;box-shadow:0 0 0 1px rgba(255,255,255,.15);display:grid;place-items:center;padding-left:6px;transition:.2s}\n.bigplay:hover{background:rgba(34,197,94,.35);transform:scale(1.05)}\n.ploading{position:absolute;inset:0;z-index:5;display:none;flex-direction:column;align-items:center;justify-content:center;gap:12px;background:rgba(0,0,0,.85);color:#fff}\n.spinner{width:36px;height:36px;border:3px solid rgba(255,255,255,.15);border-top-color:#fff;border-radius:50%;animation:spin .75s linear infinite}\n.perror{display:none;position:absolute;left:12px;right:12px;bottom:12px;z-index:8;padding:12px;border-radius:12px;background:rgba(127,20,20,.95);color:#fff;font-size:12px;line-height:1.55}\n.pbar{display:flex;align-items:center;gap:8px;padding:8px 12px;background:#0a0a0a;flex-shrink:0;flex-wrap:wrap}\n.pstat{flex:1;min-width:100px;font-size:11px;color:#9ca3af}\n.ptime,.ppct{font-size:11px;color:#fff;font-variant-numeric:tabular-nums;direction:ltr}\n.quality{position:relative}\n.quality select{appearance:none;border:1px solid rgba(255,255,255,.1);background:#161616;color:#fff;border-radius:10px;padding:8px 28px 8px 10px;font:600 11px Cairo;cursor:pointer;outline:none}\n.quality::after{content:'▾';position:absolute;left:10px;top:50%;transform:translateY(-50%);font-size:10px;color:#9ca3af;pointer-events:none}\n.speed select{appearance:none;border:1px solid rgba(255,255,255,.1);background:#161616;color:#fff;border-radius:10px;padding:8px 10px;font:600 11px Cairo;cursor:pointer;outline:none}\n\n@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}\n@keyframes cardIn{from{opacity:0;transform:translateY(12px) scale(.98)}to{opacity:1;transform:none}}\n@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}\n@keyframes spin{to{transform:rotate(360deg)}}\n@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}\n@keyframes fadeIn{from{opacity:0}to{opacity:1}}\n.card:nth-child(1){animation-delay:.02s}.card:nth-child(2){animation-delay:.05s}.card:nth-child(3){animation-delay:.08s}\n.card:nth-child(4){animation-delay:.11s}.card:nth-child(5){animation-delay:.14s}.card:nth-child(6){animation-delay:.17s}\n</style>\n</head>\n<body>\n<div class=\"bg-glow\"></div>\n<div id=\"app\">\n  <div class=\"hero\">\n    <div class=\"hero-card\">\n      <div class=\"hero-title\">Coursatk</div>\n      <div class=\"hero-sub\">بث HLS • فك تشفير على السيرفر • سجل مشاهدة</div>\n      <div class=\"badge\"><i></i> جاهز للتشغيل</div>\n    </div>\n  </div>\n  <div class=\"search-wrap\">\n    <span class=\"ico\">⌕</span>\n    <input id=\"search\" type=\"search\" placeholder=\"ابحث في القائمة الحالية…\" autocomplete=\"off\">\n  </div>\n  <div class=\"crumbs\" id=\"crumbs\"></div>\n  <div id=\"content\"></div>\n</div>\n\n<div id=\"fab\">\n  <button type=\"button\" id=\"btn-home\" title=\"الرئيسية\">⌂</button>\n  <button type=\"button\" class=\"main\" id=\"btn-back\" title=\"رجوع\">←</button>\n</div>\n\n<div id=\"player\">\n  <div class=\"pshell\">\n    <div class=\"phead\">\n      <div class=\"ptitle\" id=\"ptitle\">فيديو</div>\n      <button class=\"pbtn\" id=\"pclose\" type=\"button\">✕</button>\n    </div>\n    <div class=\"pvideo-wrap\">\n      <video class=\"pvideo\" id=\"pvideo\" playsinline controls preload=\"none\"></video>\n      <div class=\"pstart\" id=\"pstart\">\n        <button class=\"bigplay\" id=\"pbig\" type=\"button\">▶</button>\n        <div style=\"color:#aaa;font-size:12px\">اضغط تشغيل لبدء الجلب</div>\n      </div>\n      <div class=\"ploading\" id=\"ploading\"><div class=\"spinner\"></div><div id=\"pload-txt\">جاري التجهيز…</div></div>\n      <div class=\"perror\" id=\"perror\"></div>\n    </div>\n    <div class=\"pbar\">\n      <div class=\"pstat\" id=\"pstat\">في انتظار التشغيل</div>\n      <div class=\"ptime\" id=\"ptime\">0:00 / --:--</div>\n      <div class=\"ppct\" id=\"ppct\">0%</div>\n      <div class=\"quality\">\n        <select id=\"pquality\" title=\"الجودة\"><option value=\"-1\">جودة تلقائي</option></select>\n      </div>\n      <div class=\"speed\">\n        <select id=\"pspeed\" title=\"السرعة\">\n          <option value=\"0.75\">0.75×</option>\n          <option value=\"1\" selected>1×</option>\n          <option value=\"1.25\">1.25×</option>\n          <option value=\"1.5\">1.5×</option>\n          <option value=\"2\">2×</option>\n        </select>\n      </div>\n    </div>\n  </div>\n</div>\n\n<div class=\"toast\" id=\"toast\"></div>\n\n<script src=\"https://cdn.jsdelivr.net/npm/hls.js@1.6.15/dist/hls.min.js\"></script>\n<script>\n(function(){\n'use strict';\nconst YEAR_ID = 4;\nconst HP = 'coursatk_watch_v6_';\nconst S = { stack:[], cache:{}, view:'subjects', player:null, filter:'' };\n\nconst $ = id => document.getElementById(id);\nconst content = $('content');\nconst fmt = s => {\n  s = Math.floor(+s||0); const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),x=s%60;\n  return h? h+':'+String(m).padStart(2,'0')+':'+String(x).padStart(2,'0') : m+':'+String(x).padStart(2,'0');\n};\nconst haptic = () => { try{ navigator.vibrate&&navigator.vibrate(8)}catch{} };\nconst toast = (msg, ms=2800) => {\n  const t=$('toast'); t.textContent=msg; t.classList.add('show');\n  clearTimeout(toast._t); toast._t=setTimeout(()=>t.classList.remove('show'), ms);\n};\nconst img = (url, cls='ph') => url\n  ? '<img src=\"'+url+'\" alt=\"\" loading=\"lazy\" onerror=\"this.parentNode.innerHTML=\\\\'<div class=ph>🎬</div>\\\\'\">'\n  : '<div class=\"'+cls+'\">🎬</div>';\n\nfunction hk(id){ return HP+String(id) }\nfunction getW(id){ try{return JSON.parse(localStorage.getItem(hk(id))||'null')}catch{return null} }\nfunction setW(id,st){ try{localStorage.setItem(hk(id),JSON.stringify({videoId:String(id),currentTime:+(st.currentTime||0),duration:+(st.duration||0),percent:+(st.percent||0),watched:!!st.watched,updatedAt:Date.now()}))}catch{} }\n\nasync function api(path){\n  const r = await fetch(path,{headers:{Accept:'application/json'},credentials:'same-origin',cache:'no-store'});\n  let d; try{d=await r.json()}catch{throw new Error('رد غير صالح ('+r.status+')')}\n  if(!r.ok) throw new Error(d?.message||('HTTP '+r.status));\n  return d;\n}\n\nfunction skel(n=6, row=false){\n  const f=document.createDocumentFragment();\n  if(row){ for(let i=0;i<n;i++){ const d=document.createElement('div'); d.className='skel row'; f.appendChild(d)} content.innerHTML=''; content.appendChild(f); return }\n  const g=document.createElement('div'); g.className='grid';\n  for(let i=0;i<n;i++){ const d=document.createElement('div'); d.className='skel'; g.appendChild(d)}\n  content.innerHTML=''; content.appendChild(g);\n}\nfunction empty(ico,title,desc){\n  content.innerHTML='<div class=\"state\"><div class=\"ico\">'+ico+'</div><h3>'+title+'</h3>'+(desc?'<p>'+desc+'</p>':'')+'</div>';\n}\nfunction err(msg, retry){\n  content.innerHTML='<div class=\"state\"><div class=\"ico\">⚠️</div><h3>حدث خطأ</h3><p>'+msg+'</p><p style=\"margin-top:12px\"><button class=\"btn btn-p\" id=\"retry\">إعادة المحاولة</button></p></div>';\n  if(retry) $('retry').onclick=retry;\n}\n\nfunction crumbs(){\n  const el=$('crumbs'); el.innerHTML='';\n  const items=[{label:'الرئيسية',i:0}, ...S.stack.map((x,i)=>({label:x.label,i:i+1}))];\n  items.forEach((c,idx)=>{\n    if(idx){ const s=document.createElement('span'); s.className='sep'; s.textContent='›'; el.appendChild(s) }\n    const b=document.createElement('span'); b.textContent=c.label;\n    b.className='crumb '+(idx===items.length-1?'cur':'link');\n    if(idx<items.length-1) b.onclick=()=>{ haptic(); goTo(c.i) };\n    el.appendChild(b);\n  });\n}\n\nfunction goTo(index){\n  if(index===0){ S.stack=[]; crumbs(); loadSubjects(true); return }\n  S.stack=S.stack.slice(0,index); crumbs();\n  const t=S.stack[S.stack.length-1];\n  if(!t) return loadSubjects(true);\n  nav(t.view);\n}\nfunction goBack(){\n  if(!S.stack.length){ loadSubjects(true); return }\n  S.stack.pop(); crumbs();\n  const p=S.stack[S.stack.length-1];\n  p? nav(p.view) : loadSubjects(true);\n}\nfunction nav(view){\n  if(view==='teachers'){ const r=S.stack[0]?._ref; r?loadTeachers(r,false):loadSubjects(true) }\n  else if(view==='chapters'){ const r=S.stack[1]?._ref; r?loadChapters(r,false):loadSubjects(true) }\n  else if(view==='lectures'){ const r=S.stack[2]?._ref; r?loadLectures(r,false):loadSubjects(true) }\n  else if(view==='content'){ const r=S.stack[3]?._ref; r?loadContent(r,false):loadSubjects(true) }\n  else loadSubjects(true);\n}\nfunction push(label, view, ref){\n  S.stack.push({label, view, _ref:ref}); crumbs();\n}\n\nfunction matchFilter(text){\n  const q=(S.filter||'').trim().toLowerCase();\n  if(!q) return true;\n  return String(text||'').toLowerCase().includes(q);\n}\n\n/* -------- Views -------- */\nasync function loadSubjects(reset){\n  if(reset) S.stack=[]; S.view='subjects'; crumbs(); skel(8);\n  try{\n    const res=await api('/api/subjects/'+YEAR_ID);\n    const list=res.data||[]; S.cache.subjects=list; renderSubjects(list);\n  }catch(e){ err(e.message, ()=>loadSubjects(reset)) }\n}\nfunction renderSubjects(list){\n  const filtered=list.filter(s=>matchFilter(s.name));\n  if(!filtered.length) return empty('📚','لا توجد مواد', S.filter?'لا نتائج للبحث':'');\n  const sec=document.createElement('div'); sec.className='section';\n  sec.innerHTML='<h2>المواد</h2><span>'+filtered.length+'</span>';\n  const g=document.createElement('div'); g.className='grid';\n  filtered.forEach(s=>{\n    const c=document.createElement('div'); c.className='card';\n    c.innerHTML='<div class=\"card-media\">'+(s.image_url?'<img src=\"'+s.image_url+'\" alt=\"\" loading=\"lazy\" onerror=\"this.parentNode.innerHTML=\\\\'<div class=ph>📘</div>\\\\'\">':'<div class=\"ph\">📘</div>')+'<div class=\"overlay\"></div></div><div class=\"card-body\"><div class=\"card-title\">'+esc(s.name)+'</div><div class=\"card-meta\"><span class=\"chip b\">#'+s.id+'</span></div></div>';\n    c.onclick=()=>{ haptic(); loadTeachers(s,true) };\n    g.appendChild(c);\n  });\n  content.innerHTML=''; content.appendChild(sec); content.appendChild(g);\n}\n\nasync function loadTeachers(subject, pushFlag){\n  if(pushFlag) push(subject.name,'teachers',subject);\n  S.view='teachers'; skel(6);\n  try{\n    const res=await api('/api/subjects/'+subject.id+'/teachers');\n    const teachers=res.data?.teachers||res.data||[]; renderTeachers(teachers, subject);\n  }catch(e){ err(e.message, ()=>loadTeachers(subject,false)) }\n}\nfunction renderTeachers(list, subject){\n  const filtered=list.filter(t=>matchFilter(t.name));\n  if(!filtered.length) return empty('👨‍🏫','لا يوجد مدرسين');\n  const sec=document.createElement('div'); sec.className='section';\n  sec.innerHTML='<h2>مدرسين '+esc(subject.name)+'</h2><span>'+filtered.length+'</span>';\n  const g=document.createElement('div'); g.className='grid';\n  filtered.forEach(t=>{\n    const c=document.createElement('div'); c.className='card';\n    c.innerHTML='<div class=\"card-media\">'+(t.image_url?'<img src=\"'+t.image_url+'\" alt=\"\" loading=\"lazy\" onerror=\"this.parentNode.innerHTML=\\\\'<div class=ph>👨‍🏫</div>\\\\'\">':'<div class=\"ph\">👨‍🏫</div>')+'<div class=\"overlay\"></div></div><div class=\"card-body\"><div class=\"card-title\">'+esc(t.name)+'</div><div class=\"card-meta\"><span class=\"chip g\">'+(t.chapter_count||0)+' شابتر</span></div></div>';\n    c.onclick=()=>{ haptic(); loadChapters(t,true) };\n    g.appendChild(c);\n  });\n  content.innerHTML=''; content.appendChild(sec); content.appendChild(g);\n}\n\nasync function loadChapters(teacher, pushFlag){\n  if(pushFlag) push(teacher.name,'chapters',teacher);\n  S.view='chapters'; skel(6);\n  try{\n    const res=await api('/api/teachers/'+teacher.id+'/chapters');\n    renderChapters(res.data||[], teacher);\n  }catch(e){ err(e.message, ()=>loadChapters(teacher,false)) }\n}\nfunction renderChapters(list, teacher){\n  const filtered=list.filter(c=>matchFilter(c.name));\n  if(!filtered.length) return empty('📖','لا يوجد شباتر');\n  const sec=document.createElement('div'); sec.className='section';\n  sec.innerHTML='<h2>شباتر</h2><span>'+filtered.length+'</span>';\n  const g=document.createElement('div'); g.className='grid';\n  filtered.forEach(c=>{\n    const card=document.createElement('div'); card.className='card';\n    card.innerHTML='<div class=\"card-media\">'+(c.image_url?'<img src=\"'+c.image_url+'\" alt=\"\" loading=\"lazy\" onerror=\"this.parentNode.innerHTML=\\\\'<div class=ph>📖</div>\\\\'\">':'<div class=\"ph\">📖</div>')+'<div class=\"overlay\"></div></div><div class=\"card-body\"><div class=\"card-title\">'+esc(c.name)+'</div><div class=\"card-meta\"><span class=\"chip g\">'+(c.lecture_count||0)+' محاضرة</span></div></div>';\n    card.onclick=()=>{ haptic(); loadLectures(c,true) };\n    g.appendChild(card);\n  });\n  content.innerHTML=''; content.appendChild(sec); content.appendChild(g);\n}\n\nasync function loadLectures(chapter, pushFlag){\n  if(pushFlag) push(chapter.name,'lectures',chapter);\n  S.view='lectures'; skel(6);\n  try{\n    const res=await api('/api/chapters/'+chapter.id+'/lectures');\n    renderLectures(res.data||[], chapter);\n  }catch(e){ err(e.message, ()=>loadLectures(chapter,false)) }\n}\nfunction renderLectures(list, chapter){\n  const filtered=list.filter(l=>matchFilter(l.name));\n  if(!filtered.length) return empty('🎓','لا يوجد محاضرات');\n  const sec=document.createElement('div'); sec.className='section';\n  sec.innerHTML='<h2>محاضرات</h2><span>'+filtered.length+'</span>';\n  const g=document.createElement('div'); g.className='grid';\n  filtered.forEach(l=>{\n    const c=document.createElement('div'); c.className='card';\n    c.innerHTML='<div class=\"card-media\">'+(l.image_url?'<img src=\"'+l.image_url+'\" alt=\"\" loading=\"lazy\" onerror=\"this.parentNode.innerHTML=\\\\'<div class=ph>🎓</div>\\\\'\">':'<div class=\"ph\">🎓</div>')+'<div class=\"overlay\"></div></div><div class=\"card-body\"><div class=\"card-title\">'+esc(l.name)+'</div><div class=\"card-meta\"><span class=\"chip b\">'+(l.video_count||0)+' فيديو</span>'+(l.pdf_count?'<span class=\"chip\">'+(l.pdf_count)+' PDF</span>':'')+'</div></div>';\n    c.onclick=()=>{ haptic(); loadContent(l,true) };\n    g.appendChild(c);\n  });\n  content.innerHTML=''; content.appendChild(sec); content.appendChild(g);\n}\n\nasync function loadContent(lecture, pushFlag){\n  if(pushFlag) push(lecture.name,'content',lecture);\n  S.view='content'; skel(5,true);\n  try{\n    const res=await api('/api/lectures/'+lecture.id+'/content');\n    const d=res.data||{};\n    renderContent({videos:d.videos||[],pdfs:d.pdfs||[],exams:d.exams||[]}, lecture);\n  }catch(e){ err(e.message, ()=>loadContent(lecture,false)) }\n}\nfunction renderContent(data, lecture){\n  const q=(S.filter||'').trim().toLowerCase();\n  const videos=data.videos.filter(v=>!q||String(v.title).toLowerCase().includes(q));\n  const frag=document.createDocumentFragment();\n\n  if(videos.length){\n    const sec=document.createElement('div'); sec.className='section';\n    sec.innerHTML='<h2>🎬 فيديوهات</h2><span>'+videos.length+'</span>';\n    frag.appendChild(sec);\n    const list=document.createElement('div'); list.className='list';\n    videos.forEach(v=>{\n      const st=getW(v.id); const pct=Math.round(st?.percent||0);\n      const card=document.createElement('div'); card.className='vcard'+(pct>0||st?.watched?' accent':'');\n      card.dataset.vid=String(v.id);\n      const chips=[];\n      if(v.duration||v.duration_seconds) chips.push('<span class=\"chip b\">'+fmt(v.duration||v.duration_seconds)+'</span>');\n      if(st?.watched) chips.push('<span class=\"chip g sw-watch\">✓ تمت المشاهدة</span>');\n      else if(pct>0) chips.push('<span class=\"chip o sw-watch\">'+pct+'%</span>');\n      else chips.push('<span class=\"chip sw-watch\">لم تبدأ</span>');\n      const label=st?.watched?'▶️ إعادة':(pct>0?'▶️ متابعة':'▶️ تشغيل');\n      card.innerHTML='<div class=\"vthumb\"><div class=\"ph\">▶</div><div class=\"play\">▶</div>'+(pct>0?'<div class=\"progress-bar\"><i style=\"width:'+pct+'%\"></i></div>':'')+'</div><div class=\"vbody\"><div class=\"vtitle\">'+esc(v.title)+'</div><div class=\"vmeta\">'+chips.join('')+'</div></div><div class=\"vact\"><button class=\"btn btn-p sw-act\">'+label+'</button></div>';\n      const play=()=>{ haptic(); openPlayer(v.id, v.title) };\n      card.onclick=play;\n      card.querySelector('.sw-act').onclick=e=>{ e.stopPropagation(); play() };\n      list.appendChild(card);\n    });\n    frag.appendChild(list);\n  }\n\n  if(data.pdfs.length){\n    const sec=document.createElement('div'); sec.className='section';\n    sec.innerHTML='<h2>📄 ملفات PDF</h2><span>'+data.pdfs.length+'</span>';\n    frag.appendChild(sec);\n    const list=document.createElement('div'); list.className='list';\n    data.pdfs.forEach(p=>{\n      const card=document.createElement('div'); card.className='vcard';\n      card.innerHTML='<div class=\"vthumb\"><div class=\"ph\">📄</div></div><div class=\"vbody\"><div class=\"vtitle\">'+esc(p.title)+'</div></div><div class=\"vact\"><button class=\"btn btn-s\">فتح</button></div>';\n      card.onclick=()=>window.open(p.url,'_blank');\n      list.appendChild(card);\n    });\n    frag.appendChild(list);\n  }\n\n  if(data.exams.length){\n    const sec=document.createElement('div'); sec.className='section';\n    sec.innerHTML='<h2>📝 امتحانات</h2><span>'+data.exams.length+'</span>';\n    frag.appendChild(sec);\n    const list=document.createElement('div'); list.className='list';\n    data.exams.forEach(e=>{\n      const card=document.createElement('div'); card.className='vcard';\n      card.innerHTML='<div class=\"vthumb\"><div class=\"ph\">📝</div></div><div class=\"vbody\"><div class=\"vtitle\">'+esc(e.title)+'</div><div class=\"vmeta\"><span class=\"chip o\">'+(e.question_count||0)+' سؤال</span><span class=\"chip b\">'+(e.duration_minutes||0)+' د</span></div></div>';\n      list.appendChild(card);\n    });\n    frag.appendChild(list);\n  }\n\n  if(!videos.length && !data.pdfs.length && !data.exams.length) return empty('📭','لا يوجد محتوى');\n  content.innerHTML=''; content.appendChild(frag);\n}\n\nfunction esc(s){ return String(s||'').replace(/[&<>\"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[m])) }\n\n/* -------- Player -------- */\nfunction destroyPlayer(){\n  const p=S.player; if(!p) return;\n  p.destroyed=true;\n  try{p.hls?.stopLoad()}catch{}\n  try{p.hls?.detachMedia()}catch{}\n  try{p.hls?.destroy()}catch{}\n  try{p.video.pause()}catch{}\n  try{p.video.removeAttribute('src'); p.video.load()}catch{}\n  $('player').classList.remove('open');\n  S.player=null;\n}\n\nfunction openPlayer(videoId, title){\n  destroyPlayer();\n  const video=$('pvideo');\n  const player={\n    videoId, title, video, hls:null, destroyed:false, started:false,\n    duration:0, lastSaved:0, saved:getW(videoId)\n  };\n  S.player=player;\n  $('ptitle').textContent=title||'فيديو';\n  $('pstat').textContent='في انتظار التشغيل';\n  $('ptime').textContent='0:00 / --:--';\n  $('ppct').textContent='0%';\n  $('perror').style.display='none';\n  $('ploading').style.display='none';\n  $('pstart').style.display='flex';\n  $('pquality').innerHTML='<option value=\"-1\">جودة تلقائي</option>';\n  $('pspeed').value='1';\n  video.playbackRate=1;\n  $('player').classList.add('open');\n\n  const start=()=>{ if(player.destroyed||player.started) return; player.started=true; $('pstart').style.display='none'; runHls(player) };\n  $('pbig').onclick=e=>{ e.preventDefault(); haptic(); start() };\n  $('pclose').onclick=destroyPlayer;\n  $('player').onclick=e=>{ if(e.target===$('player')) destroyPlayer() };\n\n  video.ontimeupdate=()=>{\n    if(player.destroyed) return;\n    const d=Number(video.duration), t=Number(video.currentTime)||0;\n    const real=Number.isFinite(d)&&d>0?d:player.duration;\n    const pct=real>0?Math.min(100,t/real*100):0;\n    $('ptime').textContent=fmt(t)+' / '+(fmt(real)||'--:--');\n    $('ppct').textContent=Math.round(pct)+'%';\n    if(Date.now()-player.lastSaved>=1000){\n      player.lastSaved=Date.now();\n      setW(videoId,{currentTime:t,duration:real,percent:pct,watched:pct>=90});\n      updCard(videoId);\n    }\n  };\n  video.onplay=()=>{ if(!player.started) start(); $('pstat').textContent='يعمل' };\n  video.onpause=()=>{ if(!video.ended) $('pstat').textContent='متوقف' };\n  video.onended=()=>{\n    const d=Number(video.duration)||player.duration||0;\n    setW(videoId,{currentTime:d,duration:d,percent:100,watched:true});\n    $('ppct').textContent='100%'; $('pstat').textContent='تمت المشاهدة'; updCard(videoId);\n  };\n  video.onloadedmetadata=()=>{\n    if(player.saved?.currentTime>0){\n      try{ const d=video.duration||player.duration; const r=Math.min(Number(player.saved.currentTime), Math.max(0,d-0.5)); if(r>0) video.currentTime=r }catch{}\n    }\n  };\n  video.onerror=()=>{ if(!player.destroyed&&video.error) showPErr(player,'الفيديو لم يُشغّل') };\n\n  $('pspeed').onchange=()=>{ video.playbackRate=Number($('pspeed').value)||1 };\n  $('pquality').onchange=()=>{\n    if(!player.hls) return;\n    const v=Number($('pquality').value);\n    player.hls.currentLevel = v;\n    toast(v<0?'جودة تلقائي':'تم تغيير الجودة');\n  };\n}\n\nfunction showLoad(msg){ $('pload-txt').textContent=msg||'جاري التحميل…'; $('ploading').style.display='flex' }\nfunction hideLoad(){ $('ploading').style.display='none' }\nfunction showPErr(player,msg){ $('perror').textContent=msg||'خطأ'; $('perror').style.display='block'; hideLoad(); $('pstart').style.display='flex'; $('pstat').textContent='خطأ' }\n\nasync function runHls(player){\n  try{\n    showLoad('جاري جلب بيانات التشغيل…');\n    const res=await fetch('/api/play/'+encodeURIComponent(player.videoId),{method:'POST',headers:{Accept:'application/json'},credentials:'same-origin',cache:'no-store'});\n    let data=null; try{data=await res.json()}catch{}\n    if(!res.ok) throw new Error(data?.message||('Playback HTTP '+res.status));\n    if(!data?.success||!data?.data?.manifest_url) throw new Error('بيانات التشغيل ناقصة');\n    const manifestUrl=location.origin+data.data.manifest_url;\n\n    if(!window.Hls || !Hls.isSupported()){\n      player.video.src=manifestUrl; hideLoad();\n      try{ await player.video.play() }catch{ $('pstart').style.display='flex' }\n      return;\n    }\n\n    showLoad('جاري تجهيز المشغل…');\n    const hls=new Hls({\n      enableWorker:true, lowLatencyMode:false,\n      maxBufferLength:18, maxMaxBufferLength:18, maxBufferSize:2*1024*1024,\n      backBufferLength:8, capLevelToPlayerSize:true,\n      startPosition: player.saved?.currentTime>0 ? Number(player.saved.currentTime) : -1\n    });\n    player.hls=hls;\n\n    hls.on(Hls.Events.MANIFEST_PARSED, async (_, data)=>{\n      hideLoad();\n      // quality options\n      const sel=$('pquality');\n      sel.innerHTML='<option value=\"-1\">جودة تلقائي</option>';\n      (data.levels||[]).forEach((lv,i)=>{\n        const h=lv.height||0; const br=lv.bitrate? Math.round(lv.bitrate/1000)+'kbps' : '';\n        const label=(h? h+'p' : 'Level '+i)+(br?' · '+br:'');\n        const o=document.createElement('option'); o.value=String(i); o.textContent=label; sel.appendChild(o);\n      });\n      $('pstat').textContent='جاهز للتشغيل';\n      try{ await player.video.play() }catch{ $('pstart').style.display='flex'; $('pstat').textContent='اضغط تشغيل' }\n    });\n    hls.on(Hls.Events.LEVEL_LOADED, (_, d)=>{\n      const dur=Number(d?.details?.totalduration);\n      if(dur>0){ player.duration=dur; $('ptime').textContent='0:00 / '+fmt(dur) }\n    });\n    hls.on(Hls.Events.ERROR, (_, d)=>{\n      if(!d?.fatal) return;\n      if(d.type===Hls.ErrorTypes.NETWORK_ERROR){ $('pstat').textContent='إعادة الاتصال…'; try{hls.startLoad()}catch{}; return }\n      if(d.type===Hls.ErrorTypes.MEDIA_ERROR){ $('pstat').textContent='إصلاح المسار…'; try{hls.recoverMediaError()}catch{}; return }\n      showPErr(player, 'HLS: '+(d.details||'فشل'));\n    });\n    hls.loadSource(manifestUrl); hls.attachMedia(player.video);\n  }catch(e){\n    if(player.destroyed) return;\n    console.error(e); showPErr(player, e.message||'فشل التشغيل');\n  }\n}\n\nfunction updCard(videoId){\n  const card=document.querySelector('.vcard[data-vid=\"'+CSS.escape(String(videoId))+'\"]');\n  if(!card) return;\n  const st=getW(videoId); if(!st) return;\n  const pct=Math.round(st.percent||0);\n  const chip=card.querySelector('.sw-watch');\n  const btn=card.querySelector('.sw-act');\n  if(chip){ chip.textContent=st.watched?'✓ تمت المشاهدة':pct+'%'; chip.className='chip sw-watch '+(st.watched?'g':'o') }\n  if(btn) btn.textContent=st.watched?'▶️ إعادة':(pct>0?'▶️ متابعة':'▶️ تشغيل');\n  if(st.watched||pct>0) card.classList.add('accent');\n  let bar=card.querySelector('.progress-bar');\n  if(pct>0){\n    if(!bar){ bar=document.createElement('div'); bar.className='progress-bar'; bar.innerHTML='<i></i>'; card.querySelector('.vthumb')?.appendChild(bar) }\n    const i=bar.querySelector('i'); if(i) i.style.width=pct+'%';\n  }\n}\n\n/* -------- Wire -------- */\n$('btn-home').onclick=()=>{ haptic(); S.stack=[]; crumbs(); loadSubjects(true) };\n$('btn-back').onclick=()=>{ haptic(); goBack() };\n$('search').oninput=e=>{\n  S.filter=e.target.value||'';\n  if(S.view==='subjects') renderSubjects(S.cache.subjects||[]);\n  else if(S.view==='teachers'&&S.stack[0]?._ref) loadTeachers(S.stack[0]._ref,false);\n  else if(S.view==='chapters'&&S.stack[1]?._ref) loadChapters(S.stack[1]._ref,false);\n  else if(S.view==='lectures'&&S.stack[2]?._ref) loadLectures(S.stack[2]._ref,false);\n  else if(S.view==='content'&&S.stack[3]?._ref) loadContent(S.stack[3]._ref,false);\n};\n\ncrumbs();\nloadSubjects(true);\n})();\n</script>\n</body>\n</html>";

app.get("/", (_req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(INDEX_HTML);
});

app.use("/api", (_req, res) => jsonError(res, 404, "API route غير موجود"));

app.get("*", (_req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(INDEX_HTML);
});

// Boot
await loadDecryptionUtils();
app.listen(PORT, () => {
  console.log(`[Coursatk] listening on :${PORT} (server-side AES unwrap)`);
});
