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
const INDEX_HTML = `<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Coursatk</title>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
<style>
html,body{margin:0;min-height:100%;background:#050505;color:#fff;font-family:Cairo,system-ui,sans-serif}
#coursatk-server-page{min-height:100vh;background:radial-gradient(circle at top,#171717,#050505 42%)}
.server-hero{padding:28px 18px 20px;max-width:1100px;margin:auto}
.server-hero-card{border:1px solid rgba(255,255,255,.08);border-radius:22px;background:linear-gradient(145deg,#151515,#0a0a0a);padding:18px;box-shadow:0 18px 55px rgba(0,0,0,.4)}
.server-hero-title{font-size:20px;font-weight:800}
.server-hero-sub{margin-top:4px;color:#888;font-size:11px}
.server-hero-badge{display:inline-flex;margin-top:12px;padding:6px 10px;border-radius:999px;background:rgba(76,175,80,.12);color:#74e0a1;font-size:10px}
.server-open{margin-top:12px;border:0;border-radius:12px;padding:10px 14px;background:linear-gradient(135deg,#4CAF50,#388E3C);color:#fff;font:700 12px Cairo;cursor:pointer}
#sw-toggle{position:fixed;bottom:20px;right:20px;z-index:999998;width:62px;height:62px;border-radius:50%;border:none;background:linear-gradient(135deg,#4CAF50,#2E7D32);color:#fff;font-size:26px;cursor:pointer;box-shadow:0 8px 28px rgba(76,175,80,.45);display:flex;align-items:center;justify-content:center}
#sw-toggle.sw-active{background:linear-gradient(135deg,#f44336,#c62828)}
#sw-panel{position:fixed;left:0;right:0;bottom:0;z-index:999999;background:linear-gradient(180deg,rgba(20,22,28,.98),rgba(12,14,18,.99));backdrop-filter:blur(24px);border-top-left-radius:24px;border-top-right-radius:24px;border-top:1px solid rgba(255,255,255,.08);color:#fff;box-shadow:0 -20px 60px rgba(0,0,0,.9);transform:translateY(105%);transition:transform .42s cubic-bezier(.32,.72,0,1);max-height:88vh;display:flex;flex-direction:column;overflow:hidden}
#sw-panel.sw-open{transform:translateY(0)}
.sw-handle{width:100%;padding:10px 0 6px;display:flex;justify-content:center;cursor:grab}
.sw-handle::before{content:'';width:42px;height:4px;border-radius:4px;background:rgba(255,255,255,.18)}
.sw-header{display:flex;align-items:center;gap:10px;padding:4px 16px 12px}
.sw-icon-btn,.sw-close{width:38px;height:38px;border:none;border-radius:12px;background:rgba(255,255,255,.06);color:#ccc;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center}
.sw-icon-btn.sw-hidden{display:none}
.sw-brand{flex:1;min-width:0}
.sw-brand h3{margin:0;font-size:15px;font-weight:700}
.sw-brand p{margin:1px 0 0;font-size:10px;color:#6b7280}
.sw-breadcrumb{display:flex;align-items:center;gap:6px;padding:0 16px 12px;font-size:11px;color:#6b7280;overflow-x:auto}
.sw-breadcrumb span{white-space:nowrap;padding:3px 8px;border-radius:6px}
.sw-crumb-link{cursor:pointer;color:#9ca3af;background:rgba(255,255,255,.04)}
.sw-crumb-current{color:#4CAF50;font-weight:600}
.sw-sep{color:#374151;padding:0}
.sw-content{flex:1;overflow-y:auto;padding:0 12px 16px;min-height:120px}
.sw-section{display:flex;align-items:center;gap:8px;padding:14px 6px 8px;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase}
.sw-section::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,rgba(255,255,255,.08),transparent)}
.sw-card{display:flex;align-items:center;gap:12px;padding:14px;margin-bottom:8px;background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.05);border-radius:14px;cursor:pointer}
.sw-card-accent::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:linear-gradient(180deg,#4CAF50,#2E7D32)}
.sw-card{position:relative;overflow:hidden}
.sw-card-icon{width:40px;height:40px;border-radius:11px;background:linear-gradient(135deg,rgba(76,175,80,.18),rgba(76,175,80,.06));display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;border:1px solid rgba(76,175,80,.15)}
.sw-card-body{flex:1;min-width:0}
.sw-card-title{font-size:14px;font-weight:600;color:#e5e7eb;line-height:1.35;overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.sw-card-sub{font-size:11px;color:#6b7280;margin-top:3px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.sw-chip{display:inline-flex;padding:2px 7px;background:rgba(255,255,255,.06);border-radius:6px;font-size:10px;font-weight:500;color:#9ca3af}
.sw-chip-green{background:rgba(76,175,80,.15);color:#4CAF50}
.sw-chip-blue{background:rgba(33,150,243,.15);color:#64b5f6}
.sw-chip-orange{background:rgba(255,152,0,.15);color:#FFB74D}
.sw-btn{padding:8px 14px;border:none;border-radius:10px;font-weight:600;font-size:12px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;font-family:inherit}
.sw-btn-primary{background:linear-gradient(135deg,#4CAF50,#388E3C);color:#fff}
.sw-btn-secondary{background:rgba(255,255,255,.08);color:#d1d5db}
.sw-skeleton{background:linear-gradient(90deg,rgba(255,255,255,.04),rgba(255,255,255,.08),rgba(255,255,255,.04));background-size:200% 100%;animation:swShimmer 1.4s infinite;border-radius:14px;height:68px;margin-bottom:8px}
@keyframes swShimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.sw-state{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:48px 24px;text-align:center;color:#6b7280;gap:12px}
.sw-state-icon{font-size:42px;opacity:.6}
.sw-state-title{font-size:15px;font-weight:600;color:#9ca3af}
.sw-state-desc{font-size:12px;color:#6b7280;max-width:260px;line-height:1.5}
#sw-player-overlay{position:fixed;inset:0;z-index:1000001;background:#000;display:flex;align-items:center;justify-content:center}
.sw-player-shell{width:100%;max-width:1200px;height:100%;max-height:100vh;display:flex;flex-direction:column;background:#000}
.sw-player-head{min-height:54px;display:flex;align-items:center;gap:10px;padding:8px 12px;background:#070707;color:#fff}
.sw-player-title{flex:1;min-width:0;font-size:14px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sw-player-close{width:40px;height:40px;border:0;border-radius:12px;background:#181818;color:#fff;cursor:pointer;font-size:17px}
.sw-video-wrap{position:relative;width:100%;flex:1;min-height:0;background:#000;display:flex;align-items:center;justify-content:center}
.sw-video{width:100%;height:100%;display:block;background:#000;object-fit:contain}
.sw-player-start{position:absolute;inset:0;z-index:4;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:15px;background:#000}
.sw-big-play{width:92px;height:92px;border:0;border-radius:50%;background:rgba(255,255,255,.12);color:#fff;font-size:39px;cursor:pointer;display:grid;place-items:center;padding-left:7px}
.sw-start-text{color:#aaa;font-size:12px}
.sw-player-loading{position:absolute;inset:0;z-index:5;display:none;flex-direction:column;align-items:center;justify-content:center;gap:12px;background:rgba(0,0,0,.88);color:#fff;pointer-events:none}
.sw-spinner{width:34px;height:34px;border:3px solid rgba(255,255,255,.18);border-top-color:#fff;border-radius:50%;animation:swSpin .8s linear infinite}
@keyframes swSpin{to{transform:rotate(360deg)}}
.sw-player-error{display:none;position:absolute;z-index:8;left:12px;right:12px;bottom:12px;padding:11px 13px;border-radius:10px;background:rgba(125,18,18,.95);color:#fff;font-size:12px;line-height:1.6}
.sw-player-info{min-height:42px;display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;background:#070707;color:#999;font-size:10px}
.sw-player-time,.sw-player-progress{color:#fff;font-variant-numeric:tabular-nums}
.sw-pdf-hidden{display:none!important}
@media(min-width:700px){.sw-player-shell{height:auto;max-height:96vh;border-radius:16px}.sw-video-wrap{aspect-ratio:16/9;flex:0 1 auto}}
</style>
</head>
<body>
<div id="coursatk-server-page">
  <div class="server-hero">
    <div class="server-hero-card">
      <div class="server-hero-title">Coursatk</div>
      <div class="server-hero-sub">Server-side key unwrap • HLS • Railway</div>
      <div class="server-hero-badge">AES-128 decrypted on server</div>
      <br>
      <button class="server-open" id="server-open">فتح لوحة كورساتك</button>
    </div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/hls.js@1.6.15/dist/hls.min.js"></script>
<script>
(function(){
  'use strict';
  const CONFIG = { YEAR_ID: 4 };
  const HISTORY_PREFIX = 'coursatk_watch_v6_';
  const STATE = { view:'subjects', stack:[], cache:{}, ui:{visible:false}, player:null };

  const $ = id => document.getElementById(id);
  const el = (tag, cls, text) => { const e=document.createElement(tag); if(cls)e.className=cls; if(text!=null)e.textContent=text; return e; };
  function formatDuration(s){ if(!s)return''; const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=Math.floor(s%60); return h>0?\`\${h}:\${String(m).padStart(2,'0')}:\${String(sec).padStart(2,'0')}\`:\`\${m}:\${String(sec).padStart(2,'0')}\`; }
  function haptic(ms=8){ try{navigator.vibrate&&navigator.vibrate(ms)}catch{} }
  function historyKey(id){ return HISTORY_PREFIX+String(id); }
  function getWatchState(id){ try{return JSON.parse(localStorage.getItem(historyKey(id))||'null')}catch{return null} }
  function saveWatchState(id,st){ try{localStorage.setItem(historyKey(id),JSON.stringify({videoId:String(id),currentTime:+(st.currentTime||0),duration:+(st.duration||0),percent:+(st.percent||0),watched:!!st.watched,updatedAt:Date.now()}))}catch{} }

  async function apiGet(path){
    const res = await fetch(path,{headers:{Accept:'application/json'},credentials:'same-origin',cache:'no-store'});
    let data; try{data=await res.json()}catch{throw new Error('رد غير صالح (HTTP '+res.status+')')}
    if(!res.ok) throw new Error(data?.message||('HTTP '+res.status));
    return data;
  }

  // ---- Player (plain key from server — no DecryptionUtils needed) ----
  function destroyPlayer(){
    const p=STATE.player; if(!p)return;
    p.destroyed=true;
    try{p.hls?.stopLoad()}catch{}
    try{p.hls?.detachMedia()}catch{}
    try{p.hls?.destroy()}catch{}
    try{p.video?.pause()}catch{}
    try{p.video?.removeAttribute('src')}catch{}
    try{p.video?.load()}catch{}
    try{p.overlay?.remove()}catch{}
    STATE.player=null;
  }

  function createPlayerOverlay(videoId, title){
    destroyPlayer();
    const overlay=document.createElement('div');
    overlay.id='sw-player-overlay';
    overlay.innerHTML=\`
      <div class="sw-player-shell">
        <div class="sw-player-head">
          <div class="sw-player-title"></div>
          <button class="sw-player-close" type="button">✕</button>
        </div>
        <div class="sw-video-wrap">
          <video class="sw-video" playsinline controls preload="none"></video>
          <div class="sw-player-start">
            <button class="sw-big-play" type="button"><span>▶</span></button>
            <div class="sw-start-text">اضغط تشغيل لبدء جلب الفيديو</div>
          </div>
          <div class="sw-player-loading">
            <div class="sw-spinner"></div>
            <div class="sw-player-loading-text">جاري تجهيز الفيديو...</div>
          </div>
          <div class="sw-player-error"></div>
        </div>
        <div class="sw-player-info">
          <span class="sw-player-status">في انتظار التشغيل</span>
          <span class="sw-player-time">0:00 / --:--</span>
          <span class="sw-player-progress">0%</span>
        </div>
      </div>\`;
    document.body.appendChild(overlay);
    const video=overlay.querySelector('.sw-video');
    const titleEl=overlay.querySelector('.sw-player-title');
    const startLayer=overlay.querySelector('.sw-player-start');
    const bigPlay=overlay.querySelector('.sw-big-play');
    const loading=overlay.querySelector('.sw-player-loading');
    const loadingText=overlay.querySelector('.sw-player-loading-text');
    const errorEl=overlay.querySelector('.sw-player-error');
    const statusEl=overlay.querySelector('.sw-player-status');
    const timeEl=overlay.querySelector('.sw-player-time');
    const progressEl=overlay.querySelector('.sw-player-progress');
    titleEl.textContent=title||'فيديو';
    overlay.querySelector('.sw-player-close').onclick=destroyPlayer;
    overlay.addEventListener('click',e=>{if(e.target===overlay)destroyPlayer()});

    const player={videoId,title,overlay,video,startLayer,bigPlay,loading,loadingText,errorEl,statusEl,timeEl,progressEl,hls:null,destroyed:false,started:false,duration:0,lastSaved:0,savedState:getWatchState(videoId)};
    STATE.player=player;

    const start=()=>{if(player.destroyed||player.started)return;player.started=true;startLayer.style.display='none';startHLS(player)};
    bigPlay.onclick=e=>{e.preventDefault();e.stopPropagation();haptic();start()};
    video.addEventListener('play',()=>{if(!player.started)start();statusEl.textContent='يعمل'});
    video.addEventListener('pause',()=>{if(!video.ended)statusEl.textContent='متوقف مؤقتًا'});
    video.addEventListener('timeupdate',()=>{
      if(player.destroyed)return;
      const d=Number(video.duration),t=Number(video.currentTime)||0,real=Number.isFinite(d)&&d>0?d:player.duration;
      const pct=real>0?Math.min(100,t/real*100):0;
      timeEl.textContent=\`\${formatDuration(t)} / \${formatDuration(real)||'--:--'}\`;
      progressEl.textContent=\`\${Math.round(pct)}%\`;
      if(Date.now()-player.lastSaved>=1000){player.lastSaved=Date.now();saveWatchState(videoId,{currentTime:t,duration:real,percent:pct,watched:pct>=90});updateVideoCardProgress(videoId)}
    });
    video.addEventListener('durationchange',()=>{if(Number.isFinite(video.duration)&&video.duration>0){player.duration=video.duration}});
    video.addEventListener('loadedmetadata',()=>{
      if(player.savedState?.currentTime>0){try{const d=video.duration||player.duration;const r=Math.min(Number(player.savedState.currentTime),Math.max(0,d-.5));if(r>0)video.currentTime=r}catch{}}
    });
    video.addEventListener('ended',()=>{
      const d=Number(video.duration)||player.duration||0;
      saveWatchState(videoId,{currentTime:d,duration:d,percent:100,watched:true});
      progressEl.textContent='100%';statusEl.textContent='تمت المشاهدة';updateVideoCardProgress(videoId);
    });
    video.addEventListener('error',()=>{if(!player.destroyed&&video.error)showErr(player,'الفيديو لم يُشغّل')});
    return player;
  }

  function showLoad(p,m){p.loadingText.textContent=m||'جاري التحميل...';p.loading.style.display='flex'}
  function hideLoad(p){p.loading.style.display='none'}
  function showErr(p,m){p.errorEl.textContent=m||'خطأ';p.errorEl.style.display='block';p.loading.style.display='none';p.startLayer.style.display='flex';p.statusEl.textContent='خطأ في التشغيل'}

  async function startHLS(player){
    try{
      showLoad(player,'جاري جلب بيانات التشغيل...');
      const res=await fetch('/api/play/'+encodeURIComponent(player.videoId),{method:'POST',headers:{Accept:'application/json'},credentials:'same-origin',cache:'no-store'});
      let data=null; try{data=await res.json()}catch{}
      if(!res.ok) throw new Error(data?.message||('Playback HTTP '+res.status));
      if(!data?.success||!data?.data?.manifest_url) throw new Error('بيانات التشغيل ناقصة');
      const manifestUrl=location.origin+data.data.manifest_url;

      if(!window.Hls||!Hls.isSupported()){
        // Safari native HLS — key is already plain AES from our server
        player.video.src=manifestUrl;
        hideLoad(player);
        try{await player.video.play()}catch{player.startLayer.style.display='flex'}
        return;
      }

      showLoad(player,'جاري تجهيز المشغل...');
      const hls=new Hls({
        enableWorker:true,
        lowLatencyMode:false,
        maxBufferLength:18,
        maxMaxBufferLength:18,
        maxBufferSize:2*1024*1024,
        backBufferLength:8,
        capLevelToPlayerSize:true,
        startPosition: player.savedState?.currentTime>0 ? Number(player.savedState.currentTime) : -1
      });
      player.hls=hls;
      hls.on(Hls.Events.MANIFEST_PARSED, async()=>{
        hideLoad(player);
        player.statusEl.textContent='جاهز للتشغيل';
        try{await player.video.play()}catch{player.startLayer.style.display='flex';player.statusEl.textContent='اضغط تشغيل'}
      });
      hls.on(Hls.Events.LEVEL_LOADED,(_,d)=>{
        const dur=Number(d?.details?.totalduration);
        if(dur>0){player.duration=dur;player.timeEl.textContent='0:00 / '+formatDuration(dur)}
      });
      hls.on(Hls.Events.ERROR,(_,d)=>{
        if(!d?.fatal)return;
        if(d.type===Hls.ErrorTypes.NETWORK_ERROR){player.statusEl.textContent='إعادة الاتصال...';try{hls.startLoad()}catch{};return}
        if(d.type===Hls.ErrorTypes.MEDIA_ERROR){player.statusEl.textContent='إصلاح المسار...';try{hls.recoverMediaError()}catch{};return}
        showErr(player,'HLS: '+(d.details||'فشل'));
      });
      hls.loadSource(manifestUrl);
      hls.attachMedia(player.video);
    }catch(e){
      if(player.destroyed)return;
      console.error(e);
      showErr(player,e.message||'فشل التشغيل');
    }
  }

  function updateVideoCardProgress(videoId){
    const card=document.querySelector('[data-sw-video-id="'+CSS.escape(String(videoId))+'"]');
    if(!card)return;
    const state=getWatchState(videoId); if(!state)return;
    const pct=Math.round(state.percent||0);
    const chip=card.querySelector('.sw-watch-chip');
    const btn=card.querySelector('.sw-video-action');
    if(chip){chip.textContent=state.watched?'✓ تمت المشاهدة':pct+'%';chip.className='sw-chip sw-watch-chip '+(state.watched?'sw-chip-green':'sw-chip-orange')}
    if(btn)btn.innerHTML=state.watched?'▶️ إعادة':(pct>0?'▶️ متابعة':'▶️ تشغيل');
    if(state.watched||pct>0)card.classList.add('sw-card-accent');
  }

  // ---- UI ----
  const UI={
    panel:null, contentEl:null, breadcrumbEl:null, backBtn:null,
    init(){ this.build(); this.updateBreadcrumb(); },
    build(){
      const old=$('sw-panel'); if(old)old.remove();
      const ot=$('sw-toggle'); if(ot)ot.remove();
      const toggle=el('button'); toggle.id='sw-toggle'; toggle.innerHTML='▶';
      toggle.onclick=()=>UI.togglePanel(); document.body.appendChild(toggle);
      const panel=el('div'); panel.id='sw-panel';
      panel.innerHTML=\`
        <div class="sw-handle" id="sw-handle"></div>
        <div class="sw-header">
          <button class="sw-icon-btn sw-hidden" id="sw-back">←</button>
          <div class="sw-brand"><h3>Coursatk</h3><p>v6 • Server AES unwrap</p></div>
          <button class="sw-close" id="sw-close">✕</button>
        </div>
        <div class="sw-breadcrumb" id="sw-breadcrumb"></div>
        <div class="sw-content" id="sw-content"></div>\`;
      document.body.appendChild(panel);
      this.panel=panel; this.contentEl=$('sw-content'); this.breadcrumbEl=$('sw-breadcrumb'); this.backBtn=$('sw-back');
      $('sw-close').onclick=()=>this.hidePanel();
      this.backBtn.onclick=e=>{e.preventDefault();e.stopPropagation();haptic();this.goBack()};
    },
    togglePanel(){ haptic(); this.panel.classList.contains('sw-open')?this.hidePanel():this.showPanel(); },
    showPanel(){ this.panel.classList.add('sw-open'); const t=$('sw-toggle'); if(t)t.classList.add('sw-active'); STATE.ui.visible=true;
      if(!STATE.cache.subjects&&this.contentEl&&!this.contentEl.children.length) loadSubjects(); },
    hidePanel(){ this.panel.classList.remove('sw-open'); const t=$('sw-toggle'); if(t)t.classList.remove('sw-active'); STATE.ui.visible=false; },
    setContent(nodes){ if(!this.contentEl)return; this.contentEl.innerHTML=''; if(Array.isArray(nodes))nodes.forEach(n=>n&&this.contentEl.appendChild(n)); else if(nodes)this.contentEl.appendChild(nodes); },
    showLoading(){ const f=document.createDocumentFragment(); for(let i=0;i<5;i++)f.appendChild(el('div','sw-skeleton')); this.setContent(f); },
    showEmpty(icon,title,desc){ const w=el('div','sw-state'); w.innerHTML='<div class="sw-state-icon">'+icon+'</div><div class="sw-state-title">'+title+'</div>'+(desc?'<div class="sw-state-desc">'+desc+'</div>':''); this.setContent(w); },
    showError(msg,retry){ const w=el('div','sw-state'); w.innerHTML='<div class="sw-state-icon">⚠️</div><div class="sw-state-title">حدث خطأ</div><div class="sw-state-desc">'+msg+'</div>'; if(retry){const b=el('button','sw-btn sw-btn-primary');b.textContent='🔄 إعادة';b.onclick=retry;w.appendChild(b)} this.setContent(w); },
    sectionTitle(t){ return el('div','sw-section',t); },
    card({icon,title,sub,chips,action,onClick,accent}){
      const card=el('div','sw-card'+(accent?' sw-card-accent':''));
      if(onClick)card.onclick=()=>{haptic();onClick()};
      if(icon){const ic=el('div','sw-card-icon');ic.textContent=icon;card.appendChild(ic)}
      const body=el('div','sw-card-body'); body.appendChild(el('div','sw-card-title',title));
      if(sub||chips){const s=el('div','sw-card-sub'); if(sub)s.appendChild(el('span',null,sub)); if(chips)chips.forEach(c=>{const ch=el('span','sw-chip '+(c.cls||''));ch.textContent=c.text;s.appendChild(ch)}); body.appendChild(s)}
      card.appendChild(body);
      if(action){const b=el('button','sw-btn '+(action.cls||'sw-btn-primary'));b.innerHTML=action.label;b.onclick=e=>{e.stopPropagation();e.preventDefault();haptic();action.onClick(b)};card.appendChild(b)}
      return card;
    },
    updateBreadcrumb(){
      if(!this.breadcrumbEl)return; this.breadcrumbEl.innerHTML='';
      const crumbs=[{label:'الرئيسية',index:0}]; STATE.stack.forEach((s,i)=>crumbs.push({label:s.label,index:i+1}));
      crumbs.forEach((c,i)=>{ if(i>0)this.breadcrumbEl.appendChild(el('span','sw-sep','›')); const span=el('span'); span.textContent=c.label;
        if(i===crumbs.length-1)span.className='sw-crumb-current'; else{span.className='sw-crumb-link';span.onclick=e=>{e.stopPropagation();haptic();this.goBackTo(c.index)}}
        this.breadcrumbEl.appendChild(span);
      });
      if(this.backBtn){ STATE.stack.length?this.backBtn.classList.remove('sw-hidden'):this.backBtn.classList.add('sw-hidden'); }
    },
    pushStack(label,view){ STATE.stack.push({label,view,scrollTop:this.contentEl?this.contentEl.scrollTop:0}); this.updateBreadcrumb(); },
    goBack(){ if(!STATE.stack.length){loadSubjects(true);return} STATE.stack.pop(); this.updateBreadcrumb(); const p=STATE.stack[STATE.stack.length-1]; p?this.navigateTo(p.view):loadSubjects(true); },
    goBackTo(index){ if(index===0){STATE.stack=[];this.updateBreadcrumb();loadSubjects(true);return} STATE.stack=STATE.stack.slice(0,index); this.updateBreadcrumb(); const t=STATE.stack[STATE.stack.length-1]; t?this.navigateTo(t.view):loadSubjects(true); },
    navigateTo(view){
      if(view==='teachers'){const s=STATE.stack[0]?._ref; s?loadTeachers(s,false):loadSubjects(true)}
      else if(view==='chapters'){const t=STATE.stack[1]?._ref; t?loadChapters(t,false):loadSubjects(true)}
      else if(view==='lectures'){const c=STATE.stack[2]?._ref; c?loadLectures(c,false):loadSubjects(true)}
      else if(view==='content'){const l=STATE.stack[3]?._ref; l?loadLectureContent(l,false):loadSubjects(true)}
      else loadSubjects(true);
    }
  };

  async function loadSubjects(skip){
    if(!UI.contentEl){setTimeout(()=>loadSubjects(skip),300);return}
    if(skip)STATE.stack=[]; STATE.view='subjects'; UI.updateBreadcrumb(); UI.showLoading();
    try{ const res=await apiGet('/api/subjects/'+CONFIG.YEAR_ID); const subjects=res.data||[]; STATE.cache.subjects=subjects; renderSubjects(subjects); }
    catch(e){ UI.showError(e.message,()=>loadSubjects(skip)); }
  }
  function renderSubjects(subjects){
    if(!subjects.length){UI.showEmpty('📚','لا توجد مواد');return}
    const f=document.createDocumentFragment(); f.appendChild(UI.sectionTitle('المواد • '+subjects.length));
    subjects.forEach(s=>f.appendChild(UI.card({icon:'📘',title:s.name,chips:[{text:String(s.id),cls:'sw-chip-blue'}],onClick:()=>loadTeachers(s,true)})));
    UI.setContent(f);
  }
  async function loadTeachers(subject,push=true){
    if(push){UI.pushStack(subject.name,'teachers'); STATE.stack[STATE.stack.length-1]._ref=subject}
    STATE.view='teachers'; UI.updateBreadcrumb(); UI.showLoading();
    try{ const res=await apiGet('/api/subjects/'+subject.id+'/teachers'); const teachers=res.data?.teachers||res.data||[]; renderTeachers(teachers,subject); }
    catch(e){ UI.showError(e.message,()=>loadTeachers(subject,push)); }
  }
  function renderTeachers(teachers,subject){
    if(!teachers.length){UI.showEmpty('👨‍🏫','لا يوجد مدرسين');return}
    const f=document.createDocumentFragment(); f.appendChild(UI.sectionTitle('مدرسين '+subject.name+' • '+teachers.length));
    teachers.forEach(t=>f.appendChild(UI.card({icon:'👨‍🏫',title:t.name,chips:[{text:(t.chapter_count||0)+' شابتر',cls:'sw-chip-green'}],onClick:()=>loadChapters(t,true)})));
    UI.setContent(f);
  }
  async function loadChapters(teacher,push=true){
    if(push){UI.pushStack(teacher.name,'chapters'); STATE.stack[STATE.stack.length-1]._ref=teacher}
    STATE.view='chapters'; UI.updateBreadcrumb(); UI.showLoading();
    try{ const res=await apiGet('/api/teachers/'+teacher.id+'/chapters'); renderChapters(res.data||[],teacher); }
    catch(e){ UI.showError(e.message,()=>loadChapters(teacher,push)); }
  }
  function renderChapters(chapters,teacher){
    if(!chapters.length){UI.showEmpty('📖','لا يوجد شباتر');return}
    const f=document.createDocumentFragment(); f.appendChild(UI.sectionTitle('شباتر '+teacher.name+' • '+chapters.length));
    chapters.forEach(c=>f.appendChild(UI.card({icon:'📖',title:c.name,chips:[{text:(c.lecture_count||0)+' محاضرة',cls:'sw-chip-green'}],onClick:()=>loadLectures(c,true)})));
    UI.setContent(f);
  }
  async function loadLectures(chapter,push=true){
    if(push){UI.pushStack(chapter.name,'lectures'); STATE.stack[STATE.stack.length-1]._ref=chapter}
    STATE.view='lectures'; UI.updateBreadcrumb(); UI.showLoading();
    try{ const res=await apiGet('/api/chapters/'+chapter.id+'/lectures'); renderLectures(res.data||[],chapter); }
    catch(e){ UI.showError(e.message,()=>loadLectures(chapter,push)); }
  }
  function renderLectures(lectures,chapter){
    if(!lectures.length){UI.showEmpty('🎓','لا يوجد محاضرات');return}
    const f=document.createDocumentFragment(); f.appendChild(UI.sectionTitle('محاضرات • '+lectures.length));
    lectures.forEach(l=>f.appendChild(UI.card({icon:'🎓',title:l.name,onClick:()=>loadLectureContent(l,true)})));
    UI.setContent(f);
  }
  async function loadLectureContent(lecture,push=true){
    if(push){UI.pushStack(lecture.name,'content'); STATE.stack[STATE.stack.length-1]._ref=lecture}
    STATE.view='content'; UI.updateBreadcrumb(); UI.showLoading();
    try{ const res=await apiGet('/api/lectures/'+lecture.id+'/content'); const d=res.data||{}; renderContent({videos:d.videos||[],pdfs:d.pdfs||[],exams:d.exams||[]},lecture); }
    catch(e){ UI.showError(e.message,()=>loadLectureContent(lecture,push)); }
  }
  function renderContent(content,lecture){
    const f=document.createDocumentFragment();
    if(content.videos.length){
      f.appendChild(UI.sectionTitle('🎬 فيديوهات • '+content.videos.length));
      content.videos.forEach(v=>{
        const state=getWatchState(v.id); const pct=Math.round(state?.percent||0);
        const chips=[];
        if(v.duration||v.duration_seconds) chips.push({text:formatDuration(Number(v.duration||v.duration_seconds)),cls:'sw-chip-blue'});
        if(state?.watched) chips.push({text:'✓ تمت المشاهدة',cls:'sw-chip-green'});
        else if(pct>0) chips.push({text:pct+'%',cls:'sw-chip-orange'});
        else chips.push({text:'لم تبدأ',cls:''});
        const card=UI.card({
          icon:'▶', title:v.title, chips,
          action:{ label:state?.watched?'▶️ إعادة':(pct>0?'▶️ متابعة':'▶️ تشغيل'), cls:'sw-btn-primary sw-video-action',
            onClick:async btn=>{ btn.disabled=true; try{createPlayerOverlay(v.id,v.title)} finally{setTimeout(()=>btn.disabled=false,500)} }
          }
        });
        card.dataset.swVideoId=String(v.id);
        const wc=card.querySelector('.sw-chip-orange,.sw-chip-green,.sw-chip:not(.sw-chip-blue)');
        if(wc)wc.classList.add('sw-watch-chip');
        if(pct>0||state?.watched)card.classList.add('sw-card-accent');
        f.appendChild(card);
      });
    }
    if(content.pdfs?.length){
      const toggle=UI.card({icon:'▣',title:'الملفات PDF • '+content.pdfs.length,sub:'اضغط لإظهار',action:{label:'إظهار',cls:'sw-btn-secondary',onClick:btn=>{
        const sec=btn.closest('.sw-card')?.nextElementSibling;
        if(sec?.classList.contains('sw-pdf-list')){sec.classList.toggle('sw-pdf-hidden');btn.textContent=sec.classList.contains('sw-pdf-hidden')?'إظهار':'إخفاء'}
      }}});
      f.appendChild(toggle);
      const list=el('div','sw-pdf-list sw-pdf-hidden');
      content.pdfs.forEach(p=>list.appendChild(UI.card({icon:'▣',title:p.title,action:{label:'فتح',cls:'sw-btn-secondary',onClick:()=>window.open(p.url,'_blank')}})));
      f.appendChild(list);
    }
    if(content.exams?.length){
      f.appendChild(UI.sectionTitle('📝 امتحانات • '+content.exams.length));
      content.exams.forEach(e=>f.appendChild(UI.card({icon:'📝',title:e.title,chips:[{text:(e.question_count||0)+' سؤال',cls:'sw-chip-orange'},{text:(e.duration_minutes||0)+' د',cls:'sw-chip-blue'}]})));
    }
    if(!content.videos.length&&!content.pdfs?.length&&!content.exams?.length){UI.showEmpty('📭','لا يوجد محتوى');return}
    UI.setContent(f);
  }

  function init(){
    UI.init();
    const b=$('server-open'); if(b)b.onclick=()=>UI.showPanel();
    setTimeout(()=>loadSubjects().catch(()=>{}),400);
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init); else init();
})();
</script>
</body>
</html>`;

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
