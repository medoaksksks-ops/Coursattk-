/**
 * Coursatk API — protected backend
 * - Student codes (7-digit) + devices + sessions in Firebase RTDB
 * - Admin panel API (users, permissions, sections, subject IDs)
 * - Stream-Weave key unwrap + AES-128 segment decrypt (upstream token NEVER leaves server)
 * - All student/catalog/stream routes require valid session token
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
app.set("trust proxy", 1);
app.use(cors({ origin: true, credentials: false }));
app.use(express.json({ limit: "512kb" }));
app.use(compression());

// ═══════════════════════════════════════════════════════════
// Rate limit — ~50 req / minute / IP (stricter on auth)
// ═══════════════════════════════════════════════════════════
const rateBuckets = new Map();

function clientIp(req) {
  const xf = (req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return xf || req.ip || req.socket?.remoteAddress || "unknown";
}

function rateLimit(options = {}) {
  const windowMs = options.windowMs || 60_000;
  const max = options.max || 50;
  const keyFn = options.keyFn || ((req) => clientIp(req) + ":" + (options.scope || "global"));
  return (req, res, next) => {
    const key = keyFn(req);
    const now = Date.now();
    let b = rateBuckets.get(key);
    if (!b || now > b.resetAt) {
      b = { count: 0, resetAt: now + windowMs };
      rateBuckets.set(key, b);
    }
    b.count += 1;
    res.setHeader("X-RateLimit-Limit", String(max));
    res.setHeader("X-RateLimit-Remaining", String(Math.max(0, max - b.count)));
    if (b.count > max) {
      return res.status(429).json({
        success: false,
        message: "طلبات كثيرة — حاول بعد دقيقة"
      });
    }
    next();
  };
}

setInterval(() => {
  const t = Date.now();
  for (const [k, b] of rateBuckets) {
    if (t > b.resetAt) rateBuckets.delete(k);
  }
}, 60_000).unref();



// ═══════════════════════════════════════════════════════════
// CONFIG (in-code — no Railway vars required for core secrets)
// ═══════════════════════════════════════════════════════════
const CONFIG = {
  PORT: Number(process.env.PORT || 3000),
  // Upstream Coursatk — stays SERVER-SIDE only
  COURSATK_API: "https://api.coursatk.online/api/v1",
  COURSATK_TOKEN:
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDk1NTUsInJvbGUiOiJzdHVkZW50IiwidXVpZCI6IjU3OGIxNjBjMjgxZWVkY2Y1ZTY4MjViNDZmMWExNTY0In0.x9vV-N_13KcrGbx-y9owTgGdirKpKh_X0JXDpolYegs",
  DEFAULT_YEAR_ID: 4,
  STREAM_HOSTS: [
    "api.coursatk.online",
    "stream-weave.com",
    "floravon.online",
    "c-cdn.online"
  ],
  STREAM_ORIGIN: "https://coursatk.online",
  STREAM_REFERER: "https://coursatk.online/",
  STREAM_X_REQUESTED_WITH: "com.mycompany.app.soulbrowser",
  STREAM_UA:
    "Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 Chrome/153.0.0.0 Mobile Safari/537.36",
  PLAYER_JS: "https://player.stream-weave.com/assets/player.js?v=1.1.1",
  // Firebase RTDB (open rules as provided)
  FIREBASE: "https://english-73376-default-rtdb.firebaseio.com",
  // Bootstrap admin (always valid even if Firebase empty)
  BOOTSTRAP_ADMIN: {
    username: "Hema",
    // password set below — hashed at boot
    passwordHash: "",
    passwordPlain: "ibrahim@2009*#",
    permissions: {
      students_create: true,
      students_edit: true,
      students_delete: true,
      students_view: true,
      devices_kick: true,
      sections_manage: true,
      admins_manage: true
    }
  },
  // Session TTL
  STUDENT_SESSION_MS: 7 * 24 * 3600 * 1000, // 7 days max (also capped by code expiry)
  ADMIN_SESSION_MS: 12 * 3600 * 1000, // 12h
  STREAM_SESSION_MS: 15 * 60 * 1000,
  MAX_PROXY_BYTES: 12 * 1024 * 1024,
  CODE_TYPES: {
    trial: { label: "تجربة", ms: 1 * 3600 * 1000 },
    month: { label: "شهر", ms: 30 * 24 * 3600 * 1000 },
    term: { label: "ترم (6 شهور)", ms: 180 * 24 * 3600 * 1000 },
    year: { label: "سنة (12 شهر)", ms: 365 * 24 * 3600 * 1000 }
  }
};

// ═══════════════════════════════════════════════════════════
// Crypto helpers
// ═══════════════════════════════════════════════════════════
function scryptHash(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32, {
    N: 16384,
    r: 8,
    p: 1
  });
  return `scrypt$16384$8$1$${salt.toString("hex")}$${hash.toString("hex")}`;
}

function scryptVerify(password, stored) {
  try {
    if (stored.startsWith("scrypt$")) {
      const parts = stored.split("$");
      const salt = parts[4];
      const expect = parts[5];
      const hash = crypto.scryptSync(password, Buffer.from(salt, "hex"), 32, {
        N: 16384,
        r: 8,
        p: 1
      });
      return crypto.timingSafeEqual(Buffer.from(expect, "hex"), hash);
    }
    // plain fallback (bootstrap migration)
    return password === stored;
  } catch {
    return false;
  }
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function randomCode7() {
  // 1000000 – 9999999
  return String(Math.floor(1000000 + Math.random() * 9000000));
}

function now() {
  return Date.now();
}

// ═══════════════════════════════════════════════════════════
// Firebase RTDB REST
// ═══════════════════════════════════════════════════════════
async function fbGet(p) {
  const r = await fetch(`${CONFIG.FIREBASE}/${p}.json`);
  if (!r.ok) throw new Error(`Firebase GET ${p} → ${r.status}`);
  return r.json();
}

async function fbSet(p, data) {
  const r = await fetch(`${CONFIG.FIREBASE}/${p}.json`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  if (!r.ok) throw new Error(`Firebase PUT ${p} → ${r.status}`);
  return r.json();
}

async function fbPatch(p, data) {
  const r = await fetch(`${CONFIG.FIREBASE}/${p}.json`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  if (!r.ok) throw new Error(`Firebase PATCH ${p} → ${r.status}`);
  return r.json();
}


async function fbDelete(p) {
  const r = await fetch(`${CONFIG.FIREBASE}/${p}.json`, { method: "DELETE" });
  if (!r.ok) throw new Error(`Firebase DELETE ${p} → ${r.status}`);
  return true;
}

// Runtime config from Firebase (overrides in-code defaults)
let cachedCoursatkToken = null;
let cachedTokenAt = 0;
async function getCoursatkToken() {
  const ttl = 30_000;
  if (cachedCoursatkToken && Date.now() - cachedTokenAt < ttl) return cachedCoursatkToken;
  try {
    const remote = await fbGet("config/coursatkToken");
    if (remote && typeof remote === "string" && remote.length > 20) {
      cachedCoursatkToken = remote;
      cachedTokenAt = Date.now();
      return remote;
    }
    if (remote && remote.token) {
      cachedCoursatkToken = remote.token;
      cachedTokenAt = Date.now();
      return remote.token;
    }
  } catch {}
  cachedCoursatkToken = CONFIG.COURSATK_TOKEN;
  cachedTokenAt = Date.now();
  return CONFIG.COURSATK_TOKEN;
}


// ═══════════════════════════════════════════════════════════
// In-memory session caches (source of truth also in Firebase)
// ═══════════════════════════════════════════════════════════
const studentSessions = new Map(); // token -> session
const adminSessions = new Map();
const streamSessions = new Map();

function jsonError(res, status, message) {
  return res.status(status).json({ success: false, message });
}

function getBearer(req) {
  const h = req.headers.authorization || "";
  if (h.startsWith("Bearer ")) return h.slice(7).trim();
  return req.headers["x-session-token"] || req.query.token || "";
}

// ── Student auth middleware ──
async function requireStudent(req, res, next) {
  try {
    const token = getBearer(req);
    if (!token) return jsonError(res, 401, "مطلوب تسجيل الدخول");

    let sess = studentSessions.get(token);
    if (!sess) {
      const remote = await fbGet(`sessions/${token}`);
      if (!remote) return jsonError(res, 401, "جلسة غير صالحة");
      sess = remote;
      studentSessions.set(token, sess);
    }

    if (sess.expiresAt && now() > sess.expiresAt) {
      studentSessions.delete(token);
      try { await fbDelete(`sessions/${token}`); } catch {}
      return jsonError(res, 401, "انتهت صلاحية الجلسة");
    }

    // Validate student still exists & active & not expired
    const student = await fbGet(`students/${sess.code}`);
    if (!student || student.active === false) {
      studentSessions.delete(token);
      return jsonError(res, 401, "الحساب غير موجود أو موقوف");
    }
    if (student.expiresAt && now() > student.expiresAt) {
      return jsonError(res, 403, "انتهت صلاحية كود الاشتراك");
    }

    // Device still registered?
    const devices = student.devices || {};
    if (sess.deviceId && !devices[sess.deviceId]) {
      studentSessions.delete(token);
      try { await fbDelete(`sessions/${token}`); } catch {}
      return jsonError(res, 401, "تم تسجيل خروج هذا الجهاز من لوحة التحكم");
    }

    req.student = student;
    req.session = sess;
    req.sessionToken = token;
    next();
  } catch (e) {
    console.error("[auth student]", e.message);
    return jsonError(res, 500, "خطأ في التحقق من الجلسة");
  }
}

// ── Admin auth middleware ──
function requireAdmin(permission) {
  return async (req, res, next) => {
    try {
      const token = getBearer(req);
      if (!token) return jsonError(res, 401, "مطلوب دخول الأدمن");

      let sess = adminSessions.get(token);
      if (!sess) {
        const remote = await fbGet(`admin_sessions/${token}`);
        if (!remote) return jsonError(res, 401, "جلسة أدمن غير صالحة");
        sess = remote;
        adminSessions.set(token, sess);
      }

      if (sess.expiresAt && now() > sess.expiresAt) {
        adminSessions.delete(token);
        try { await fbDelete(`admin_sessions/${token}`); } catch {}
        return jsonError(res, 401, "انتهت جلسة الأدمن");
      }

      // Load admin record
      let admin = null;
      if (sess.username === CONFIG.BOOTSTRAP_ADMIN.username) {
        admin = {
          username: CONFIG.BOOTSTRAP_ADMIN.username,
          permissions: CONFIG.BOOTSTRAP_ADMIN.permissions,
          bootstrap: true
        };
      } else {
        admin = await fbGet(`admins/${sess.adminId}`);
        if (!admin || admin.active === false) {
          return jsonError(res, 401, "حساب الأدمن غير موجود");
        }
      }

      if (permission) {
        const perms = admin.permissions || {};
        if (!perms[permission] && !perms.all) {
          return jsonError(res, 403, `لا تملك صلاحية: ${permission}`);
        }
      }

      req.admin = admin;
      req.adminSession = sess;
      req.adminToken = token;
      next();
    } catch (e) {
      console.error("[auth admin]", e.message);
      return jsonError(res, 500, "خطأ في تحقق الأدمن");
    }
  };
}

// ═══════════════════════════════════════════════════════════
// Stream-Weave decrypt (server-only)
// ═══════════════════════════════════════════════════════════
let decryptPlaybackKeyFn = null;

async function loadDecryptionUtils() {
  const cachePath = path.join(__dirname, "player.stream-weave.cache.js");
  let source = null;
  try {
    if (fs.existsSync(cachePath)) source = fs.readFileSync(cachePath, "utf8");
  } catch {}
  if (!source) {
    console.log("[crypto] fetching player.js…");
    const r = await fetch(CONFIG.PLAYER_JS, {
      headers: { "User-Agent": "Mozilla/5.0", Accept: "*/*" }
    });
    if (!r.ok) throw new Error(`player.js HTTP ${r.status}`);
    source = await r.text();
    try { fs.writeFileSync(cachePath, source); } catch {}
  }
  const { webcrypto } = crypto;
  const sandbox = {
    window: {}, self: {}, globalThis: {}, global: {},
    console: { log() {}, warn() {}, error() {}, info() {} },
    crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer,
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
  sandbox.window = sandbox; sandbox.self = sandbox;
  sandbox.globalThis = sandbox; sandbox.global = sandbox;
  vm.runInNewContext(source, sandbox, { timeout: 8000 });
  const du = sandbox.DecryptionUtils;
  if (!du?.decryptPlaybackKey) throw new Error("DecryptionUtils missing");
  decryptPlaybackKeyFn = du.decryptPlaybackKey.bind(du);
  console.log("[crypto] ready");
}

async function unwrapKey(wrappedBuf, videoId) {
  if (!decryptPlaybackKeyFn) throw new Error("crypto not loaded");
  const wrapped = Buffer.isBuffer(wrappedBuf)
    ? new Uint8Array(wrappedBuf)
    : new Uint8Array(wrappedBuf);
  if (wrapped.byteLength === 16) return Buffer.from(wrapped);
  const result = await decryptPlaybackKeyFn(wrapped, String(videoId));
  const key = result?.key;
  if (!key) throw new Error("empty key");
  const aes = Buffer.isBuffer(key)
    ? key
    : key instanceof ArrayBuffer
      ? Buffer.from(key)
      : Buffer.from(key.buffer || key, key.byteOffset || 0, key.byteLength || key.length);
  if (aes.length !== 16) throw new Error(`key len ${aes.length}`);
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

// Upstream helpers (token never exposed)
async function upstreamHeaders(extra = {}) {
  const tok = await getCoursatkToken();
  return {
    Authorization: `Bearer ${tok}`,
    Accept: "application/json",
    ...extra
  };
}

async function upstreamJson(apiPath, options = {}) {
  const r = await fetch(`${CONFIG.COURSATK_API}${apiPath}`, {
    ...options,
    headers: await upstreamHeaders(options.headers || {})
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch {
    throw new Error(`Upstream non-JSON (${r.status})`);
  }
  if (!r.ok) throw new Error(data?.message || `Upstream HTTP ${r.status}`);
  return data;
}

function allowedStreamUrl(raw, session = null) {
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:") return false;
    const hosts = new Set(CONFIG.STREAM_HOSTS);
    if (session?.allowedHosts) for (const h of session.allowedHosts) hosts.add(h);
    if (session?.streamUrl) {
      try { hosts.add(new URL(session.streamUrl).hostname); } catch {}
    }
    return [...hosts].some(h => u.hostname === h || u.hostname.endsWith("." + h));
  } catch {
    return false;
  }
}

async function streamFetch(session, url, extra = {}, clientHeaders = null) {
  if (!allowedStreamUrl(url, session)) throw new Error(`URL غير مسموح: ${url}`);
  const ch = clientHeaders || {};
  const headers = {
    Authorization: `Bearer ${session.token}`,
    Accept: "*/*",
    "Cache-Control": "no-cache",
    Origin: CONFIG.STREAM_ORIGIN,
    Referer: CONFIG.STREAM_REFERER,
    "X-Requested-With": CONFIG.STREAM_X_REQUESTED_WITH,
    "User-Agent": ch["user-agent"] || CONFIG.STREAM_UA
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

// ═══════════════════════════════════════════════════════════
// PUBLIC (no auth)
// ═══════════════════════════════════════════════════════════
app.use(rateLimit({ max: 50, windowMs: 60_000, scope: "global" }));

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "coursatk-protected-api",
    cryptoReady: Boolean(decryptPlaybackKeyFn),
    decryptSegments: true,
    now: new Date().toISOString()
  });
});

app.get("/api/public/code-types", (_req, res) => {
  const types = {};
  for (const [k, v] of Object.entries(CONFIG.CODE_TYPES)) {
    types[k] = { label: v.label, durationMs: v.ms };
  }
  res.json({ success: true, data: types });
});

// ═══════════════════════════════════════════════════════════
// STUDENT AUTH
// ═══════════════════════════════════════════════════════════
/**
 * POST /api/auth/login
 * body: { code: "1234567", deviceId: "uuid", deviceName?: "Chrome" }
 */
app.post("/api/auth/login", rateLimit({ max: 15, windowMs: 60_000, scope: "login" }), async (req, res) => {
  try {
    const code = String(req.body?.code || "").trim();
    const deviceId = String(req.body?.deviceId || "").trim();
    const deviceName = String(req.body?.deviceName || "Unknown").slice(0, 80);

    if (!/^\d{7}$/.test(code)) {
      return jsonError(res, 400, "الكود يجب أن يكون 7 أرقام");
    }
    if (!deviceId || deviceId.length < 8) {
      return jsonError(res, 400, "deviceId مطلوب");
    }

    const student = await fbGet(`students/${code}`);
    if (!student || student.active === false) {
      return jsonError(res, 401, "كود غير صحيح أو موقوف");
    }
    if (student.expiresAt && now() > student.expiresAt) {
      return jsonError(res, 403, "انتهت صلاحية الاشتراك");
    }

    const devices = student.devices || {};
    const maxDevices = Number(student.maxDevices || 1);

    if (!devices[deviceId]) {
      const activeCount = Object.keys(devices).length;
      if (activeCount >= maxDevices) {
        return jsonError(
          res,
          403,
          `تم بلوغ الحد الأقصى للأجهزة (${maxDevices}). اطلب من الأدمن حذف جهاز.`
        );
      }
      devices[deviceId] = {
        name: deviceName,
        addedAt: now(),
        lastSeen: now()
      };
      await fbSet(`students/${code}/devices`, devices);
    } else {
      devices[deviceId].lastSeen = now();
      devices[deviceId].name = deviceName || devices[deviceId].name;
      await fbSet(`students/${code}/devices/${deviceId}`, devices[deviceId]);
    }

    const sessionTtl = Math.min(
      CONFIG.STUDENT_SESSION_MS,
      Math.max(60_000, (student.expiresAt || now() + CONFIG.STUDENT_SESSION_MS) - now())
    );
    const token = randomToken(32);
    const sess = {
      token,
      code,
      deviceId,
      name: student.name,
      section: student.section || null,
      createdAt: now(),
      expiresAt: now() + sessionTtl
    };
    studentSessions.set(token, sess);
    await fbSet(`sessions/${token}`, sess);

    // Resolve subject IDs for section
    let subjectIds = [];
    let yearId = CONFIG.DEFAULT_YEAR_ID;
    if (student.section) {
      const sec = await fbGet(`sections/${student.section}`);
      if (sec) {
        subjectIds = sec.subjectIds || [];
        if (sec.yearId) yearId = sec.yearId;
      }
    }

    res.json({
      success: true,
      data: {
        token,
        expiresAt: sess.expiresAt,
        student: {
          name: student.name,
          code,
          section: student.section || null,
          expiresAt: student.expiresAt,
          maxDevices,
          deviceId
        },
        yearId,
        subjectIds
      }
    });
  } catch (e) {
    console.error("[login]", e.message);
    jsonError(res, 500, e.message);
  }
});

app.post("/api/auth/logout", requireStudent, async (req, res) => {
  try {
    studentSessions.delete(req.sessionToken);
    await fbDelete(`sessions/${req.sessionToken}`);
    res.json({ success: true });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.get("/api/auth/me", requireStudent, async (req, res) => {
  try {
    const s = req.student;
    let subjectIds = [];
    let yearId = CONFIG.DEFAULT_YEAR_ID;
    if (s.section) {
      const sec = await fbGet(`sections/${s.section}`);
      if (sec) {
        subjectIds = sec.subjectIds || [];
        if (sec.yearId) yearId = sec.yearId;
      }
    }
    res.json({
      success: true,
      data: {
        name: s.name,
        code: req.session.code,
        section: s.section || null,
        expiresAt: s.expiresAt,
        maxDevices: s.maxDevices || 1,
        devices: Object.keys(s.devices || {}).length,
        deviceId: req.session.deviceId,
        yearId,
        subjectIds,
        sessionExpiresAt: req.session.expiresAt
      }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

// ═══════════════════════════════════════════════════════════
// CATALOG (student token required) — proxies upstream, hides COURSATK token
// ═══════════════════════════════════════════════════════════
app.get("/api/config", requireStudent, async (req, res) => {
  let yearId = CONFIG.DEFAULT_YEAR_ID;
  let subjectIds = [];
  if (req.student.section) {
    const sec = await fbGet(`sections/${req.student.section}`);
    if (sec) {
      if (sec.yearId) yearId = sec.yearId;
      subjectIds = sec.subjectIds || [];
    }
  }
  res.json({
    success: true,
    yearId,
    subjectIds,
    cryptoReady: Boolean(decryptPlaybackKeyFn),
    decryptSegments: true
  });
});

app.get("/api/subjects/:id", requireStudent, async (req, res) => {
  try {
    const data = await upstreamJson(`/user/subjects/${encodeURIComponent(req.params.id)}`);
    // Filter by section subjectIds if configured
    let list = data.data || [];
    if (req.student.section) {
      const sec = await fbGet(`sections/${req.student.section}`);
      const ids = (sec?.subjectIds || []).map(String);
      if (ids.length) list = list.filter((s) => ids.includes(String(s.id)));
    }
    res.json({ ...data, data: list });
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

app.get("/api/subjects/:id/teachers", requireStudent, async (req, res) => {
  try {
    res.json(
      await upstreamJson(`/user/subjects/${encodeURIComponent(req.params.id)}/teachers`)
    );
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

app.get("/api/teachers/:id/chapters", requireStudent, async (req, res) => {
  try {
    res.json(
      await upstreamJson(`/user/teachers/${encodeURIComponent(req.params.id)}/chapters`)
    );
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

app.get("/api/chapters/:id/lectures", requireStudent, async (req, res) => {
  try {
    res.json(
      await upstreamJson(`/user/chapters/${encodeURIComponent(req.params.id)}/lectures`)
    );
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

app.get("/api/lectures/:id/content", requireStudent, async (req, res) => {
  try {
    res.json(
      await upstreamJson(`/user/lectures/${encodeURIComponent(req.params.id)}/content`)
    );
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

// ═══════════════════════════════════════════════════════════
// STREAM (student token) — decrypted segments
// ═══════════════════════════════════════════════════════════
app.post("/api/play/:videoId", requireStudent, async (req, res) => {
  try {
    const data = await upstreamJson(
      `/video/${encodeURIComponent(req.params.videoId)}/stream-weave/play`,
      { method: "POST", headers: { Accept: "application/json" } }
    );
    if (!data?.success || !data?.data?.token || !data?.data?.stream_url || !data?.data?.video_id) {
      throw new Error("Playback response ناقص");
    }
    const id = crypto.randomUUID();
    streamSessions.set(id, {
      id,
      videoId: String(data.data.video_id),
      token: data.data.token,
      streamUrl: data.data.stream_url,
      createdAt: now(),
      plainKey: null,
      defaultIv: null,
      allowedHosts: new Set([new URL(data.data.stream_url).hostname]),
      ownerCode: req.session.code
    });
    res.json({
      success: true,
      data: {
        session: id,
        video_id: data.data.video_id,
        manifest_url: `/api/stream/manifest/${id}`
      }
    });
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

function getStreamSession(id) {
  const s = streamSessions.get(id);
  if (!s) return null;
  if (now() - s.createdAt > CONFIG.STREAM_SESSION_MS) {
    streamSessions.delete(id);
    return null;
  }
  return s;
}

app.get("/api/stream/manifest/:sessionId", requireStudent, async (req, res) => {
  const session = getStreamSession(req.params.sessionId);
  if (!session) return jsonError(res, 404, "جلسة التشغيل منتهية");
  if (session.ownerCode !== req.session.code) {
    return jsonError(res, 403, "جلسة تشغيل ليست لك");
  }

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
          variant = new URL(next, session.streamUrl).href;
          break;
        }
      }
    }

    if (variant) {
      const variantRes = await streamFetch(session, variant, {}, req.headers);
      if (!variantRes.ok) throw new Error(`Variant HTTP ${variantRes.status}`);
      return rewritePlaylist(
        req.params.sessionId, session, await variantRes.text(), variant, res, req.headers
      );
    }
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
    if (t.startsWith("#EXT-X-MEDIA-SEQUENCE:")) mediaSeq = Number(t.split(":")[1]) || 0;
  }

  let segIndex = 0;
  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith("#EXT-X-KEY:")) {
      const uri = line.match(/URI="([^"]+)"/)?.[1];
      const ivHex = line.match(/IV=(0x[0-9a-fA-F]+|[0-9a-fA-F]{32})/i)?.[1];
      if (ivHex) currentIv = parseIvHex(ivHex);
      if (uri && !keyFetched) {
        const keyUrl = new URL(uri, baseUrl).href;
        try { session.allowedHosts.add(new URL(keyUrl).hostname); } catch {}
        const keyRes = await streamFetch(session, keyUrl, {}, clientHeaders);
        if (!keyRes.ok) throw new Error(`Key HTTP ${keyRes.status}`);
        const wrapped = Buffer.from(await keyRes.arrayBuffer());
        session.plainKey = await unwrapKey(wrapped, session.videoId);
        session.defaultIv = currentIv;
        keyFetched = true;
        console.log(`[key] unwrapped for ${session.videoId}`);
      }
      continue; // strip KEY — segments are plain
    }
    if (line && !line.startsWith("#")) {
      const segmentUrl = new URL(line, baseUrl).href;
      try { session.allowedHosts.add(new URL(segmentUrl).hostname); } catch {}
      const seq = mediaSeq + segIndex;
      const iv = currentIv || ivFromMediaSequence(seq);
      const payload = Buffer.from(
        JSON.stringify({ u: segmentUrl, iv: iv.toString("hex"), s: seq }),
        "utf8"
      ).toString("base64url");
      out.push(`/api/stream/segment/${sessionId}/${payload}`);
      segIndex++;
      continue;
    }
    out.push(raw);
  }
  if (!session.plainKey) throw new Error("فشل تجهيز مفتاح التشفير");

  res.set({
    "Content-Type": "application/vnd.apple.mpegurl",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*"
  });
  res.send(out.join("\n"));
}

app.get("/api/stream/segment/:sessionId/:encoded", requireStudent, async (req, res) => {
  const session = getStreamSession(req.params.sessionId);
  if (!session) return jsonError(res, 404, "جلسة التشغيل منتهية");
  if (session.ownerCode !== req.session.code) return jsonError(res, 403, "جلسة ليست لك");
  if (!session.plainKey) return jsonError(res, 404, "مفتاح غير متاح");

  let meta;
  try {
    meta = JSON.parse(Buffer.from(req.params.encoded, "base64url").toString("utf8"));
  } catch {
    return jsonError(res, 400, "segment meta غير صالح");
  }
  const url = meta?.u;
  if (!url || !allowedStreamUrl(url, session)) return jsonError(res, 403, "رابط غير مسموح");

  const iv = parseIvHex(meta.iv) || session.defaultIv || ivFromMediaSequence(meta.s || 0);
  try {
    const upstream = await streamFetch(session, url, {
      Range: req.headers.range || undefined
    }, req.headers);
    if (!upstream.ok && upstream.status !== 206) {
      throw new Error(`Segment HTTP ${upstream.status}`);
    }
    const encrypted = Buffer.from(await upstream.arrayBuffer());
    if (encrypted.length > CONFIG.MAX_PROXY_BYTES) {
      return jsonError(res, 413, "المقطع كبير");
    }
    let plain;
    try {
      plain = decryptSegment(encrypted, session.plainKey, iv);
    } catch {
      plain = encrypted;
    }
    res.status(200);
    res.set({
      "Content-Type": "video/mp2t",
      "Content-Length": String(plain.length),
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*"
    });
    res.send(plain);
  } catch (e) {
    if (!res.headersSent) jsonError(res, 502, e.message);
    else res.end();
  }
});

// ═══════════════════════════════════════════════════════════
// ADMIN AUTH
// ═══════════════════════════════════════════════════════════
app.post("/api/admin/login", rateLimit({ max: 10, windowMs: 60_000, scope: "admin-login" }), async (req, res) => {
  try {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    if (!username || !password) return jsonError(res, 400, "يوزر وباسورد مطلوبين");

    let adminId = null;
    let admin = null;
    let perms = null;

    if (username === CONFIG.BOOTSTRAP_ADMIN.username) {
      const ok = scryptVerify(password, CONFIG.BOOTSTRAP_ADMIN.passwordHash) ||
        password === CONFIG.BOOTSTRAP_ADMIN.passwordPlain;
      if (!ok) return jsonError(res, 401, "بيانات الدخول خطأ");
      adminId = "bootstrap";
      perms = CONFIG.BOOTSTRAP_ADMIN.permissions;
      admin = { username, permissions: perms, bootstrap: true };
    } else {
      // Find admin by username in Firebase
      const all = (await fbGet("admins")) || {};
      for (const [id, a] of Object.entries(all)) {
        if (a && a.username === username && a.active !== false) {
          if (!scryptVerify(password, a.passwordHash)) {
            return jsonError(res, 401, "بيانات الدخول خطأ");
          }
          adminId = id;
          admin = a;
          perms = a.permissions || {};
          break;
        }
      }
      if (!adminId) return jsonError(res, 401, "بيانات الدخول خطأ");
    }

    const token = randomToken(32);
    const sess = {
      token,
      adminId,
      username,
      createdAt: now(),
      expiresAt: now() + CONFIG.ADMIN_SESSION_MS
    };
    adminSessions.set(token, sess);
    await fbSet(`admin_sessions/${token}`, sess);

    res.json({
      success: true,
      data: {
        token,
        expiresAt: sess.expiresAt,
        username,
        permissions: perms
      }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.post("/api/admin/logout", requireAdmin(null), async (req, res) => {
  adminSessions.delete(req.adminToken);
  try { await fbDelete(`admin_sessions/${req.adminToken}`); } catch {}
  res.json({ success: true });
});

app.get("/api/admin/me", requireAdmin(null), (req, res) => {
  res.json({
    success: true,
    data: {
      username: req.admin.username,
      permissions: req.admin.permissions || {},
      bootstrap: !!req.admin.bootstrap
    }
  });
});


// ═══════════════════════════════════════════════════════════
// ADMIN — App config (Coursatk token)
// ═══════════════════════════════════════════════════════════
app.get("/api/admin/config", requireAdmin("sections_manage"), async (_req, res) => {
  try {
    const remote = await fbGet("config");
    const token = await getCoursatkToken();
    const masked = token
      ? token.slice(0, 12) + "…" + token.slice(-8)
      : null;
    res.json({
      success: true,
      data: {
        coursatkTokenSet: Boolean(token),
        coursatkTokenMasked: masked,
        defaultYearId: CONFIG.DEFAULT_YEAR_ID,
        codeTypes: Object.fromEntries(
          Object.entries(CONFIG.CODE_TYPES).map(([k, v]) => [k, { label: v.label, ms: v.ms }])
        ),
        firebase: remote || {}
      }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** PUT /api/admin/config/token  { token: "eyJ..." } */
app.put("/api/admin/config/token", requireAdmin("admins_manage"), async (req, res) => {
  try {
    const token = String(req.body?.token || "").trim();
    if (token.length < 20) return jsonError(res, 400, "توكن غير صالح");
    await fbSet("config/coursatkToken", token);
    cachedCoursatkToken = token;
    cachedTokenAt = Date.now();
    res.json({ success: true, message: "تم تحديث توكن كورساتك" });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

// ═══════════════════════════════════════════════════════════
// ADMIN — Students
// ═══════════════════════════════════════════════════════════
app.get("/api/admin/students", requireAdmin("students_view"), async (_req, res) => {
  try {
    const all = (await fbGet("students")) || {};
    const list = Object.entries(all).map(([code, s]) => ({
      code,
      name: s.name,
      section: s.section || null,
      type: s.type || null,
      expiresAt: s.expiresAt,
      maxDevices: s.maxDevices || 1,
      devices: Object.keys(s.devices || {}).length,
      active: s.active !== false,
      createdAt: s.createdAt || null
    }));
    list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json({ success: true, data: list });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.get("/api/admin/students/:code", requireAdmin("students_view"), async (req, res) => {
  try {
    const code = req.params.code;
    const s = await fbGet(`students/${code}`);
    if (!s) return jsonError(res, 404, "الطالب غير موجود");
    res.json({
      success: true,
      data: {
        code,
        ...s,
        deviceList: Object.entries(s.devices || {}).map(([id, d]) => ({
          deviceId: id,
          ...d
        }))
      }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/**
 * POST /api/admin/students
 * { name, section, type: trial|month|term|year, maxDevices?: number, code?: "1234567" }
 */
app.post("/api/admin/students", requireAdmin("students_create"), async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const section = String(req.body?.section || "").trim();
    const type = String(req.body?.type || "month");
    const maxDevices = Math.max(1, Math.min(10, Number(req.body?.maxDevices || 1)));
    let code = String(req.body?.code || "").trim();

    if (!name) return jsonError(res, 400, "اسم الطالب مطلوب");
    if (!CONFIG.CODE_TYPES[type]) {
      return jsonError(res, 400, "نوع الكود غير صالح (trial|month|term|year)");
    }
    if (code) {
      if (!/^\d{7}$/.test(code)) return jsonError(res, 400, "الكود يجب 7 أرقام");
      const exists = await fbGet(`students/${code}`);
      if (exists) return jsonError(res, 409, "الكود مستخدم بالفعل");
    } else {
      for (let i = 0; i < 30; i++) {
        code = randomCode7();
        const exists = await fbGet(`students/${code}`);
        if (!exists) break;
      }
    }

    const duration = CONFIG.CODE_TYPES[type].ms;
    const record = {
      name,
      section: section || null,
      type,
      maxDevices,
      devices: {},
      active: true,
      createdAt: now(),
      expiresAt: now() + duration,
      createdBy: req.admin.username
    };
    await fbSet(`students/${code}`, record);
    res.json({ success: true, data: { code, ...record } });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.patch("/api/admin/students/:code", requireAdmin("students_edit"), async (req, res) => {
  try {
    const code = req.params.code;
    const s = await fbGet(`students/${code}`);
    if (!s) return jsonError(res, 404, "غير موجود");

    const patch = {};
    if (req.body.name != null) patch.name = String(req.body.name).trim();
    if (req.body.section != null) patch.section = String(req.body.section).trim() || null;
    if (req.body.maxDevices != null) {
      patch.maxDevices = Math.max(1, Math.min(10, Number(req.body.maxDevices)));
    }
    if (req.body.active != null) patch.active = Boolean(req.body.active);
    if (req.body.type && CONFIG.CODE_TYPES[req.body.type]) {
      patch.type = req.body.type;
      // optional renew from now
      if (req.body.renew) {
        patch.expiresAt = now() + CONFIG.CODE_TYPES[req.body.type].ms;
      }
    }
    if (req.body.extendMs) {
      const base = Math.max(s.expiresAt || now(), now());
      patch.expiresAt = base + Number(req.body.extendMs);
    }
    await fbPatch(`students/${code}`, patch);
    res.json({ success: true, data: { code, ...s, ...patch } });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.delete("/api/admin/students/:code", requireAdmin("students_delete"), async (req, res) => {
  try {
    const code = req.params.code;
    // Kill all sessions for this code
    const sessions = (await fbGet("sessions")) || {};
    for (const [tok, sess] of Object.entries(sessions)) {
      if (sess && sess.code === code) {
        studentSessions.delete(tok);
        await fbDelete(`sessions/${tok}`);
      }
    }
    await fbDelete(`students/${code}`);
    res.json({ success: true });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Kick device → force logout that device */
app.delete(
  "/api/admin/students/:code/devices/:deviceId",
  requireAdmin("devices_kick"),
  async (req, res) => {
    try {
      const { code, deviceId } = req.params;
      const s = await fbGet(`students/${code}`);
      if (!s) return jsonError(res, 404, "غير موجود");

      const devices = { ...(s.devices || {}) };
      delete devices[deviceId];
      await fbSet(`students/${code}/devices`, devices);

      // Invalidate sessions for this device
      const sessions = (await fbGet("sessions")) || {};
      for (const [tok, sess] of Object.entries(sessions)) {
        if (sess && sess.code === code && sess.deviceId === deviceId) {
          studentSessions.delete(tok);
          await fbDelete(`sessions/${tok}`);
        }
      }
      res.json({ success: true, message: "تم تسجيل خروج الجهاز" });
    } catch (e) {
      jsonError(res, 500, e.message);
    }
  }
);

// ═══════════════════════════════════════════════════════════
// ADMIN — Sections (شعب) + subject IDs
// ═══════════════════════════════════════════════════════════
app.get("/api/admin/sections", requireAdmin("sections_manage"), async (_req, res) => {
  try {
    const all = (await fbGet("sections")) || {};
    const list = Object.entries(all).map(([id, s]) => ({ id, ...s }));
    res.json({ success: true, data: list });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/**
 * PUT /api/admin/sections/:id
 * { name, yearId?, subjectIds: number[] }
 */
app.put("/api/admin/sections/:id", requireAdmin("sections_manage"), async (req, res) => {
  try {
    const id = String(req.params.id).trim().replace(/[^\w\u0600-\u06FF\-]/g, "_");
    const name = String(req.body?.name || id).trim();
    const yearId = Number(req.body?.yearId || CONFIG.DEFAULT_YEAR_ID);
    const subjectIds = Array.isArray(req.body?.subjectIds)
      ? req.body.subjectIds.map(Number).filter((n) => !Number.isNaN(n))
      : [];
    const record = { name, yearId, subjectIds, updatedAt: now() };
    await fbSet(`sections/${id}`, record);
    res.json({ success: true, data: { id, ...record } });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.delete("/api/admin/sections/:id", requireAdmin("sections_manage"), async (req, res) => {
  try {
    await fbDelete(`sections/${req.params.id}`);
    res.json({ success: true });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

// ═══════════════════════════════════════════════════════════
// ADMIN — manage other admins
// ═══════════════════════════════════════════════════════════
app.get("/api/admin/admins", requireAdmin("admins_manage"), async (_req, res) => {
  try {
    const all = (await fbGet("admins")) || {};
    const list = Object.entries(all).map(([id, a]) => ({
      id,
      username: a.username,
      permissions: a.permissions || {},
      active: a.active !== false,
      createdAt: a.createdAt || null
    }));
    res.json({
      success: true,
      data: [
        {
          id: "bootstrap",
          username: CONFIG.BOOTSTRAP_ADMIN.username,
          permissions: CONFIG.BOOTSTRAP_ADMIN.permissions,
          active: true,
          bootstrap: true
        },
        ...list
      ]
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/**
 * POST /api/admin/admins
 * { username, password, permissions: { students_create, ... } }
 */
app.post("/api/admin/admins", requireAdmin("admins_manage"), async (req, res) => {
  try {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    if (!username || username.length < 3) return jsonError(res, 400, "يوزر غير صالح");
    if (!password || password.length < 6) return jsonError(res, 400, "باسورد قصير");
    if (username === CONFIG.BOOTSTRAP_ADMIN.username) {
      return jsonError(res, 409, "اسم محجوز");
    }

    const all = (await fbGet("admins")) || {};
    for (const a of Object.values(all)) {
      if (a && a.username === username) return jsonError(res, 409, "اليوزر موجود");
    }

    const permissions = {
      students_view: !!req.body?.permissions?.students_view,
      students_create: !!req.body?.permissions?.students_create,
      students_edit: !!req.body?.permissions?.students_edit,
      students_delete: !!req.body?.permissions?.students_delete,
      devices_kick: !!req.body?.permissions?.devices_kick,
      sections_manage: !!req.body?.permissions?.sections_manage,
      admins_manage: !!req.body?.permissions?.admins_manage
    };

    const id = crypto.randomUUID();
    const record = {
      username,
      passwordHash: scryptHash(password),
      permissions,
      active: true,
      createdAt: now(),
      createdBy: req.admin.username
    };
    await fbSet(`admins/${id}`, record);
    res.json({
      success: true,
      data: { id, username, permissions, active: true }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.patch("/api/admin/admins/:id", requireAdmin("admins_manage"), async (req, res) => {
  try {
    if (req.params.id === "bootstrap") {
      return jsonError(res, 400, "لا يمكن تعديل الأدمن الأساسي من هنا");
    }
    const a = await fbGet(`admins/${req.params.id}`);
    if (!a) return jsonError(res, 404, "غير موجود");
    const patch = {};
    if (req.body.password) patch.passwordHash = scryptHash(String(req.body.password));
    if (req.body.permissions) {
      patch.permissions = {
        students_view: !!req.body.permissions.students_view,
        students_create: !!req.body.permissions.students_create,
        students_edit: !!req.body.permissions.students_edit,
        students_delete: !!req.body.permissions.students_delete,
        devices_kick: !!req.body.permissions.devices_kick,
        sections_manage: !!req.body.permissions.sections_manage,
        admins_manage: !!req.body.permissions.admins_manage
      };
    }
    if (req.body.active != null) patch.active = Boolean(req.body.active);
    await fbPatch(`admins/${req.params.id}`, patch);
    res.json({ success: true });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.delete("/api/admin/admins/:id", requireAdmin("admins_manage"), async (req, res) => {
  try {
    if (req.params.id === "bootstrap") {
      return jsonError(res, 400, "لا يمكن حذف الأدمن الأساسي");
    }
    await fbDelete(`admins/${req.params.id}`);
    res.json({ success: true });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

// ═══════════════════════════════════════════════════════════
// Fallback
// ═══════════════════════════════════════════════════════════
// Root / unknown — require client handshake (no API dump)
app.get("/", (_req, res) => {
  res.status(403).json({
    success: false,
    message: "خطأ: يلزم مصادقة. الوصول المباشر غير مسموح."
  });
});

app.use((req, res) => {
  res.status(403).json({
    success: false,
    message: "خطأ: يلزم مصادقة أو المسار غير موجود.",
    path: req.path
  });
});

// Cleanup timers
setInterval(() => {
  const t = now();
  for (const [k, s] of studentSessions) {
    if (s.expiresAt && t > s.expiresAt) studentSessions.delete(k);
  }
  for (const [k, s] of adminSessions) {
    if (s.expiresAt && t > s.expiresAt) adminSessions.delete(k);
  }
  for (const [k, s] of streamSessions) {
    if (t - s.createdAt > CONFIG.STREAM_SESSION_MS) streamSessions.delete(k);
  }
}, 60_000).unref();

// Boot: hash bootstrap password properly + load crypto
CONFIG.BOOTSTRAP_ADMIN.passwordHash = scryptHash(CONFIG.BOOTSTRAP_ADMIN.passwordPlain);
await loadDecryptionUtils();

// Seed default sections if missing
try {
  // Always ensure correct subject IDs for the 3 main sections
  // علمي علوم: 57 عربي، 58 English، 59 فيزياء، 60 كيمياء، 61 أحياء
  // علمي رياضة: نفس علوم مع 65 رياضة بدل 61 أحياء
  // أدبي: 57 عربي، 58 English + 62،63،64
  const sectionDefaults = {
    scientific_sciences: {
      name: "علمي علوم",
      yearId: 4,
      subjectIds: [57, 58, 59, 60, 61],
      updatedAt: Date.now()
    },
    scientific_math: {
      name: "علمي رياضة",
      yearId: 4,
      subjectIds: [57, 58, 59, 60, 65],
      updatedAt: Date.now()
    },
    literary: {
      name: "أدبي",
      yearId: 4,
      subjectIds: [57, 58, 62, 63, 64],
      updatedAt: Date.now()
    }
  };
  const secs = (await fbGet("sections")) || {};
  let changed = false;
  for (const [id, def] of Object.entries(sectionDefaults)) {
    const cur = secs[id];
    const same =
      cur &&
      Array.isArray(cur.subjectIds) &&
      cur.subjectIds.length === def.subjectIds.length &&
      def.subjectIds.every((x, i) => Number(cur.subjectIds[i]) === x);
    if (!same) {
      await fbSet(`sections/${id}`, { ...(cur || {}), ...def });
      changed = true;
    }
  }
  if (changed) console.log("[API] sections subjectIds synced");
  else console.log("[API] sections OK");
} catch (e) {
  console.warn("[API] section seed skip:", e.message);
}

app.listen(CONFIG.PORT, () => {
  console.log(`[API] :${CONFIG.PORT} protected · segment-decrypt ON`);
  console.log(`[API] bootstrap admin ready (Hema)`);
});
