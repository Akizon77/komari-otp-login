const server = require("server");
const crypto = require("crypto");
const fs = require("node:fs");
const path = require("node:path");

const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const SEND_LOCK_TTL_MS = 15 * 1000;
const MAX_TRACKED_IPS = 4096;
const MAX_USER_AGENT_LENGTH = 200;

const DEFAULT_CONFIG = {
  codeTtlSeconds: 180,
  resendCooldownSeconds: 60,
  maxCodeAttempts: 5,
  globalSendWindowSeconds: 900,
  globalSendMaxRequests: 10,
  globalVerifyWindowSeconds: 900,
  globalVerifyMaxRequests: 30,
  ipSendWindowSeconds: 900,
  ipSendMaxRequests: 5,
  ipVerifyWindowSeconds: 900,
  ipVerifyMaxRequests: 10,
};

function buildRuntimeConfig(raw) {
  const source = raw && typeof raw === "object" ? raw : {};
  const codeTtlSeconds = clampInt(source.code_ttl_seconds, DEFAULT_CONFIG.codeTtlSeconds, 30, 3600);
  const resendCooldownSeconds = clampInt(
    source.resend_cooldown_seconds,
    DEFAULT_CONFIG.resendCooldownSeconds,
    5,
    3600,
  );
  const maxCodeAttempts = clampInt(source.max_code_attempts, DEFAULT_CONFIG.maxCodeAttempts, 1, 100);
  const globalSendWindowSeconds = clampInt(
    source.global_send_window_seconds,
    DEFAULT_CONFIG.globalSendWindowSeconds,
    10,
    86400,
  );
  const globalSendMaxRequests = clampInt(
    source.global_send_max_requests,
    DEFAULT_CONFIG.globalSendMaxRequests,
    1,
    1000,
  );
  const globalVerifyWindowSeconds = clampInt(
    source.global_verify_window_seconds,
    DEFAULT_CONFIG.globalVerifyWindowSeconds,
    10,
    86400,
  );
  const globalVerifyMaxRequests = clampInt(
    source.global_verify_max_requests,
    DEFAULT_CONFIG.globalVerifyMaxRequests,
    1,
    5000,
  );
  const ipSendWindowSeconds = clampInt(
    source.ip_send_window_seconds,
    DEFAULT_CONFIG.ipSendWindowSeconds,
    10,
    86400,
  );
  const ipSendMaxRequests = clampInt(
    source.ip_send_max_requests,
    DEFAULT_CONFIG.ipSendMaxRequests,
    1,
    1000,
  );
  const ipVerifyWindowSeconds = clampInt(
    source.ip_verify_window_seconds,
    DEFAULT_CONFIG.ipVerifyWindowSeconds,
    10,
    86400,
  );
  const ipVerifyMaxRequests = clampInt(
    source.ip_verify_max_requests,
    DEFAULT_CONFIG.ipVerifyMaxRequests,
    1,
    5000,
  );

  return {
    codeTtlSeconds: codeTtlSeconds,
    codeTtlMs: codeTtlSeconds * 1000,
    resendCooldownSeconds: resendCooldownSeconds,
    resendCooldownMs: resendCooldownSeconds * 1000,
    maxCodeAttempts: maxCodeAttempts,
    globalSendWindowMs: globalSendWindowSeconds * 1000,
    globalSendMaxRequests: globalSendMaxRequests,
    globalVerifyWindowMs: globalVerifyWindowSeconds * 1000,
    globalVerifyMaxRequests: globalVerifyMaxRequests,
    ipSendWindowMs: ipSendWindowSeconds * 1000,
    ipSendMaxRequests: ipSendMaxRequests,
    ipVerifyWindowMs: ipVerifyWindowSeconds * 1000,
    ipVerifyMaxRequests: ipVerifyMaxRequests,
  };
}

function clampInt(value, fallback, min, max) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  const integer = Math.floor(parsed);
  if (integer < min) {
    return min;
  }
  if (integer > max) {
    return max;
  }
  return integer;
}

function createGlobalRateLimiter() {
  let timestamps = [];

  function prune(at, windowMs) {
    const cutoff = at - windowMs;
    if (timestamps.length === 0) {
      return;
    }
    let firstValid = 0;
    while (firstValid < timestamps.length && timestamps[firstValid] <= cutoff) {
      firstValid += 1;
    }
    if (firstValid > 0) {
      timestamps = timestamps.slice(firstValid);
    }
  }

  return {
    check: function (at, windowMs, maxRequests) {
      prune(at, windowMs);
      if (timestamps.length >= maxRequests) {
        const retryAfterMs = Math.max(1000, timestamps[0] + windowMs - at);
        return {
          allowed: false,
          retryAfter: Math.ceil(retryAfterMs / 1000),
        };
      }
      return { allowed: true, retryAfter: 0 };
    },
    record: function (at, windowMs) {
      prune(at, windowMs);
      timestamps.push(at);
    },
    reset: function () {
      timestamps = [];
    },
  };
}

function createIPRateLimiter() {
  const buckets = new Map();

  function normalizeKey(ip) {
    return ip || "unknown";
  }

  function pruneBucket(timestamps, at, windowMs) {
    const cutoff = at - windowMs;
    let firstValid = 0;
    while (firstValid < timestamps.length && timestamps[firstValid] <= cutoff) {
      firstValid += 1;
    }
    if (firstValid === 0) {
      return timestamps;
    }
    if (firstValid >= timestamps.length) {
      return [];
    }
    return timestamps.slice(firstValid);
  }

  function evictIfFull(at, windowMs) {
    if (buckets.size < MAX_TRACKED_IPS) {
      return;
    }
    buckets.forEach(function (timestamps, key) {
      const active = pruneBucket(timestamps, at, windowMs);
      if (active.length === 0) {
        buckets.delete(key);
      } else if (active !== timestamps) {
        buckets.set(key, active);
      }
    });
    while (buckets.size >= MAX_TRACKED_IPS) {
      const oldestKey = buckets.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      buckets.delete(oldestKey);
    }
  }

  return {
    check: function (ip, at, windowMs, maxRequests) {
      const key = normalizeKey(ip);
      const existing = buckets.get(key);
      if (!existing) {
        return { allowed: true, retryAfter: 0 };
      }
      const active = pruneBucket(existing, at, windowMs);
      if (active.length === 0) {
        buckets.delete(key);
        return { allowed: true, retryAfter: 0 };
      }
      if (active !== existing) {
        buckets.set(key, active);
      }
      if (active.length >= maxRequests) {
        const retryAfterMs = Math.max(1000, active[0] + windowMs - at);
        return {
          allowed: false,
          retryAfter: Math.ceil(retryAfterMs / 1000),
        };
      }
      return { allowed: true, retryAfter: 0 };
    },
    record: function (ip, at, windowMs) {
      const key = normalizeKey(ip);
      const existing = buckets.get(key);
      let active = existing ? pruneBucket(existing, at, windowMs) : [];
      if (!existing) {
        evictIfFull(at, windowMs);
      } else {
        // Refresh insertion order so active IPs are retained over stale ones on eviction.
        buckets.delete(key);
      }
      active.push(at);
      buckets.set(key, active);
    },
    reset: function () {
      buckets.clear();
    },
  };
}

let config = buildRuntimeConfig(null);
// Only a single active verification code may exist at any moment.
let activeCode = null;
let nextCodeSendAt = 0;
let sendLockToken = null;
let sendLockExpiresAt = 0;

const globalSendLimiter = createGlobalRateLimiter();
const ipSendLimiter = createIPRateLimiter();
const globalVerifyLimiter = createGlobalRateLimiter();
const ipVerifyLimiter = createIPRateLimiter();

function now() {
  return new Date().toISOString();
}

function stringValue(value) {
  return typeof value === "string" ? value : "";
}

function formatDurationZh(seconds) {
  const total = Math.max(1, Math.floor(Number(seconds) || 0));
  if (total % 60 === 0) {
    return String(total / 60) + " 分钟";
  }
  return String(total) + " 秒";
}

function jsonResponse(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(body));
}

function failure(res, status, code) {
  jsonResponse(res, status, { ok: false, code: code });
}

function rateLimitFailure(res, code, retryAfter) {
  const seconds = Math.max(1, Math.ceil(Number(retryAfter) || 1));
  res.setHeader("Retry-After", String(seconds));
  jsonResponse(res, 429, { ok: false, code: code, retry_after: seconds });
}

function headerValue(req, name) {
  if (!req || !req.headers || typeof req.headers !== "object") {
    return "";
  }
  return stringValue(req.headers[name]);
}

function isCrossSiteRequest(req) {
  return headerValue(req, "sec-fetch-site").trim().toLowerCase() === "cross-site";
}

function hasJSONContentType(req) {
  const mediaType = headerValue(req, "content-type").split(";")[0].trim().toLowerCase();
  return mediaType === "application/json";
}

function sanitizeUserAgent(req) {
  const raw = stringValue(req.context && req.context.user_agent);
  const cleaned = raw.replace(/[\x00-\x1f\x7f]+/g, " ").trim();
  if (cleaned.length <= MAX_USER_AGENT_LENGTH) {
    return cleaned;
  }
  return cleaned.slice(0, MAX_USER_AGENT_LENGTH);
}

function parseBody(req, res) {
  if (isCrossSiteRequest(req)) {
    failure(res, 403, "forbidden");
    return null;
  }
  if (!hasJSONContentType(req)) {
    failure(res, 415, "invalid_request");
    return null;
  }
  try {
    const value = JSON.parse(req.body || "{}");
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      failure(res, 400, "invalid_request");
      return null;
    }
    return value;
  } catch (_) {
    failure(res, 400, "invalid_request");
    return null;
  }
}

function randomCode() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let code = "";
  for (let index = 0; index < 8; index += 1) {
    code += alphabet[crypto.randomInt(0, alphabet.length)];
  }
  return code;
}

function randomToken() {
  return crypto.randomBytes(32).toString("hex");
}

function codeHash(code, salt) {
  return crypto
    .createHash("sha256")
    .update(salt + ":" + code)
    .digest("hex");
}

function equalHash(left, right) {
  const leftBuffer = Buffer.from(left, "hex");
  const rightBuffer = Buffer.from(right, "hex");
  return (
    leftBuffer.length === rightBuffer.length &&
    crypto.timingSafeEqual(leftBuffer, rightBuffer)
  );
}

function equalText(left, right) {
  const leftDigest = crypto.createHash("sha256").update(stringValue(left)).digest();
  const rightDigest = crypto.createHash("sha256").update(stringValue(right)).digest();
  return crypto.timingSafeEqual(leftDigest, rightDigest);
}

function clientIP(req) {
  return stringValue(req.context && req.context.remote_ip).trim();
}

function isExpired(record, at) {
  return !record || at >= record.expiresAt;
}

function getActiveCode(at) {
  if (isExpired(activeCode, at)) {
    activeCode = null;
    return null;
  }
  return activeCode;
}

function consumeDualRateLimit(
  ipLimiter,
  globalLimiter,
  ip,
  at,
  ipWindowMs,
  ipMaxRequests,
  globalWindowMs,
  globalMaxRequests,
) {
  // Check both limiters before recording so an abusive IP hitting its per-IP
  // ceiling cannot also exhaust the global quota for other clients.
  const ipCheck = ipLimiter.check(ip, at, ipWindowMs, ipMaxRequests);
  if (!ipCheck.allowed) {
    return {
      allowed: false,
      code: "ip_rate_limited",
      retryAfter: ipCheck.retryAfter,
    };
  }
  const globalCheck = globalLimiter.check(at, globalWindowMs, globalMaxRequests);
  if (!globalCheck.allowed) {
    return {
      allowed: false,
      code: "global_rate_limited",
      retryAfter: globalCheck.retryAfter,
    };
  }
  ipLimiter.record(ip, at, ipWindowMs);
  globalLimiter.record(at, globalWindowMs);
  return { allowed: true, code: "", retryAfter: 0 };
}

function acquireSendLock(at) {
  if (sendLockToken !== null && at < sendLockExpiresAt) {
    return null;
  }
  const token = randomToken();
  sendLockToken = token;
  sendLockExpiresAt = at + SEND_LOCK_TTL_MS;
  return token;
}

function releaseSendLock(token) {
  if (token !== null && sendLockToken === token) {
    sendLockToken = null;
    sendLockExpiresAt = 0;
  }
}

function cookieSecure(req) {
  const forwarded = headerValue(req, "x-forwarded-proto")
    .split(",")[0]
    .trim()
    .toLowerCase();
  if (forwarded) {
    return forwarded === "https";
  }
  const forwardedProtocol = headerValue(req, "x-forwarded-protocol")
    .split(",")[0]
    .trim()
    .toLowerCase();
  if (forwardedProtocol) {
    return forwardedProtocol === "https";
  }
  if (headerValue(req, "x-forwarded-ssl").trim().toLowerCase() === "on") {
    return true;
  }
  const urlScheme = headerValue(req, "x-url-scheme").trim().toLowerCase();
  if (urlScheme) {
    return urlScheme === "https";
  }
  return headerValue(req, "origin").trim().toLowerCase().startsWith("https://");
}

function sessionCookie(token, req) {
  const parts = [
    "session_token=" + token,
    "Path=/",
    "Max-Age=" + SESSION_TTL_SECONDS,
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (cookieSecure(req)) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

async function dbExec(sql, args) {
  await server.call("admin:dbExec", {
    database: "main",
    sql: sql,
    args: args,
  });
}

async function onlyUser() {
  const result = await server.call("admin:dbQuery", {
    database: "main",
    sql: "SELECT uuid, username FROM users LIMIT 1",
    args: [],
    limit: 1,
  });
  if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) {
    throw new Error("user_unavailable");
  }
  const user = {
    uuid: stringValue(result.rows[0][0]),
    username: stringValue(result.rows[0][1]),
  };
  if (!user.uuid || !user.username) {
    throw new Error("user_unavailable");
  }
  return user;
}

async function createSession(req, userUUID) {
  const token = randomToken();
  const createdAt = now();
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
  await dbExec(
    "INSERT INTO sessions (uuid, session, user_agent, ip, login_method, latest_online, latest_user_agent, latest_ip, expires, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
      userUUID,
      token,
      sanitizeUserAgent(req),
      clientIP(req),
      "one-time code",
      createdAt,
      "",
      "",
      expiresAt,
      createdAt,
    ],
  );
  return token;
}

async function ensureNotificationEnabled() {
  const settings = await server.call("admin:getSettings");
  if (!settings || settings.notification_enabled !== true) {
    throw new Error("notification_disabled");
  }
  const method = stringValue(settings.notification_method).trim().toLowerCase();
  if (!method || method === "none") {
    throw new Error("notification_unconfigured");
  }
}

async function dispatchCodeNotification(record, code) {
  // Enforce at-most-once notification dispatch per generated code record.
  if (!record || record.notificationSent) {
    throw new Error("code_notification_already_sent");
  }
  record.notificationSent = true;
  await server.call("admin:sendNotification", {
    event: {
      event: "Login",
      time: now(),
      emoji: "🔐",
      message:
        "Komari 一次性登录验证码：" +
        code +
        "\n有效期：" +
        formatDurationZh(config.codeTtlSeconds) +
        "。验证码由大写字母和数字组成。若非本人操作，请忽略此通知。",
    },
  });
}

function notifySuccessfulLogin(req, username) {
  void server
    .call("admin:sendNotification", {
      event: {
        event: "Login",
        time: now(),
        emoji: "✅",
        message:
          "Komari 一次性验证码登录成功" +
          "\n用户名：" +
          username +
          "\nIP：" +
          clientIP(req) +
          "\n设备：" +
          sanitizeUserAgent(req),
      },
    })
    .catch(function (error) {
      console.error("[komari-otp-login] failed to send login notification:", error);
    });
}

async function sendCode(req, res) {
  const at = Date.now();
  const ip = clientIP(req);

  const sendRateLimit = consumeDualRateLimit(
    ipSendLimiter,
    globalSendLimiter,
    ip,
    at,
    config.ipSendWindowMs,
    config.ipSendMaxRequests,
    config.globalSendWindowMs,
    config.globalSendMaxRequests,
  );
  if (!sendRateLimit.allowed) {
    rateLimitFailure(res, sendRateLimit.code, sendRateLimit.retryAfter);
    return;
  }

  const body = parseBody(req, res);
  if (!body) {
    return;
  }
  const username = stringValue(body.username).trim();
  if (!username) {
    failure(res, 401, "invalid_username");
    return;
  }

  const lockToken = acquireSendLock(at);
  if (lockToken === null) {
    rateLimitFailure(res, "send_in_progress", 1);
    return;
  }

  try {
    if (at < nextCodeSendAt) {
      rateLimitFailure(
        res,
        "resend_too_soon",
        Math.max(1, Math.ceil((nextCodeSendAt - at) / 1000)),
      );
      return;
    }

    let user;
    try {
      user = await onlyUser();
    } catch (error) {
      console.error("[komari-otp-login] failed to read user:", error);
      if (!res.isAborted()) {
        failure(res, 500, "login_failed");
      }
      return;
    }

    if (!equalText(username, user.username)) {
      if (!res.isAborted()) {
        failure(res, 401, "invalid_username");
      }
      return;
    }

    try {
      await ensureNotificationEnabled();
    } catch (error) {
      console.error("[komari-otp-login] notification channel unavailable:", error);
      if (!res.isAborted()) {
        failure(res, 502, "notification_failed");
      }
      return;
    }

    const issuedAt = Date.now();
    if (issuedAt < nextCodeSendAt) {
      if (!res.isAborted()) {
        rateLimitFailure(
          res,
          "resend_too_soon",
          Math.max(1, Math.ceil((nextCodeSendAt - issuedAt) / 1000)),
        );
      }
      return;
    }

    const code = randomCode();
    const salt = randomToken();
    const record = {
      id: randomToken(),
      ip: ip,
      hash: codeHash(code, salt),
      salt: salt,
      createdAt: issuedAt,
      expiresAt: issuedAt + config.codeTtlMs,
      attempts: 0,
      username: user.username,
      userUUID: user.uuid,
      notificationSent: false,
    };

    // Issuing a new code immediately replaces and invalidates any prior active code.
    activeCode = record;

    try {
      await dispatchCodeNotification(record, code);
    } catch (error) {
      console.error("[komari-otp-login] failed to send code:", error);
      if (activeCode === record) {
        activeCode = null;
      }
      if (!res.isAborted()) {
        failure(res, 502, "notification_failed");
      }
      return;
    }

    const sentAt = Date.now();
    if (activeCode === record) {
      record.expiresAt = sentAt + config.codeTtlMs;
    }
    if (sendLockToken === lockToken) {
      nextCodeSendAt = sentAt + config.resendCooldownMs;
    }

    if (!res.isAborted()) {
      jsonResponse(res, 200, {
        ok: true,
        expires_in: config.codeTtlSeconds,
        resend_in: config.resendCooldownSeconds,
      });
    }
  } finally {
    releaseSendLock(lockToken);
  }
}

async function verifyCode(req, res) {
  const at = Date.now();
  const ip = clientIP(req);

  const verifyRateLimit = consumeDualRateLimit(
    ipVerifyLimiter,
    globalVerifyLimiter,
    ip,
    at,
    config.ipVerifyWindowMs,
    config.ipVerifyMaxRequests,
    config.globalVerifyWindowMs,
    config.globalVerifyMaxRequests,
  );
  if (!verifyRateLimit.allowed) {
    rateLimitFailure(res, verifyRateLimit.code, verifyRateLimit.retryAfter);
    return;
  }

  const body = parseBody(req, res);
  if (!body) {
    return;
  }

  const record = getActiveCode(at);
  if (!record || record.ip !== ip) {
    failure(res, 400, "code_expired");
    return;
  }

  const username = stringValue(body.username).trim();
  const code = stringValue(body.code).trim().toUpperCase();
  if (!username || !/^[A-Z0-9]{8}$/.test(code)) {
    failure(res, 400, "invalid_code");
    return;
  }

  if (!equalText(record.username, username)) {
    failure(res, 400, "code_expired");
    return;
  }
  if (record.attempts >= config.maxCodeAttempts) {
    activeCode = null;
    failure(res, 429, "too_many_attempts");
    return;
  }
  if (!equalHash(record.hash, codeHash(code, record.salt))) {
    record.attempts += 1;
    if (record.attempts >= config.maxCodeAttempts) {
      activeCode = null;
      failure(res, 429, "too_many_attempts");
      return;
    }
    failure(res, 401, "invalid_code");
    return;
  }

  // Consume the one-time code synchronously before awaiting session creation.
  activeCode = null;
  try {
    const token = await createSession(req, record.userUUID);
    res.setHeader("Set-Cookie", sessionCookie(token, req));
    notifySuccessfulLogin(req, record.username);
    if (!res.isAborted()) {
      jsonResponse(res, 200, { ok: true, logged_in: true });
    }
  } catch (error) {
    console.error("[komari-otp-login] failed to create session:", error);
    if (!res.isAborted()) {
      failure(res, 500, "login_failed");
    }
  }
}

function route(handler) {
  return function (req, res) {
    Promise.resolve(handler(req, res)).catch(function (error) {
      console.error("[komari-otp-login] route failed:", error);
      if (!res.isAborted()) {
        failure(res, 500, "internal_error");
      }
    });
  };
}

async function loadConfig() {
  if (typeof server.getConfig !== "function") {
    config = buildRuntimeConfig(null);
    return;
  }
  try {
    const raw = await server.getConfig();
    config = buildRuntimeConfig(raw);
  } catch (error) {
    console.error("[komari-otp-login] failed to load configuration, using defaults:", error);
    config = buildRuntimeConfig(null);
  }
}

async function load() {
  await loadConfig();
  server.route("POST", "/api/komari-otp-login/send", route(sendCode));
  server.route("POST", "/api/komari-otp-login/verify", route(verifyCode));
  server.injectHTML(
    '<style id="komari-otp-login-styles">' +
      fs.readFileSync(path.join(__dirname, "assets", "otp-login.css"), "utf8") +
      "</style>",
    '<script id="komari-otp-login-ui">' +
      fs.readFileSync(path.join(__dirname, "assets", "otp-login.js"), "utf8") +
      "</script>",
  );
  console.log("[komari-otp-login] loaded");
}

function unload() {
  activeCode = null;
  nextCodeSendAt = 0;
  sendLockToken = null;
  sendLockExpiresAt = 0;
  globalSendLimiter.reset();
  ipSendLimiter.reset();
  globalVerifyLimiter.reset();
  ipVerifyLimiter.reset();
}
