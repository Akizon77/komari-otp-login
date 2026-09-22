const server = require("server");
const crypto = require("crypto");
const fs = require("node:fs");
const path = require("node:path");

const CODE_TTL_MS = 3 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const MAX_CODE_ATTEMPTS = 5;
const IP_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const MAX_IP_ATTEMPTS = 10;
const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;

const loginCodesByIP = new Map();
const failedAttemptsByIP = new Map();
let nextCodeSendAt = 0;

function now() {
  return new Date().toISOString();
}

function stringValue(value) {
  return typeof value === "string" ? value : "";
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

function parseBody(req, res) {
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

function clientIP(req) {
  return stringValue(req.context && req.context.remote_ip);
}

function isExpired(record, at) {
  return !record || at >= record.expiresAt;
}

function currentRecord(ip, at) {
  const record = loginCodesByIP.get(ip);
  if (isExpired(record, at)) {
    loginCodesByIP.delete(ip);
    return null;
  }
  return record || null;
}

function ipAttemptRecord(ip, at) {
  const key = ip || "unknown";
  const record = failedAttemptsByIP.get(key);
  if (!record || at >= record.expiresAt) {
    failedAttemptsByIP.delete(key);
    return null;
  }
  return record;
}

function isIPRateLimited(ip, at) {
  const record = ipAttemptRecord(ip, at);
  return record !== null && record.count >= MAX_IP_ATTEMPTS;
}

function registerIPFailure(ip, at) {
  const key = ip || "unknown";
  let record = ipAttemptRecord(key, at);
  if (!record) {
    record = { count: 0, expiresAt: at + IP_ATTEMPT_WINDOW_MS };
    failedAttemptsByIP.set(key, record);
  }
  record.count += 1;
  return record.count;
}

function clearIPFailures(ip) {
  failedAttemptsByIP.delete(ip || "unknown");
}

function cookieSecure(req) {
  const forwarded = stringValue(req.headers["x-forwarded-proto"])
    .split(",")[0]
    .trim()
    .toLowerCase();
  if (forwarded) {
    return forwarded === "https";
  }
  return stringValue(req.headers.origin).toLowerCase().startsWith("https://");
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
      stringValue(req.context && req.context.user_agent),
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
          stringValue(req.context && req.context.user_agent),
      },
    })
    .catch(function (error) {
      console.error("[komari-otp-login] failed to send login notification:", error);
    });
}

async function sendCode(req, res) {
  const at = Date.now();
  const ip = clientIP(req);
  const body = parseBody(req, res);
  if (!body) {
    return;
  }
  const username = stringValue(body.username).trim();
  let user;
  try {
    user = await onlyUser();
  } catch (error) {
    console.error("[komari-otp-login] failed to read user:", error);
    failure(res, 500, "login_failed");
    return;
  }
  if (!username || username !== user.username) {
    failure(res, 401, "invalid_username");
    return;
  }

  if (at < nextCodeSendAt) {
    failure(res, 429, "resend_too_soon");
    return;
  }

  const existing = currentRecord(ip, at);
  if (existing && at < existing.resendAt) {
    failure(res, 429, "resend_too_soon");
    return;
  }

  const code = randomCode();
  const salt = randomToken();
  const record = {
    hash: codeHash(code, salt),
    salt: salt,
    expiresAt: at + CODE_TTL_MS,
    resendAt: at + RESEND_COOLDOWN_MS,
    attempts: 0,
    username: user.username,
    userUUID: user.uuid,
  };

  try {
    await server.call("admin:sendNotification", {
      event: {
        event: "Login",
        time: now(),
        emoji: "🔐",
        message:
          "Komari 一次性登录验证码：" +
          code +
          "\n有效期：3 分钟。验证码由大写字母和数字组成。若非本人操作，请忽略此通知。",
      },
    });
  } catch (error) {
    console.error("[komari-otp-login] failed to send code:", error);
    failure(res, 502, "notification_failed");
    return;
  }

  // A successful resend replaces and invalidates every prior active code.
  loginCodesByIP.clear();
  loginCodesByIP.set(ip, record);
  nextCodeSendAt = at + RESEND_COOLDOWN_MS;
  jsonResponse(res, 200, {
    ok: true,
    expires_in: Math.floor(CODE_TTL_MS / 1000),
    resend_in: Math.floor(RESEND_COOLDOWN_MS / 1000),
  });
}

async function verifyCode(req, res) {
  const body = parseBody(req, res);
  if (!body) {
    return;
  }
  const at = Date.now();
  const ip = clientIP(req);
  const record = currentRecord(ip, at);
  if (!record) {
    failure(res, 400, "code_expired");
    return;
  }
  if (isIPRateLimited(ip, at)) {
    failure(res, 429, "ip_rate_limited");
    return;
  }

  const username = stringValue(body.username).trim();
  const code = stringValue(body.code).trim().toUpperCase();
  if (!username || !/^[A-Z0-9]{8}$/.test(code)) {
    registerIPFailure(ip, at);
    failure(res, 400, "invalid_code");
    return;
  }

  if (record.username !== username) {
    registerIPFailure(ip, at);
    failure(res, 400, "code_expired");
    return;
  }
  if (record.attempts >= MAX_CODE_ATTEMPTS) {
    loginCodesByIP.delete(ip);
    failure(res, 429, "too_many_attempts");
    return;
  }
  if (!equalHash(record.hash, codeHash(code, record.salt))) {
    record.attempts += 1;
    const ipAttempts = registerIPFailure(ip, at);
    if (ipAttempts >= MAX_IP_ATTEMPTS) {
      failure(res, 429, "ip_rate_limited");
      return;
    }
    if (record.attempts >= MAX_CODE_ATTEMPTS) {
      loginCodesByIP.delete(ip);
      failure(res, 429, "too_many_attempts");
      return;
    }
    failure(res, 401, "invalid_code");
    return;
  }

  loginCodesByIP.delete(ip);
  clearIPFailures(ip);
  try {
    const token = await createSession(req, record.userUUID);
    res.setHeader("Set-Cookie", sessionCookie(token, req));
    notifySuccessfulLogin(req, record.username);
    jsonResponse(res, 200, { ok: true, logged_in: true });
  } catch (error) {
    console.error("[komari-otp-login] failed to create session:", error);
    failure(res, 500, "login_failed");
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

function load() {
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
