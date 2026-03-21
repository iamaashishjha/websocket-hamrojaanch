const http = require("http");
const crypto = require("crypto");
const { WebSocketServer } = require("ws");
const { parse } = require("url");

const parsePositiveInt = (value, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  const normalized = Math.floor(parsed);
  if (normalized < min) return min;
  if (normalized > max) return max;
  return normalized;
};

const PORT = parsePositiveInt(process.env.SIGNALING_PORT, 3001, { min: 1, max: 65535 });
const TOKEN_TTL_SECONDS = parsePositiveInt(process.env.SIGNALING_TOKEN_TTL, 600, { min: 60, max: 3600 });
const SECRET = process.env.SIGNALING_SECRET || "dev_secret_change_me";
const ALLOW_DIRECT_TOKEN_ENDPOINT = process.env.ALLOW_DIRECT_TOKEN_ENDPOINT === "true";
const CORS_ORIGIN = process.env.SIGNALING_CORS_ORIGIN || "http://localhost:8081";
const SHUTDOWN_GRACE_MS = parsePositiveInt(process.env.SHUTDOWN_GRACE_MS, 15000, { min: 1000, max: 120000 });
const HEARTBEAT_INTERVAL_MS = parsePositiveInt(process.env.WS_HEARTBEAT_INTERVAL_MS, 30000, { min: 5000, max: 120000 });
const MAX_MESSAGE_BYTES = parsePositiveInt(process.env.WS_MAX_MESSAGE_BYTES, 64 * 1024, { min: 1024, max: 1024 * 1024 });
const MAX_CONNECTIONS_PER_IP = parsePositiveInt(process.env.WS_MAX_CONNECTIONS_PER_IP, 40, { min: 1, max: 5000 });
const MAX_VIEWERS_PER_ROOM = parsePositiveInt(process.env.WS_MAX_VIEWERS_PER_ROOM, 60, { min: 1, max: 5000 });
const MAX_ROOMS = parsePositiveInt(process.env.WS_MAX_ROOMS, 5000, { min: 1, max: 1000000 });
const JOIN_RATE_WINDOW_MS = parsePositiveInt(process.env.WS_JOIN_RATE_WINDOW_MS, 60000, { min: 1000, max: 3600000 });
const MAX_JOIN_ATTEMPTS_PER_WINDOW = parsePositiveInt(process.env.WS_MAX_JOIN_ATTEMPTS_PER_WINDOW, 30, { min: 1, max: 100000 });
const MESSAGE_RATE_WINDOW_MS = parsePositiveInt(process.env.WS_MESSAGE_RATE_WINDOW_MS, 10000, { min: 1000, max: 120000 });
const MAX_MESSAGES_PER_WINDOW = parsePositiveInt(process.env.WS_MAX_MESSAGES_PER_WINDOW, 200, { min: 10, max: 100000 });
const IS_PROD = process.env.NODE_ENV === "production";
const LOG_LEVELS = Object.freeze({
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
});
const requestedLogLevel = String(process.env.LOG_LEVEL || "info").toLowerCase();
const ACTIVE_LOG_LEVEL = Object.prototype.hasOwnProperty.call(LOG_LEVELS, requestedLogLevel)
  ? requestedLogLevel
  : "info";

const ROLE_CAN_PUBLISH = new Set(["candidate"]);
const ROLE_CAN_VIEW = new Set(["admin", "teacher", "proctor"]);
const SIGNALING_ROLES = new Set(["publisher", "viewer"]);
const ROOM_ID_PATTERN = /^[a-zA-Z0-9:_-]{3,190}$/;
const OPEN_STATE = 1;

const ALLOWED_ORIGINS = new Set(
  CORS_ORIGIN.split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
);

const shouldLog = (level) => LOG_LEVELS[level] >= LOG_LEVELS[ACTIVE_LOG_LEVEL];

const createLogger = (baseContext = {}) => {
  const writeLog = (level, context = {}, message = "log.event") => {
    if (!shouldLog(level)) return;
    const entry = {
      time: new Date().toISOString(),
      level,
      ...baseContext,
      ...context,
      msg: message,
    };
    process.stdout.write(`${JSON.stringify(entry)}\n`);
  };

  return {
    child(context = {}) {
      return createLogger({ ...baseContext, ...context });
    },
    debug(context = {}, message) {
      writeLog("debug", context, message);
    },
    info(context = {}, message) {
      writeLog("info", context, message);
    },
    warn(context = {}, message) {
      writeLog("warn", context, message);
    },
    error(context = {}, message) {
      writeLog("error", context, message);
    },
  };
};

const logger = createLogger({
  service: "hamrojaanch-signaling",
  module: "signaling-ws",
});

const makeId = (prefix) =>
  typeof crypto.randomUUID === "function"
    ? `${prefix}_${crypto.randomUUID()}`
    : `${prefix}_${Math.random().toString(36).slice(2, 10)}`;

const toHeaderString = (value) => {
  if (typeof value === "string") return value.trim();
  if (Array.isArray(value) && value[0] && typeof value[0] === "string") {
    return value[0].trim();
  }
  return "";
};

const serializeError = (error) => {
  if (!error || typeof error !== "object") return undefined;
  const normalized = {
    errorName: error.name || "Error",
    errorMessage: error.message || "Unknown error",
  };
  if (!IS_PROD && error.stack) {
    normalized.stack = error.stack;
  }
  return normalized;
};

const statusToLogLevel = (statusCode) => {
  if (statusCode >= 500) return "error";
  if (statusCode >= 400) return "warn";
  return "info";
};

const closeReasonToString = (reason) => {
  if (!reason) return "";
  if (typeof reason === "string") return reason;
  if (Buffer.isBuffer(reason)) return reason.toString("utf8");
  return String(reason);
};

const rooms = new Map();
const connectionsByIp = new Map();
const joinWindowByIp = new Map();
let isShuttingDown = false;

if (IS_PROD && SECRET === "dev_secret_change_me") {
  throw new Error("SIGNALING_SECRET must be configured in production.");
}
if (IS_PROD && ALLOW_DIRECT_TOKEN_ENDPOINT) {
  throw new Error("ALLOW_DIRECT_TOKEN_ENDPOINT must be false in production.");
}
if (IS_PROD && ALLOWED_ORIGINS.has("*")) {
  throw new Error("SIGNALING_CORS_ORIGIN cannot use wildcard in production.");
}

logger.info({
  layer: "system",
  action: "config",
  outcome: "success",
  environment: process.env.NODE_ENV || "development",
  logLevel: ACTIVE_LOG_LEVEL,
  port: PORT,
  tokenTtlSeconds: TOKEN_TTL_SECONDS,
  allowDirectTokenEndpoint: ALLOW_DIRECT_TOKEN_ENDPOINT,
  allowedOrigins: Array.from(ALLOWED_ORIGINS),
  shutdownGraceMs: SHUTDOWN_GRACE_MS,
  heartbeatIntervalMs: HEARTBEAT_INTERVAL_MS,
  maxMessageBytes: MAX_MESSAGE_BYTES,
  maxConnectionsPerIp: MAX_CONNECTIONS_PER_IP,
  maxViewersPerRoom: MAX_VIEWERS_PER_ROOM,
  maxRooms: MAX_ROOMS,
  joinRateWindowMs: JOIN_RATE_WINDOW_MS,
  maxJoinAttemptsPerWindow: MAX_JOIN_ATTEMPTS_PER_WINDOW,
  messageRateWindowMs: MESSAGE_RATE_WINDOW_MS,
  maxMessagesPerWindow: MAX_MESSAGES_PER_WINDOW,
}, "server.config.loaded");

const nowSeconds = () => Math.floor(Date.now() / 1000);

const base64Url = (input) =>
  Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

const decodeBase64Url = (input) => {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(input.length / 4) * 4, "=");
  return Buffer.from(padded, "base64").toString("utf8");
};

const sign = (payload) =>
  base64Url(crypto.createHmac("sha256", SECRET).update(payload).digest());

const timingSafeEqual = (a, b) => {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
};

const issueToken = ({ role, room }) => {
  const payload = JSON.stringify({
    role,
    room,
    exp: nowSeconds() + TOKEN_TTL_SECONDS,
  });
  const encoded = base64Url(payload);
  const signature = sign(encoded);
  return `${encoded}.${signature}`;
};

const verifyToken = (token) => {
  if (!token || typeof token !== "string") return null;
  const [encoded, signature] = token.split(".");
  if (!encoded || !signature) return null;
  if (!timingSafeEqual(sign(encoded), signature)) return null;
  try {
    const payload = JSON.parse(decodeBase64Url(encoded));
    if (!payload || payload.exp < nowSeconds()) return null;
    return payload;
  } catch {
    return null;
  }
};

const send = (ws, message) => {
  if (ws.readyState === OPEN_STATE) {
    ws.send(JSON.stringify(message));
  }
};

const sendError = (ws, message) => send(ws, { type: "error", message });

const getRoom = (roomId) => {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, { publisher: null, viewers: new Map() });
  }
  return rooms.get(roomId);
};

const getClientIp = (req) => {
  const header = req.headers["x-forwarded-for"];
  if (typeof header === "string") {
    const [first] = header.split(",");
    if (first && first.trim()) return first.trim();
  }
  if (Array.isArray(header) && header[0] && header[0].trim()) {
    return header[0].trim();
  }
  return req.socket?.remoteAddress || "0.0.0.0";
};

const getOrCreateRequestId = (req) => {
  if (typeof req.requestId === "string" && req.requestId.trim()) {
    return req.requestId.trim();
  }
  const requestIdHeader = toHeaderString(req.headers["x-request-id"]);
  const correlationIdHeader = toHeaderString(req.headers["x-correlation-id"]);
  const requestId = requestIdHeader || correlationIdHeader || makeId("req");
  req.requestId = requestId;
  return requestId;
};

const reserveConnection = (ip) => {
  const current = connectionsByIp.get(ip) || 0;
  if (current >= MAX_CONNECTIONS_PER_IP) return false;
  connectionsByIp.set(ip, current + 1);
  return true;
};

const releaseConnection = (ip) => {
  const current = connectionsByIp.get(ip) || 0;
  if (current <= 1) {
    connectionsByIp.delete(ip);
    return;
  }
  connectionsByIp.set(ip, current - 1);
};

const canJoin = (ip) => {
  const now = Date.now();
  const existing = joinWindowByIp.get(ip);
  if (!existing || now - existing.startMs >= JOIN_RATE_WINDOW_MS) {
    joinWindowByIp.set(ip, { startMs: now, count: 1, touchedAt: now });
    return true;
  }
  if (existing.count >= MAX_JOIN_ATTEMPTS_PER_WINDOW) {
    existing.touchedAt = now;
    return false;
  }
  existing.count += 1;
  existing.touchedAt = now;
  return true;
};

const applyCorsHeaders = (req, res) => {
  const requestOrigin = typeof req.headers.origin === "string" ? req.headers.origin : "";
  if (requestOrigin) {
    if (ALLOWED_ORIGINS.has("*") || ALLOWED_ORIGINS.has(requestOrigin)) {
      res.setHeader("Access-Control-Allow-Origin", requestOrigin);
      res.setHeader("Vary", "Origin");
      return true;
    }
    return false;
  }

  if (ALLOWED_ORIGINS.size === 1 && !ALLOWED_ORIGINS.has("*")) {
    for (const allowed of ALLOWED_ORIGINS) {
      res.setHeader("Access-Control-Allow-Origin", allowed);
      break;
    }
  }
  return true;
};

const isWebSocketOriginAllowed = (req) => {
  const requestOrigin = typeof req.headers.origin === "string" ? req.headers.origin : "";
  if (!requestOrigin) {
    return !IS_PROD;
  }
  return ALLOWED_ORIGINS.has("*") || ALLOWED_ORIGINS.has(requestOrigin);
};

const httpServer = http.createServer((req, res) => {
  const requestId = getOrCreateRequestId(req);
  const requestLog = logger.child({
    layer: "http",
    action: "request",
    requestId,
    method: req.method,
    route: req.url || "/",
    ip: getClientIp(req),
    origin: toHeaderString(req.headers.origin) || undefined,
    userAgent: toHeaderString(req.headers["user-agent"]) || undefined,
  });
  const startedAt = Date.now();
  res.setHeader("X-Request-Id", requestId);
  requestLog.info({ outcome: "start" }, "request.start");

  res.on("finish", () => {
    const durationMs = Date.now() - startedAt;
    const level = statusToLogLevel(res.statusCode);
    requestLog[level]({
      outcome: res.statusCode >= 400 ? "failure" : "success",
      statusCode: res.statusCode,
      durationMs,
    }, "request.complete");
  });

  const originAllowed = applyCorsHeaders(req, res);
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    if (!originAllowed) {
      requestLog.warn({ outcome: "failure", reason: "cors_origin_not_allowed", statusCode: 403 }, "request.failure");
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Origin not allowed." }));
      return;
    }
    res.writeHead(204);
    res.end();
    return;
  }

  if (!originAllowed) {
    requestLog.warn({ outcome: "failure", reason: "cors_origin_not_allowed", statusCode: 403 }, "request.failure");
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Origin not allowed." }));
    return;
  }

  const url = parse(req.url, true);
  if (url.pathname === "/live" || url.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, status: isShuttingDown ? "draining" : "live" }));
    return;
  }

  if (url.pathname === "/ready") {
    if (isShuttingDown) {
      requestLog.warn({ outcome: "failure", reason: "server_shutting_down", statusCode: 503 }, "request.failure");
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, ready: false, message: "Server is shutting down" }));
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, ready: true }));
    return;
  }

  if (url.pathname === "/token") {
    const role = String(url.query.role || "").toLowerCase();
    const examId = String(url.query.examId || "");
    const attemptId = String(url.query.attemptId || "");
    const tokenLog = requestLog.child({
      action: "token",
      requestedRole: role || undefined,
      examId: examId || undefined,
      attemptId: attemptId || undefined,
    });
    tokenLog.info({ outcome: "start" }, "token.start");

    if (isShuttingDown) {
      tokenLog.warn({ outcome: "failure", reason: "server_shutting_down", statusCode: 503 }, "token.failure");
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Server is shutting down." }));
      return;
    }
    if (!ALLOW_DIRECT_TOKEN_ENDPOINT) {
      tokenLog.warn({ outcome: "failure", reason: "direct_token_disabled", statusCode: 403 }, "token.failure");
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Direct token issuance is disabled." }));
      return;
    }
    if (!role || !examId || !attemptId) {
      tokenLog.warn({ outcome: "failure", reason: "missing_params", statusCode: 400 }, "token.failure");
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "role, examId, and attemptId are required." }));
      return;
    }
    if (!ROLE_CAN_PUBLISH.has(role) && !ROLE_CAN_VIEW.has(role)) {
      tokenLog.warn({ outcome: "failure", reason: "role_not_permitted", statusCode: 403 }, "token.failure");
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Role not permitted." }));
      return;
    }

    const room = `${examId}:${attemptId}`;
    if (!ROOM_ID_PATTERN.test(room)) {
      tokenLog.warn({ outcome: "failure", reason: "invalid_room_id", statusCode: 400, room }, "token.failure");
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid room id format." }));
      return;
    }

    const token = issueToken({ role, room });
    const expiresAt = new Date((nowSeconds() + TOKEN_TTL_SECONDS) * 1000).toISOString();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ token, expiresAt }));
    tokenLog.info({ outcome: "success", room, expiresAt }, "token.success");
    return;
  }

  requestLog.warn({ outcome: "failure", reason: "route_not_found", statusCode: 404 }, "request.failure");
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found." }));
});

httpServer.keepAliveTimeout = 65000;
httpServer.headersTimeout = 66000;

const wss = new WebSocketServer({
  server: httpServer,
  path: "/ws",
  maxPayload: MAX_MESSAGE_BYTES,
  perMessageDeflate: false,
});

const heartbeatLog = logger.child({ layer: "websocket", action: "heartbeat" });
const joinWindowCleanupLog = logger.child({ layer: "websocket", action: "joinWindowCleanup" });

const heartbeatTimer = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      const meta = ws.meta && typeof ws.meta === "object" ? ws.meta : {};
      heartbeatLog.warn({
        ...meta,
        outcome: "failure",
        reason: "heartbeat_timeout",
      }, "ws.heartbeat.timeout");
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, HEARTBEAT_INTERVAL_MS);
if (typeof heartbeatTimer.unref === "function") {
  heartbeatTimer.unref();
}

const joinWindowCleanupTimer = setInterval(() => {
  const now = Date.now();
  const staleAfter = Math.max(JOIN_RATE_WINDOW_MS * 2, 120000);
  let removedEntries = 0;
  for (const [ip, entry] of joinWindowByIp.entries()) {
    if (now - entry.touchedAt > staleAfter) {
      joinWindowByIp.delete(ip);
      removedEntries += 1;
    }
  }
  if (removedEntries > 0) {
    joinWindowCleanupLog.debug({ outcome: "success", removedEntries }, "ws.join_window.cleaned");
  }
}, Math.max(30000, JOIN_RATE_WINDOW_MS));
if (typeof joinWindowCleanupTimer.unref === "function") {
  joinWindowCleanupTimer.unref();
}

wss.on("connection", (ws, req) => {
  const requestId = getOrCreateRequestId(req);
  const connectionId = makeId("conn");
  const clientIp = getClientIp(req);
  const baseWsLog = logger.child({
    layer: "websocket",
    action: "connection",
    requestId,
    connectionId,
    method: "WS",
    route: req.url || "/ws",
    ip: clientIp,
    origin: toHeaderString(req.headers.origin) || undefined,
    userAgent: toHeaderString(req.headers["user-agent"]) || undefined,
  });

  baseWsLog.info({ outcome: "start", activeConnections: wss.clients.size }, "ws.connection.start");

  if (isShuttingDown) {
    baseWsLog.warn({ outcome: "failure", reason: "server_shutting_down", closeCode: 1012 }, "ws.connection.rejected");
    ws.close(1012, "Server restarting");
    return;
  }

  if (!isWebSocketOriginAllowed(req)) {
    baseWsLog.warn({ outcome: "failure", reason: "origin_not_allowed", closeCode: 1008 }, "ws.connection.rejected");
    ws.close(1008, "Origin not allowed");
    return;
  }

  if (!reserveConnection(clientIp)) {
    baseWsLog.warn({
      outcome: "failure",
      reason: "connection_limit_reached",
      closeCode: 1013,
      activeConnectionsFromIp: connectionsByIp.get(clientIp) || 0,
    }, "ws.connection.rejected");
    ws.close(1013, "Connection limit reached");
    return;
  }

  let connectionReleased = false;
  const releaseTrackedConnection = (releaseReason) => {
    if (connectionReleased) return;
    connectionReleased = true;
    releaseConnection(clientIp);
    baseWsLog.debug({
      outcome: "success",
      releaseReason,
      activeConnectionsFromIp: connectionsByIp.get(clientIp) || 0,
    }, "ws.connection.release");
  };

  ws.isAlive = true;
  ws.meta = { requestId, connectionId, ip: clientIp };
  ws.on("pong", () => {
    ws.isAlive = true;
  });

  const client = {
    id: makeId("client"),
    role: null,
    tokenRole: null,
    roomId: null,
  };
  ws.meta.clientId = client.id;
  const wsLog = baseWsLog.child({ clientId: client.id });
  wsLog.info({
    outcome: "success",
    activeConnectionsFromIp: connectionsByIp.get(clientIp) || 0,
  }, "ws.connection.accepted");

  let messageWindowStartMs = Date.now();
  let messageCount = 0;

  const consumeMessageQuota = () => {
    const now = Date.now();
    if (now - messageWindowStartMs >= MESSAGE_RATE_WINDOW_MS) {
      messageWindowStartMs = now;
      messageCount = 0;
    }
    messageCount += 1;
    return messageCount <= MAX_MESSAGES_PER_WINDOW;
  };

  ws.on("message", (raw) => {
    const rawSize = typeof raw === "string" ? Buffer.byteLength(raw) : raw.length;
    if (!consumeMessageQuota()) {
      wsLog.warn({
        outcome: "failure",
        action: "message",
        reason: "message_rate_limit_exceeded",
        rawSize,
        closeCode: 1008,
      }, "ws.message.rejected");
      sendError(ws, "Message rate limit exceeded.");
      ws.close(1008, "Rate limit exceeded");
      return;
    }

    if (rawSize > MAX_MESSAGE_BYTES) {
      wsLog.warn({
        outcome: "failure",
        action: "message",
        reason: "message_size_exceeded",
        rawSize,
        maxMessageBytes: MAX_MESSAGE_BYTES,
        closeCode: 1009,
      }, "ws.message.rejected");
      sendError(ws, "Message exceeds maximum allowed size.");
      ws.close(1009, "Message too large");
      return;
    }

    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      wsLog.warn({ outcome: "failure", action: "message", reason: "invalid_json", rawSize }, "ws.message.rejected");
      sendError(ws, "Invalid JSON message.");
      return;
    }

    if (!message || typeof message.type !== "string") {
      wsLog.warn({ outcome: "failure", action: "message", reason: "malformed_message", rawSize }, "ws.message.rejected");
      sendError(ws, "Malformed message.");
      return;
    }

    wsLog.debug({
      outcome: "start",
      action: "message",
      messageType: message.type,
      roomId: client.roomId || undefined,
      role: client.role || undefined,
    }, "ws.message.received");

    if (message.type === "join") {
      const role = message.role;
      const roomId = message.room;
      if (!canJoin(clientIp)) {
        wsLog.warn({
          outcome: "failure",
          action: "join",
          messageType: "join",
          requestedRole: role,
          roomId: typeof roomId === "string" ? roomId : undefined,
          reason: "join_rate_limit_exceeded",
        }, "ws.join.failure");
        sendError(ws, "Too many join attempts from this IP. Please retry shortly.");
        return;
      }
      if (client.roomId || client.role) {
        wsLog.warn({
          outcome: "failure",
          action: "join",
          reason: "already_joined",
          roomId: client.roomId,
          role: client.role,
        }, "ws.join.failure");
        sendError(ws, "Client has already joined a room.");
        return;
      }

      if (!SIGNALING_ROLES.has(role)) {
        wsLog.warn({
          outcome: "failure",
          action: "join",
          requestedRole: role,
          reason: "invalid_signaling_role",
        }, "ws.join.failure");
        sendError(ws, "Invalid signaling role.");
        return;
      }
      if (typeof roomId !== "string" || !ROOM_ID_PATTERN.test(roomId)) {
        wsLog.warn({
          outcome: "failure",
          action: "join",
          requestedRole: role,
          roomId: typeof roomId === "string" ? roomId : undefined,
          reason: "invalid_room_id",
        }, "ws.join.failure");
        sendError(ws, "Invalid room id.");
        return;
      }

      const tokenPayload = verifyToken(message.token);
      if (!tokenPayload) {
        wsLog.warn({ outcome: "failure", action: "join", requestedRole: role, roomId, reason: "invalid_or_expired_token" }, "ws.join.failure");
        sendError(ws, "Invalid or expired token.");
        return;
      }
      if (tokenPayload.room !== roomId) {
        wsLog.warn({
          outcome: "failure",
          action: "join",
          requestedRole: role,
          roomId,
          tokenRoom: tokenPayload.room,
          reason: "token_room_mismatch",
        }, "ws.join.failure");
        sendError(ws, "Token room mismatch.");
        return;
      }
      if (role === "publisher" && !ROLE_CAN_PUBLISH.has(tokenPayload.role)) {
        wsLog.warn({
          outcome: "failure",
          action: "join",
          requestedRole: role,
          roomId,
          tokenRole: tokenPayload.role,
          reason: "token_role_cannot_publish",
        }, "ws.join.failure");
        sendError(ws, "Role cannot publish.");
        return;
      }
      if (role === "viewer" && !ROLE_CAN_VIEW.has(tokenPayload.role)) {
        wsLog.warn({
          outcome: "failure",
          action: "join",
          requestedRole: role,
          roomId,
          tokenRole: tokenPayload.role,
          reason: "token_role_cannot_view",
        }, "ws.join.failure");
        sendError(ws, "Role cannot view.");
        return;
      }

      const existingRoom = rooms.get(roomId);
      if (!existingRoom && rooms.size >= MAX_ROOMS) {
        wsLog.warn({ outcome: "failure", action: "join", requestedRole: role, roomId, reason: "max_rooms_reached" }, "ws.join.failure");
        sendError(ws, "Server room capacity reached.");
        return;
      }
      const room = getRoom(roomId);
      if (role === "viewer" && room.viewers.size >= MAX_VIEWERS_PER_ROOM) {
        wsLog.warn({
          outcome: "failure",
          action: "join",
          requestedRole: role,
          roomId,
          reason: "max_viewers_reached",
          roomViewerCount: room.viewers.size,
          maxViewersPerRoom: MAX_VIEWERS_PER_ROOM,
        }, "ws.join.failure");
        sendError(ws, "Room viewer limit reached.");
        return;
      }

      client.role = role;
      client.tokenRole = tokenPayload.role;
      client.roomId = roomId;
      ws.meta.role = client.role;
      ws.meta.roomId = client.roomId;

      if (role === "publisher") {
        if (room.publisher && room.publisher.ws !== ws) {
          wsLog.warn({
            outcome: "success",
            action: "join",
            roomId,
            replacedPublisherId: room.publisher.id,
            reason: "publisher_replaced",
          }, "ws.join.publisher_replaced");
          sendError(room.publisher.ws, "Publisher replaced.");
          room.publisher.ws.close();
        }
        room.publisher = { ...client, ws };
        room.viewers.forEach((viewer) => {
          send(viewer.ws, { type: "publisher-ready" });
          send(ws, { type: "viewer-joined", viewerId: viewer.id });
        });
      } else {
        room.viewers.set(client.id, { ...client, ws });
        if (room.publisher) {
          send(room.publisher.ws, { type: "viewer-joined", viewerId: client.id });
        } else {
          send(ws, { type: "publisher-offline" });
        }
      }

      send(ws, { type: "joined", clientId: client.id, role, room: roomId });
      wsLog.info({
        outcome: "success",
        action: "join",
        role,
        roomId,
        tokenRole: tokenPayload.role,
        roomViewerCount: room.viewers.size,
        hasPublisher: !!room.publisher,
      }, "ws.join.success");
      return;
    }

    if (!client.roomId || !client.role) {
      wsLog.warn({
        outcome: "failure",
        action: "message",
        messageType: message.type,
        reason: "join_required",
      }, "ws.message.rejected");
      sendError(ws, "Join required before signaling.");
      return;
    }

    const room = rooms.get(client.roomId);
    if (!room) {
      wsLog.warn({
        outcome: "failure",
        action: "message",
        messageType: message.type,
        roomId: client.roomId,
        reason: "room_not_found",
      }, "ws.message.rejected");
      sendError(ws, "Room not found.");
      return;
    }

    if (message.type === "offer" && client.role === "publisher") {
      const target = room.viewers.get(message.targetId);
      if (!target) {
        wsLog.warn({
          outcome: "failure",
          action: "offer",
          messageType: message.type,
          roomId: client.roomId,
          targetId: message.targetId,
          reason: "target_viewer_not_found",
        }, "ws.signal.dropped");
        return;
      }
      send(target.ws, { type: "offer", senderId: client.id, sdp: message.sdp });
      wsLog.debug({
        outcome: "success",
        action: "offer",
        messageType: message.type,
        roomId: client.roomId,
        targetId: message.targetId,
      }, "ws.signal.forwarded");
      return;
    }

    if (message.type === "answer" && client.role === "viewer") {
      if (!room.publisher) {
        wsLog.warn({
          outcome: "failure",
          action: "answer",
          messageType: message.type,
          roomId: client.roomId,
          reason: "publisher_offline",
        }, "ws.signal.dropped");
        return;
      }
      send(room.publisher.ws, { type: "answer", senderId: client.id, sdp: message.sdp });
      wsLog.debug({
        outcome: "success",
        action: "answer",
        messageType: message.type,
        roomId: client.roomId,
      }, "ws.signal.forwarded");
      return;
    }

    if (message.type === "ice-candidate") {
      const target = client.role === "publisher" ? room.viewers.get(message.targetId) : room.publisher;
      if (!target) {
        wsLog.warn({
          outcome: "failure",
          action: "ice-candidate",
          messageType: message.type,
          roomId: client.roomId,
          targetId: message.targetId,
          reason: "target_not_found",
        }, "ws.signal.dropped");
        return;
      }
      send(target.ws, { type: "ice-candidate", senderId: client.id, candidate: message.candidate });
      wsLog.debug({
        outcome: "success",
        action: "ice-candidate",
        messageType: message.type,
        roomId: client.roomId,
        targetId: message.targetId,
      }, "ws.signal.forwarded");
      return;
    }

    if (message.type === "ping") {
      send(ws, { type: "pong" });
      wsLog.debug({ outcome: "success", action: "ping", messageType: "ping", roomId: client.roomId }, "ws.ping.pong");
      return;
    }

    if (message.type === "proctor-command" && client.role === "viewer") {
      if (!ROLE_CAN_VIEW.has(client.tokenRole || "")) {
        wsLog.warn({
          outcome: "failure",
          action: "proctor-command",
          messageType: message.type,
          roomId: client.roomId,
          tokenRole: client.tokenRole,
          reason: "token_role_cannot_issue_proctor_command",
        }, "ws.proctor.failure");
        sendError(ws, "Role cannot issue proctor commands.");
        return;
      }

      const action = message.action === "terminate" ? "terminate" : "warn";
      if (room.publisher) {
        send(room.publisher.ws, {
          type: action === "terminate" ? "proctor-terminate" : "proctor-warn",
          reason: message.reason || undefined,
        });
        wsLog.info({
          outcome: "success",
          action: "proctor-command",
          messageType: message.type,
          command: action,
          roomId: client.roomId,
        }, "ws.proctor.command_forwarded");
      } else {
        wsLog.warn({
          outcome: "failure",
          action: "proctor-command",
          messageType: message.type,
          command: action,
          roomId: client.roomId,
          reason: "publisher_offline",
        }, "ws.proctor.command_dropped");
      }
      return;
    }

    wsLog.warn({
      outcome: "failure",
      action: "message",
      messageType: message.type,
      roomId: client.roomId,
      role: client.role,
      reason: "unsupported_message",
    }, "ws.message.rejected");
    sendError(ws, "Unsupported message.");
  });

  ws.on("close", (code, reason) => {
    const closeReason = closeReasonToString(reason) || undefined;
    releaseTrackedConnection("close");
    wsLog.info({
      outcome: "success",
      action: "close",
      closeCode: code,
      closeReason,
      role: client.role || undefined,
      roomId: client.roomId || undefined,
    }, "ws.connection.closed");

    if (!client.roomId) return;

    const room = rooms.get(client.roomId);
    if (!room) {
      wsLog.warn({
        outcome: "failure",
        action: "close",
        roomId: client.roomId,
        reason: "room_not_found_on_close",
      }, "ws.room.close_cleanup_skipped");
      return;
    }

    if (client.role === "publisher") {
      if (room.publisher && room.publisher.id === client.id) {
        room.publisher = null;
        room.viewers.forEach((viewer) => send(viewer.ws, { type: "publisher-offline" }));
        wsLog.info({
          outcome: "success",
          action: "publisher_left",
          roomId: client.roomId,
          notifiedViewers: room.viewers.size,
        }, "ws.room.publisher_left");
      }
    } else if (client.role === "viewer") {
      room.viewers.delete(client.id);
      if (room.publisher) {
        send(room.publisher.ws, { type: "viewer-left", viewerId: client.id });
      }
      wsLog.info({
        outcome: "success",
        action: "viewer_left",
        roomId: client.roomId,
        remainingViewers: room.viewers.size,
      }, "ws.room.viewer_left");
    }

    if (!room.publisher && room.viewers.size === 0) {
      rooms.delete(client.roomId);
      wsLog.info({ outcome: "success", action: "room_deleted", roomId: client.roomId }, "ws.room.deleted");
    }
  });

  ws.on("error", (error) => {
    releaseTrackedConnection("error");
    wsLog.error({
      outcome: "failure",
      action: "error",
      ...(serializeError(error) || {}),
    }, "ws.connection.error");
  });
});

httpServer.listen(PORT, () => {
  logger.info({
    layer: "system",
    action: "startup",
    outcome: "success",
    port: PORT,
  }, "server.started");
});

function shutdown(signal) {
  if (isShuttingDown) {
    logger.warn({
      layer: "system",
      action: "shutdown",
      outcome: "failure",
      signal,
      reason: "already_shutting_down",
    }, "server.shutdown.duplicate_signal");
    return;
  }
  isShuttingDown = true;
  const shutdownLog = logger.child({
    layer: "system",
    action: "shutdown",
    signal,
  });
  shutdownLog.warn({
    outcome: "start",
    activeConnections: wss.clients.size,
    graceMs: SHUTDOWN_GRACE_MS,
  }, "server.shutdown.start");
  clearInterval(heartbeatTimer);
  clearInterval(joinWindowCleanupTimer);

  const forceTimer = setTimeout(() => {
    shutdownLog.error({
      outcome: "failure",
      reason: "grace_period_expired",
      remainingConnections: wss.clients.size,
    }, "server.shutdown.force_terminate");
    for (const client of wss.clients) {
      client.terminate();
    }
    process.exit(0);
  }, SHUTDOWN_GRACE_MS);

  for (const client of wss.clients) {
    try {
      send(client, { type: "server-shutdown", message: "Signaling server is restarting." });
      client.close(1012, "Server restarting");
    } catch {
      // no-op
    }
  }

  httpServer.close(() => {
    clearTimeout(forceTimer);
    shutdownLog.info({
      outcome: "success",
      remainingConnections: wss.clients.size,
    }, "server.shutdown.complete");
    process.exit(0);
  });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
