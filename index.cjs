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
  const originAllowed = applyCorsHeaders(req, res);
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    if (!originAllowed) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Origin not allowed." }));
      return;
    }
    res.writeHead(204);
    res.end();
    return;
  }

  if (!originAllowed) {
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
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, ready: false, message: "Server is shutting down" }));
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, ready: true }));
    return;
  }

  if (url.pathname === "/token") {
    if (isShuttingDown) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Server is shutting down." }));
      return;
    }
    if (!ALLOW_DIRECT_TOKEN_ENDPOINT) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Direct token issuance is disabled." }));
      return;
    }

    const role = String(url.query.role || "").toLowerCase();
    const examId = String(url.query.examId || "");
    const attemptId = String(url.query.attemptId || "");
    if (!role || !examId || !attemptId) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "role, examId, and attemptId are required." }));
      return;
    }
    if (!ROLE_CAN_PUBLISH.has(role) && !ROLE_CAN_VIEW.has(role)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Role not permitted." }));
      return;
    }

    const room = `${examId}:${attemptId}`;
    if (!ROOM_ID_PATTERN.test(room)) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid room id format." }));
      return;
    }

    const token = issueToken({ role, room });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ token, expiresAt: new Date((nowSeconds() + TOKEN_TTL_SECONDS) * 1000).toISOString() }));
    return;
  }

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

const heartbeatTimer = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
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
  for (const [ip, entry] of joinWindowByIp.entries()) {
    if (now - entry.touchedAt > staleAfter) {
      joinWindowByIp.delete(ip);
    }
  }
}, Math.max(30000, JOIN_RATE_WINDOW_MS));
if (typeof joinWindowCleanupTimer.unref === "function") {
  joinWindowCleanupTimer.unref();
}

wss.on("connection", (ws, req) => {
  if (isShuttingDown) {
    ws.close(1012, "Server restarting");
    return;
  }

  const clientIp = getClientIp(req);
  if (!isWebSocketOriginAllowed(req)) {
    ws.close(1008, "Origin not allowed");
    return;
  }
  if (!reserveConnection(clientIp)) {
    ws.close(1013, "Connection limit reached");
    return;
  }

  let connectionReleased = false;
  const releaseTrackedConnection = () => {
    if (connectionReleased) return;
    connectionReleased = true;
    releaseConnection(clientIp);
  };

  ws.isAlive = true;
  ws.on("pong", () => {
    ws.isAlive = true;
  });

  const client = {
    id: typeof crypto.randomUUID === "function" ? `client_${crypto.randomUUID()}` : `client_${Math.random().toString(36).slice(2, 10)}`,
    role: null,
    tokenRole: null,
    roomId: null,
  };
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
    if (!consumeMessageQuota()) {
      sendError(ws, "Message rate limit exceeded.");
      ws.close(1008, "Rate limit exceeded");
      return;
    }

    const rawSize = typeof raw === "string" ? Buffer.byteLength(raw) : raw.length;
    if (rawSize > MAX_MESSAGE_BYTES) {
      sendError(ws, "Message exceeds maximum allowed size.");
      ws.close(1009, "Message too large");
      return;
    }

    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      sendError(ws, "Invalid JSON message.");
      return;
    }

    if (!message || typeof message.type !== "string") {
      sendError(ws, "Malformed message.");
      return;
    }

    if (message.type === "join") {
      if (!canJoin(clientIp)) {
        sendError(ws, "Too many join attempts from this IP. Please retry shortly.");
        return;
      }
      if (client.roomId || client.role) {
        sendError(ws, "Client has already joined a room.");
        return;
      }

      const role = message.role;
      const roomId = message.room;
      if (!SIGNALING_ROLES.has(role)) {
        sendError(ws, "Invalid signaling role.");
        return;
      }
      if (typeof roomId !== "string" || !ROOM_ID_PATTERN.test(roomId)) {
        sendError(ws, "Invalid room id.");
        return;
      }

      const tokenPayload = verifyToken(message.token);
      if (!tokenPayload) {
        sendError(ws, "Invalid or expired token.");
        return;
      }
      if (tokenPayload.room !== roomId) {
        sendError(ws, "Token room mismatch.");
        return;
      }
      if (role === "publisher" && !ROLE_CAN_PUBLISH.has(tokenPayload.role)) {
        sendError(ws, "Role cannot publish.");
        return;
      }
      if (role === "viewer" && !ROLE_CAN_VIEW.has(tokenPayload.role)) {
        sendError(ws, "Role cannot view.");
        return;
      }

      const existingRoom = rooms.get(roomId);
      if (!existingRoom && rooms.size >= MAX_ROOMS) {
        sendError(ws, "Server room capacity reached.");
        return;
      }
      const room = getRoom(roomId);
      if (role === "viewer" && room.viewers.size >= MAX_VIEWERS_PER_ROOM) {
        sendError(ws, "Room viewer limit reached.");
        return;
      }

      client.role = role;
      client.tokenRole = tokenPayload.role;
      client.roomId = roomId;

      if (role === "publisher") {
        if (room.publisher && room.publisher.ws !== ws) {
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
      return;
    }

    if (!client.roomId || !client.role) {
      sendError(ws, "Join required before signaling.");
      return;
    }

    const room = rooms.get(client.roomId);
    if (!room) {
      sendError(ws, "Room not found.");
      return;
    }

    if (message.type === "offer" && client.role === "publisher") {
      const target = room.viewers.get(message.targetId);
      if (target) {
        send(target.ws, { type: "offer", senderId: client.id, sdp: message.sdp });
      }
      return;
    }

    if (message.type === "answer" && client.role === "viewer") {
      if (room.publisher) {
        send(room.publisher.ws, { type: "answer", senderId: client.id, sdp: message.sdp });
      }
      return;
    }

    if (message.type === "ice-candidate") {
      const target =
        client.role === "publisher"
          ? room.viewers.get(message.targetId)
          : room.publisher;
      if (target) {
        send(target.ws, { type: "ice-candidate", senderId: client.id, candidate: message.candidate });
      }
      return;
    }

    if (message.type === "ping") {
      send(ws, { type: "pong" });
      return;
    }

    if (message.type === "proctor-command" && client.role === "viewer") {
      if (!ROLE_CAN_VIEW.has(client.tokenRole || "")) {
        sendError(ws, "Role cannot issue proctor commands.");
        return;
      }

      const action = message.action === "terminate" ? "terminate" : "warn";
      if (room.publisher) {
        send(room.publisher.ws, {
          type: action === "terminate" ? "proctor-terminate" : "proctor-warn",
          reason: message.reason || undefined,
        });
      }
      return;
    }

    sendError(ws, "Unsupported message.");
  });

  ws.on("close", () => {
    releaseTrackedConnection();
    if (!client.roomId) return;

    const room = rooms.get(client.roomId);
    if (!room) return;

    if (client.role === "publisher") {
      if (room.publisher && room.publisher.id === client.id) {
        room.publisher = null;
        room.viewers.forEach((viewer) => send(viewer.ws, { type: "publisher-offline" }));
      }
    } else if (client.role === "viewer") {
      room.viewers.delete(client.id);
      if (room.publisher) {
        send(room.publisher.ws, { type: "viewer-left", viewerId: client.id });
      }
    }

    if (!room.publisher && room.viewers.size === 0) {
      rooms.delete(client.roomId);
    }
  });

  ws.on("error", () => {
    releaseTrackedConnection();
  });
});

httpServer.listen(PORT, () => {
  console.log(`Signaling server running on http://localhost:${PORT}`);
});

function shutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`[ws] Received ${signal}. Starting graceful shutdown...`);
  clearInterval(heartbeatTimer);
  clearInterval(joinWindowCleanupTimer);

  const forceTimer = setTimeout(() => {
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
    console.log("[ws] Shutdown complete.");
    process.exit(0);
  });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
