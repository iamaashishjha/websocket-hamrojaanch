# Live Proctor Signaling Server

This server provides WebSocket signaling for WebRTC candidate live feeds.

## Install

```bash
cd ws
npm install
```

## Run

```bash
npm run dev
```

The server listens on `http://localhost:3001` by default.

## Environment Variables

- `NODE_ENV` (set `production` in production)
- `SIGNALING_PORT` (default: `3001`)
- `SIGNALING_SECRET` (default: `dev_secret_change_me`)
- `SIGNALING_TOKEN_TTL` (default: `600` seconds)
- `SIGNALING_CORS_ORIGIN` (comma-separated allowed origins)
- `ALLOW_DIRECT_TOKEN_ENDPOINT` (default: `false`, must remain `false` in production)
- `SHUTDOWN_GRACE_MS` (default: `15000`)
- `WS_HEARTBEAT_INTERVAL_MS` (default: `30000`)
- `WS_MAX_MESSAGE_BYTES` (default: `65536`)
- `WS_MAX_CONNECTIONS_PER_IP` (default: `40`)
- `WS_MAX_VIEWERS_PER_ROOM` (default: `60`)
- `WS_MAX_ROOMS` (default: `5000`)
- `WS_JOIN_RATE_WINDOW_MS` (default: `60000`)
- `WS_MAX_JOIN_ATTEMPTS_PER_WINDOW` (default: `30`)

## Frontend Config (Vite)

Optional env overrides:

- `VITE_SIGNALING_URL` (default: `ws://localhost:3001/ws`)
- `VITE_SIGNALING_HTTP_URL` (default: `http://localhost:3001`)
- `VITE_ICE_SERVERS` JSON array, example:

```json
[{"urls":"stun:stun.l.google.com:19302"}]
```

In production, provide TURN servers in `VITE_ICE_SERVERS`.
