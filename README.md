# Live Proctor Signaling Server

Production websocket signaling service for WebRTC candidate live feeds.

## Install

```bash
cd websocket-hamrojaanch
npm install
```

## Run

```bash
npm run dev
```

The root entrypoint is `index.cjs`, which boots `src/server.cjs`.
By default, the server listens on `http://localhost:3001` and websocket path `/ws`.

## Environment Variables

Required:
- `SIGNALING_SECRET` (strong random secret; required in all environments)

Core:
- `NODE_ENV` (`development` | `production`)
- `SIGNALING_PORT` (default: `3001`)
- `SIGNALING_TOKEN_TTL` (default: `600` seconds)
- `SIGNALING_CORS_ORIGIN` (comma-separated allowed origins)
- `SIGNALING_TRUST_PROXY` (`true` only behind trusted reverse proxy)
- `ALLOW_DIRECT_TOKEN_ENDPOINT` (default: `false`; must remain `false` in production)

Observability:
- `LOG_LEVEL` (`debug` | `info` | `warn` | `error`)
- `SIGNALING_SERVICE_NAME` (default: `backend-api`)
- `SIGNALING_SERVICE_VERSION` (default: `v1`)
- `SIGNALING_LOG_SCOPE` (default: `signaling`)

Abuse controls:
- `SHUTDOWN_GRACE_MS` (default: `15000`)
- `WS_HEARTBEAT_INTERVAL_MS` (default: `30000`)
- `WS_MAX_MESSAGE_BYTES` (default: `65536`)
- `WS_MAX_SIGNAL_FIELD_BYTES` (default: `16384`)
- `WS_MAX_CONNECTIONS_PER_IP` (default: `40`)
- `WS_MAX_VIEWERS_PER_ROOM` (default: `60`)
- `WS_MAX_ROOMS` (default: `5000`)
- `WS_JOIN_RATE_WINDOW_MS` (default: `60000`)
- `WS_MAX_JOIN_ATTEMPTS_PER_WINDOW` (default: `30`)
- `WS_MESSAGE_RATE_WINDOW_MS` (default: `10000`)
- `WS_MAX_MESSAGES_PER_WINDOW` (default: `200`)

## Frontend Config (Vite)

Supported env keys:
- `VITE_SIGNALING_WS_URL` (preferred)
- `VITE_SIGNALING_URL` (legacy fallback)
- `VITE_SIGNALING_HTTP_URL`
- `VITE_ICE_SERVERS` JSON array, example:

```json
[{"urls":"stun:stun.l.google.com:19302"}]
```

In production, provide TURN servers in `VITE_ICE_SERVERS`.
