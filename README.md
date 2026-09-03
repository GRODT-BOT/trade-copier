# Trade Copier relay

Relay and control panel for a NinjaTrader 8 remote trade copier.

Deployed on Railway. No dependencies, no build step.

- Control panel: `/admin`
- Health check: `/v1/health`

Environment variables (both optional):

| Name | Default | Purpose |
|---|---|---|
| `DATA_DIR` | app directory | Where `data.json` lives. Point at a mounted volume so members and the admin password survive redeploys. |
| `POLL_MS` | `20000` | How long a follower's request is held open before returning empty. |
