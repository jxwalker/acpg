# Service Script Guide

ACPG provides helper scripts in `scripts/` for local orchestration.

## Scripts

- `./scripts/install.sh`: one-shot setup for backend + frontend dependencies and env bootstrap
- `./scripts/start.sh`: starts backend + frontend, auto-selects free ports near 6000/6001
- `./scripts/status.sh`: shows process and URL status
- `./scripts/stop.sh`: graceful shutdown and cleanup
- `./scripts/restart.sh`: stop then start

## Installer Options

```bash
./scripts/install.sh --help
./scripts/install.sh --with-static-tools
./scripts/install.sh --recreate-venv
./scripts/install.sh --npm-ci
./scripts/install.sh --skip-backend
./scripts/install.sh --skip-frontend
```

Installer behavior:
- Creates `.env` from `.env.example` if missing
- Creates `backend/.env` from `backend/.env.example` if missing
- Creates/uses `backend/venv` and installs `backend/requirements.txt`
- Installs frontend dependencies with `npm install` (or `npm ci`)

## Behavior

- Uses `config.yaml` for PID/log locations and shutdown timeout
- Writes PID/port files under configured `pid_dir` (default `/tmp/acpg_pids`)
- Rewrites `frontend/vite.config.ts` for proxy/port and restores backup on stop

## Typical Workflow

```bash
./scripts/start.sh
./scripts/status.sh
# ...work...
./scripts/stop.sh
```

## Logs

Default log paths (from `config.yaml`):
- Backend: `/tmp/acpg_backend.log`
- Frontend: `/tmp/acpg_frontend.log`

## Troubleshooting

- If startup fails, inspect logs above.
- If stale PID files exist, run `./scripts/stop.sh` and retry.
