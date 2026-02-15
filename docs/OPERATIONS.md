# ACPG Operations Runbook

Operational procedures for the Agentic Compliance and Policy Governor (ACPG).

---

## 1. Starting and Stopping Services

ACPG consists of two services: a **backend** (FastAPI/Uvicorn) and a **frontend** (Vite dev server). The `scripts/` directory contains lifecycle scripts that manage both.

### Start

```bash
./scripts/start.sh
```

This script:
- Sources shared config from `scripts/_common.sh`, which reads `config.yaml` for PID directory, log paths, and timeouts.
- Finds free ports starting from **6000** (backend) and **6001** (frontend).
- Activates the backend virtualenv at `backend/venv/`.
- Launches `uvicorn main:app --host 0.0.0.0 --port <PORT>` via `nohup`.
- Waits up to 30 seconds for the backend `/api/v1/health` endpoint to respond.
- Launches the frontend with `npm run dev`, passing `VITE_PORT` and `VITE_BACKEND_URL`.
- Writes PID files to the configured `pid_dir` (default: `./data/pids/`).
- Writes port files (`backend.port`, `frontend.port`) and a lock file (`acpg.lock`).

### Stop

```bash
./scripts/stop.sh
```

This script:
- Sends `SIGTERM` to each service PID and waits up to `graceful_shutdown_timeout` seconds (default: 10).
- Falls back to `kill -9` if the process does not exit in time.
- Kills any remaining processes listening on the recorded ports.
- Cleans up PID files, port files, and the lock file.

### Restart

```bash
./scripts/restart.sh
```

### PID and Port Files

All state files live in the directory configured by `process.pid_dir` in `config.yaml` (default `./data/pids/`):

| File              | Purpose                            |
|-------------------|------------------------------------|
| `backend.pid`     | Backend Uvicorn process ID         |
| `frontend.pid`    | Frontend Vite process ID           |
| `backend.port`    | Actual port the backend is using   |
| `frontend.port`   | Actual port the frontend is using  |
| `acpg.lock`       | Prevents duplicate startup         |

### Verify Running Ports

```bash
# Check what is listening on the expected ports
lsof -Pi :6000 -sTCP:LISTEN
lsof -Pi :6001 -sTCP:LISTEN

# Or read the actual ports from state files
cat ./data/pids/backend.port
cat ./data/pids/frontend.port
```

---

## 2. Health Checks and Diagnostics

### Health Endpoint

```bash
curl -s http://localhost:6000/api/v1/health | python3 -m json.tool
```

Returns component-level status for: **api**, **database**, **tools** (static analyzers), **llm** (provider connectivity), **policies**, and **signing** (key manager).

Top-level `status` values:
- `healthy` -- all components operational.
- `degraded` -- at least one component reports an issue.

Example response (abbreviated):

```json
{
  "status": "healthy",
  "service": "ACPG",
  "version": "1.0.0",
  "components": {
    "api":      { "status": "healthy" },
    "database": { "status": "healthy" },
    "tools":    { "status": "healthy", "available": ["bandit", "semgrep"] },
    "llm":      { "status": "healthy", "provider": "OpenAI GPT-4", "model": "gpt-4" },
    "policies": { "status": "healthy", "count": 42 },
    "signing":  { "status": "healthy", "fingerprint": "a1b2c3d4..." }
  },
  "timestamp": "2026-02-15T12:00:00+00:00"
}
```

### Metrics Endpoint (JSON)

```bash
curl -s http://localhost:6000/api/v1/metrics | python3 -m json.tool
```

Returns cache hit/miss rates, enabled tool counts, policy statistics, and performance notes.

### System Info

```bash
curl -s http://localhost:6000/api/v1/info | python3 -m json.tool
```

---

## 3. Log Locations and Rotation

### Default Log Paths

Configured in `config.yaml` under `logging`:

| Service   | Default path                       |
|-----------|------------------------------------|
| Backend   | `./data/logs/acpg_backend.log`     |
| Frontend  | `./data/logs/acpg_frontend.log`    |

The start script redirects `nohup` stdout/stderr to these files.

### Structured JSON Logging

The backend emits structured JSON logs to stdout (and optionally to a rotating file). Each log line is a JSON object:

```json
{
  "timestamp": "2026-02-15T12:00:00.123456+00:00",
  "level": "INFO",
  "logger": "acpg.middleware",
  "message": "GET /api/v1/health - 200",
  "request_id": "d4e5f6a7-...",
  "event": "api_request",
  "method": "GET",
  "path": "/api/v1/health",
  "status_code": 200,
  "duration_ms": 12.34,
  "client_ip": "127.0.0.1"
}
```

The `request_id` field is populated automatically by the `RequestIdMiddleware` and correlates with the `X-Request-ID` response header.

### File-Based Log Rotation

For bare-metal deployments, enable rotating file logs by setting these environment variables:

```bash
export LOG_FILE=/var/log/acpg/acpg.log
export LOG_MAX_BYTES=10485760   # 10 MB (default)
export LOG_BACKUP_COUNT=5       # Keep 5 rotated files (default)
```

This creates a `RotatingFileHandler` that rolls over when the file reaches `LOG_MAX_BYTES`. Rotated files are named `acpg.log.1`, `acpg.log.2`, etc.

### Log Level

Set via the `LOG_LEVEL` environment variable (or in `.env`). Valid values: `DEBUG`, `INFO`, `WARNING`, `ERROR`.

```bash
export LOG_LEVEL=DEBUG
```

### Tail Logs

```bash
# Backend log (nohup output)
tail -f ./data/logs/acpg_backend.log

# Structured file log (if LOG_FILE is set)
tail -f /var/log/acpg/acpg.log | python3 -m json.tool --no-ensure-ascii
```

---

## 4. Database Backup and Restore

ACPG supports SQLite (default) and PostgreSQL. The active database is controlled by the `DATABASE_URL` environment variable.

### SQLite

The default database file is `backend/acpg.db`.

**Backup:**

```bash
# Stop the backend first to avoid database-locked issues, or use .backup
cp backend/acpg.db backend/acpg.db.bak.$(date +%Y%m%d_%H%M%S)
```

**Restore:**

```bash
./scripts/stop.sh
cp backend/acpg.db.bak.20260215_120000 backend/acpg.db
./scripts/start.sh
```

### PostgreSQL

Set the connection string in `.env` or the environment:

```bash
export DATABASE_URL=postgresql://user:pass@localhost:5432/acpg
```

**Backup:**

```bash
pg_dump -Fc -h localhost -U user -d acpg -f acpg_backup_$(date +%Y%m%d_%H%M%S).dump
```

**Restore:**

```bash
pg_restore -h localhost -U user -d acpg --clean --if-exists acpg_backup_20260215_120000.dump
```

### PostgreSQL Connection Pool Tuning

The following env vars control pool behavior when using PostgreSQL:

| Variable                  | Default | Description                          |
|---------------------------|---------|--------------------------------------|
| `DB_POOL_SIZE`            | 5       | Number of persistent connections     |
| `DB_MAX_OVERFLOW`         | 10      | Extra connections above pool size    |
| `DB_POOL_RECYCLE_SECONDS` | 300     | Recycle connections after N seconds  |

---

## 5. Common Troubleshooting

### LLM Timeouts or Errors

**Symptom:** `/api/v1/health` reports `llm.status: "unhealthy"`, or analysis/enforcement calls return 500 errors.

**Checks:**

```bash
# Verify the API key is set
grep OPENAI_API_KEY .env          # or ANTHROPIC_API_KEY, KIMI_API_KEY
curl -s http://localhost:6000/api/v1/health | python3 -c "import sys,json; print(json.load(sys.stdin)['components']['llm'])"
```

**Common causes:**
- Missing or invalid API key in `.env`.
- Rate limits hit on the provider side. Check provider dashboard for quota.
- Network connectivity issues to the LLM API.
- Wrong `ACPG_LLM_PROVIDER` value. Valid options: `local_vllm`, `openai_gpt4`, `openai_gpt4_turbo`, `openai_gpt35`, `ollama_codellama`, `kimi`.

### Port Conflicts

**Symptom:** `start.sh` auto-increments the port (e.g., backend starts on 6002 instead of 6000).

```bash
# Find what is using the port
lsof -Pi :6000 -sTCP:LISTEN

# Kill a specific PID
kill <PID>
```

The start script will automatically find the next free port, but if you need a specific port, free it first and restart.

### Stale PID / Lock Files

**Symptom:** `start.sh` says "ACPG is already running" but services are actually down.

The start script detects stale lock files automatically. If it does not, clean up manually:

```bash
rm -f ./data/pids/acpg.lock ./data/pids/*.pid ./data/pids/*.port
./scripts/start.sh
```

### Database Locked (SQLite)

**Symptom:** `sqlite3.OperationalError: database is locked`.

**Causes:**
- Multiple Uvicorn workers writing concurrently. The default config uses 1 worker for SQLite; do not increase it.
- A backup process (`cp`) has the file open. Use `./scripts/stop.sh` before backing up, or switch to PostgreSQL for concurrent access.
- A leftover `alembic` migration process. Check for stale processes:

```bash
lsof backend/acpg.db
```

### Health Endpoint Reports "degraded"

Inspect individual components:

```bash
curl -s http://localhost:6000/api/v1/health | python3 -c "
import sys, json
data = json.load(sys.stdin)
for name, info in data['components'].items():
    if info.get('status') != 'healthy':
        print(f'  {name}: {info}')
"
```

---

## 6. Monitoring

### Prometheus Metrics

Scrape the Prometheus-format endpoint:

```bash
curl -s http://localhost:6000/api/v1/metrics/prometheus
```

Example output:

```
# HELP acpg_cache_entries_total Total number of cache entries
# TYPE acpg_cache_entries_total gauge
acpg_cache_entries_total 12
# HELP acpg_policies_total Total number of policies
# TYPE acpg_policies_total gauge
acpg_policies_total 42
# HELP acpg_health_status System health status (1=healthy, 0=unhealthy)
# TYPE acpg_health_status gauge
acpg_health_status 1
```

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'acpg'
    metrics_path: '/api/v1/metrics/prometheus'
    static_configs:
      - targets: ['localhost:6000']
```

### Request ID Tracing

Every request is assigned a unique `X-Request-ID`. You can also supply your own:

```bash
curl -H "X-Request-ID: my-trace-123" http://localhost:6000/api/v1/health
```

The same ID appears in:
- The `X-Request-ID` response header.
- Every structured JSON log line emitted during that request (`"request_id": "my-trace-123"`).
- The `request_id` column in the `audit_logs` database table.

### Searching Logs by Request ID

```bash
# If using file-based logging
grep '"request_id": "my-trace-123"' /var/log/acpg/acpg.log

# From the nohup log
grep '"request_id": "my-trace-123"' ./data/logs/acpg_backend.log
```

### Alerting Suggestions

| Metric / Check                  | Condition                       | Severity |
|---------------------------------|---------------------------------|----------|
| `/api/v1/health` status         | != `healthy`                    | Warning  |
| `/api/v1/health` HTTP status    | Non-200 or timeout > 5s        | Critical |
| `acpg_health_status`            | 0                               | Critical |
| `acpg_cache_hit_rate`           | < 0.3 sustained                 | Warning  |
| Backend process (PID check)     | Not running                     | Critical |

---

## 7. Alembic Database Migrations

Alembic manages schema changes. The configuration lives in `backend/alembic.ini` and migration scripts are in `backend/alembic/versions/`.

All commands below must be run from the `backend/` directory with the virtualenv active.

```bash
cd backend
source venv/bin/activate
```

### Apply All Pending Migrations

```bash
alembic upgrade head
```

### Check Current Migration Version

```bash
alembic current
```

### View Migration History

```bash
alembic history --verbose
```

### Create a New Migration (Autogenerate)

After modifying SQLAlchemy models in `app/core/database.py`:

```bash
alembic revision --autogenerate -m "Add new_column to audit_logs"
```

Review the generated file in `alembic/versions/` before applying.

### Downgrade One Revision

```bash
alembic downgrade -1
```

### Notes

- The default `sqlalchemy.url` in `alembic.ini` points to `sqlite:///acpg.db`. For PostgreSQL, either edit `alembic.ini` or set `DATABASE_URL` in the environment (if `alembic/env.py` reads it).
- The application also runs lightweight self-bootstrap migrations on startup via `init_db()`, but Alembic should be the primary mechanism for schema changes.

---

## 8. Deployment Checklist

### Environment Variables

Set these in `.env` or the system environment before starting:

```bash
# Required: At least one LLM provider key
OPENAI_API_KEY=sk-...
# -- or --
ANTHROPIC_API_KEY=sk-ant-...
# -- or --
KIMI_API_KEY=...

# Optional: Override the active provider
ACPG_LLM_PROVIDER=openai_gpt4

# Optional: Master API key for authentication
ACPG_API_KEY=your-secure-api-key

# Logging
LOG_LEVEL=INFO

# Database (omit for SQLite default)
DATABASE_URL=postgresql://user:pass@localhost:5432/acpg

# Log rotation (bare-metal)
LOG_FILE=/var/log/acpg/acpg.log
LOG_MAX_BYTES=10485760
LOG_BACKUP_COUNT=5
```

### Dependency Installation

```bash
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install
```

### Database Initialization

```bash
cd backend
source venv/bin/activate

# Option A: Let the app self-bootstrap (creates tables on first start)
# Just start the app -- init_db() runs automatically.

# Option B: Use Alembic (recommended for production)
alembic upgrade head
```

### CORS Origins

CORS origins are configured in two places:

1. **`config.yaml`** under `api.cors_origins` -- add your production frontend URL here.
2. **`main.py`** hardcodes common dev ports (`localhost:3000`, `localhost:5173`).

For production, edit `config.yaml`:

```yaml
api:
  cors_origins:
    - "https://your-production-domain.com"
    - "http://localhost:6001"
```

### Log Rotation Configuration

For systemd or bare-metal deployments where the app writes to a file:

```bash
export LOG_FILE=/var/log/acpg/acpg.log
export LOG_MAX_BYTES=10485760   # 10 MB
export LOG_BACKUP_COUNT=5
```

Ensure the log directory exists and is writable:

```bash
sudo mkdir -p /var/log/acpg
sudo chown $(whoami) /var/log/acpg
```

For container deployments, skip `LOG_FILE` and rely on stdout (captured by Docker/Kubernetes).

### Pre-Start Verification

```bash
# 1. Check env file exists
test -f .env && echo "OK" || echo "MISSING .env"

# 2. Check backend venv exists
test -d backend/venv && echo "OK" || echo "MISSING backend/venv"

# 3. Check frontend node_modules
test -d frontend/node_modules && echo "OK" || echo "Run: cd frontend && npm install"

# 4. Check ports are free
lsof -Pi :6000 -sTCP:LISTEN && echo "PORT 6000 IN USE" || echo "Port 6000 free"
lsof -Pi :6001 -sTCP:LISTEN && echo "PORT 6001 IN USE" || echo "Port 6001 free"

# 5. Start services
./scripts/start.sh

# 6. Verify health
sleep 5
curl -sf http://localhost:6000/api/v1/health | python3 -m json.tool
```
