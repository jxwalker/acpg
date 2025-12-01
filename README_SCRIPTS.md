# ACPG Service Management Scripts

## Overview

ACPG now uses YAML-based configuration and automated service management scripts for graceful startup, shutdown, and port management.

## Configuration

All settings are in `config.yaml`:

```yaml
services:
  backend:
    base_port: 6000
    auto_find_port: true  # Automatically find next available port if base is in use
    
  frontend:
    base_port: 6001
    auto_find_port: true

api:
  cors_origins:
    - "http://localhost:6001"
    - "http://localhost:6002"
    # ... more ports
```

## Scripts

### Start Services

```bash
./scripts/start.sh
```

**Features**:
- Reads ports from `config.yaml`
- Automatically finds free ports if base ports are in use
- Starts backend first, waits for it to be ready
- Starts frontend with correct proxy configuration
- Saves PIDs and ports to `/tmp/acpg_pids/`
- Shows startup status and URLs

**Output**:
```
Starting ACPG Services...
Backend port: 6000
Frontend port: 6001
✓ Backend is ready
✓ Frontend is ready

Backend:  http://localhost:6000
Frontend: http://localhost:6001
```

### Stop Services

```bash
./scripts/stop.sh
```

**Features**:
- Graceful shutdown (SIGTERM) with timeout
- Force kill if graceful shutdown fails
- Restores original vite.config.ts
- Cleans up PID and port files
- Kills any remaining processes

### Restart Services

```bash
./scripts/restart.sh
```

Stops all services, waits 2 seconds, then starts them again.

### Check Status

```bash
./scripts/status.sh
```

**Shows**:
- Running/stopped status for each service
- Process IDs
- Port numbers
- Service URLs

**Example Output**:
```
ACPG Service Status
==================

Backend:  RUNNING (PID: 12345, Port: 6000)
Frontend: RUNNING (PID: 12346, Port: 6001)

URLs:
  Backend:  http://localhost:6000
  Frontend: http://localhost:6001
```

## Port Management

### Automatic Port Finding

If `auto_find_port: true`:
- Script checks if base port is available
- If in use, finds next available port (base+1, base+2, etc.)
- Saves actual port to `/tmp/acpg_pids/{service}.port`

### Manual Port Override

Set environment variable:
```bash
ACPG_BACKEND_PORT=7000 ./scripts/start.sh
```

## File Locations

- **Config**: `config.yaml` (project root)
- **PIDs**: `/tmp/acpg_pids/backend.pid`, `/tmp/acpg_pids/frontend.pid`
- **Ports**: `/tmp/acpg_pids/backend.port`, `/tmp/acpg_pids/frontend.port`
- **Logs**: 
  - Backend: `/tmp/acpg_backend.log` (configurable)
  - Frontend: `/tmp/acpg_frontend.log` (configurable)

## Graceful Shutdown

1. Sends SIGTERM to processes
2. Waits up to 10 seconds (configurable) for graceful shutdown
3. If still running, sends SIGKILL
4. Cleans up all files

## Troubleshooting

### Port Already in Use

The script automatically finds the next available port. Check status:
```bash
./scripts/status.sh
```

### Services Won't Start

Check logs:
```bash
tail -f /tmp/acpg_backend.log
tail -f /tmp/acpg_frontend.log
```

### Can't Stop Services

Force stop:
```bash
./scripts/stop.sh
# If that doesn't work:
pkill -9 -f "uvicorn main:app"
pkill -9 -f "vite"
```

### Restore Original Vite Config

If vite.config.ts was modified:
```bash
cd frontend
mv vite.config.ts.bak vite.config.ts
```

## Integration with Backend

The backend reads CORS origins from `config.yaml`:
- Automatically includes all ports in `cors_origins` list
- Adds common dev ports (3000, 5173)
- No hardcoded ports in code

## Best Practices

1. **Always use scripts**: Don't start services manually
2. **Check status first**: `./scripts/status.sh` before starting
3. **Use restart**: `./scripts/restart.sh` for updates
4. **Monitor logs**: Watch logs during startup for errors
5. **Clean shutdown**: Always use `./scripts/stop.sh` before stopping

