> [!NOTE]
> Documentation Refresh Note (February 11, 2026): this file is retained as specialized or historical context.
> For current product behavior and authoritative guidance, start at /Users/James/code/GAD/apcg/README.md and /Users/James/code/GAD/apcg/docs/README.md.

# ACPG Deployment Guide

## Production Deployment

This guide covers deploying ACPG in production environments.

---

## Prerequisites

- Python 3.10+
- Node.js 18+
- Static analysis tools (Bandit, Safety, etc.)
- LLM provider configured (OpenAI, vLLM, or Ollama)

---

## Deployment Options

### Option 1: Service Scripts (Recommended)

**Best for**: Development, testing, small deployments

```bash
# Start services
./scripts/start.sh

# Check status
./scripts/status.sh

# Stop services
./scripts/stop.sh
```

**Advantages**:
- Simple setup
- Automatic port management
- Graceful startup/shutdown
- YAML configuration

---

### Option 2: Systemd Services

**Best for**: Production Linux servers

**Backend Service** (`/etc/systemd/system/acpg-backend.service`):
```ini
[Unit]
Description=ACPG Backend API
After=network.target

[Service]
Type=simple
User=acpg
WorkingDirectory=/opt/acpg/backend
Environment="PATH=/opt/acpg/backend/venv/bin"
ExecStart=/opt/acpg/backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 6000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Frontend Service** (`/etc/systemd/system/acpg-frontend.service`):
```ini
[Unit]
Description=ACPG Frontend
After=network.target acpg-backend.service

[Service]
Type=simple
User=acpg
WorkingDirectory=/opt/acpg/frontend
Environment="PATH=/usr/bin"
ExecStart=/usr/bin/npm run dev -- --port 6001
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable services**:
```bash
sudo systemctl enable acpg-backend
sudo systemctl enable acpg-frontend
sudo systemctl start acpg-backend
sudo systemctl start acpg-frontend
```

---

### Option 3: Docker Compose

**Best for**: Containerized deployments

**docker-compose.yml**:
```yaml
version: '3.8'

services:
  backend:
    build: ./backend
    ports:
      - "6000:6000"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - ./policies:/app/policies
      - ./backend/.keys:/app/.keys
    restart: unless-stopped

  frontend:
    build: ./frontend
    ports:
      - "6001:6001"
    depends_on:
      - backend
    restart: unless-stopped
```

**Deploy**:
```bash
docker-compose up -d
```

---

### Option 4: Kubernetes

**Best for**: Large-scale, cloud deployments

**k8s/backend-deployment.yaml**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: acpg-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: acpg-backend
  template:
    metadata:
      labels:
        app: acpg-backend
    spec:
      containers:
      - name: backend
        image: acpg-backend:latest
        ports:
        - containerPort: 6000
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: acpg-secrets
              key: openai-api-key
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
```

---

## Configuration

### Environment Variables

**Backend** (`.env` or environment):
```bash
OPENAI_API_KEY=sk-...
STATIC_ANALYSIS_CACHE_TTL=3600
MAX_FIX_ITERATIONS=3
SIGNER_NAME=ACPG-Production
```

### YAML Configuration

Edit `config.yaml`:
```yaml
services:
  backend:
    base_port: 6000
    auto_find_port: true
    
  frontend:
    base_port: 6001
    auto_find_port: true

api:
  cors_origins:
    - "https://yourdomain.com"
    - "https://app.yourdomain.com"
```

---

## Security Considerations

### 1. API Keys

- Store in environment variables
- Never commit to repository
- Use secrets management (Vault, AWS Secrets Manager)

### 2. CORS Configuration

- Restrict to known origins
- Don't use `*` in production
- Update `config.yaml` with production domains

### 3. Signing Keys

- Use persistent keys in production
- Store securely (encrypted)
- Rotate keys periodically
- Backup key material

### 4. Database

- Use PostgreSQL in production (not SQLite)
- Enable encryption at rest
- Regular backups
- Connection pooling

### 5. Rate Limiting

- Configure rate limits
- Monitor for abuse
- Use reverse proxy (nginx) for additional protection

---

## Monitoring

### Health Checks

**Endpoint**: `GET /api/v1/health`

**Monitoring**:
```bash
# Simple health check
curl http://localhost:6000/api/v1/health

# With alerting
watch -n 30 'curl -s http://localhost:6000/api/v1/health | jq .status'
```

**Integration**:
- Prometheus: Scrape `/api/v1/metrics`
- Grafana: Create dashboards
- AlertManager: Alert on unhealthy status

### Metrics

**Endpoint**: `GET /api/v1/metrics`

**Key Metrics**:
- Cache hit rate (target: >50%)
- Tool execution times
- Policy coverage
- System health

---

## Scaling

### Horizontal Scaling

**Backend**:
- Stateless design (scales horizontally)
- Use load balancer
- Shared database
- Shared cache (Redis recommended)

**Frontend**:
- Static assets (CDN recommended)
- API calls to backend
- No state (scales easily)

### Vertical Scaling

**Backend**:
- Increase memory for large code analysis
- More CPU for parallel tool execution
- Faster disk for cache

---

## Backup & Recovery

### What to Backup

1. **Signing Keys**: `backend/.keys/`
2. **Policies**: `policies/`
3. **Tool Mappings**: `policies/tool_mappings.json`
4. **Tool Config**: `policies/tool_config.json`
5. **Database**: SQLite file or PostgreSQL dump
6. **Proof Bundles**: If stored externally

### Backup Script

```bash
#!/bin/bash
# Backup ACPG data

BACKUP_DIR="/backups/acpg/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup keys
cp -r backend/.keys "$BACKUP_DIR/"

# Backup policies
cp -r policies "$BACKUP_DIR/"

# Backup database
sqlite3 backend/acpg.db ".backup $BACKUP_DIR/database.db"

# Compress
tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
```

---

## Troubleshooting

### Services Won't Start

1. Check ports: `netstat -tlnp | grep 6000`
2. Check logs: `tail -f /tmp/acpg_backend.log`
3. Check health: `curl http://localhost:6000/api/v1/health`
4. Check permissions: Verify file permissions

### Tools Not Running

1. Check installation: `which bandit`
2. Check enablement: Tools → Tools tab
3. Check health: Look at `/api/v1/health` tools section
4. Check logs: Backend logs show tool errors

### Performance Issues

1. Check metrics: `/api/v1/metrics`
2. Check cache: Cache hit rate should be >50%
3. Check tools: Disable unnecessary tools
4. Check resources: CPU, memory usage

---

## Production Checklist

### Pre-Deployment

- [ ] Environment variables configured
- [ ] CORS origins updated
- [ ] Signing keys generated and secured
- [ ] Database configured (PostgreSQL recommended)
- [ ] Static analysis tools installed
- [ ] LLM provider configured
- [ ] Monitoring set up
- [ ] Backup strategy in place

### Post-Deployment

- [ ] Health check passing
- [ ] Metrics endpoint accessible
- [ ] Tools executing correctly
- [ ] Proof bundles generating
- [ ] Frontend accessible
- [ ] No errors in logs
- [ ] Performance acceptable

---

## Maintenance

### Regular Tasks

1. **Weekly**:
   - Review cache statistics
   - Check tool versions
   - Review error logs

2. **Monthly**:
   - Update tool mappings
   - Review policy coverage
   - Performance optimization
   - Security updates

3. **Quarterly**:
   - Key rotation
   - Database optimization
   - Documentation updates

---

## Support

- **Documentation**: `docs/` directory
- **API Docs**: `http://localhost:6000/docs`
- **Health Check**: `http://localhost:6000/api/v1/health`
- **Metrics**: `http://localhost:6000/api/v1/metrics`

---

## Next Steps

1. ✅ Deployment guide complete
2. ⏳ Add Prometheus export
3. ⏳ Add cache management API
4. ⏳ Add bulk operations
5. ⏳ Production hardening

