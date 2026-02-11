> [!NOTE]
> Documentation Refresh Note (February 11, 2026): this file is retained as specialized or historical context.
> For current product behavior and authoritative guidance, start at /Users/James/code/GAD/apcg/README.md and /Users/James/code/GAD/apcg/docs/README.md.

# Prometheus Metrics Guide

## Overview

ACPG exposes metrics in Prometheus format for monitoring and alerting. Metrics are available at `/api/v1/metrics/prometheus`.

## Endpoint

### GET `/api/v1/metrics/prometheus`

Returns metrics in Prometheus exposition format (text/plain).

**Content-Type**: `text/plain; version=0.0.4`

---

## Available Metrics

### Cache Metrics

#### `acpg_cache_entries_total`
- **Type**: Gauge
- **Description**: Total number of cache entries
- **Labels**: None

#### `acpg_cache_size_bytes`
- **Type**: Gauge
- **Description**: Total cache size in bytes
- **Labels**: None

#### `acpg_cache_hits_total`
- **Type**: Counter
- **Description**: Total number of cache hits
- **Labels**: None

#### `acpg_cache_misses_total`
- **Type**: Counter
- **Description**: Total number of cache misses
- **Labels**: None

#### `acpg_cache_hit_rate`
- **Type**: Gauge
- **Description**: Cache hit rate percentage (0-100)
- **Labels**: None

### Tool Metrics

#### `acpg_tools_enabled_total`
- **Type**: Gauge
- **Description**: Total number of enabled static analysis tools
- **Labels**: None

#### `acpg_tool_enabled`
- **Type**: Gauge
- **Description**: Whether a specific tool is enabled (1=enabled, 0=disabled)
- **Labels**:
  - `tool`: Tool name (e.g., "bandit", "eslint")
  - `language`: Language (e.g., "python", "javascript")

### Policy Metrics

#### `acpg_policies_total`
- **Type**: Gauge
- **Description**: Total number of loaded policies
- **Labels**: None

### Health Metrics

#### `acpg_health_status`
- **Type**: Gauge
- **Description**: System health status (1=healthy, 0=unhealthy)
- **Labels**: None

---

## Example Output

```
# HELP acpg_cache_entries_total Total number of cache entries
# TYPE acpg_cache_entries_total gauge
acpg_cache_entries_total 8

# HELP acpg_cache_size_bytes Total cache size in bytes
# TYPE acpg_cache_size_bytes gauge
acpg_cache_size_bytes 20480

# HELP acpg_cache_hits_total Total cache hits
# TYPE acpg_cache_hits_total counter
acpg_cache_hits_total 15

# HELP acpg_cache_misses_total Total cache misses
# TYPE acpg_cache_misses_total counter
acpg_cache_misses_total 8

# HELP acpg_cache_hit_rate Cache hit rate percentage
# TYPE acpg_cache_hit_rate gauge
acpg_cache_hit_rate 65.22

# HELP acpg_tool_enabled Whether a tool is enabled
# TYPE acpg_tool_enabled gauge
acpg_tool_enabled{tool="bandit",language="python"} 1
acpg_tool_enabled{tool="safety",language="python"} 1
acpg_tool_enabled{tool="eslint",language="javascript"} 1

# HELP acpg_tools_enabled_total Total number of enabled tools
# TYPE acpg_tools_enabled_total gauge
acpg_tools_enabled_total 3

# HELP acpg_policies_total Total number of policies
# TYPE acpg_policies_total gauge
acpg_policies_total 39

# HELP acpg_health_status System health status (1=healthy, 0=unhealthy)
# TYPE acpg_health_status gauge
acpg_health_status 1
```

---

## Prometheus Configuration

### prometheus.yml

```yaml
scrape_configs:
  - job_name: 'acpg'
    scrape_interval: 30s
    metrics_path: '/api/v1/metrics/prometheus'
    static_configs:
      - targets: ['localhost:6000']
```

### Docker Compose

```yaml
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
  
  acpg:
    # ... ACPG configuration
```

---

## Grafana Dashboards

### Example Queries

**Cache Hit Rate**:
```promql
(acpg_cache_hits_total / (acpg_cache_hits_total + acpg_cache_misses_total)) * 100
```

**Cache Size Over Time**:
```promql
acpg_cache_size_bytes
```

**Enabled Tools Count**:
```promql
acpg_tools_enabled_total
```

**Tool Status**:
```promql
acpg_tool_enabled
```

**Policy Count**:
```promql
acpg_policies_total
```

**System Health**:
```promql
acpg_health_status
```

### Alerting Rules

**Low Cache Hit Rate**:
```yaml
groups:
  - name: acpg
    rules:
      - alert: LowCacheHitRate
        expr: acpg_cache_hit_rate < 30
        for: 5m
        annotations:
          summary: "ACPG cache hit rate is below 30%"
```

**System Unhealthy**:
```yaml
      - alert: SystemUnhealthy
        expr: acpg_health_status == 0
        for: 1m
        annotations:
          summary: "ACPG system is unhealthy"
```

**High Cache Size**:
```yaml
      - alert: HighCacheSize
        expr: acpg_cache_size_bytes > 52428800  # 50MB
        for: 5m
        annotations:
          summary: "ACPG cache size exceeds 50MB"
```

---

## Integration Examples

### Kubernetes ServiceMonitor

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: acpg
spec:
  selector:
    matchLabels:
      app: acpg
  endpoints:
    - port: http
      path: /api/v1/metrics/prometheus
      interval: 30s
```

### Docker Compose with Prometheus

```yaml
version: '3.8'
services:
  acpg:
    # ... ACPG service
  
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
```

---

## Best Practices

### Scrape Interval

- **Development**: 30-60 seconds
- **Production**: 15-30 seconds
- **High-frequency monitoring**: 10-15 seconds

### Retention

- **Short-term**: 7-15 days (detailed metrics)
- **Long-term**: 30-90 days (aggregated metrics)

### Alerting

- Set alerts for:
  - System health (`acpg_health_status == 0`)
  - Low cache hit rate (`acpg_cache_hit_rate < 30`)
  - High cache size (`acpg_cache_size_bytes > threshold`)
  - Tool failures (if tool-specific metrics added)

### Dashboard Design

1. **Overview Panel**: System health, cache hit rate, tool count
2. **Cache Panel**: Cache size, hits, misses, hit rate over time
3. **Tool Panel**: Enabled tools, tool status
4. **Policy Panel**: Policy count, policy coverage
5. **Performance Panel**: Analysis times (if added)

---

## Future Enhancements

### Planned Metrics

- `acpg_analysis_duration_seconds` - Analysis execution time
- `acpg_tool_execution_duration_seconds` - Per-tool execution time
- `acpg_violations_total` - Total violations detected
- `acpg_proof_bundles_generated_total` - Proof bundles created
- `acpg_enforcements_total` - Compliance enforcements
- `acpg_policy_checks_total` - Policy checks performed

### Custom Metrics

You can extend the metrics endpoint to include:
- Business-specific metrics
- Custom performance indicators
- Integration-specific metrics

---

## Troubleshooting

### Metrics Not Appearing

1. **Check endpoint**: `curl http://localhost:6000/api/v1/metrics/prometheus`
2. **Check Prometheus config**: Verify scrape config
3. **Check network**: Ensure Prometheus can reach ACPG
4. **Check logs**: Look for errors in ACPG logs

### Missing Metrics

- Some metrics may not appear if components aren't initialized
- Cache metrics require cache to be used
- Tool metrics require tools to be configured

### Format Issues

- Ensure Prometheus version supports the format
- Check content-type header
- Verify metric names follow Prometheus conventions

---

## Summary

ACPG provides comprehensive Prometheus metrics for:
- ✅ Cache performance
- ✅ Tool status
- ✅ Policy coverage
- ✅ System health

These metrics enable:
- Real-time monitoring
- Performance optimization
- Alerting and notifications
- Historical analysis

**Endpoint**: `/api/v1/metrics/prometheus`  
**Format**: Prometheus exposition format  
**Update Frequency**: Real-time (on scrape)

