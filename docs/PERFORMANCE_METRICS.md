> [!NOTE]
> Documentation Refresh Note (February 11, 2026): this file is retained as specialized or historical context.
> For current product behavior and authoritative guidance, start at /Users/James/code/GAD/apcg/README.md and /Users/James/code/GAD/apcg/docs/README.md.

# Performance Metrics Guide

## Overview

ACPG provides comprehensive performance metrics through the `/api/v1/metrics` endpoint. This helps monitor system performance, cache effectiveness, and resource usage.

## Metrics Endpoint

### GET `/api/v1/metrics`

Returns detailed performance and system metrics.

**Response Structure:**
```json
{
  "timestamp": "2024-12-19T22:30:14.141405+00:00",
  "cache": {
    "hits": 15,
    "misses": 8,
    "total_entries": 12,
    "total_size_mb": 0.05,
    "hit_rate": 65.22,
    "ttl_seconds": 3600
  },
  "tools": {
    "total_enabled": 2,
    "details": {
      "bandit": {
        "enabled": true,
        "language": "python",
        "timeout": 30,
        "format": "json"
      },
      "safety": {
        "enabled": true,
        "language": "python",
        "timeout": 20,
        "format": "json"
      }
    }
  },
  "policies": {
    "total": 39,
    "by_category": {
      "default": 21,
      "owasp": 10,
      "nist": 8
    }
  },
  "performance": {
    "note": "Performance metrics collected during analysis",
    "typical_analysis_time": "1-2 seconds",
    "tool_execution": "Parallel execution enabled"
  }
}
```

## Cache Metrics

### Understanding Cache Statistics

**Hits**: Number of times cached results were used
- Higher is better
- Indicates cache is working effectively

**Misses**: Number of times cache was checked but no result found
- Includes expired entries
- Normal during initial analysis

**Hit Rate**: Percentage of requests served from cache
- Formula: `(hits / (hits + misses)) * 100`
- Target: >50% for repeated analysis
- Higher hit rate = faster analysis

**Total Entries**: Number of cached results
- Grows as more unique code is analyzed
- Capped by TTL expiration

**Total Size**: Disk space used by cache
- Typically small (<10MB for most use cases)
- Automatically cleaned by TTL

### Improving Cache Hit Rate

1. **Re-analyze same code**: Cache works best with repeated analysis
2. **Increase TTL**: Longer TTL = more cache hits (if code doesn't change)
3. **Disable unnecessary tools**: Fewer tools = more cache hits per tool
4. **Analyze similar code**: Similar code patterns benefit from cache

## Tool Metrics

### Tool Statistics

Shows which tools are enabled and their configuration:
- **Total Enabled**: Number of active tools
- **Details**: Per-tool configuration
  - Language support
  - Timeout settings
  - Output format

### Tool Performance

**Typical Execution Times:**
- Bandit: 300-800ms (depends on code size)
- Safety: 200-500ms (depends on dependencies)
- ESLint: 500-1500ms (depends on code size and config)

**Parallel Execution:**
- Tools run in parallel when possible
- Total time ≈ slowest tool (not sum)
- Example: Bandit (500ms) + Safety (300ms) = ~500ms total

## Policy Metrics

### Policy Statistics

- **Total**: Total number of policies loaded
- **By Category**: Breakdown by policy source
  - Default: Core security policies
  - OWASP: OWASP Top 10 policies
  - NIST: NIST 800-218 policies

## Performance Benchmarks

### Typical Analysis Times

**Small Code (<100 lines):**
- Language detection: <50ms
- Tool execution: 300-800ms
- Policy checks: 100-300ms
- Adjudication: 100-200ms
- **Total: ~1-1.5 seconds**

**Medium Code (100-1000 lines):**
- Language detection: <50ms
- Tool execution: 800-2000ms
- Policy checks: 300-800ms
- Adjudication: 200-400ms
- **Total: ~1.5-3 seconds**

**Large Code (>1000 lines):**
- Language detection: <50ms
- Tool execution: 2000-5000ms
- Policy checks: 800-2000ms
- Adjudication: 400-800ms
- **Total: ~3-8 seconds**

### Cache Impact

**Without Cache:**
- First analysis: Full execution time
- Re-analysis: Full execution time again

**With Cache (50% hit rate):**
- First analysis: Full execution time
- Re-analysis: ~50% faster (cached tools skip execution)

**With Cache (80% hit rate):**
- First analysis: Full execution time
- Re-analysis: ~80% faster

## Monitoring Best Practices

### 1. Regular Monitoring

Check metrics periodically:
```bash
curl http://localhost:6000/api/v1/metrics | jq
```

### 2. Cache Health

Monitor hit rate:
- **<30%**: Cache not effective, consider increasing TTL
- **30-60%**: Normal for varied code analysis
- **>60%**: Excellent, cache working well

### 3. Tool Performance

Monitor tool execution times:
- If tools are slow, consider:
  - Increasing timeout
  - Disabling unnecessary tools
  - Optimizing tool configurations

### 4. Resource Usage

Monitor cache size:
- **<10MB**: Normal
- **10-50MB**: Growing, but acceptable
- **>50MB**: Consider cache cleanup or TTL reduction

## Cache Management

### Clear Cache

**Via API (future):**
```bash
# Clear all cache
curl -X DELETE http://localhost:6000/api/v1/cache

# Clear specific tool cache
curl -X DELETE http://localhost:6000/api/v1/cache/bandit
```

**Manually:**
```bash
# Cache location
rm -rf /tmp/acpg_tool_cache
```

### Cache TTL

Default: 3600 seconds (1 hour)

Configure in `backend/app/core/config.py`:
```python
STATIC_ANALYSIS_CACHE_TTL = 3600  # seconds
```

**Recommendations:**
- **Development**: 3600s (1 hour) - good balance
- **Production**: 7200s (2 hours) - if code changes infrequently
- **CI/CD**: 0s (disabled) - always fresh results

## Performance Optimization Tips

### 1. Enable Caching

Ensure caching is enabled (default: enabled):
- Check `use_cache=True` in tool execution
- Verify cache directory is writable

### 2. Parallel Execution

Tools run in parallel automatically:
- No configuration needed
- Benefits increase with more tools

### 3. Tool Selection

Enable only needed tools:
- Fewer tools = faster analysis
- Disable tools you don't use

### 4. Code Size

For very large files:
- Consider splitting into smaller files
- Or increase tool timeouts
- Cache helps with repeated analysis

### 5. Cache Warm-up

For consistent performance:
- Run analysis once to populate cache
- Subsequent analyses will be faster

## Troubleshooting

### Low Cache Hit Rate

**Possible Causes:**
- Code changes frequently
- TTL too short
- Cache directory issues

**Solutions:**
- Increase TTL if code is stable
- Check cache directory permissions
- Verify cache is being used (check logs)

### Slow Tool Execution

**Possible Causes:**
- Very large files
- Tool configuration issues
- System resource constraints

**Solutions:**
- Increase tool timeout
- Optimize tool configurations
- Check system resources (CPU, memory)

### High Cache Size

**Possible Causes:**
- Many unique code analyses
- Long TTL
- Large tool outputs

**Solutions:**
- Reduce TTL
- Clear cache periodically
- Check for cache leaks

## Example Monitoring Script

```bash
#!/bin/bash
# Monitor ACPG metrics

while true; do
  echo "=== $(date) ==="
  curl -s http://localhost:6000/api/v1/metrics | jq '{
    cache_hit_rate: .cache.hit_rate,
    cache_entries: .cache.total_entries,
    cache_size_mb: .cache.total_size_mb,
    tools_enabled: .tools.total_enabled,
    policies: .policies.total
  }'
  sleep 60
done
```

## Integration with Monitoring Tools

### Prometheus (Future)

Metrics endpoint can be adapted for Prometheus format:
```python
# Future: /api/v1/metrics/prometheus
acpg_cache_hits_total 15
acpg_cache_misses_total 8
acpg_cache_hit_rate 65.22
acpg_tools_enabled 2
acpg_policies_total 39
```

### Grafana Dashboard (Future)

Visualize metrics:
- Cache hit rate over time
- Tool execution times
- Policy coverage
- System health

---

## Summary

The metrics endpoint provides:
- ✅ Cache effectiveness (hits, misses, hit rate)
- ✅ Tool configuration status
- ✅ Policy statistics
- ✅ Performance insights

Use these metrics to:
- Monitor system health
- Optimize cache settings
- Identify performance bottlenecks
- Track system usage

