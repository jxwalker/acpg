> [!NOTE]
> Documentation Refresh Note (February 11, 2026): this file is retained as specialized or historical context.
> For current product behavior and authoritative guidance, start at /Users/James/code/GAD/apcg/README.md and /Users/James/code/GAD/apcg/docs/README.md.

# Static Analysis Integration Guide

## Overview

ACPG now integrates industry-standard static analysis tools (Bandit, ESLint, etc.) into the compliance pipeline. These tools run alongside the existing regex/AST policy checks, and their findings are adjudicated using Dung's Abstract Argumentation Framework.

## Architecture

```
Code Input
    ↓
Language Detection
    ↓
Static Analysis Tools (Bandit, ESLint, etc.)
    ↓
Tool Output Parsers
    ↓
Tool-to-Policy Mapping
    ↓
Prosecutor (combines with regex/AST checks)
    ↓
Adjudicator (Dung's AAF)
    ↓
Proof Bundle (with tool metadata)
```

## Supported Tools

### Python
- **Bandit** - Security linter (enabled by default)
- **Pylint** - Code quality (disabled by default)
- **Safety** - Dependency vulnerability checker (enabled by default)

### JavaScript/TypeScript
- **ESLint** - Linting tool (enabled by default)

### Generic
- **SARIF** - Any tool that outputs SARIF format (Semgrep, CodeQL, etc.)

## Configuration

### Tool Configuration

Tools are configured in `backend/app/core/static_analyzers.py`. Each tool has:

- `command`: Command template with `{target}` placeholder
- `parser`: Parser class name
- `enabled`: Whether tool is active
- `timeout`: Execution timeout in seconds
- `output_format`: Expected output format (json, sarif, etc.)

### Tool-to-Policy Mapping

Mappings are defined in `policies/tool_mappings.json`:

```json
{
  "bandit": {
    "B608": {
      "policy_id": "SQL-001",
      "confidence": "high",
      "severity": "critical",
      "description": "SQL injection via string formatting"
    }
  }
}
```

## Usage

### Automatic Detection

The system automatically:
1. Detects code language from file extension/shebang
2. Selects appropriate tools for that language
3. Executes tools in parallel
4. Maps findings to ACPG policies
5. Combines with existing policy checks

### API Endpoints

#### List Static Analysis Tools
```bash
GET /api/v1/static-analysis/tools
```

Returns:
```json
{
  "tools_by_language": {
    "python": [
      {
        "name": "bandit",
        "enabled": true,
        "timeout": 30,
        "output_format": "json"
      }
    ]
  },
  "cache_stats": {
    "total_entries": 42,
    "total_size_bytes": 1024000,
    "ttl_seconds": 3600
  }
}
```

## Performance

### Caching

Tool results are cached based on:
- Content hash (SHA256)
- Tool name
- Tool version

Cache TTL: 1 hour (configurable via `STATIC_ANALYSIS_CACHE_TTL`)

### Parallel Execution

Multiple tools execute in parallel using `ThreadPoolExecutor` for faster analysis.

## Evidence in Proof Bundles

Proof bundles now include:

```json
{
  "argumentation": {
    "tools_used": ["bandit", "eslint"],
    "tool_versions": {},
    ...
  },
  "evidence": [
    {
      "rule_id": "SQL-001",
      "tool": "bandit",
      "tool_rule_id": "B608",
      "confidence": "high",
      ...
    }
  ]
}
```

## Frontend Display

Violations found by static analysis tools display a tool badge:

```
[SQL-001] [bandit] SQL injection vulnerability
```

Tool badges only appear for static analysis tools (not regex/ast checks).

## Adding New Tools

### 1. Create Parser

Create a parser in `backend/app/services/parsers/`:

```python
from .base_parser import BaseParser, ParsedFinding

class MyToolParser(BaseParser):
    def __init__(self):
        super().__init__("mytool")
    
    def parse(self, output: str) -> List[ParsedFinding]:
        # Parse tool output
        findings = []
        # ... parsing logic ...
        return findings
```

### 2. Register Tool

Add tool configuration in `static_analyzers.py`:

```python
"python": {
    "mytool": ToolConfig(
        name="mytool",
        command=["mytool", "--format", "json", "{target}"],
        parser="mytool_parser",
        enabled=True,
        timeout=30,
        languages=["python"]
    )
}
```

### 3. Add Mappings

Add tool-to-policy mappings in `tool_mappings.json`:

```json
{
  "mytool": {
    "RULE-001": {
      "policy_id": "SEC-001",
      "confidence": "high",
      "severity": "high"
    }
  }
}
```

### 4. Register Parser

Add parser to `parsers/__init__.py` and register in `prosecutor.py`.

## Troubleshooting

### Tool Not Running

1. Check if tool is installed: `which bandit`
2. Check if tool is enabled in configuration
3. Check logs for execution errors

### No Findings Mapped

1. Verify tool rule ID matches mapping in `tool_mappings.json`
2. Check parser is correctly extracting rule IDs
3. Review tool output format matches parser expectations

### Performance Issues

1. Check cache is working (see cache stats in API)
2. Reduce number of enabled tools
3. Increase timeout if tools are slow
4. Check parallel execution is working (multiple tools should run simultaneously)

## Settings

Configuration in `backend/app/core/config.py`:

- `ENABLE_STATIC_ANALYSIS`: Enable/disable static analysis (default: True)
- `STATIC_ANALYSIS_TIMEOUT`: Default timeout in seconds (default: 30)
- `STATIC_ANALYSIS_CACHE_TTL`: Cache TTL in seconds (default: 3600)

## Logging

Tool execution is logged with:
- Tool name and language
- Execution time
- Success/failure status
- Error messages (if failed)
- Summary statistics

Check logs for detailed execution information.

