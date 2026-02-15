# ACPG Documentation and User Guide

**Agentic Compliance and Policy Governor**
**Version**: 1.0.0 | **Last updated**: February 15, 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Installation](#2-installation)
3. [Quick Start](#3-quick-start)
4. [Core Concepts](#4-core-concepts)
5. [CLI Usage](#5-cli-usage)
6. [Web UI Guide](#6-web-ui-guide)
7. [API Reference](#7-api-reference)
8. [Policy System](#8-policy-system)
9. [Proof Bundles and Verification](#9-proof-bundles-and-verification)
10. [Runtime Compliance](#10-runtime-compliance)
11. [LLM Provider Management](#11-llm-provider-management)
12. [CI/CD Integration](#12-cicd-integration)
13. [Configuration](#13-configuration)
14. [Demo Lab](#14-demo-lab)
15. [Sample Suite](#15-sample-suite)
16. [Administration](#16-administration)
17. [Troubleshooting](#17-troubleshooting)
18. [Architecture Reference](#18-architecture-reference)

---

## 1. Overview

ACPG analyzes code for security policy violations, makes formal compliance decisions using abstract argumentation theory, auto-fixes violations with LLM assistance, and produces cryptographically signed proof bundles. It is designed for regulated environments where compliance must be provable, not probabilistic.

### What Makes ACPG Different

| Capability | Traditional scanners | ACPG |
|---|---|---|
| Find violations | Yes | Yes |
| Formal compliance decision | No | Argumentation semantics |
| Cryptographic proof | No | ECDSA-SHA256 signed bundles |
| Auto-fix loop | Limited | Iterative LLM-powered repair |
| Defeasible policies | No | Priority-based overrides |
| Runtime agent guard | No | Allow/deny/monitor controls |
| Evidence chain | Partial | Static + runtime + dynamic |

### Current Baseline

- 39 policies (OWASP, NIST, default, JS/TS)
- 80+ API endpoints
- 124 passing tests
- Python and JavaScript/TypeScript support
- Multi-provider LLM support (OpenAI, Anthropic, compatible APIs)

---

## 2. Installation

### Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| Node.js | 18+ |
| npm | Latest stable |

### Automated Install

```bash
./scripts/install.sh
```

Optional flags:

```bash
./scripts/install.sh --with-static-tools    # Install Bandit and Safety
./scripts/install.sh --recreate-venv         # Rebuild Python venv
./scripts/install.sh --npm-ci               # Use npm ci for frontend
./scripts/install.sh --skip-frontend        # Backend only
```

### Install CLI

```bash
source backend/venv/bin/activate
pip install -e .
```

This makes the `acpg` command available. See [Section 5: CLI Usage](#5-cli-usage).

### Configure LLM

Create or edit `backend/.env`:

```bash
OPENAI_API_KEY="sk-..."
# Or for Anthropic:
ANTHROPIC_API_KEY="sk-ant-..."
```

### Start Services

```bash
./scripts/start.sh      # Start backend + frontend
./scripts/status.sh     # Check status
./scripts/stop.sh       # Stop services
./scripts/restart.sh    # Restart services
```

Default ports: Backend on 6000, Frontend on 6001.

### Verify

```bash
curl http://localhost:6000/api/v1/health
```

A healthy response shows status for database, tools, LLM, policies, and signing components.

### Docker

```bash
docker-compose up -d
```

Multi-stage production build with health checks, non-root user, port 8000.

---

## 3. Quick Start

### Three ways to use ACPG:

**CLI** (fastest for single files):

```bash
acpg check --input code.py                    # Analyze
acpg enforce --input code.py --proof proof.json  # Fix + prove
acpg verify --proof proof.json                # Verify
```

**API** (for integrations):

```bash
# Analyze
curl -X POST http://localhost:6000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"code":"password = \"secret\"","language":"python"}'

# Enforce (analyze + fix + prove)
curl -X POST http://localhost:6000/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{"code":"password = \"secret\"","language":"python","max_iterations":3}'
```

**Web UI** (for interactive use):

Open http://localhost:6001 in your browser. Paste code, click Analyze or Auto-Fix & Certify.

---

## 4. Core Concepts

### The Multi-Agent Pipeline

ACPG uses four agents in sequence:

```
Code → [Prosecutor] → [Adjudicator] → [Generator] → [Proof Assembler]
          Analyze         Decide          Fix            Sign
```

1. **Prosecutor**: Runs static analysis tools (Bandit, ESLint, Safety) and policy checks. Maps findings to formal policy violations.

2. **Adjudicator**: Makes a compliance decision using abstract argumentation theory. Each violation becomes an argument; arguments can attack each other. The grounded extension gives a deterministic, conflict-free decision.

3. **Generator**: If non-compliant, uses an LLM to fix violations. The loop repeats (analyze → adjudicate → fix) until compliant or max iterations.

4. **Proof Assembler**: Creates and signs a proof bundle containing the code, all evidence, the argumentation trace, and an ECDSA-SHA256 digital signature.

### Argumentation Semantics

ACPG supports four semantics for compliance decisions:

| Semantics | Behavior | Use case |
|---|---|---|
| `grounded` | Deterministic, skeptical. Unique minimal extension. | Default for regulated environments |
| `auto` | Grounded decision + optional solver evidence | Recommended general use |
| `stable` | Solver-backed (clingo). All conflict-free stable extensions. | Advanced conflict analysis |
| `preferred` | Solver-backed (clingo). Maximal admissible extensions. | Advanced conflict analysis |

**Decision modes** (for stable/preferred):
- `auto` → defaults to skeptical
- `skeptical` → accept only universally acceptable arguments
- `credulous` → accept any viable extension argument

### Policy Types

- **Strict**: Violations are always non-compliant. Cannot be overridden.
- **Defeasible**: Can be overridden by higher-priority exceptions or counter-arguments.

### Joint Attacks

ACPG supports Nielsen-Parsons style joint attacks where multiple arguments must work together to defeat another argument. This models real-world policy conflicts where a single exception isn't enough — several conditions must hold simultaneously.

---

## 5. CLI Usage

### Installation

```bash
source backend/venv/bin/activate
pip install -e .
```

### Commands

| Command | Description |
|---|---|
| `acpg version` | Version, policy count, signer, LLM status |
| `acpg check -i file` | Analyze a file for violations |
| `acpg enforce -i file` | Auto-fix loop with optional proof |
| `acpg verify -p proof.json` | Verify proof signature and hash |
| `acpg list-policies` | List all 39 policies |
| `acpg proof -i file` | Generate proof for compliant code |
| `acpg init-hook` | Install git pre-commit hook |
| `acpg init-config` | Create `.acpgrc` config file |
| `acpg show-config` | Show current configuration |

### Global Flags

| Flag | Description |
|---|---|
| `-q` / `--quiet` | Suppress output, exit code only |
| `-v` / `--verbose` | Verbose output |

### Typical Workflow

```bash
# 1. Check if code is compliant
acpg check --input src/auth.py

# 2. If not, auto-fix and generate proof
acpg enforce --input src/auth.py --output src/auth_fixed.py --proof auth_proof.json

# 3. Verify the proof
acpg verify --proof auth_proof.json

# 4. Use in CI (exit code only)
acpg -q check --input src/auth.py || exit 1
```

For the full CLI reference with all flags and examples, see `docs/CLI_REFERENCE.md`.

---

## 6. Web UI Guide

### Layout

The UI has three main areas:
- **Header**: View tabs, LLM selector, semantics selector, theme toggle, samples dropdown
- **Pipeline bar**: Visual indicator of Prosecutor → Adjudicator → Generator → Proof stages
- **Main content**: Code editor (left), results panel (right)

### View Tabs

| Tab | Purpose |
|---|---|
| Editor | Code input, analysis, enforce |
| Proof | Full proof bundle viewer |
| Policies | Policy groups, CRUD, history, diff |
| Tools | Static analysis tools, mappings |
| Models | LLM provider configuration |
| Verify | Proof verification form |

### Analyzing Code

1. Paste code in the editor (or load a sample from the dropdown)
2. Click **Analyze** (or `Cmd+Enter`)
3. View results in the right panel: compliance status, violation table, tool execution, unmapped findings

### Auto-Fix and Certification

1. Click **Auto-Fix & Certify** (or `Shift+Cmd+Enter`)
2. Watch the pipeline bar progress through each agent
3. View fixed code using Original / Fixed / Diff tabs
4. Proof bundle appears in the Proof tab

### Managing Policies

1. Open the **Policies** tab
2. Toggle policy groups on/off (Default, OWASP, NIST, JavaScript)
3. Create custom policies with regex or manual checks
4. View version history and diffs for any policy
5. Preview group rollout changes against test cases

### Configuring Tools

1. Open the **Tools** tab
2. Enable/disable Bandit, Safety, ESLint per language
3. View and manage tool-to-policy mappings (e.g., Bandit B105 → SEC-001)
4. Map unmapped findings to policies

### Switching LLM Providers

1. Open the **Models** tab (or use the header dropdown)
2. View configured providers and their status
3. Click to switch the active provider
4. Test connectivity with the Test button

### Verifying Proofs

1. Open the **Verify** tab
2. Paste a proof bundle JSON
3. Click **Verify**
4. Results show signature validity, code hash integrity, and signer fingerprint

### Compliance History

Click the clock icon in the header to open the history sidebar showing recent analyses with pass/fail status, timestamps, and violation counts.

### Theme

Use the theme selector in the header: Dark, Light, or System.

### Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Cmd+Enter` | Analyze |
| `Shift+Cmd+Enter` | Auto-Fix & Certify |

---

## 7. API Reference

Base URL: `http://localhost:6000/api/v1`

Interactive API docs: `http://localhost:6000/docs` (Swagger UI)

### Core Compliance

| Method | Endpoint | Description |
|---|---|---|
| POST | `/analyze` | Analyze code for violations |
| POST | `/analyze/summary` | Violation summary only |
| POST | `/analyze/batch` | Batch analyze multiple snippets |
| POST | `/adjudicate` | Run adjudication on analysis |
| POST | `/adjudicate/guidance` | Decision guidance |
| POST | `/enforce` | Full enforce loop (analyze → fix → prove) |
| POST | `/generate` | Generate policy-aware code |
| POST | `/fix` | One-shot fix for violations |

### Enforce Options

```json
{
  "code": "...",
  "language": "python",
  "max_iterations": 3,
  "semantics": "auto",
  "solver_decision_mode": "auto",
  "stop_on_stagnation": true
}
```

### Proof & Verification

| Method | Endpoint | Description |
|---|---|---|
| POST | `/proof/generate` | Generate signed proof bundle |
| POST | `/proof/verify` | Verify proof integrity |
| GET | `/proof/public-key` | Get signing public key |
| GET | `/proof/{hash}` | Retrieve stored proof by hash |
| GET | `/proofs` | List all stored proofs |
| POST | `/proof/export` | Export proof in format |

### LangGraph Orchestration

| Method | Endpoint | Description |
|---|---|---|
| POST | `/graph/enforce` | Full workflow with runtime events |
| POST | `/graph/enforce/stream` | Streaming execution (SSE) |
| GET | `/graph/visualize` | Workflow graph definition |

### Policy Management

| Method | Endpoint | Description |
|---|---|---|
| GET | `/policies` | List all policies |
| GET | `/policies/{id}` | Get single policy |
| POST | `/policies/` | Create policy |
| PUT | `/policies/{id}` | Update policy |
| DELETE | `/policies/{id}` | Delete policy |
| GET | `/policies/audit/history` | All policy changes |
| GET | `/policies/{id}/audit/history` | Single policy history |
| GET | `/policies/{id}/audit/versions/{v}` | Specific version |
| GET | `/policies/{id}/audit/diff` | Compare versions |
| GET | `/policy-groups/` | List groups |
| POST | `/policy-groups/` | Create group |
| PUT | `/policy-groups/{id}` | Update group |
| DELETE | `/policy-groups/{id}` | Delete group |
| POST | `/policies/groups/rollout/preview` | Rollout simulation |

### LLM Management

| Method | Endpoint | Description |
|---|---|---|
| GET | `/llm/providers` | List providers |
| GET | `/llm/active` | Active provider |
| POST | `/llm/switch` | Switch provider |
| POST | `/llm/test` | Test connection |
| GET | `/llm/catalog/openai` | OpenAI model catalog |
| POST | `/llm/providers/` | Create custom provider |
| PUT | `/llm/providers/{id}` | Update provider |
| DELETE | `/llm/providers/{id}` | Delete provider |

### Static Analysis

| Method | Endpoint | Description |
|---|---|---|
| GET | `/static-analysis/tools` | List configured tools |
| PATCH | `/static-analysis/tools/{lang}/{tool}` | Toggle tool |
| GET | `/static-analysis/mappings` | Get tool-policy mappings |
| PUT | `/static-analysis/mappings` | Update all mappings |
| POST | `/static-analysis/mappings/{tool}/{rule}` | Add mapping |
| DELETE | `/static-analysis/mappings/{tool}/{rule}` | Remove mapping |

### Runtime Policies

| Method | Endpoint | Description |
|---|---|---|
| GET | `/runtime/policies` | List runtime rules |
| POST | `/runtime/policies/reload` | Reload rules |
| POST | `/runtime/policies/evaluate` | Evaluate tool/network/filesystem event |

### Test Cases

| Method | Endpoint | Description |
|---|---|---|
| GET | `/test-cases` | List all (file + DB) |
| GET | `/test-cases/tags` | Tag catalog |
| GET | `/test-cases/export` | Export test cases |
| POST | `/test-cases/import` | Bulk import |
| GET | `/test-cases/{id}` | Get test case |
| POST | `/test-cases` | Create test case |
| PUT | `/test-cases/{id}` | Update test case |
| DELETE | `/test-cases/{id}` | Delete test case |

### History & Audit

| Method | Endpoint | Description |
|---|---|---|
| GET | `/history` | Compliance history |
| GET | `/history/trends` | Trend analytics (1-365 days) |
| GET | `/history/dynamic-artifacts` | Dynamic replay artifacts |

### Authentication & Tenancy

| Method | Endpoint | Description |
|---|---|---|
| GET | `/auth/me` | Current user info |
| GET | `/auth/roles` | Available roles |
| GET/POST | `/auth/tenants` | List/create tenants |
| GET/POST | `/auth/keys` | List/create API keys |
| POST | `/auth/keys/{name}/revoke` | Revoke key |

Enable with `ACPG_REQUIRE_AUTH=true`. Tenant-scoped requests use `X-Tenant-ID` header.

### Admin & Health

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Component health status |
| GET | `/info` | System information |
| GET | `/admin/audit-logs` | Audit log access |
| GET | `/admin/stats` | System statistics |
| GET | `/admin/database/diagnostics` | DB pool and connection status |
| GET | `/metrics` | Performance metrics |
| GET | `/metrics/prometheus` | Prometheus format |
| DELETE | `/cache` | Clear tool result cache |

---

## 8. Policy System

### Policy Catalogs

| Catalog | Policies | File |
|---|---|---|
| Default | 9 | `policies/default_policies.json` |
| OWASP | 10 | `policies/owasp_policies.json` |
| NIST | 8 | `policies/nist_policies.json` |
| JavaScript/TS | 10 | `policies/javascript_policies.json` |
| Runtime | Variable | `policies/runtime_policies.json` |
| Custom | User-defined | `policies/custom_policies.json` |

### Policy Structure

```json
{
  "id": "SEC-001",
  "description": "No hardcoded credentials (passwords, API keys) in code",
  "type": "strict",
  "severity": "high",
  "check": "regex",
  "patterns": ["password\\s*=\\s*['\"]", "api_key\\s*=\\s*['\"]"],
  "exclude_patterns": ["os\\.environ", "getenv"],
  "fix_suggestion": "Use environment variables or a secrets manager"
}
```

### Check Types

| Type | Description |
|---|---|
| `regex` | Pattern matching with optional exclude patterns |
| `ast` | Python AST analysis (semantic checks) |
| `manual` | Tool-based detection (Bandit rules, ESLint rules) |

### Tool-to-Policy Mapping

Static analysis tools produce findings with their own rule IDs. These are mapped to ACPG policies:

| Tool Finding | ACPG Policy |
|---|---|
| Bandit B105 | SEC-001 (hardcoded password) |
| Bandit B608 | SQL-001 (SQL injection) |
| Bandit B102 | SEC-003 (exec) |
| Bandit B301 | OWASP-A08 (insecure deserialization) |

Mappings are managed via the Tools tab in the UI or via API.

Findings from tools that aren't mapped to a policy appear as "unmapped findings" in the analysis results.

### Custom Policies

Create custom policies via the API or UI:

```bash
curl -X POST http://localhost:6000/api/v1/policies/ \
  -H "Content-Type: application/json" \
  -d '{
    "id": "CUSTOM-001",
    "description": "No TODO comments in production code",
    "type": "defeasible",
    "severity": "low",
    "check": "regex",
    "patterns": ["#\\s*TODO"],
    "fix_suggestion": "Remove TODO comments or convert to tracked issues"
  }'
```

### Policy Groups

Groups organize policies for bulk enable/disable. Use rollout preview to simulate changes:

```bash
curl -X POST http://localhost:6000/api/v1/policies/groups/rollout/preview \
  -H "Content-Type: application/json" \
  -d '{"group_id": "owasp", "enabled": false}'
```

### Policy Audit

Every policy change is versioned:

```bash
# View change history
curl http://localhost:6000/api/v1/policies/SEC-001/audit/history

# Compare versions
curl "http://localhost:6000/api/v1/policies/SEC-001/audit/diff?from_version=1&to_version=2"
```

---

## 9. Proof Bundles and Verification

### What's in a Proof Bundle

```json
{
  "artifact": {
    "hash": "sha256:...",
    "name": "code.py",
    "language": "python",
    "timestamp": "2026-02-15T12:00:00Z"
  },
  "code": "import os\n...",
  "policies": [
    {"rule_id": "SEC-001", "outcome": "satisfied"},
    {"rule_id": "SQL-001", "outcome": "satisfied"}
  ],
  "evidence": [
    {"source": "bandit", "rule": "B105", "finding": "..."}
  ],
  "argumentation": {
    "arguments": [...],
    "attacks": [...],
    "grounded_extension": [...]
  },
  "decision": "Compliant",
  "signed": {
    "signature": "MEUCIQD...",
    "signer": "ACPG-Adjudicator",
    "algorithm": "ECDSA-SHA256",
    "public_key_fingerprint": "516e29c929b926fb",
    "signed_at": "2026-02-15T12:00:01Z"
  }
}
```

### Cryptographic Details

- **Algorithm**: ECDSA with SHA-256
- **Curve**: SECP256R1 (P-256)
- **Signed payload**: artifact metadata, code, policies, evidence, argumentation, decision, timestamp
- **Code hash**: SHA-256, included in artifact metadata

### Verification

**CLI**:

```bash
acpg verify --proof proof.json
```

**API**:

```bash
curl -X POST http://localhost:6000/api/v1/proof/verify \
  -H "Content-Type: application/json" \
  -d @proof.json
```

**Independent verification**: Use `GET /api/v1/proof/public-key` to get the public key. Reconstruct the signed payload from the bundle and verify the ECDSA signature yourself.

### Tamper Detection

| Attack | Result |
|---|---|
| Modify code | Signature invalid + hash mismatch |
| Modify evidence/argumentation | Signature invalid |
| Change decision | Signature invalid |
| Replace signature with different key | Signer fingerprint mismatch |

---

## 10. Runtime Compliance

### Runtime Guard

When running LangGraph workflows, the runtime guard evaluates tool actions against runtime policies:

| Action Level | Behavior |
|---|---|
| `allow` | Permitted, no logging |
| `allow_with_monitoring` | Permitted, captured as runtime evidence |
| `require_approval` | Treated as non-compliant until approved |
| `deny` | Blocked, converted to formal violation |

### Runtime Policies

Defined in `policies/runtime_policies.json` for three event classes:

- **Tool events**: pip install, npm commands, safety checks
- **Network events**: HTTP requests, API calls
- **Filesystem events**: File read/write operations

### Runtime Evidence in Proofs

When using LangGraph orchestration, runtime events are captured and included in proof bundles:

```bash
curl -X POST http://localhost:6000/api/v1/graph/enforce \
  -H "Content-Type: application/json" \
  -d '{"code":"...","language":"python","max_iterations":3}'
```

Response includes `runtime_events` and the proof bundle contains `RUNTIME` evidence.

### Dynamic Analysis

When `ENABLE_DYNAMIC_TESTING=true`, ACPG runs code in a sandboxed subprocess:

- Timeout: 3 seconds (configurable)
- Resource limits enforced
- Deterministic replay artifacts generated
- Violations: `DYN-EXEC-TIMEOUT`, `DYN-EXEC-EXCEPTION`, `DYN-EXEC-CRASH`
- Replay artifacts included in proof bundles

---

## 11. LLM Provider Management

### Supported Providers

| Provider | API Style | Configuration |
|---|---|---|
| OpenAI | Responses API first, Chat Completions fallback | `OPENAI_API_KEY` |
| Anthropic | Messages API | `ANTHROPIC_API_KEY` |
| Compatible APIs | OpenAI-compatible endpoint | Custom provider config |

### Configuration

Providers are defined in `backend/llm_config.yaml`:

```yaml
providers:
  - name: OpenAI
    type: openai
    model: gpt-4
    api_key_env: OPENAI_API_KEY
  - name: Anthropic
    type: anthropic
    model: claude-3-5-sonnet
    api_key_env: ANTHROPIC_API_KEY

active_provider: OpenAI
```

### Switching Providers

**API**:

```bash
curl -X POST http://localhost:6000/api/v1/llm/switch \
  -H "Content-Type: application/json" \
  -d '{"provider_name": "Anthropic"}'
```

**UI**: Use the LLM selector dropdown in the header, or the Models tab.

### Testing Connection

```bash
curl -X POST http://localhost:6000/api/v1/llm/test
```

---

## 12. CI/CD Integration

### GitHub Actions

ACPG includes a CI pipeline (`.github/workflows/ci.yml`) with stages:

1. **Lint**: `ruff check`, frontend lint
2. **Test**: `pytest` (124 tests)
3. **Build**: Frontend build
4. **Integration**: End-to-end compliance check
5. **Docker**: Container build and test

### Compliance Gate

The CI compliance gate evaluates results against configurable profiles:

**Profiles** (`.github/compliance-gate-profiles.json`):

- `strict`: Fails on any violation
- `monitor`: Logs violations but does not block

**Usage**:

```bash
python scripts/ci/compliance_gate.py --profile strict
```

Set `ACPG_COMPLIANCE_GATE_PROFILE` in GitHub Actions variables to select profile.

### CLI in CI

```bash
# Install ACPG in CI
pip install -e .

# Check all Python files
for f in $(find src -name "*.py"); do
  acpg -q check --input "$f" || exit 1
done
```

### Pre-commit Hook

```bash
acpg init-hook --api-url http://localhost:6000
```

Checks staged Python/JS/TS files before each commit. Requires the ACPG backend running.

---

## 13. Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | (required for fixes) | OpenAI API key |
| `ANTHROPIC_API_KEY` | (optional) | Anthropic API key |
| `OPENAI_MODEL` | `gpt-4` | Default LLM model |
| `OPENAI_TEMPERATURE` | `0.3` | LLM creativity |
| `OPENAI_MAX_TOKENS` | `2000` | Max output tokens |
| `ACPG_REQUIRE_AUTH` | `false` | Enable API authentication |
| `ACPG_MASTER_API_KEY` | (empty) | Master API key |
| `DATABASE_URL` | `sqlite:///backend/acpg.db` | Database connection |
| `DB_POOL_SIZE` | `5` | Connection pool size |
| `DB_MAX_OVERFLOW` | `10` | Overflow connections |
| `DB_POOL_RECYCLE_SECONDS` | `300` | Connection recycle |
| `ENABLE_STATIC_ANALYSIS` | `true` | Enable static tools |
| `ENABLE_RUNTIME_GUARDS` | `true` | Enable runtime checks |
| `ENABLE_DYNAMIC_TESTING` | `false` | Enable sandbox execution |
| `DYNAMIC_SANDBOX_TIMEOUT_SECONDS` | `3` | Sandbox timeout |
| `STATIC_ANALYSIS_TIMEOUT` | `30` | Tool timeout (seconds) |
| `SOLVER_DECISION_MODE` | `auto` | auto/skeptical/credulous |
| `POLICIES_DIR` | `./policies` | Policy catalog location |

### Project Configuration (`.acpgrc`)

Create with `acpg init-config`. Supports YAML and JSON. ACPG searches up the directory tree for config files.

```yaml
# .acpgrc
enabled_policies: []          # Empty = all
disabled_policies: []
policy_groups: []

include_patterns:
  - "**/*.py"
  - "**/*.js"
  - "**/*.ts"

exclude_patterns:
  - "**/node_modules/**"
  - "**/.venv/**"

fail_on_severity: low         # low, medium, high, critical
auto_fix_enabled: false
max_iterations: 3

api_url: http://localhost:8000
output_format: text           # text, json, sarif
proof_bundle: false
```

---

## 14. Demo Lab

The UI includes a Demo Lab section with specialized tabs for exploring backend capabilities:

### Runtime Policy Simulator

Test runtime policy evaluation for tool, network, and filesystem events:

1. Select event type (tool/network/filesystem)
2. Enter event parameters (tool name, command, host, path, etc.)
3. Click **Evaluate Policy Decision**
4. View allow/deny/monitor decision with matched rules

### LangGraph Stream Viewer

Watch the LangGraph orchestration in real-time:

1. Enter code and select semantics/solver mode
2. Click **Start Stream**
3. Watch server-sent events (agent messages, state updates, runtime events)
4. View the graph definition with nodes and transitions

### Batch Test Runner

Run analysis against multiple test cases at once:

1. Load test cases (file samples + DB test cases)
2. Select cases with checkboxes (or Select All)
3. Click **Run Batch**
4. View pass/fail results with violation counts and risk scores

### Proof Registry

Browse all stored proof bundles:

1. View list of proofs with artifact names, hashes, decisions
2. Click a proof to view the full JSON bundle
3. See the signer public key (fingerprint, algorithm, curve)

### Dynamic Artifact Explorer

Browse dynamic analysis replay artifacts:

1. Set filters (limit, suite ID, violation rule, violations only)
2. View artifacts with compliance status, duration, fingerprints
3. Inspect individual replay details

---

## 15. Sample Suite

16 sample files in `samples/` demonstrating different capabilities:

| # | File | Purpose | Key Violations |
|---|---|---|---|
| 01 | `hardcoded_secrets.py` | Embedded credentials | SEC-001, NIST-IA-5 |
| 02 | `sql_injection.py` | SQL injection patterns | SQL-001 |
| 03 | `dangerous_functions.py` | eval, exec, pickle | SEC-003, OWASP-A08 |
| 04 | `weak_crypto.py` | MD5, SHA1 | CRYPTO-001, NIST-SC-13 |
| 05 | `insecure_http.py` | HTTP instead of HTTPS | SEC-004, NIST-SC-8 |
| 06 | `mixed_vulnerabilities.py` | Multiple types | Mixed |
| 07 | `owasp_top10.py` | OWASP Top 10 | OWASP-A01 through A10 |
| 08 | `strict_policies.py` | Strict enforcement | No exceptions |
| 09 | `defeasible_policies.py` | Policy exceptions | INPUT-001, ERR-001, LOG-001 |
| 10 | `argumentation_conflict.py` | Conflict resolution | Multiple competing rules |
| 11 | `severity_priority.py` | Severity-based triage | Graded severity |
| 12 | `tool_demo.py` | Tool-to-policy mapping | Mapped + unmapped findings |
| 13 | `semantics_stable_vs_grounded.py` | Semantics comparison | Competing extensions |
| 14 | `joint_attack_nelson_parsons.py` | Joint attacks | Nielsen-Parsons reasoning |
| 15 | `runtime_policy_events.py` | Runtime events | Tool/network/filesystem actions |
| 16 | `dynamic_analysis_replay.py` | Dynamic replay | Sandbox execution artifacts |

Load samples from the Samples dropdown in the UI, or use directly with the CLI:

```bash
acpg check --input samples/01_hardcoded_secrets.py
```

---

## 16. Administration

### RBAC and Multi-Tenancy

Enable with `ACPG_REQUIRE_AUTH=true` and set `ACPG_MASTER_API_KEY`.

**Roles**: `admin`, `analyst`, `viewer`

**Create tenant**:

```bash
curl -X POST http://localhost:6000/api/v1/auth/tenants \
  -H "X-API-Key: $ACPG_MASTER_API_KEY" \
  -d '{"name": "engineering"}'
```

**Create API key**:

```bash
curl -X POST http://localhost:6000/api/v1/auth/keys \
  -H "X-API-Key: $ACPG_MASTER_API_KEY" \
  -d '{"name": "ci-key", "tenant_id": 1, "permissions": ["analyze:write", "proof:read"]}'
```

Tenant-scoped requests use `X-Tenant-ID` header. History and audit views are filtered to the caller's tenant for non-master keys.

### Database

Default: SQLite at `backend/acpg.db`. PostgreSQL supported via `DATABASE_URL`.

**Diagnostics**:

```bash
curl http://localhost:6000/api/v1/admin/database/diagnostics
```

Returns dialect, driver, pool status, connection latency, and redacted DB URL.

### Monitoring

**Health**: `GET /api/v1/health`
**Stats**: `GET /api/v1/admin/stats`
**Audit logs**: `GET /api/v1/admin/audit-logs`
**Prometheus**: `GET /api/v1/metrics/prometheus`

---

## 17. Troubleshooting

### Backend not responding

```bash
./scripts/status.sh                              # Check if running
curl http://localhost:6000/api/v1/health          # Check health
./scripts/restart.sh                              # Restart
```

### "LLM connection failed"

1. Check `OPENAI_API_KEY` in `backend/.env`
2. Test provider: `curl -X POST http://localhost:6000/api/v1/llm/test`
3. Check network access to API endpoints
4. Try a different provider in the Models tab

### No violations when expected

1. Verify policy groups are enabled (Policies tab)
2. Check tool-to-policy mappings (Tools tab)
3. Ensure static analysis tools are installed: `which bandit && which safety`
4. Load a known-bad sample (e.g., `01_hardcoded_secrets.py`)

### Enforce stops early

- **Stagnation**: Violations did not decrease between iterations
- **Max iterations reached**: Increase with `--iterations` flag or API parameter
- **LLM error**: Check provider connectivity and API key

### Static analysis tools not found

```bash
pip install bandit safety
# or
./scripts/install.sh --with-static-tools
```

### Proof verification fails

- Ensure the proof was generated by the same ACPG instance (same signing key)
- Check that the proof JSON has not been modified or reformatted
- Use `acpg verify --proof proof.json` for detailed diagnostics

### Database connection issues

```bash
curl http://localhost:6000/api/v1/admin/database/diagnostics
```

Check pool status, connection latency, and overflow counts.

---

## 18. Architecture Reference

### Technology Stack

| Component | Technology |
|---|---|
| Backend | FastAPI, Python 3.10+ |
| Frontend | React 18, TypeScript, Vite |
| Editor | Monaco Editor |
| Database | SQLite (default), PostgreSQL (supported) |
| LLM | OpenAI (Responses API), Anthropic (Messages API) |
| Orchestration | LangGraph |
| Static Analysis | Bandit, Safety, ESLint |
| Formal Methods | Abstract argumentation, ASP/clingo solver |
| Cryptography | ECDSA-SHA256 (SECP256R1) |
| Deployment | Docker, GitHub Actions CI |

### Service Architecture

```
backend/
├── app/
│   ├── api/              # Route handlers (routes, langgraph, llm, policy, auth)
│   ├── core/             # Infrastructure (config, database, crypto, auth, llm)
│   ├── models/           # Pydantic schemas (100+)
│   ├── services/         # Business logic
│   │   ├── prosecutor.py       # Static analysis orchestration
│   │   ├── adjudicator.py      # Formal argumentation engine
│   │   ├── generator.py        # LLM-backed code fixing
│   │   ├── proof_assembler.py  # Proof bundle creation + signing
│   │   ├── runtime_guard.py    # Tool action validation
│   │   ├── dynamic_analyzer.py # Sandboxed execution
│   │   └── parsers/            # Tool output parsers
│   └── orchestration/    # LangGraph workflow (graph, nodes, state)
├── cli.py                # CLI entry point
└── main.py               # FastAPI app entry point
```

### Database Models

| Model | Purpose |
|---|---|
| `AuditLog` | Compliance check history |
| `StoredProof` | Proof bundle persistence |
| `PolicyHistory` | Policy change audit trail |
| `DynamicAnalysisArtifact` | Execution replay artifacts |
| `TestCase` | Managed test cases |
| `Tenant` | Multi-tenancy |
| `APIKey` | API authentication |

### Further Reading

- `README.md` — Project overview and endpoint summary
- `docs/CLI_REFERENCE.md` — Full CLI documentation
- `docs/VC_DEMO_SCRIPT.md` — Live demo script
- `docs/INVESTOR_PITCH_BRIEF.md` — Pitch deck design brief
- `docs/archive/runtime_policy_compliance.md` — Runtime compliance details (archived)
- `docs/archive/TAMPER_DETECTION.md` — Proof integrity details (archived)
- `docs/archive/CI_CD_INTEGRATION.md` — CI pipeline details (archived)
- `docs/archive/DEPLOYMENT_GUIDE.md` — Production deployment (archived)
