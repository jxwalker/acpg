# ACPG CLI Reference

**Version**: 1.0.0
**Last updated**: February 15, 2026

## Installation

From the project root:

```bash
cd /path/to/acpg
source backend/venv/bin/activate
pip install -e .
```

This installs the `acpg` command. Verify with:

```bash
acpg version
```

You can also run directly without installing:

```bash
cd backend
python cli.py version
```

## Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--quiet` | `-q` | Suppress all output; uses exit code only (0 = compliant, 1 = non-compliant/error) |
| `--verbose` | `-v` | Enable verbose output |

Global flags go **before** the command:

```bash
acpg --quiet check --input code.py
acpg -v enforce --input code.py
```

## Commands

### `acpg version`

Show ACPG version, policy count, signer fingerprint, and active LLM provider.

```bash
acpg version
```

```
╭─────────────── ACPG — Agentic Compliance and Policy Governor ────────────────╮
│   Version         1.0.0                                                      │
│   Policies        39                                                         │
│   Signer          516e29c929b926fb                                           │
│   Algorithm       ECDSA-SHA256 (SECP256R1)                                   │
│   LLM Provider    OpenAI (gpt-4)                                             │
╰──────────────────────────────────────────────────────────────────────────────╯
```

---

### `acpg check`

Analyze a file for compliance violations. Does not fix code.

```bash
acpg check --input code.py
acpg check --input code.py --json
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--input` | `-i` | Yes | File to analyze |
| `--json` | `-j` | No | Output as JSON |

**Exit codes**: 0 = compliant, 1 = non-compliant or error.

**Example output** (non-compliant):

```
            Violations in code.py
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Severity   ┃ Rule         ┃ Description           ┃   Line ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ HIGH       │ SEC-001      │ No hardcoded creds     │     19 │
│ CRITICAL   │ SQL-001      │ Use parameterized SQL  │      8 │
└────────────┴──────────────┴───────────────────────┴────────┘

NON-COMPLIANT — 2 violation(s)
Run acpg enforce --input code.py to auto-fix
```

**Example output** (compliant):

```
╭────────────────────────── code.py ───────────────────────────╮
│ COMPLIANT                                                    │
│                                                              │
│ Policies satisfied: 39                                       │
╰──────────────────────────────────────────────────────────────╯
```

**CI usage** (exit code only):

```bash
acpg -q check --input code.py || echo "FAILED"
```

---

### `acpg enforce`

Run the full compliance enforcement loop: analyze, fix with LLM, re-analyze, repeat until compliant or max iterations. Optionally generates a proof bundle.

```bash
acpg enforce --input code.py
acpg enforce --input code.py --output fixed.py --proof proof.json
acpg enforce --input code.py --iterations 5
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--input` | `-i` | Yes | Input file |
| `--output` | `-o` | No | Output file (default: overwrite input) |
| `--proof` | `-p` | No | Write proof bundle to file |
| `--iterations` | `-n` | No | Max fix iterations (default: 3) |

**Requires**: A configured LLM provider with API key.

**Exit codes**: 0 = achieved compliance, 1 = could not achieve compliance.

**Example**:

```bash
acpg enforce -i vulnerable.py -o fixed.py -p proof.json -n 5
```

```
LLM: OpenAI (gpt-4)
⠋ Iteration 1/5: analyzing...
⠋ Iteration 1/5: fixing 4 violations...
⠋ Iteration 2/5: analyzing...

╭──────────────────────────────────────────────────────────────╮
│ COMPLIANT after 2 iteration(s)                               │
╰──────────────────────────────────────────────────────────────╯
Fixed code written to: fixed.py
Proof bundle written to: proof.json
```

---

### `acpg verify`

Verify a proof bundle's cryptographic signature and code hash integrity.

```bash
acpg verify --proof proof.json
acpg verify --proof proof.json --json
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--proof` | `-p` | Yes | Proof bundle JSON file |
| `--json` | `-j` | No | Also output result as JSON |

**Exit codes**: 0 = proof is valid, 1 = verification failed.

**Example** (valid):

```
╭─────────────────────────── Proof Verified ────────────────────────────────╮
│   File         proof.json                                                │
│   Decision     Compliant                                                 │
│   Artifact     fixed.py                                                  │
│   Language     python                                                    │
│   Hash         414102a68872b366dbc1d53b...                               │
│   Algorithm    ECDSA-SHA256                                              │
│   Signer       ACPG-Adjudicator                                         │
│                                                                          │
│   Signature    VALID                                                     │
│   Code Hash    VALID                                                     │
╰──────────────────────────────────────────────────────────────────────────╯
```

**Example** (tampered):

```
╭──────────────────────── Verification Failed ──────────────────────────────╮
│   ...                                                                     │
│   Signature    INVALID                                                    │
│   Code Hash    TAMPERED                                                   │
╰──────────────────────────────────────────────────────────────────────────╯
```

---

### `acpg list-policies`

List all loaded policies with ID, type, severity, and description.

```bash
acpg list-policies
acpg list-policies --json
```

| Flag | Short | Description |
|------|-------|-------------|
| `--json` | `-j` | Output as JSON |

Policies are sorted by severity (critical first) then by ID.

---

### `acpg proof`

Generate a proof bundle for code that is already compliant. Fails if code has violations.

```bash
acpg proof --input clean_code.py
acpg proof --input clean_code.py --output proof.json
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--input` | `-i` | Yes | Input file (must be compliant) |
| `--output` | `-o` | No | Output file (default: `<input>.proof.json`) |

---

### `acpg init-hook`

Install a git pre-commit hook that checks staged Python/JS/TS files against the ACPG API before each commit.

```bash
acpg init-hook
acpg init-hook --api-url http://localhost:6000
```

| Flag | Description |
|------|-------------|
| `--api-url` | ACPG API URL (default: `http://localhost:8000` or `$ACPG_API_URL`) |

**Requires**: The ACPG backend running when commits are made. The hook calls the `/api/v1/analyze` endpoint.

To skip the hook temporarily: `git commit --no-verify`

---

### `acpg gen-hook`

Generate a pre-commit hook script to stdout or a file (without installing it).

```bash
acpg gen-hook
acpg gen-hook --output pre-commit.sh
```

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Write to file instead of stdout |
| `--api-url` | | ACPG API URL to embed in the hook |

---

### `acpg init-config`

Create a `.acpgrc` project configuration file with default settings.

```bash
acpg init-config
acpg init-config --output acpg.config.yaml
acpg init-config --force
```

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Output file path (default: `.acpgrc`) |
| `--force` | `-f` | Overwrite existing file |

The config file supports YAML or JSON format and controls:
- Enabled/disabled policies
- File include/exclude patterns
- Severity thresholds
- Auto-fix settings
- API URL and authentication
- Output format

---

### `acpg show-config`

Display current configuration, showing values from `.acpgrc` if found or defaults.

```bash
acpg show-config
```

ACPG searches for config files up the directory tree: `.acpgrc`, `.acpgrc.yaml`, `.acpgrc.yml`, `.acpgrc.json`, `acpg.config.yaml`, `acpg.config.json`.

---

## Common Workflows

### CI Pipeline Check

```bash
# Exit code 0 = pass, 1 = fail
acpg -q check --input src/main.py
```

### Fix and Prove

```bash
acpg enforce --input vulnerable.py --output fixed.py --proof proof.json
acpg verify --proof proof.json
```

### Batch Check (shell loop)

```bash
for f in src/*.py; do
  acpg -q check --input "$f" || echo "FAIL: $f"
done
```

### Pre-commit Hook Setup

```bash
acpg init-hook --api-url http://localhost:6000
```

### Project Configuration

```bash
acpg init-config
# Edit .acpgrc to customize policies, patterns, thresholds
acpg show-config
```
