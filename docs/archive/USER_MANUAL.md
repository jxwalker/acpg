# ACPG User Manual
## Agentic Compliance and Policy Governor

**Audience**: Sales teams, customers, and CISOs  
**Last updated**: February 12, 2026  
**Version**: 1.0

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Product Overview](#2-product-overview)
3. [Complete Feature Reference](#3-complete-feature-reference)
4. [Sales Demo Guide](#4-sales-demo-guide)
5. [CISO Technical Guide](#5-ciso-technical-guide)
6. [Quick Reference & API Summary](#6-quick-reference--api-summary)
7. [Appendix: Sample Files](#7-appendix-sample-files)

---

## 1. Executive Summary

ACPG (Agentic Compliance and Policy Governor) is a **multi-agent compliance platform** for AI-generated and AI-assisted code. It gives organizations:

- **Provable compliance**: Formal argumentation-based decisions with cryptographically signed proofs
- **Automated remediation**: AI-driven fixes that respect policy while preserving intent
- **Runtime safety**: Policy enforcement for agent workflows (tools, network, filesystem)
- **Audit readiness**: Tamper-evident proof bundles and full policy lifecycle tracking

**Value proposition for sales**:
- "Ensure every AI-generated line of code meets your security policy before it reaches production."
- "Turn compliance from a bottleneck into an automated, auditable workflow."
- "Proof bundles that CISOs and auditors can cryptographically verify—no trust, verify."

**Value proposition for CISOs**:
- Deterministic compliance decisions (grounded semantics)
- Cryptographic integrity (ECDSA-SHA256 signed proof bundles)
- Policy-as-code with full version history and diff
- Runtime guard for agent tool invocations

---

## 2. Product Overview

### Architecture

ACPG uses four core agents working together:

| Agent | Role | Capability |
|-------|------|------------|
| **Prosecutor** | Detects violations | Runs static analysis tools (Bandit, Safety, ESLint), maps findings to policies, ingests runtime guard denials |
| **Adjudicator** | Decides compliance | Uses abstract argumentation (grounded/stable/preferred semantics) for deterministic decisions |
| **Generator** | Fixes code | LLM-backed auto-fix that resolves violations while preserving functionality |
| **Proof Assembler** | Creates audit trail | Assembles signed proof bundles with evidence, argumentation, and decision |

### Supported Languages

- **Primary**: Python (Bandit, Safety)
- **Secondary**: JavaScript/TypeScript (ESLint via configured tools)

### Policy Framework

Policies are defined as JSON and loaded from catalogs:

- **Default policies**: SEC-001 (hardcoded secrets), SEC-003 (dangerous functions), SQL-001 (SQL injection), CRYPTO-001 (weak crypto), SEC-004 (insecure HTTP), etc.
- **OWASP**: OWASP Top 10 mapped policies
- **NIST**: NIST cybersecurity framework alignments
- **JavaScript/TS**: Language-specific policies
- **Custom**: User-defined policies stored in `custom_policies.json`

**39 policies** are loaded by default.

---

## 3. Complete Feature Reference

### 3.1 Static Analysis and Policy Checking

| Feature | Description | Where to Use |
|---------|-------------|--------------|
| **Analyze** | Run static analysis and policy checks on code; no fixes | Main workflow, first step |
| **Batch Analyze** | Analyze multiple code snippets in one request | CI pipelines, repo sweeps |
| **Tool execution** | Bandit, Safety, ESLint (configurable) run in parallel | Tools panel, config |
| **Tool-to-policy mapping** | Map tool rule IDs (e.g. Bandit B105) to policy IDs (e.g. SEC-001) | Tools → Mappings |
| **Unmapped findings** | See tool findings not yet mapped to policies | Violations panel, tool execution |
| **Policy groups** | Organize policies into groups (Default, OWASP, NIST, etc.) | Policies → Groups |
| **Enable/disable groups** | Control which policies apply to analysis | Policies → Groups → Toggle |

### 3.2 Formal Adjudication

| Feature | Description | Where to Use |
|---------|-------------|--------------|
| **Grounded semantics** | Skeptical, deterministic compliance decision | Default for regulated use |
| **AUTO semantics** | Grounded decision + optional stable/preferred evidence | When secondary evidence is needed |
| **Stable/Preferred** | Solver-backed semantics (clingo) with skeptical/credulous mode | Advanced scenarios |
| **Argumentation trace** | Full reasoning graph in proof bundles | Proof view, verification |
| **Joint attacks** | Nielsen-Parsons style attacks in grounded extension | Conflict resolution |
| **Fix guidance** | Prioritized guidance for resolving violations | Adjudicate → Guidance |

### 3.3 Code Generation and Auto-Fix

| Feature | Description | Where to Use |
|---------|-------------|--------------|
| **Enforce** | Full loop: analyze → adjudicate → fix → repeat until compliant or max iterations | Main workflow |
| **Fix** | One-shot fix for specific violations | Manual fix flow |
| **Generate** | Generate policy-aware code from specification | Code generation |
| **Stop on stagnation** | Stop when fix iterations don't reduce violations | Enforce options |
| **LLM provider switching** | Switch between OpenAI, Anthropic, compatible APIs | Models panel |

### 3.4 Proof-Carrying Artifacts

| Feature | Description | Where to Use |
|---------|-------------|--------------|
| **Proof bundle** | Signed artifact (code, evidence, argumentation, decision) | Enforce, Proof Generate |
| **Verification** | Cryptographically verify bundle integrity | Verify tab |
| **Public key** | Retrieve public key for independent verification | API, integrations |
| **Export** | Export proof bundle in portable format | Proof view |
| **Storage** | Proofs stored in DB for retrieval by hash | Proof storage |

**Cryptographic details**:
- ECDSA-SHA256 signatures
- SECP256R1 (P-256) curve
- Code hash (SHA-256) included in signed payload
- Tamper detection on any modification

### 3.5 Runtime Compliance

| Feature | Description | Where to Use |
|---------|-------------|--------------|
| **LangGraph enforce** | Enforce with runtime event trace capture | Agent workflows |
| **Runtime policies** | Allow/deny/require_approval/allow_with_monitoring for tool, network, filesystem | Runtime policy config |
| **Runtime guard** | Evaluates tool actions against policy; denials become violations | Agent execution |
| **Dynamic analysis** | Sandboxed Python execution with timeout; replay artifacts in proofs | When enabled |
| **Streaming** | Stream LangGraph enforce events | Real-time dashboards |

### 3.6 Policy Lifecycle and Audit

| Feature | Description | Where to Use |
|---------|-------------|--------------|
| **Policy CRUD** | Create, update, delete custom policies | Policies panel |
| **Policy history** | Version history per policy | Policies → History |
| **Policy diff** | Compare policy versions | Policies → Diff |
| **Group rollout preview** | Simulate policy group changes against test cases | Groups → Rollout |
| **Import/Export** | Bulk policy import and export | Policies → Import/Export |
| **Policy templates** | Apply templates to groups | Groups → Templates |

### 3.7 Test Case Management

| Feature | Description | Where to Use |
|---------|-------------|--------------|
| **File samples** | Pre-built samples (01–12) with known violations | Samples dropdown |
| **DB test cases** | Create, update, delete test cases in database | Test cases panel |
| **Unified list** | Combined file + DB test cases | Test cases API |
| **Batch import** | Bulk import test cases | API |

### 3.8 Reporting and Metrics

| Feature | Description | Where to Use |
|---------|-------------|--------------|
| **Compliance report** | JSON, Markdown, or HTML report | Report API |
| **Report download** | Download report as file | Report download API |
| **Analysis history** | Recent analyses (last 100) | History sidebar |
| **Admin stats** | Total analyses, compliance rate, proofs, enforcements | Admin API |
| **Audit logs** | All analysis, enforcement, proof actions | Admin API |
| **Prometheus metrics** | Cache, tools, policies, health | `/metrics/prometheus` |
| **Health check** | Component status (DB, tools, LLM, policies, signing) | Health API |

### 3.9 Operational Features

| Feature | Description | Where to Use |
|---------|-------------|--------------|
| **Tool cache** | Cache tool results; clear per tool or all | Cache API |
| **Tool toggle** | Enable/disable static analysis tools | Tools panel |
| **Theme** | Dark, light, system | UI settings |
| **Auto-save** | Persist code to localStorage | Editor |

---

## 4. Sales Demo Guide

### 4.1 Pre-Demo Checklist

- [ ] Backend running: `./scripts/start.sh` or `cd backend && uvicorn main:app --reload --port 6000`
- [ ] Frontend running: `cd frontend && npm run dev`
- [ ] `OPENAI_API_KEY` set in `backend/.env`
- [ ] Health check passes: `curl http://localhost:6000/api/v1/health`
- [ ] Have one sample loaded (default vulnerable code is fine)

### 4.2 15-Minute Core Demo

**Goal**: Show analyze → adjudicate → enforce → proof in one flow.

| Step | Action | Talking Point |
|------|--------|---------------|
| 1 | Open app, show code editor with vulnerable sample | "ACPG analyzes any code—AI-generated or hand-written—against your policies." |
| 2 | Click **Analyze** | "Prosecutor runs Bandit and Safety, maps findings to policies like SEC-001, SQL-001." |
| 3 | Point to violations list: rule ID, severity, location | "Each violation is tied to a policy and evidence." |
| 4 | Show adjudication: compliant vs non-compliant | "Adjudicator uses formal argumentation—no ambiguity." |
| 5 | Click **Enforce** | "Generator auto-fixes until compliant or max iterations." |
| 6 | Switch to **Diff** view | "You see exactly what changed: original vs fixed." |
| 7 | Open **Proof** tab | "Signed proof bundle: code, evidence, argumentation, decision." |
| 8 | Open **Verify** tab, paste proof, verify | "Any auditor can cryptographically verify integrity." |

### 4.3 Advanced Demos

#### Demo A: Policy Groups and Custom Policies

1. Go to **Policies**.
2. Show policy groups: Default, OWASP, NIST, JavaScript.
3. Toggle a group off → analyze → show fewer violations.
4. Create a custom policy (regex or manual check).
5. Add to a group, enable, re-analyze.

**Talking point**: "Policy-as-code with full lifecycle—version history, diff, rollout preview."

#### Demo B: Tool Mappings and Unmapped Findings

1. Load `samples/12_tool_demo.py` (or similar).
2. Go to **Tools**.
3. Show Bandit rules: which are mapped (e.g. B608→SQL-001), which unmapped.
4. Add a mapping for an unmapped rule.
5. Re-analyze; show new violation appears.

**Talking point**: "Extend coverage by mapping any tool finding to your policies."

#### Demo C: Proof Verification and Tamper Detection

1. Run **Enforce** to get a proof bundle.
2. Open **Verify**, paste proof, verify → "Integrity verified."
3. Manually edit the JSON (e.g. change one character of code).
4. Verify again → "Tampering detected."

**Talking point**: "CISO can verify without trusting us—cryptography speaks."

#### Demo D: LangGraph Runtime Flow

1. Use API: `POST /api/v1/graph/enforce` with same code.
2. Show `runtime_events` in response.
3. Show proof bundle includes `RUNTIME` evidence.

**Talking point**: "Runtime compliance for agent workflows—tool denials become formal violations."

#### Demo E: Report Generation

1. Run analyze.
2. `POST /api/v1/report` with `format: "html"` or `format: "markdown"`.
3. Show formatted report for compliance reviews.

**Talking point**: "Export reports for reviews, sign-offs, and audit packs."

### 4.4 Sample Files for Demos

| File | Best For | Key Violations |
|------|----------|----------------|
| `01_hardcoded_secrets.py` | SEC-001 | Passwords, API keys |
| `02_sql_injection.py` | SQL-001 | String concatenation in SQL |
| `06_mixed_vulnerabilities.py` | Mixed | Multiple policy types |
| `07_owasp_top10.py` | OWASP | OWASP Top 10 |
| `08_strict_policies.py` | Argumentation | No exceptions |
| `09_defeasible_policies.py` | Argumentation | Exceptions defeat violations |
| `12_tool_demo.py` | Tool mapping | Mapped vs unmapped findings |

---

## 5. CISO Technical Guide

### 5.1 Security Posture Summary

| Concern | ACPG Approach |
|---------|---------------|
| **Compliance determinism** | Grounded semantics: skeptical, unique extension; no non-determinism in final decision |
| **Integrity of proofs** | ECDSA-SHA256; code, policies, evidence, argumentation in signed payload |
| **Key management** | Keys in `backend/.keys/`; private key encrypted at rest; fingerprint in bundle |
| **Audit trail** | Audit logs (analyze, enforce, proof) in SQLite; policy history per policy |
| **Runtime safety** | Runtime guard evaluates tool/network/filesystem actions; denials = violations |
| **No fallbacks in production** | Per policy: no mocks or fallbacks that mask failures; clear errors |

### 5.2 Tamper Detection

Proof bundles are tamper-evident:

1. **Signature**: Covers artifact metadata, code, policies, evidence, argumentation, decision, timestamp.
2. **Code hash**: SHA-256 of code; must match `artifact.hash`.
3. **Verification**: `POST /api/v1/proof/verify` checks both signature and hash.

**Attack scenarios and outcomes**:

| Attack | Result |
|--------|--------|
| Modify code | Signature invalid |
| Modify policies/evidence/argumentation | Signature invalid |
| Change code but not hash | Hash mismatch |
| Replace signature with another key | Signer fingerprint mismatch |

See `docs/TAMPER_DETECTION.md` for full details.

### 5.3 Compliance Model

**Grounded semantics (recommended)**:
- Each policy violation is an *argument* against compliance.
- Grounded extension: unattacked arguments accepted; attacked arguments rejected.
- Fixpoint iteration → deterministic result.
- Suitable for regulatory use.

**Runtime compliance**:
- Tool invocations evaluated against runtime policy.
- Actions: `deny`, `require_approval`, `allow_with_monitoring`, `allow`.
- Denials become formal violations; adjudicator treats them like static violations.
- Proof bundles include `RUNTIME` evidence.

See `docs/runtime_policy_compliance.md` for implementation details.

### 5.4 Policy Lifecycle and Audit

- **Version history**: Every policy change stored with timestamp, actor, before/after.
- **Diff**: Compare any two versions.
- **Rollout preview**: Simulate policy group changes against test cases before enabling.
- **Import/Export**: Bulk policy management with validation.

**Endpoints**:
- `GET /api/v1/policies/audit/history`
- `GET /api/v1/policies/{id}/audit/history`
- `GET /api/v1/policies/{id}/audit/diff`
- `POST /api/v1/policies/groups/rollout/preview`

### 5.5 Operational Security

- **API**: No embedded secrets; use environment variables or config files.
- **Database**: SQLite by default; supports connection string for external DB.
- **LLM**: API keys in env; Responses API first, fallback to Chat Completions when needed.
- **Metrics**: Prometheus `/metrics/prometheus` for monitoring.

### 5.6 CISO FAQ

**Q: Can I verify proofs without using ACPG?**  
A: Yes. Use `GET /api/v1/proof/public-key` for the public key. Reconstruct signed payload from bundle, verify ECDSA signature, compare code hash.

**Q: What if the LLM introduces new vulnerabilities when fixing?**  
A: Each fix iteration is re-analyzed. Violations must decrease or loop stops (stagnation). Proof bundle records all iterations and final state.

**Q: How are policy conflicts resolved?**  
A: Abstract argumentation. Competing arguments attack each other; grounded extension gives the skeptical, conflict-free set. Strict policies cannot be defeated; defeasible ones can have exceptions.

**Q: Is runtime policy enforcement mandatory?**  
A: Runtime guard is opt-in per deployment. When used, denied tool actions become violations and flow into adjudication and proofs.

---

## 6. Quick Reference & API Summary

### Primary Endpoints (Base: `/api/v1`)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/analyze` | Analyze code for violations |
| POST | `/analyze/batch` | Batch analyze multiple snippets |
| POST | `/adjudicate` | Run adjudication on analysis |
| POST | `/enforce` | Full enforce loop (analyze→fix→proof) |
| POST | `/fix` | One-shot fix for violations |
| POST | `/proof/generate` | Generate proof bundle |
| POST | `/proof/verify` | Verify proof bundle |
| GET | `/proof/public-key` | Get signing public key |
| POST | `/graph/enforce` | Enforce with LangGraph runtime trace |
| POST | `/graph/enforce/stream` | Streaming enforce |
| GET | `/health` | Health check |
| GET | `/metrics` | Performance metrics |
| GET | `/metrics/prometheus` | Prometheus metrics |

### Policy Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/policies` | List policies |
| GET | `/policies/audit/history` | Policy change history |
| GET | `/policies/{id}/audit/diff` | Policy version diff |
| GET | `/policies/groups` | List policy groups |
| POST | `/policies/groups/rollout/preview` | Rollout simulation |

### LLM Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/llm/providers` | List providers |
| POST | `/llm/switch` | Switch active provider |
| POST | `/llm/test` | Test provider connection |

### Enforce Options

- `stop_on_stagnation` (default: true): Stop when iterations do not reduce violations
- `solver_decision_mode`: `auto` | `skeptical` | `credulous` for stable/preferred
- `semantics`: `grounded` | `auto` | `stable` | `preferred`
- `max_iterations`: Default 3

---

## 7. Appendix: Sample Files

| File | Description | Violations |
|------|-------------|------------|
| `01_hardcoded_secrets.py` | Embedded credentials, API keys | SEC-001 |
| `02_sql_injection.py` | SQL injection | SQL-001 |
| `03_dangerous_functions.py` | eval, exec, pickle | SEC-003 |
| `04_weak_crypto.py` | MD5, SHA1, weak random | CRYPTO-001 |
| `05_insecure_http.py` | HTTP instead of HTTPS | SEC-004 |
| `06_mixed_vulnerabilities.py` | Multiple types | Mixed |
| `07_owasp_top10.py` | OWASP Top 10 | OWASP-* |
| `08_strict_policies.py` | Strict, no exceptions | SEC-001, SEC-003, SQL-001, CRYPTO-001 |
| `09_defeasible_policies.py` | Defeasible with exceptions | INPUT-001, ERR-001, LOG-001 |
| `10_argumentation_conflict.py` | Conflict resolution | Multiple |
| `11_severity_priority.py` | Severity-based triage | Multiple |
| `12_tool_demo.py` | Tool mapping demo | Mapped + unmapped |

---

*For technical implementation details, see `README.md`, `QUICKSTART.md`, and `docs/README.md`.*
