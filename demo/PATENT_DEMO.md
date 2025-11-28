# ACPG Patent Demonstration Guide

## Overview

This guide demonstrates the key innovations of the **Agentic Compliance and Policy Governor (ACPG)** system for patent examination purposes.

## Key Patent Claims Demonstrated

### Claim 1: Multi-Agent Compliance Architecture
The system implements a "digital compliance courtroom" with three autonomous agents:
- **Generator Agent** - AI-powered code creation/modification
- **Prosecutor Agent** - Security violation detection
- **Adjudicator Agent** - Formal logic-based decision making

### Claim 2: Formal Argumentation Framework
Uses Dung's Abstract Argumentation with grounded semantics for compliance decisions.

### Claim 3: Proof-Carrying Artifacts
Generates cryptographically-signed proof bundles that travel with code artifacts.

---

## Demo Prerequisites

```bash
cd /home/james/code/acpg/backend
source venv/bin/activate
export OPENAI_API_KEY="your-key"  # Only needed for auto-fix
```

---

## Demo 1: Violation Detection (Prosecutor Agent)

**Purpose**: Show automatic detection of security policy violations.

```bash
python cli.py check --input ../demo/vulnerable_code.py
```

**Expected Output**:
- 7 violations detected across 6 different policy categories
- Each violation shows: rule ID, severity, line number, evidence

**Key Innovation**: Combines static analysis (Bandit) with policy-specific pattern matching.

---

## Demo 2: Compliance Verification (Adjudicator Agent)

**Purpose**: Show formal argumentation-based compliance decision.

```bash
python cli.py check --input ../demo/compliant_code.py
```

**Expected Output**:
- "COMPLIANT - No violations detected"
- All 8 policies satisfied

**Key Innovation**: Uses grounded semantics algorithm to compute minimal defensible argument set.

---

## Demo 3: Proof Bundle Generation

**Purpose**: Show cryptographically-signed compliance certificate.

```bash
python cli.py proof --input ../demo/compliant_code.py --output ../demo/proof.json
```

**Expected Output**:
```json
{
  "artifact": {
    "hash": "sha256-of-code",
    "language": "python",
    "generator": "ACPG-gpt-4"
  },
  "policies": [
    {"id": "SEC-001", "result": "satisfied"},
    ...
  ],
  "decision": "Compliant",
  "signed": {
    "signature": "ECDSA-signature",
    "algorithm": "ECDSA-SHA256"
  }
}
```

**Key Innovation**: Proof bundle is cryptographically bound to the specific code artifact.

---

## Demo 4: Full Compliance Loop (All Agents)

**Purpose**: Show iterative generate → check → fix → certify loop.

### Via CLI (requires OpenAI API key):
```bash
python cli.py enforce --input ../demo/vulnerable_code.py \
    --output ../demo/fixed_code.py \
    --proof ../demo/enforcement_proof.json
```

### Via API:
```bash
# Start server
uvicorn main:app --host 0.0.0.0 --port 8000 &

# Call enforce endpoint
curl -X POST http://localhost:8000/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "code": "password = \"secret123\"",
    "language": "python",
    "max_iterations": 3
  }'
```

**Key Innovation**: Autonomous loop continues until compliance achieved or iteration limit.

---

## Demo 5: Web Interface

**Purpose**: Show interactive compliance checking with visual feedback.

```bash
# Terminal 1: Backend
cd backend && source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000

# Terminal 2: Frontend  
cd frontend && npm install && npm run dev
```

Open http://localhost:3000 in browser.

**Interactive Demo**:
1. Load "Vulnerable Code" sample
2. Click "Analyze" → See violation list with severity colors
3. Click "Auto-Fix & Certify" → Watch iterative fixing
4. Copy generated proof bundle

---

## Demo 6: Argumentation Visualization

**Purpose**: Explain formal logic decision process.

The adjudicator builds an argumentation graph:

```
Arguments:
  C_SEC001: "Code complies with SEC-001 (no hardcoded credentials)"
  V_SEC001: "Violation: password = 'secret123' on line 10"
  
Attack Relation:
  V_SEC001 attacks C_SEC001

Grounded Extension Computation:
  1. V_SEC001 is unattacked → ACCEPT
  2. C_SEC001 is attacked by accepted argument → REJECT
  3. Violation argument accepted → Code is NON-COMPLIANT
```

---

## API Endpoints for Demonstration

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/policies` | List all 8 security policies |
| `POST /api/v1/analyze` | Detect violations in code |
| `POST /api/v1/adjudicate` | Run argumentation framework |
| `POST /api/v1/enforce` | Full compliance loop |
| `POST /api/v1/proof/generate` | Create signed proof bundle |
| `POST /api/v1/proof/verify` | Verify proof signature |

---

## Technical Specifications

### Policy Types
- **Strict Rules**: Cannot be overridden (e.g., no hardcoded secrets)
- **Defeasible Rules**: Can have exceptions (e.g., input validation)

### Cryptographic Properties
- **Algorithm**: ECDSA with P-256 curve
- **Hash**: SHA-256 for artifact binding
- **Signature**: Base64-encoded, covers all proof data

### Argumentation Semantics
- **Framework**: Dung's Abstract Argumentation (1995)
- **Semantics**: Grounded extension (skeptical, minimal)
- **Computation**: Fixpoint iteration algorithm

---

## Sample Output Files

After running demos, these files are created:
- `demo/proof_bundle.json` - Signed compliance certificate
- `demo/fixed_code.py` - Auto-remediated code (if using enforce)

---

## Contact

For questions about this patent demonstration, refer to the technical documentation in the project repository.

