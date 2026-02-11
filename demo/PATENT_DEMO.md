> [!NOTE]
> Documentation Refresh Note (February 11, 2026): this file is retained as specialized or historical context.
> For current product behavior and authoritative guidance, start at /Users/James/code/GAD/apcg/README.md and /Users/James/code/GAD/apcg/docs/README.md.

# ACPG Patent Demonstration Guide

## 🎯 Overview

This guide demonstrates the key innovations of the **Agentic Compliance and Policy Governor (ACPG)** system for patent examination purposes.

---

## 💡 Core Patent Claims

### Claim 1: Multi-Agent Compliance Architecture
A system comprising three specialized AI agents that collaborate to analyze, remediate, and certify code compliance:

1. **Generator Agent** - AI-powered code generation and remediation
2. **Prosecutor Agent** - Static analysis and violation detection  
3. **Adjudicator Engine** - Formal logic-based compliance decisions

### Claim 2: Formal Argumentation for Software Compliance
Application of Dung's Abstract Argumentation Framework with grounded semantics to produce provably correct compliance decisions.

### Claim 3: Proof-Carrying Code Artifacts
Cryptographically-signed compliance certificates (proof bundles) that provide tamper-evident verification of code compliance.

### Claim 4: Policy-as-Code System
Machine-readable policy definitions in JSON format that can be compiled into executable compliance checks.

### Claim 5: Iterative Compliance Refinement
Automated feedback loop between agents to iteratively fix violations until compliance is achieved.

---

## 🖥️ Demo Setup

### Prerequisites
- Python 3.10+
- Node.js 18+
- Local LLM server (optional) or OpenAI API key

### Quick Start

```bash
# Terminal 1: Start Backend
cd backend
source venv/bin/activate
uvicorn main:app --port 8000

# Terminal 2: Start Frontend
cd frontend
npm run dev
```

Access the UI at: **http://localhost:3000**

---

## 📋 Demonstration Script

### Demo 1: Vulnerability Detection (Prosecutor Agent)

**Purpose**: Show automated static analysis detecting security violations

1. Open the web UI at http://localhost:3000
2. Click **"Vulnerable Code"** to load sample code with security issues
3. Click **"Analyze Code"**

**Expected Result**:
```
❌ NON-COMPLIANT
Violations found: 6

🔴 SEC-001: Hardcoded credentials (line 5)
🔴 SEC-001: Hardcoded API key (line 6)
🔴 SQL-001: SQL injection vulnerability (line 9)
🔴 SEC-003: Dangerous eval() usage (line 12)
🔴 CRYPTO-001: Weak MD5 hash (line 16)
```

**Innovation Demonstrated**: Multi-pattern static analysis combining Bandit security scanner with custom regex rules.

---

### Demo 2: AI-Powered Auto-Fix (Generator Agent)

**Purpose**: Show AI automatically fixing security violations

1. With vulnerable code loaded, click **"Auto-Fix & Certify"**
2. Watch the workflow pipeline progress through each agent
3. Observe the code being automatically corrected

**Expected Transformation**:

| Before | After |
|--------|-------|
| `password = "secret123"` | `password = os.getenv("PASSWORD")` |
| `query = "SELECT * FROM users WHERE name = '" + username + "'"` | `query = "SELECT * FROM users WHERE name = ?"` |
| `eval(password_input)` | Direct function call |
| `hashlib.md5(...)` | `hashlib.sha256(...)` |

**Innovation Demonstrated**: LLM-based code remediation with policy awareness and context preservation.

---

### Demo 3: Formal Adjudication (Adjudicator Engine)

**Purpose**: Show argumentation-based compliance decisions

The Adjudicator uses **Dung's Abstract Argumentation Framework**:

1. **Arguments** are generated from evidence (violations and defenses)
2. **Attack relations** model conflicts between arguments
3. **Grounded semantics** compute the minimal defensible extension
4. **Compliance decision** is derived from accepted arguments

**CLI Demo**:
```bash
python cli.py check --input demo/vulnerable_code.py --verbose
```

**Innovation Demonstrated**: Formal logic foundations for compliance decisions, supporting both strict and defeasible rules.

---

### Demo 4: Proof Bundle Generation (Proof Assembler)

**Purpose**: Show cryptographically-signed compliance certificates

After successful compliance enforcement:

1. View the **Proof Bundle** card in the UI
2. Click **"Export"** to copy the full JSON
3. Note the ECDSA signature and artifact hash

**Proof Bundle Structure**:
```json
{
  "artifact": {
    "hash": "sha256:a1b2c3d4...",
    "language": "python",
    "generator": "ACPG-Qwen2.5-Coder",
    "timestamp": "2024-11-28T10:30:00Z"
  },
  "policies": [
    {"id": "SEC-001", "result": "satisfied"},
    {"id": "SQL-001", "result": "satisfied"}
  ],
  "decision": "Compliant",
  "signed": {
    "signature": "MEUCIQDx...",
    "algorithm": "ECDSA-SHA256",
    "public_key": "-----BEGIN PUBLIC KEY-----..."
  }
}
```

**Verify Signature**:
```bash
curl -X POST http://localhost:8000/api/v1/proof/verify \
  -H "Content-Type: application/json" \
  -d @proof.json
```

**Innovation Demonstrated**: Tamper-evident compliance artifacts enabling third-party verification.

---

### Demo 5: Policy-as-Code System

**Purpose**: Show machine-readable policy definitions

**View Policies**:
```bash
python cli.py list-policies
```

**Example Policy Definition**:
```json
{
  "id": "SEC-001",
  "type": "strict",
  "severity": "high",
  "description": "No hardcoded credentials in source code",
  "category": "security",
  "patterns": [
    "password\\s*=\\s*['\"][^'\"]+['\"]",
    "api_key\\s*=\\s*['\"][^'\"]+['\"]"
  ],
  "fix_suggestion": "Use environment variables or a secrets manager"
}
```

**Innovation Demonstrated**: Declarative policy language with executable patterns and remediation guidance.

---

### Demo 6: Iterative Refinement Loop

**Purpose**: Show the feedback loop between agents

1. Load code with multiple violations
2. Run enforcement with `max_iterations=3`
3. Observe iteration count in the workflow

**Workflow**:
```
Iteration 1: 11 violations → AI fix → 4 remaining
Iteration 2:  4 violations → AI fix → 2 remaining
Iteration 3:  2 violations → AI fix → 0 remaining
Result: COMPLIANT ✓
```

**Innovation Demonstrated**: Convergent compliance through iterative agent collaboration.

---

## 🔬 Technical Deep Dive

### Agent Communication Flow

```
┌─────────────┐     Violations     ┌─────────────┐
│  Prosecutor │ ─────────────────▶ │ Adjudicator │
│   (Bandit)  │                    │   (Logic)   │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │ Evidence                         │ Decision
       │                                  │
       ▼                                  ▼
┌─────────────┐     Fix Request    ┌─────────────┐
│  Generator  │ ◀───────────────── │   Proof     │
│   (LLM)     │                    │  Assembler  │
└─────────────┘                    └─────────────┘
       │                                  │
       │ Fixed Code                       │ Signed Bundle
       └────────────────────┬─────────────┘
                            ▼
                      Final Output
```

### Grounded Semantics Algorithm

```python
def compute_grounded_extension(arguments, attacks):
    """
    Compute the grounded extension using iterative fixpoint.
    
    1. Start with unattacked arguments
    2. Add arguments defended by accepted set
    3. Repeat until fixpoint
    """
    accepted = set()
    while True:
        newly_accepted = set()
        for arg in arguments:
            if is_acceptable(arg, accepted, attacks):
                newly_accepted.add(arg)
        if newly_accepted == accepted:
            break
        accepted = newly_accepted
    return accepted
```

### Proof Signing Process

```python
def sign_proof_bundle(bundle, private_key):
    """
    Sign proof bundle with ECDSA-SHA256.
    
    1. Serialize bundle to canonical JSON
    2. Compute SHA-256 hash
    3. Sign with ECDSA private key
    4. Attach signature to bundle
    """
    canonical = json.dumps(bundle, sort_keys=True)
    digest = hashlib.sha256(canonical.encode()).digest()
    signature = private_key.sign(digest, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()
```

---

## 📊 Performance Metrics

| Metric | Value |
|--------|-------|
| Policies checked | 38 |
| Analysis time | ~500ms |
| Fix iteration | ~3s (with local LLM) |
| Proof generation | ~50ms |
| Signature verification | <10ms |

---

## 🏛️ Legal & Compliance

### Applicable Standards
- OWASP Top 10 (2021)
- NIST 800-218 SSDF
- CWE Top 25
- SANS Top 25

### Target Industries
- Financial Services (SEC, SOX)
- Healthcare (HIPAA)
- Government (FedRAMP)
- E-commerce (PCI-DSS)

---

## 📞 Contact

For patent examination inquiries, please contact the inventor.

---

*Document Version: 1.1*  
*Last Updated: November 2024*
