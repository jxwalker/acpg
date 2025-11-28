# ACPG: Agentic Compliance and Policy Governor

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/React-18-61DAFB.svg" alt="React">
  <img src="https://img.shields.io/badge/FastAPI-0.104-009688.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

ACPG is an **automated compliance system** that implements a "digital compliance courtroom" with three AI-powered agents. It generates compliant code, validates it against policies, and produces **cryptographically-signed proof certificates**.

## 🎯 Key Features

- **✅ Automated Compliance Checking** - Static analysis with Bandit + regex pattern matching
- **🔧 AI-Powered Auto-Fix** - Uses GPT-4 to automatically fix violations
- **⚖️ Formal Argumentation** - Grounded semantics for compliance decisions
- **📜 Proof Bundles** - Cryptographically-signed compliance certificates (ECDSA)
- **🔄 Iterative Refinement** - Generate → Test → Fix → Certify loop
- **🌐 REST API + Web UI** - FastAPI backend with React frontend

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ACPG System                                  │
├─────────────────────────────────────────────────────────────────────┤
│  POLICY LAYER                                                       │
│    └── Policy Compiler (JSON → Executable Checks)                   │
├─────────────────────────────────────────────────────────────────────┤
│  GENERATION LAYER                                                   │
│    └── Generator Agent (OpenAI GPT-4)                               │
├─────────────────────────────────────────────────────────────────────┤
│  EVALUATION LAYER                                                   │
│    ├── Prosecutor Agent (Bandit + Regex + AST)                      │
│    └── Adjudicator (Argumentation Framework)                        │
├─────────────────────────────────────────────────────────────────────┤
│  PROOF LAYER                                                        │
│    └── Proof Assembler (ECDSA Signing)                              │
└─────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- OpenAI API key

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Set your OpenAI API key
export OPENAI_API_KEY="sk-your-key-here"

# Run the server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Then open http://localhost:3000 in your browser.

## 📖 Usage

### 1. Web UI

1. Navigate to http://localhost:3000
2. Paste or edit code in the editor
3. Click **"Analyze"** to check compliance
4. Click **"Auto-Fix & Certify"** to automatically fix violations
5. Download the signed proof bundle

### 2. REST API

```python
import requests

# Check compliance
response = requests.post("http://localhost:8000/api/v1/analyze", json={
    "code": "password = 'secret123'",
    "language": "python"
})
print(response.json())  # {"violations": [...]}

# Auto-fix and certify
response = requests.post("http://localhost:8000/api/v1/enforce", json={
    "code": "password = 'secret123'",
    "language": "python",
    "max_iterations": 3
})
result = response.json()
if result["compliant"]:
    print("Fixed code:", result["final_code"])
    print("Proof bundle:", result["proof_bundle"])
```

### 3. Command Line

```bash
cd backend

# Check code for violations
python cli.py check --input mycode.py

# Auto-fix code
python cli.py enforce --input mycode.py --output fixed.py --proof proof.json

# List all policies
python cli.py list-policies
```

## 📋 Default Policies

| ID | Description | Type | Severity |
|----|-------------|------|----------|
| SEC-001 | No hardcoded credentials | Strict | High |
| SEC-002 | No sensitive data in logs | Strict | Medium |
| SEC-003 | No eval/exec functions | Strict | Critical |
| SEC-004 | Use HTTPS not HTTP | Strict | High |
| INPUT-001 | Validate user inputs | Defeasible | High |
| ERR-001 | Proper exception handling | Strict | Medium |
| SQL-001 | Use parameterized queries | Strict | Critical |
| CRYPTO-001 | No weak crypto (MD5/SHA1) | Strict | High |

## 🔧 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/policies` | GET | List all policies |
| `/api/v1/analyze` | POST | Analyze code for violations |
| `/api/v1/adjudicate` | POST | Run argumentation on analysis |
| `/api/v1/generate` | POST | Generate code from spec |
| `/api/v1/fix` | POST | Fix specific violations |
| `/api/v1/enforce` | POST | Full compliance loop |
| `/api/v1/proof/generate` | POST | Generate proof bundle |
| `/api/v1/proof/verify` | POST | Verify proof signature |

## 📦 Proof Bundle Structure

```json
{
  "artifact": {
    "hash": "sha256-of-code",
    "language": "python",
    "generator": "ACPG-gpt-4",
    "timestamp": "2024-01-15T10:30:00Z"
  },
  "policies": [
    {"id": "SEC-001", "result": "satisfied"},
    {"id": "SQL-001", "result": "satisfied"}
  ],
  "evidence": [...],
  "argumentation": {...},
  "decision": "Compliant",
  "signed": {
    "signature": "base64-ecdsa-signature",
    "signer": "ACPG-Adjudicator",
    "algorithm": "ECDSA-SHA256"
  }
}
```

## 🧪 Running Tests

```bash
cd backend
pip install pytest pytest-asyncio
pytest tests/ -v
```

## 📁 Project Structure

```
acpg/
├── backend/
│   ├── app/
│   │   ├── api/            # FastAPI routes
│   │   ├── core/           # Config, crypto
│   │   ├── models/         # Pydantic schemas
│   │   └── services/       # Business logic
│   │       ├── policy_compiler.py
│   │       ├── prosecutor.py
│   │       ├── generator.py
│   │       ├── adjudicator.py
│   │       └── proof_assembler.py
│   ├── main.py             # FastAPI app
│   ├── cli.py              # Command-line interface
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.tsx         # Main React component
│   │   ├── api.ts          # API client
│   │   └── types.ts        # TypeScript types
│   └── package.json
├── policies/
│   └── default_policies.json
└── tests/
```

## 🔬 The Three Agents

### 1. Generator Agent (AI)
Uses OpenAI GPT-4 to:
- Generate policy-aware code from specifications
- Fix violations based on prosecutor feedback
- Provide explanations for changes

### 2. Prosecutor Agent (Security Scanner)
Detects violations using:
- **Bandit** - Python security linter
- **Regex patterns** - Custom policy rules
- **AST analysis** - Semantic code checks

### 3. Adjudicator (Logic Engine)
Makes formal decisions using:
- **Dung's Argumentation Framework** - Formal logic
- **Grounded Semantics** - Minimal defensible extensions
- Handles exceptions for defeasible rules

## 📊 The Compliance Loop

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Generator  │────▶│  Prosecutor │────▶│ Adjudicator │
│   (GPT-4)   │     │  (Bandit)   │     │   (Logic)   │
└─────────────┘     └─────────────┘     └──────┬──────┘
       ▲                                       │
       │                              ┌────────┴────────┐
       │                              │   Compliant?    │
       │                              └────────┬────────┘
       │                                Yes ▼     │ No
       │                           ┌─────────┐   │
       └───────────────────────────│ Proof   │◀──┘
                Feedback           │ Bundle  │
                                   └─────────┘
```

## 🔒 Security Notes

- **Never commit** your `.env` file or API keys
- Proof signatures are generated fresh each run (ephemeral keys)
- For production, implement persistent key management
- The proof bundle proves compliance at signing time

## 📄 License

MIT License - See LICENSE file for details.

## 📚 References

- [Dung's Abstract Argumentation Framework](https://en.wikipedia.org/wiki/Argumentation_framework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST 800-218 SSDF](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [Proof-Carrying Code](https://en.wikipedia.org/wiki/Proof-carrying_code)

---

**Built with ❤️ for secure, compliant software development**
