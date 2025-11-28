# ACPG: Agentic Compliance and Policy Governor

## Overview

ACPG is an automated compliance system that generates compliant code, validates it against policies, and produces cryptographically-signed proof certificates. It implements a "digital compliance courtroom" with three automated agents:

1. **Generator Agent**: AI-powered code generator (using LLMs) that produces policy-aware code
2. **Prosecutor Agent**: Static and dynamic analysis tools that find policy violations  
3. **Adjudicator**: Structured argumentation engine that resolves compliance using formal logic

## Key Features

- ✅ Automated compliance checking and fixing
- ✅ Policy-as-code with formal logic reasoning
- ✅ Proof-carrying artifacts with cryptographic signatures
- ✅ Explainable decisions via argumentation framework
- ✅ Iterative refinement loop (generate → test → adjudicate → fix)
- ✅ Support for strict and defeasible rules with exceptions

## Architecture

```
User/Developer
      ↓
[Policy Rules] → [Policy Compiler]
      ↓                    ↓
[Code Input] → [Generator Agent] → [Code Artifact]
                       ↓
               [Prosecutor Agents]
            (Static + Dynamic Analysis)
                       ↓
                [Adjudicator]
           (Argumentation Engine)
                       ↓
          ┌─────────────────────┐
          │   Compliant?        │
          └─────────────────────┘
           Yes ↓         ↓ No
      [Proof Assembler]  [Feedback to Generator]
              ↓
[Signed Proof Bundle]
```

## Technology Stack

- **Backend**: Python 3.10+, FastAPI
- **AI**: OpenAI API (GPT-4)
- **Static Analysis**: Bandit, regex patterns
- **Dynamic Testing**: Hypothesis (optional)
- **Crypto**: Python cryptography library (ECDSA)
- **Frontend**: React, TypeScript

## Project Structure

```
acpg/
├── backend/
│   ├── app/
│   │   ├── api/          # FastAPI endpoints
│   │   ├── core/         # Configuration, crypto
│   │   ├── models/       # Data models
│   │   └── services/     # Business logic (agents)
│   ├── requirements.txt
│   └── main.py
├── frontend/
│   ├── src/
│   └── package.json
├── policies/             # Policy rule definitions
│   └── default_policies.json
├── tests/
└── README.md
```

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 16+
- OpenAI API key

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt

# Set environment variables
export OPENAI_API_KEY="your-api-key-here"

# Run server
uvicorn main:app --reload
```

### Frontend Setup

```bash
cd frontend
npm install
npm start
```

## Usage

### 1. Via Web UI
- Navigate to `http://localhost:3000`
- Paste or write code
- Click "Check Compliance"
- Review violations and click "Auto-Fix" if needed
- Download proof bundle when compliant

### 2. Via API

```python
import requests

# Check compliance
response = requests.post("http://localhost:8000/analyze", json={
    "code": "def login(pwd): password = 'secret123'",
    "language": "python"
})

# Auto-fix violations
response = requests.post("http://localhost:8000/enforce", json={
    "code": "...",
    "max_iterations": 3
})

# Get proof bundle
proof = response.json()["proof_bundle"]
```

### 3. Via CLI

```bash
python cli.py check --input code.py --policies policies/default_policies.json
python cli.py enforce --input code.py --output fixed_code.py --proof proof.json
```

## Policy Rules

Policies are defined in JSON format with support for:
- **Strict rules**: Mandatory requirements (e.g., no hardcoded secrets)
- **Defeasible rules**: Guidelines with exceptions (e.g., encrypt unless public data)

Example policy:

```json
{
  "policy_id": "SEC-001",
  "description": "No hardcoded credentials in code",
  "type": "strict",
  "severity": "high",
  "check": {
    "type": "regex",
    "pattern": "(?i)(password\\s*=|api[_-]?key\\s*=)",
    "languages": ["python", "javascript"]
  }
}
```

## Proof-Carrying Artifacts

Compliant code is packaged with a cryptographically-signed proof bundle containing:
- List of policies checked and their status
- Evidence from static/dynamic analysis
- Argumentation trace showing how compliance was verified
- Digital signature for tamper-evidence

## Development

### Running Tests

```bash
pytest tests/
```

### Adding New Policies

1. Edit `policies/default_policies.json`
2. Add static/dynamic checks in `backend/app/services/prosecutor.py`
3. Test with sample code

### Contributing

See CONTRIBUTING.md for development guidelines.

## License

[To be determined]

## References

- ACPG Design Document
- OWASP Top 10
- NIST 800-218 (Secure Software Development Framework)
- Dung's Abstract Argumentation Framework
