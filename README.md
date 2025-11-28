# ACPG: Agentic Compliance and Policy Governor

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/React-18-61DAFB.svg" alt="React">
  <img src="https://img.shields.io/badge/FastAPI-0.104-009688.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/LangGraph-0.2-purple.svg" alt="LangGraph">
  <img src="https://img.shields.io/badge/Tests-52%20passing-brightgreen.svg" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

<p align="center">
  <strong>A multi-agent AI system that automatically analyzes, fixes, and certifies code for compliance with security policies.</strong>
</p>

---

## 🎯 What is ACPG?

ACPG implements a **"digital compliance courtroom"** with three specialized AI agents:

| Agent | Role | Technology |
|-------|------|------------|
| **🤖 Generator** | Writes and fixes code | GPT-4, Qwen2.5-Coder, Ollama |
| **🔍 Prosecutor** | Detects policy violations | Bandit, 40+ regex patterns |
| **⚖️ Adjudicator** | Makes compliance decisions | Dung's Argumentation Framework |

The system produces **cryptographically-signed proof bundles** that serve as tamper-evident compliance certificates.

## ✨ Key Features

- **🔄 Automated Compliance Loop** - Analyze → Fix → Verify → Certify
- **🧠 Multi-LLM Support** - OpenAI, local vLLM, Ollama
- **📜 38+ Security Policies** - OWASP, NIST, custom rules
- **🔐 Proof Bundles** - ECDSA-signed compliance certificates
- **⚡ LangGraph Orchestration** - Stateful agent workflows
- **🌐 REST API + Web UI** - FastAPI backend, React frontend
- **🐳 Docker Ready** - One-command deployment

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ACPG System                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│    ┌──────────┐      ┌────────────┐      ┌─────────────┐            │
│    │GENERATOR │ ───▶ │ PROSECUTOR │ ───▶ │ ADJUDICATOR │            │
│    │  (LLM)   │      │  (Bandit)  │      │  (Logic)    │            │
│    └────┬─────┘      └────────────┘      └──────┬──────┘            │
│         │                                        │                   │
│         │            ◀── Feedback ──             │                   │
│         │                                        │                   │
│         └───────────▶ PROOF BUNDLE ◀─────────────┘                   │
│                      (ECDSA Signed)                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Option 1: Local Development

```bash
# Clone the repository
git clone https://github.com/jxwalker/acpg.git
cd acpg

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure LLM (edit llm_config.yaml for local models)
# Or set OpenAI API key:
export OPENAI_API_KEY="sk-your-key"

# Start backend
uvicorn main:app --reload --port 8000

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev
```

### Option 2: Docker

```bash
docker-compose up -d
# Access at http://localhost:3000
```

## 🔧 LLM Configuration

ACPG supports multiple LLM providers. Configure in `backend/llm_config.yaml`:

```yaml
active_provider: local_vllm  # or: openai_gpt4, ollama_codellama

providers:
  local_vllm:
    base_url: "http://localhost:8001/v1"
    model: "Qwen/Qwen2.5-Coder-14B-Instruct-AWQ"
    max_tokens: 4096
    
  openai_gpt4:
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    model: "gpt-4"
```

Switch providers via API:
```bash
curl -X POST http://localhost:8000/api/v1/llm/switch \
  -H "Content-Type: application/json" \
  -d '{"provider_id": "openai_gpt4"}'
```

## 📖 Usage

### Web UI

1. Open http://localhost:3000
2. Paste code in the editor
3. Click **"Analyze"** to detect violations
4. Click **"Auto-Fix & Certify"** to fix and generate proof

### REST API

```python
import requests

# Analyze code
response = requests.post("http://localhost:8000/api/v1/analyze", json={
    "code": "password = 'secret123'",
    "language": "python"
})
print(response.json()["violations"])

# Full compliance enforcement
response = requests.post("http://localhost:8000/api/v1/enforce", json={
    "code": "password = 'secret123'",
    "language": "python",
    "max_iterations": 3
})
result = response.json()
print(f"Compliant: {result['compliant']}")
print(f"Proof Bundle: {result['proof_bundle']}")
```

### Command Line

```bash
# Check for violations
python cli.py check --input vulnerable.py

# Auto-fix and certify
python cli.py enforce --input vulnerable.py --output fixed.py --proof proof.json

# List all policies
python cli.py list-policies
```

### LangGraph API (Advanced)

```python
# Full agentic workflow with state management
response = requests.post("http://localhost:8000/api/v1/langgraph/enforce", json={
    "code": "password = 'secret'",
    "language": "python",
    "max_iterations": 3
})
# Returns detailed execution state with all agent outputs
```

## 📋 Policy Categories

| Category | Rules | Examples |
|----------|-------|----------|
| **Default Security** | 8 | Hardcoded secrets, SQL injection, eval() |
| **OWASP Top 10** | 10 | XSS, CSRF, broken authentication |
| **NIST 800-218** | 8 | Secure development practices |
| **JavaScript/TS** | 12 | DOM XSS, prototype pollution |
| **Total** | **38** | |

## 🔐 Proof Bundle Structure

```json
{
  "artifact": {
    "hash": "sha256:a1b2c3...",
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

## 🔌 API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/policies` | GET | List all policies |
| `/api/v1/analyze` | POST | Analyze code for violations |
| `/api/v1/adjudicate` | POST | Run argumentation engine |
| `/api/v1/fix` | POST | AI-fix specific violations |
| `/api/v1/enforce` | POST | Full compliance loop |
| `/api/v1/proof/generate` | POST | Generate proof bundle |
| `/api/v1/proof/verify` | POST | Verify proof signature |
| `/api/v1/llm/providers` | GET | List LLM providers |
| `/api/v1/llm/switch` | POST | Switch active LLM |
| `/api/v1/langgraph/enforce` | POST | LangGraph workflow |

## 🧪 Testing

```bash
cd backend
pytest tests/ -v

# Output:
# 52 passed in 2.13s
```

## 📁 Project Structure

```
acpg/
├── backend/
│   ├── app/
│   │   ├── api/          # FastAPI routes
│   │   ├── core/         # Config, crypto, auth
│   │   ├── models/       # Pydantic schemas
│   │   ├── orchestration/# LangGraph workflow
│   │   └── services/     # Business logic
│   ├── main.py           # FastAPI app
│   ├── cli.py            # CLI tool
│   └── llm_config.yaml   # LLM configuration
├── frontend/             # React UI
├── policies/             # JSON policy files
├── tests/                # Test suite
├── demo/                 # Demo files
└── docker-compose.yml
```

## 🔬 The Three Agents

### 1. Generator Agent
- Uses configurable LLMs (GPT-4, Qwen, Ollama)
- Generates policy-aware code from specifications
- Fixes violations based on prosecutor feedback
- Explains all changes made

### 2. Prosecutor Agent
- **Bandit** - Python security linter
- **40+ regex patterns** - Custom policy rules
- Generates detailed violation reports with evidence

### 3. Adjudicator Engine
- **Dung's Argumentation Framework** - Formal logic
- **Grounded Semantics** - Minimal defensible extensions
- Handles strict vs. defeasible rules
- Produces formal compliance decisions

## 🔒 Security Notes

- API keys are loaded from environment variables
- Proof signatures use ECDSA-SHA256
- Keys can be ephemeral or persistent (configurable)
- Rate limiting protects against abuse
- Audit logs track all compliance decisions

## 🛣️ Roadmap

See [ROADMAP.md](./ROADMAP.md) for planned features:
- [ ] VS Code extension
- [ ] GitHub PR integration
- [ ] Team workspaces
- [ ] Custom policy editor
- [ ] Compliance dashboards

## 📄 License

MIT License - See [LICENSE](./LICENSE) file for details.

## 📚 References

- [Dung's Abstract Argumentation Framework](https://en.wikipedia.org/wiki/Argumentation_framework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST 800-218 SSDF](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)
- [Proof-Carrying Code](https://en.wikipedia.org/wiki/Proof-carrying_code)

---

<p align="center">
  <strong>Built for secure, compliant software development</strong><br>
  <a href="https://github.com/jxwalker/acpg">GitHub</a> •
  <a href="./SETUP.md">Setup Guide</a> •
  <a href="./demo/PATENT_DEMO.md">Demo</a>
</p>
