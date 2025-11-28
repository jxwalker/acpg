# ACPG Project Summary

## 🎯 Project Status: Production Ready

**ACPG (Agentic Compliance and Policy Governor)** is a complete automated compliance system implementing a "digital compliance courtroom" with three AI agents that analyze, fix, and certify code against security policies.

## ✅ Implemented Features

### Core Agent Architecture
| Agent | Description | Implementation |
|-------|-------------|----------------|
| **Generator** | AI-powered code generation and fixing | OpenAI GPT-4, Local vLLM (Qwen2.5-Coder) |
| **Prosecutor** | Static analysis and violation detection | Bandit + 40+ regex patterns |
| **Adjudicator** | Formal logic compliance decisions | Dung's Argumentation Framework |
| **Proof Assembler** | Cryptographic certification | ECDSA-SHA256 signatures |

### Backend Services
- ✅ **Policy Compiler** - Loads and validates 38+ security rules
- ✅ **Prosecutor Service** - Static analysis with Bandit + regex
- ✅ **Generator Service** - AI code generation/fixing
- ✅ **Adjudicator Engine** - Grounded semantics argumentation
- ✅ **Proof Assembler** - Signed compliance certificates
- ✅ **LangGraph Orchestration** - Agentic workflow management

### Infrastructure
- ✅ **FastAPI Backend** - Full REST API with 15+ endpoints
- ✅ **React Frontend** - Modern UI with Monaco editor
- ✅ **SQLite Database** - Audit logs and proof storage
- ✅ **API Key Authentication** - Secure access control
- ✅ **Rate Limiting** - Token bucket algorithm
- ✅ **Structured Logging** - JSON format for observability
- ✅ **Webhooks** - Event notifications
- ✅ **Docker/Compose** - Containerized deployment
- ✅ **GitHub Actions CI** - Automated testing

### LLM Support
- ✅ **OpenAI GPT-4/3.5** - Cloud-based models
- ✅ **Local vLLM** - Self-hosted models (Qwen2.5-Coder)
- ✅ **Ollama** - Local model runner
- ✅ **Multi-provider Config** - Hot-swappable backends

### Policy Coverage
| Category | Policies | Examples |
|----------|----------|----------|
| Default Security | 8 rules | Hardcoded secrets, SQL injection, eval |
| OWASP Top 10 | 10 rules | XSS, CSRF, broken auth |
| NIST 800-218 | 8 rules | Secure development practices |
| JavaScript/TS | 12 rules | DOM XSS, prototype pollution |
| **Total** | **38 rules** | |

### Testing
- ✅ 52 unit tests passing
- ✅ API endpoint tests
- ✅ Service integration tests
- ✅ LangGraph workflow tests

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ACPG System                                    │
│                  Agentic Compliance and Policy Governor                  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │                          │                          │
    ┌────▼─────┐            ┌───────▼───────┐          ┌──────▼──────┐
    │GENERATOR │            │  PROSECUTOR   │          │ ADJUDICATOR │
    │  Agent   │            │    Agent      │          │   Engine    │
    │          │            │               │          │             │
    │ OpenAI   │            │   Bandit +    │          │  Grounded   │
    │ GPT-4 /  │◀──────────▶│   Regex +     │─────────▶│  Semantics  │
    │ Qwen2.5  │  Feedback  │   38 Rules    │ Evidence │  Framework  │
    └────┬─────┘            └───────────────┘          └──────┬──────┘
         │                                                     │
         │                  ┌────────────────┐                 │
         └─────────────────▶│ PROOF ASSEMBLER│◀────────────────┘
                            │   + Crypto     │
                            │   ECDSA-256    │
                            └───────┬────────┘
                                    │
                           ┌────────▼────────┐
                           │  SIGNED PROOF   │
                           │     BUNDLE      │
                           │                 │
                           │ • Artifact Hash │
                           │ • Policy Results│
                           │ • Evidence      │
                           │ • Signature     │
                           └─────────────────┘
```

## 📁 Complete File Structure

```
acpg/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes.py           # Core API endpoints
│   │   │   ├── langgraph_routes.py # LangGraph workflow API
│   │   │   └── llm_routes.py       # LLM management API
│   │   ├── core/
│   │   │   ├── config.py           # Settings management
│   │   │   ├── crypto.py           # ECDSA signatures
│   │   │   ├── database.py         # SQLAlchemy models
│   │   │   ├── auth.py             # API key authentication
│   │   │   ├── key_manager.py      # Persistent key storage
│   │   │   ├── rate_limit.py       # Request throttling
│   │   │   ├── logging.py          # Structured JSON logs
│   │   │   ├── webhooks.py         # Event notifications
│   │   │   └── llm_config.py       # Multi-provider LLM config
│   │   ├── models/
│   │   │   └── schemas.py          # 20+ Pydantic models
│   │   ├── orchestration/
│   │   │   ├── state.py            # LangGraph state
│   │   │   ├── nodes.py            # Agent node functions
│   │   │   └── graph.py            # Workflow graph definition
│   │   └── services/
│   │       ├── policy_compiler.py  # Policy loading/validation
│   │       ├── prosecutor.py       # Static analysis
│   │       ├── generator.py        # AI code generation
│   │       ├── adjudicator.py      # Argumentation engine
│   │       └── proof_assembler.py  # Proof bundle creation
│   ├── main.py                     # FastAPI application
│   ├── cli.py                      # Command-line interface
│   ├── llm_config.yaml             # LLM provider configuration
│   └── requirements.txt            # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── App.tsx                 # Main React component
│   │   ├── api.ts                  # API client
│   │   └── types.ts                # TypeScript definitions
│   ├── index.html
│   └── package.json
├── policies/
│   ├── default_policies.json       # Core security rules
│   ├── owasp_policies.json         # OWASP Top 10
│   ├── nist_policies.json          # NIST 800-218
│   └── javascript_policies.json    # JS/TS specific
├── tests/
│   ├── test_api.py
│   ├── test_prosecutor.py
│   ├── test_adjudicator.py
│   ├── test_crypto.py
│   ├── test_langgraph.py
│   └── test_policy_compiler.py
├── demo/
│   ├── vulnerable_code.py          # Example vulnerable code
│   ├── compliant_code.py           # Example compliant code
│   ├── fixed_by_qwen.py            # AI-fixed code sample
│   └── PATENT_DEMO.md              # Demo instructions
├── .github/
│   └── workflows/ci.yml            # GitHub Actions
├── Dockerfile
├── docker-compose.yml
├── README.md
├── SETUP.md
└── PROJECT_SUMMARY.md
```

## 🔑 Key Innovations (Patent Claims)

1. **Multi-Agent Compliance Architecture**
   - Three specialized agents (Generator, Prosecutor, Adjudicator)
   - Clear separation of concerns with defined interfaces
   - Iterative refinement loop with feedback

2. **Formal Argumentation for Compliance**
   - Dung's Abstract Argumentation Framework
   - Grounded semantics for minimal defensible extensions
   - Handles strict vs. defeasible policy rules

3. **Proof-Carrying Code Artifacts**
   - Cryptographically-signed compliance certificates
   - Tamper-evident proof bundles
   - Machine-readable compliance evidence

4. **Policy-as-Code System**
   - JSON-based policy definitions
   - Executable checks with regex patterns
   - Extensible rule categories

5. **Agentic LLM Orchestration**
   - LangGraph-based workflow management
   - Configurable LLM backends (cloud/local)
   - Stateful compliance refinement

## 🚀 Quick Start Commands

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev

# CLI
python backend/cli.py check --input code.py
python backend/cli.py enforce --input code.py --output fixed.py --proof proof.json

# Tests
pytest tests/ -v
```

## 📊 Test Results

```
52 passed in 2.13s

Coverage:
- Policy Compiler: 100%
- Prosecutor: 100%
- Adjudicator: 100%
- Crypto: 100%
- API Endpoints: 100%
- LangGraph: 100%
```

## 🎯 Demo Capabilities

1. **Vulnerability Detection** - Detects 11 security violations in sample code
2. **AI Auto-Fix** - Qwen2.5-Coder fixes 9/11 violations automatically
3. **Formal Adjudication** - Argumentation-based compliance decisions
4. **Proof Generation** - ECDSA-signed compliance certificates
5. **Iterative Refinement** - Up to 3 fix iterations

---

**Project Status**: ✅ Production Ready  
**Last Updated**: November 2024  
**Repository**: https://github.com/jxwalker/acpg
