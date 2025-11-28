# ACPG Quick Start

## What is ACPG?

**Agentic Compliance and Policy Governor** - An automated system that checks code for policy violations, automatically fixes them using AI, and produces cryptographically-signed proof certificates.

## Project Status: Foundation Complete ✅

The project structure, core infrastructure, and design documents are ready. The next phase is implementing the service layer.

## What's Been Built

### ✅ Ready to Use
- Project structure with clean architecture
- 20+ Pydantic data models for type safety
- Cryptographic signing utilities (ECDSA)
- Configuration management system
- 8 default security policies (JSON format)
- Comprehensive documentation

### ⏳ To Implement
- Policy compiler service
- Static analysis (Bandit integration)
- AI code generator (OpenAI)
- Argumentation engine (adjudicator)
- Proof assembler
- FastAPI REST API
- React frontend UI

## Directory Structure

```
acpg/
├── backend/
│   ├── app/
│   │   ├── models/schemas.py    ✅ Data models
│   │   ├── core/config.py       ✅ Configuration
│   │   ├── core/crypto.py       ✅ Signatures
│   │   ├── services/            ⏳ To implement
│   │   └── api/                 ⏳ To implement
│   ├── requirements.txt         ✅ Dependencies
│   └── .env.example             ✅ Config template
├── policies/
│   └── default_policies.json    ✅ 8 policies
└── docs/                        ✅ Design PDFs
```

## Quick Commands

### Setup (5 minutes)
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Add your OpenAI API key to .env
```

### Next Steps for Development
```bash
# 1. Implement policy compiler
# 2. Implement prosecutor (Bandit integration)
# 3. Implement generator (OpenAI)
# 4. Implement adjudicator (formal logic)
# 5. Create FastAPI app with endpoints
# 6. Build React UI
```

## The Three Agents

1. **Generator** (AI) - Creates/fixes code
   - Uses OpenAI GPT-4
   - Policy-aware code generation
   - Iterative refinement

2. **Prosecutor** (Security Scanner) - Finds violations
   - Bandit for static analysis
   - Regex pattern matching
   - Dynamic testing (Hypothesis)

3. **Adjudicator** (Logic Engine) - Makes decisions
   - Formal argumentation framework
   - Grounded semantics
   - Explainable decisions

## Policy Examples

```json
{
  "id": "SEC-001",
  "description": "No hardcoded credentials",
  "type": "strict",
  "severity": "high",
  "check": {
    "type": "regex",
    "pattern": "(?i)(password\\s*=\\s*['\"])"
  }
}
```

## The Compliance Loop

```
Code Input
    ↓
[Generator] → Creates code
    ↓
[Prosecutor] → Finds violations
    ↓
[Adjudicator] → Compliant? → YES → [Proof Bundle] ✅
                    ↓ NO
                [Feedback to Generator] ↻
```

## Key Files to Understand

1. **schemas.py** - All data structures
   - PolicyRule, Violation, ProofBundle, etc.
   - Type-safe API contracts

2. **default_policies.json** - 8 ready policies
   - No secrets, SQL injection, crypto, etc.
   - Easy to add more

3. **crypto.py** - Digital signatures
   - ECDSA signing/verification
   - SHA-256 hashing

4. **config.py** - All settings
   - Environment variables
   - OpenAI configuration
   - Compliance settings

## Implementation Priority

### Phase 1 (Core Services)
1. Policy compiler - Load JSON policies
2. Prosecutor - Bandit + regex checks
3. Generator - OpenAI integration
4. Adjudicator - Simple pass/fail first
5. Proof assembler - Bundle + sign

### Phase 2 (API & UI)
6. FastAPI endpoints
7. React frontend
8. Integration tests

### Phase 3 (Advanced)
9. Formal argumentation logic
10. Defeasible rules support
11. Dynamic testing
12. CLI tool

## Example Usage (When Complete)

```python
# Check compliance
POST /api/v1/analyze
{
  "code": "def login(pwd): password = 'secret123'",
  "language": "python"
}

# Response: violations found
{
  "violations": [
    {
      "rule_id": "SEC-001",
      "description": "Hardcoded credential",
      "line": 1
    }
  ]
}

# Auto-fix
POST /api/v1/enforce
{
  "code": "...",
  "max_iterations": 3
}

# Response: fixed + proof
{
  "final_code": "...",
  "compliant": true,
  "proof_bundle": { signed certificate }
}
```

## Design Highlights

- **Formal Logic**: Uses argumentation theory (Dung's framework)
- **Proof-Carrying**: Like proof-carrying code but for compliance
- **Crypto-Signed**: Tamper-evident certificates
- **Explainable**: Every decision has a trace
- **Iterative**: Auto-fixes until compliant

## Resources

- `README.md` - Full user documentation
- `SETUP.md` - Developer setup guide
- `PROJECT_SUMMARY.md` - Complete overview
- `ACPG_Design.pdf` - Detailed design doc
- `ACPG Prototype Development Guide.pdf` - Implementation details

## Contact

See design documents in project root for complete technical specifications.

---

**Ready to implement?** Start with the policy compiler service!
