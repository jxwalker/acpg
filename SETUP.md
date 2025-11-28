# ACPG Setup Guide

## Project Structure Created

The ACPG project has been initialized with the following structure:

```
acpg/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── api/              # FastAPI endpoint definitions (to be implemented)
│   │   ├── core/             # Configuration and utilities
│   │   │   ├── config.py     # Settings management
│   │   │   └── crypto.py     # Digital signature utilities
│   │   ├── models/           # Pydantic data models
│   │   │   └── schemas.py    # Request/response schemas
│   │   └── services/         # Business logic (to be implemented)
│   │       ├── policy_compiler.py    # Load and parse policy rules
│   │       ├── generator.py          # AI code generator (OpenAI)
│   │       ├── prosecutor.py         # Static/dynamic analysis
│   │       ├── adjudicator.py        # Argumentation engine
│   │       └── proof_assembler.py    # Proof bundle generation
│   ├── .env.example          # Environment variable template
│   ├── requirements.txt      # Python dependencies
│   └── main.py               # FastAPI application (to be created)
├── frontend/
│   └── src/                  # React application (to be implemented)
├── policies/
│   └── default_policies.json # Sample policy rules (8 policies included)
├── tests/                    # Test files (to be implemented)
├── .gitignore
└── README.md
```

## Next Steps for Implementation

### Phase 1: Policy Compiler Service
Create `backend/app/services/policy_compiler.py`:
- Load policies from JSON
- Parse and validate policy rules
- Support for strict and defeasible rules

### Phase 2: Prosecutor Service
Create `backend/app/services/prosecutor.py`:
- Integrate Bandit for Python security scanning
- Implement regex-based pattern matching
- Generate violation reports

### Phase 3: Generator Service
Create `backend/app/services/generator.py`:
- OpenAI API integration
- Code generation with policy awareness
- Code fixing based on violations

### Phase 4: Adjudicator Service
Create `backend/app/services/adjudicator.py`:
- Build argumentation graph
- Implement grounded semantics
- Resolve compliance decisions

### Phase 5: Proof Assembler Service
Create `backend/app/services/proof_assembler.py`:
- Compile proof bundles
- Digital signing integration
- Audit logging

### Phase 6: FastAPI Application
Create `backend/main.py` and `backend/app/api/` endpoints:
- `/policies` - Policy management
- `/analyze` - Run compliance checks
- `/generate` - Generate code
- `/adjudicate` - Make decisions
- `/enforce` - Full compliance loop
- `/proof` - Generate signed proofs

### Phase 7: Frontend
Implement React UI in `frontend/src/`:
- Code editor component
- Compliance results display
- Proof visualization
- Auto-fix functionality

## Installation Instructions

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Dependencies Installed

- **FastAPI**: Web framework
- **OpenAI**: AI code generation
- **Bandit**: Security scanning
- **Cryptography**: Digital signatures
- **Pydantic**: Data validation
- **Pytest**: Testing framework

## Configuration

Edit `backend/.env`:

```env
OPENAI_API_KEY=sk-...your-key-here...
OPENAI_MODEL=gpt-4
MAX_FIX_ITERATIONS=3
```

## Policy Rules

The system includes 8 default policies in `policies/default_policies.json`:

1. **SEC-001**: No hardcoded credentials
2. **SEC-002**: Don't log sensitive information
3. **INPUT-001**: Validate user inputs (defeasible)
4. **SEC-003**: No eval/exec functions
5. **SEC-004**: Use HTTPS not HTTP
6. **ERR-001**: Proper exception handling
7. **SQL-001**: Use parameterized SQL queries
8. **CRYPTO-001**: No weak cryptography (MD5/SHA1)

## Testing

Once implementation is complete:

```bash
pytest tests/
```

## Development Workflow

1. Implement services one by one (following phases above)
2. Create unit tests for each service
3. Implement FastAPI endpoints
4. Test end-to-end with sample code
5. Build React frontend
6. Integration testing

## Key Design Decisions

- **Multi-agent architecture**: Generator, Prosecutor, Adjudicator
- **Formal logic**: Structured argumentation with grounded semantics
- **Proof-carrying artifacts**: Cryptographically signed compliance certificates
- **Policy-as-code**: JSON-based policy definitions
- **Iterative refinement**: Auto-fix loop until compliant

## Resources

- Design documents in project root (ACPG_Design.pdf, ACPG Prototype Development Guide.pdf)
- OWASP Top 10 for policy ideas
- NIST 800-218 for secure development practices

## Support

For implementation questions, refer to the comprehensive design documentation provided in the project directory.
