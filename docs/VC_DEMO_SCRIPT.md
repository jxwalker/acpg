# ACPG VC Demo Script

Target duration: **5-7 minutes live demo** + Q&A

Prerequisites: backend running on port 6000, frontend on port 5173, `OPENAI_API_KEY` set.

---

## Act 1: The Problem (30 seconds)

**Talking point:** "AI agents are writing more code than ever. But in regulated environments — fintech, healthcare, defense — you can't ship code that's *probably* compliant. You need *provably* compliant. That's what ACPG does."

---

## Act 2: Submit Vulnerable Code (1 minute)

Open the UI at `http://localhost:5173`.

Paste this code (or use the pre-loaded sample):

```python
def login(username, password_input):
    password = "supersecret123"
    api_key = "sk-prod-abc123xyz"
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    result = eval(password_input)
    import hashlib
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    return authenticate(username, password)
```

Click **Analyze**. Walk through the violations:
- "ACPG detected 5+ violations instantly — hardcoded secrets, SQL injection, dangerous eval, weak crypto."
- "Each violation maps to a specific policy: SEC-001, SQL-001, SEC-003, CRYPTO-001."
- "These aren't just regex matches — we run Bandit, map tool findings to formal policies, and show evidence."

---

## Act 3: Formal Adjudication (1 minute)

Click **Enforce** (or use the Adjudicate button).

**Talking point:** "Now here's what makes us different. We don't just flag issues — we *formally adjudicate* compliance using abstract argumentation theory."

Walk through the adjudication result:
- "Each violation becomes a formal *argument* in an argumentation framework."
- "Arguments can *attack* each other — a defeasible exception can override a strict rule."
- "We compute the *grounded extension* — the unique, deterministic set of acceptable arguments."
- "The decision is `non-compliant` with full reasoning traces. This isn't a confidence score — it's a formal proof."

---

## Act 4: Auto-Fix Loop (1 minute)

Show the auto-fix cycle:
- "ACPG uses LLM-powered code generation to fix violations automatically."
- "It iterates: fix → re-analyze → re-adjudicate → until compliant or stagnation."

Show the fixed code in the diff viewer:
- Secrets moved to `os.environ`
- Parameterized SQL queries
- `eval` replaced with safe parsing
- MD5 replaced with SHA-256

**Talking point:** "The fix isn't just stylistic — each fix is re-analyzed against the same formal policies to confirm compliance."

---

## Act 5: The Proof Bundle (1.5 minutes — this is the money shot)

Click the **Proof** tab. Walk through the signed proof bundle:

```
"This is a proof-carrying artifact. Let me show you what's inside:"
```

1. **Artifact metadata** — code hash, language, timestamp
2. **Policy outcomes** — every policy checked, with pass/fail/waived status
3. **Evidence chain** — every detection finding with tool metadata, line numbers, confidence
4. **Argumentation trace** — the full attack graph and grounded extension
5. **Digital signature** — ECDSA-SHA256, verifiable with our public key endpoint

**Talking point:** "This proof bundle is cryptographically signed. You can verify it hasn't been tampered with. You can store it for audit. You can attach it to a PR, a deployment, a regulatory filing. *This is compliance you can prove.*"

Demo the verification:
```bash
curl -X POST http://localhost:6000/api/v1/proof/verify \
  -H "Content-Type: application/json" \
  -d '{"proof_bundle": <paste bundle>}'
```

---

## Act 6: Differentiators (1 minute)

**Slide or talking points:**

| Capability | Snyk / Semgrep | ACPG |
|---|---|---|
| Static analysis | Yes | Yes (Bandit, ESLint, Safety) |
| AI-powered fixes | Limited | Full iterative fix loop |
| Formal compliance decision | No (heuristic) | Yes (argumentation semantics) |
| Cryptographic proof | No | ECDSA-signed bundles |
| Runtime guard | No | Allow/deny/monitor/approval |
| Defeasible policies | No | Yes (policy exceptions) |
| Multi-semantics | No | Grounded/stable/preferred |
| Audit trail | Basic | Full version history + diffs |
| CI compliance gate | Partial | Configurable profiles |
| LangGraph orchestration | No | Native integration |

**Key message:** "Existing tools tell you what's wrong. ACPG proves what's right — with formal methods, cryptographic signatures, and complete evidence chains. That's the difference between a scan report and a compliance certificate."

---

## Act 7: Scale & Roadmap (30 seconds)

- 39 policies across OWASP, NIST, and custom catalogs
- 80+ API endpoints, 124 passing tests
- Docker deployment, CI/CD integration, multi-tenant RBAC
- Multi-provider LLM support (OpenAI, Anthropic, compatible APIs)
- Roadmap: expanded language coverage, enterprise auth, compliance reporting dashboards

---

## CLI Demo Alternative

If the audience prefers a CLI demo:

```bash
# 1. Analyze vulnerable code
curl -X POST http://localhost:6000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"secret123\"\nquery = \"SELECT * FROM users WHERE name = '\" + name + \"'\"", "language": "python"}'

# 2. Full enforce loop (analyze → adjudicate → fix → prove)
curl -X POST http://localhost:6000/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"secret123\"", "language": "python", "max_iterations": 3}'

# 3. Verify the proof
curl -X POST http://localhost:6000/api/v1/proof/verify \
  -H "Content-Type: application/json" \
  -d '{"proof_bundle": ...}'

# 4. Check public key
curl http://localhost:6000/api/v1/proof/public-key
```

---

## Anticipated VC Questions & Answers

**Q: Who's the buyer?**
A: CISO and engineering leads at regulated companies. Secondary: compliance officers needing audit artifacts.

**Q: Why not just use Snyk/Semgrep?**
A: They tell you what's wrong. We prove what's right. In regulated environments, the difference between a scan report and a formal compliance certificate is the difference between "we checked" and "we can prove it."

**Q: How does the formal methods approach help?**
A: Determinism. Same code + same policies = same decision, every time. No false confidence scores. Auditors get a mathematical proof, not a probability. Defeasible policies mean real-world exceptions are modeled formally, not hacked around.

**Q: What about language coverage?**
A: Python and JavaScript/TypeScript today with full static analysis. The architecture is language-agnostic — adding Go, Java, Rust is a policy + tool integration exercise, not a rewrite.

**Q: What's the competitive moat?**
A: The argumentation engine and proof system. Abstract argumentation theory, joint attacks, solver-backed semantics, and cryptographic proof bundles are not features you bolt on — they're architectural. We have 18+ months of formal methods engineering built in.

**Q: Can this run in CI?**
A: Yes. GitHub Actions pipeline included. Configurable compliance gate profiles (strict/monitor) with artifact publication. Drop it into any CI system with a curl command.
