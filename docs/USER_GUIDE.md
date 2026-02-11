# ACPG User Guide

Last refreshed: **February 11, 2026**

## What ACPG Produces

For each run, ACPG can produce:
- violations and mapped findings,
- adjudication output (compliant/non-compliant with reasoning),
- optional auto-fixed code,
- a signed proof bundle,
- runtime trace evidence for LangGraph workflows.

## Main Workflows

### 1) Analyze Code

1. Open UI and paste code.
2. Run **Analyze**.
3. Review:
- violation list,
- tool execution metadata,
- unmapped findings,
- adjudication result.

API equivalent:

```bash
curl -X POST http://localhost:6000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"code":"password = \"secret123\"","language":"python"}'
```

### 2) Enforce Compliance (Auto-fix loop)

Use **Enforce** to run analyze -> adjudicate -> fix iteration.

API:

```bash
curl -X POST http://localhost:6000/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{"code":"password = \"secret123\"","language":"python","max_iterations":3,"semantics":"auto"}'
```

### 3) LangGraph Runtime Flow

Use graph orchestration when you need runtime event traces:

```bash
curl -X POST http://localhost:6000/api/v1/graph/enforce \
  -H "Content-Type: application/json" \
  -d '{"code":"password = \"secret123\"","language":"python","max_iterations":3,"semantics":"auto"}'
```

Response includes `runtime_events`, `messages`, and optional `proof_bundle`.

## Semantics

- `grounded`: deterministic skeptical decision basis.
- `auto`: grounded decision + optional secondary stable/preferred evidence (when solver available).

Recommendation for regulated use cases: use `auto` or `grounded`, where final decision remains grounded.

## Runtime Guard Behavior

Runtime guard evaluates tool actions against allow/deny policy.

If denied:
- execution metadata records a policy decision,
- prosecutor emits a formal runtime violation,
- adjudicator includes it in compliance decision.

## Proof Bundles

Proof bundles include:
- artifact metadata and code hash,
- policy outcomes,
- evidence list,
- argumentation trace,
- signature metadata.

For LangGraph flows, runtime trace evidence is included as `RUNTIME` evidence.

## Verification

```bash
curl -X POST http://localhost:6000/api/v1/proof/verify \
  -H "Content-Type: application/json" \
  -d @verify_request.json
```

## LLM Provider Management

- List providers: `GET /api/v1/llm/providers`
- Switch provider: `POST /api/v1/llm/switch`
- Test provider: `POST /api/v1/llm/test`

OpenAI-compatible calls are Responses-first with fallback logic.

## Troubleshooting

1. Check health:

```bash
curl http://localhost:6000/api/v1/health
```

2. Check tool installation:

```bash
which bandit
which safety
```

3. Run tests locally:

```bash
pytest -q
```
