# Current Priorities

Last refreshed: **February 11, 2026**

## Immediate Priorities

1. Runtime policy compiler
- Expand beyond tool allow/deny into policy checks over runtime events.
- Define runtime policy schema and evaluator with deterministic outputs.

2. Runtime enforcement levels
- Add `deny`, `require_approval`, and `allow_with_monitoring` outcomes.
- Ensure each outcome is captured as evidence and adjudication input.

3. Dynamic analysis safety
- Implement sandboxed execution for dynamic tests.
- Record deterministic dynamic-analysis evidence in proof bundles.

4. Solver-path maturity
- Improve stable/preferred observability and failure reporting.
- Plan support for joint attacks in solver-backed semantics.

5. Policy lifecycle and governance
- Better versioning, auditability, and controlled rollout for policy changes.

## Recently Completed

- Responses-first LLM integration with fallback path
- AUTO grounded semantics behavior
- Joint attacks in grounded engine
- LangGraph runtime trace propagation
- Runtime guard -> violation flow
- CI stability fixes and passing checks

## Quality Gate

Maintain green on:
- `ruff check`
- `pytest -q`
- frontend lint/build
- GitHub Actions full workflow
