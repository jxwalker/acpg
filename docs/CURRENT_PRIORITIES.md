# Current Priorities

Last refreshed: **February 12, 2026**

## Active Delivery Checklist

1. [x] Performance diagnostics for slow analyses/enforcement (e.g., sample 9)
- Add backend timing breakdowns for tool phase, policy phase, adjudication, and total.
- Add UI visibility for timing and LLM latency/cost per run.
- Reduce avoidable overhead in tool execution path.

2. [x] Semantics expansion in API + UI
- Expose `stable` and `preferred` options in addition to `grounded` and `auto`.
- Keep conservative compliance behavior explicit for regulated use (skeptical decisioning).
- Surface fallback/solver availability details in reasoning output.

3. [x] Test code management system (CRUD + DB)
- Add DB-backed test case storage (create/read/update/delete).
- Keep file-based sample loading as a first-class source.
- Provide a unified API + UI loader for both DB and file test code.

4. [x] UX correctness fixes
- Fix status card so it does not show "Ready to Analyze" while analysis/enforcement is running.
- Fix test-case dropdown so click-away always closes it.

5. [x] Cost testing in UI
- Ensure provider test and run results expose token usage and estimated cost where pricing metadata is available.
- Keep cost fields editable in model configuration.

6. [x] Runtime policy compiler (MVP)
- Add compiled runtime policy evaluation for `tool` / `network` / `filesystem` events.
- Support graded actions: `deny`, `require_approval`, `allow_with_monitoring`.
- Feed runtime policy outcomes into runtime trace and proof evidence.

## Next Up

1. [x] Dynamic analysis coverage expansion
- Add deterministic dynamic policy suites beyond direct execution smoke checks. (MVP complete)
- Expand replay artifact indexing and UX for audit workflows. (Index API + history badges complete)
- Formal linkage of dynamic/runtime evidence into proof argumentation narratives. (MVP complete)

2. [x] Policy lifecycle UX and test operations
- Better versioning and policy diff/audit views. (MVP complete)
- Safer rollout controls for policy updates. (Preview MVP complete)
- Bulk test-case import/export and tagging workflows for regulated regression suites. (MVP complete)

## Recently Completed

- Responses-first LLM integration with fallback path
- AUTO grounded semantics behavior
- Joint attacks in grounded engine
- Runtime policy compiler + graded runtime actions
- Runtime policy API endpoints (`/runtime/policies`, reload/evaluate)
- Sandboxed dynamic analyzer with timeout/resource limits
- Deterministic dynamic replay artifacts included in proofs
- Solver-backed joint-attack support for stable/preferred semantics
- Deterministic solver decision modes (`auto` -> skeptical, `skeptical`, `credulous`)
- Policy version history and diff API/UI for audit workflows
- Policy-group rollout preview impact analysis (API + UI)
- Bulk test-case import/export API + UI tagging filters for regression workflows
- Deterministic dynamic suite runner (direct/import/entrypoint)
- Dynamic replay artifact index endpoint + history UI badges
- Proof argumentation evidence-channel narratives for runtime + dynamic signals
- LangGraph runtime trace propagation
- Runtime guard -> violation flow
- Kimi non-streaming remediation fix (safe output token caps)
- Safety tool installed by default in backend requirements
- Startup/status probe stability improvements

## Quality Gate

Maintain green on:
- `ruff check`
- `pytest -q`
- frontend lint/build
- GitHub Actions full workflow
