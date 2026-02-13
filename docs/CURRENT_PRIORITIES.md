# Current Priorities

Last refreshed: **February 13, 2026**

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

1. [x] API authorization hardening baseline for UI work
- Extend RBAC coverage to policy CRUD/groups, LLM management, and LangGraph orchestration routes.
- Validate tenant-scoped role behavior for read vs write operations in integration tests.

2. [ ] UI modernization sprint kickoff
- [x] Improve model management forms and diagnostics for provider status/offline behavior.
- [ ] Expand policy/group UX (rollout preview readability, write-operation affordances).
- [ ] Add graph/runtime evidence visualizations tuned for compliance review workflows.

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
- Compliance trend analytics endpoint + history sidebar KPI panel
- CI workflow compliance artifacts (clean adjudication + trend snapshots)
- Configurable CI compliance gate profiles with enforce/monitor modes
- Tenant-scoped API key RBAC foundation (roles + tenant-bound keys + auth routes)
- Permission-gated core APIs + tenant-scoped history/trend visibility
- Database operational diagnostics + pooled connection hardening defaults
- LangGraph runtime trace propagation
- Runtime guard -> violation flow
- Kimi non-streaming remediation fix (safe output token caps)
- Safety tool installed by default in backend requirements
- Startup/status probe stability improvements
- Model management UX refresh (provider health filters, persistent diagnostics, test latency/cost snapshots, clearer edit controls)

## Quality Gate

Maintain green on:
- `ruff check`
- `pytest -q`
- frontend lint/build
- GitHub Actions full workflow
