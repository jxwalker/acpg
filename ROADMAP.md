# ACPG Roadmap (Refreshed February 13, 2026)

## Vision

Provide provable policy compliance for AI-generated code and agent behavior, with evidence suitable for high-assurance and regulated environments.

## Completed Foundations

- Multi-agent flow: Generator, Prosecutor, Adjudicator, Proof Assembler
- Policy-as-code with default + OWASP + NIST + JS/TS coverage
- Responses-first OpenAI integration with fallback behavior
- Formal adjudication with grounded semantics
- Semantics support: grounded, auto, stable, preferred (with explicit fallback behavior)
- Joint attacks (Nielsen-Parsons style) in grounded computation
- Signed proof bundles with evidence and argumentation trace
- LangGraph orchestration with runtime event trace
- Runtime guard policy-to-violation flow for tool actions
- Runtime policy compiler for tool/network/filesystem classes
- Graded runtime controls: deny / require-approval / allow-with-monitoring
- Runtime policy outcomes linked into trace + proof evidence
- Sandboxed dynamic analysis (Python) with timeout/resource limits
- Deterministic dynamic replay artifacts linked into proof evidence
- Deterministic dynamic suite coverage (direct/import/entrypoint execution)
- Dynamic replay artifact history index for audit/CI queries
- Proof argumentation evidence-channel linkage for runtime + dynamic signals
- Compliance history trend analytics (API + UI summary panels)
- CI compliance artifacts (clean adjudication + trend snapshot publication)
- Configurable CI compliance gate profiles (strict/monitor) with threshold enforcement
- Tenant-scoped API key RBAC foundation (roles + tenant-bound keys + auth routes)
- Permission-gated core APIs + tenant-scoped history/audit views
- Permission-gated policy/LLM/LangGraph management APIs
- Database operational diagnostics + pooled connection hardening defaults
- Solver-backed joint-attack semantics for stable/preferred (ASP/clingo)
- Deterministic solver decision modes (`auto` -> skeptical, `skeptical`, `credulous`)
- Policy version history and diff/audit support (API + UI)
- Policy-group rollout preview simulation against stored test cases
- Unified test code management: file samples + DB-backed CRUD test cases
- Bulk test-case import/export APIs with UI tag filtering workflows
- Analysis/enforcement timing telemetry and UI performance visibility
- CI pipeline covering lint/test/build/integration/docker

## Active Near-Term Priorities

1. UI readiness and operator workflows
- Improve model management UX (provider create/edit diagnostics and endpoint clarity)
- Expose richer runtime/dynamic evidence views and policy rollout insights
  - Completed: Formal proof UI now renders runtime-policy evidence with structured action/tool/rule details and explicit static-vs-runtime explanation.
- Expand cost and performance visualizations for regulated regression runs
  - Completed: Compliance panel now includes iteration diagnostics (per-iteration violations, phase latencies, fix outcome, average fix latency).

2. Demo coverage closure (UI + sample suite)
- Add runtime policy simulator UI for event-level allow/deny/monitor evaluation (`/api/v1/runtime/policies/evaluate`)
- Add LangGraph live-stream trace viewer (`/api/v1/langgraph/enforce/stream`, `/api/v1/langgraph/visualize`)
- Add batch test-case runner UI for stored suites (`/api/v1/analyze/batch`)
- Add proof registry + signer public-key inspector (`/api/v1/proofs`, `/api/v1/proof/public-key`)
- Add dynamic artifact explorer in history (`/api/v1/history/dynamic-artifacts`)
- Expand sample suite with semantics-focused and runtime-focused demo cases

## Medium-Term Priorities

- Multi-tenant authn/authz and key management hardening
- PostgreSQL + operational reliability improvements
- Compliance reporting and trend analytics
- Rich CI integrations with policy gates and artifact publication

## Sample Suite Roadmap

- `12_tool_demo.py`: tool mapping + unmapped findings workflow (metadata-rich dropdown support)
- Add `13_semantics_stable_vs_grounded.py`: scenario with competing extensions to illustrate skeptical semantics
- Add `14_joint_attack_nelson_parsons.py`: joint-attack policy conflict example for Nielsen-Parsons reasoning
- Add `15_runtime_policy_events.py`: agent/tool/network/filesystem runtime event simulation target
- Add `16_dynamic_analysis_replay.py`: deterministic replay artifact and runtime-safety evidence path

## Success Criteria

- Deterministic compliance decisions for safety-critical flows
- Complete traceability from event -> violation -> argumentation -> signed proof
- Operationally reliable pipeline in CI and runtime orchestration
- Clear separation of static, runtime, and dynamic evidence channels
