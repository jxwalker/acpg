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
- Expand cost and performance visualizations for regulated regression runs

## Medium-Term Priorities

- Multi-tenant authn/authz and key management hardening
- PostgreSQL + operational reliability improvements
- Compliance reporting and trend analytics
- Rich CI integrations with policy gates and artifact publication

## Success Criteria

- Deterministic compliance decisions for safety-critical flows
- Complete traceability from event -> violation -> argumentation -> signed proof
- Operationally reliable pipeline in CI and runtime orchestration
- Clear separation of static, runtime, and dynamic evidence channels
