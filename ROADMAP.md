# ACPG Roadmap (Refreshed February 14, 2026)

## Vision

Provide provable policy compliance for AI-generated code and agent behavior, with evidence suitable for high-assurance and regulated environments.

## Completed Foundations

- Multi-agent flow: Generator, Prosecutor, Adjudicator, Proof Assembler
- Policy-as-code with default + OWASP + NIST + JS/TS coverage
- Responses-first OpenAI integration with fallback behavior
- Formal adjudication with grounded semantics
- Semantics support: grounded, auto, stable, preferred (with explicit fallback behavior)
- Joint attacks (Nielsen-Parsons style) in grounded computation
- Solver-backed joint-attack semantics for stable/preferred (ASP/clingo)
- Deterministic solver decision modes (`auto` -> skeptical, `skeptical`, `credulous`)
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
- Policy version history and diff/audit support (API + UI)
- Policy-group rollout preview simulation against stored test cases
- Unified test code management: file samples + DB-backed CRUD test cases
- Bulk test-case import/export APIs with UI tag filtering workflows
- Analysis/enforcement timing telemetry and UI performance visibility
- CI pipeline covering lint/test/build/integration/docker
- Runtime policy simulator UI (event-level allow/deny/monitor evaluation)
- LangGraph live-stream trace viewer (SSE streaming + graph visualization)
- Batch test-case runner UI for stored suites
- Proof registry + signer public-key inspector UI
- Dynamic artifact explorer UI with multi-criteria filtering
- Sample suite: 16 samples covering tools, semantics, joint attacks, runtime, dynamic analysis

## Active Near-Term Priorities (VC Pitch Readiness)

1. Demo polish and reliability
   - End-to-end walkthrough testing of the full enforce loop (analyze → adjudicate → fix → proof) in the UI
   - Verify LangGraph streaming works reliably with a live LLM provider
   - Test proof verification flow end-to-end from UI
   - Ensure clean error states when LLM keys are missing or provider is unreachable

2. Pitch materials
   - Competitor comparison slide (ACPG vs Snyk/Semgrep/Checkov)
   - Argumentation graph visualization for pitch deck (export or screenshot)
   - One-pager summarizing the formal methods differentiation

3. UI quality-of-life
   - Loading states and error boundaries for all Demo Lab tabs
   - Mobile/responsive behavior for projector-friendly demo

## Medium-Term Priorities

- Expanded language coverage (Go, Java, Rust policy catalogs and tool integrations)
- Multi-tenant authn/authz hardening (SSO/OAuth, key rotation)
- PostgreSQL production deployment and operational reliability
- Compliance reporting exports (PDF/CSV for regulatory filings)
- Rich CI integrations beyond GitHub Actions (GitLab CI, Jenkins)
- Webhook/notification integrations for compliance events

## Long-Term Vision

- SaaS deployment with org-level tenancy
- Policy marketplace for industry-specific compliance catalogs
- Agent observability dashboard for multi-agent fleet monitoring
- Integration SDK for embedding ACPG in IDE plugins and code review tools
- Formal certification pathway (SOC 2, ISO 27001 artifact generation)

## Success Criteria

- Deterministic compliance decisions for safety-critical flows
- Complete traceability from event -> violation -> argumentation -> signed proof
- Operationally reliable pipeline in CI and runtime orchestration
- Clear separation of static, runtime, and dynamic evidence channels
