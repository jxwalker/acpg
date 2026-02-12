# ACPG Roadmap (Refreshed February 12, 2026)

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
- Unified test code management: file samples + DB-backed CRUD test cases
- Analysis/enforcement timing telemetry and UI performance visibility
- CI pipeline covering lint/test/build/integration/docker

## Active Near-Term Priorities

1. Runtime policy compiler
- Turn runtime events into first-class runtime policy checks beyond tool allow/deny
- Support policy authoring for runtime controls (tool/network/filesystem classes)

2. Enforcement controls
- Introduce graded actions: deny / require-approval / allow-with-monitoring
- Feed enforcement outcomes into proof evidence and adjudication

3. Dynamic analysis hardening
- Implement sandboxed dynamic tests (timeouts, resource limits, no untrusted escape)
- Record deterministic dynamic-analysis evidence in proof bundles

4. Solver integration maturity
- Add full joint-attack semantics to solver-backed paths (stable/preferred)
- Add deterministic solver policy for skeptical vs credulous acceptance mode selection

5. Policy lifecycle UX and test operations
- Better versioning and policy diff/audit views
- Safer rollout controls for policy updates
- Bulk test-case import/export and tagging workflows for regulated regression suites

6. Runtime and dynamic compliance evidence
- Runtime event policy compiler with deterministic rule evaluation
- Sandboxed dynamic checks with reproducible replay artifacts
- Formal linkage of dynamic/runtime evidence into proof argumentation

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
