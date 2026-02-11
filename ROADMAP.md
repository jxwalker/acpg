# ACPG Roadmap (Refreshed February 11, 2026)

## Vision

Provide provable policy compliance for AI-generated code and agent behavior, with evidence suitable for high-assurance and regulated environments.

## Completed Foundations

- Multi-agent flow: Generator, Prosecutor, Adjudicator, Proof Assembler
- Policy-as-code with default + OWASP + NIST + JS/TS coverage
- Responses-first OpenAI integration with fallback behavior
- Formal adjudication with grounded semantics
- AUTO semantics mode (grounded decision, optional secondary solver evidence)
- Joint attacks (Nielsen-Parsons style) in grounded computation
- Signed proof bundles with evidence and argumentation trace
- LangGraph orchestration with runtime event trace
- Runtime guard policy-to-violation flow for tool actions
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
- Expand stable/preferred support and improve observability when solver is unavailable
- Explore joint-attack semantics support in solver-backed paths

5. Policy lifecycle UX
- Better versioning and policy diff/audit views
- Safer rollout controls for policy updates

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
