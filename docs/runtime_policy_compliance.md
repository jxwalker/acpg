# Runtime Policy Compliance for Agent Workflows

Last refreshed: **February 11, 2026**

## Objective

Provide provable runtime compliance for agent behavior, not only static code artifacts.

## Implemented Today

- LangGraph state captures `runtime_events`.
- `POST /api/v1/graph/enforce` returns runtime traces.
- Proof bundles include runtime trace evidence (`rule_id=RUNTIME`, `type=runtime_trace`).
- Runtime tool guard evaluates tool actions against allow/deny policy.
- Denied tool actions are emitted as formal violations and adjudicated.
- AUTO semantics remains conservative: grounded decision, optional secondary solver evidence.

## Compliance Model

Runtime compliance evidence path:

1. Runtime action occurs (tool invocation)
2. Runtime guard produces allow/deny decision
3. Denials become formal violations
4. Adjudicator resolves compliance under grounded semantics
5. Proof bundle captures both reasoning and runtime evidence

## Why This Matters for Regulated Use

- Deterministic decision basis for compliance (`grounded`)
- Traceable evidence linking action -> rule -> decision
- Signed artifact for audit and non-repudiation

## Current Limitations

- Runtime policy language is still minimal (guard-centric)
- Dynamic analysis execution sandbox is not fully implemented
- Solver-backed semantics do not yet fully represent joint attacks

## Next Targets

1. Runtime policy compiler over general runtime event schemas
2. Enforcement levels (`deny`, `require_approval`, `allow_with_monitoring`)
3. Sandboxed dynamic analysis with deterministic evidence packaging
