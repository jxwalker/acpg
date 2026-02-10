# Runtime Policy Compliance For Agents (Roadmap + Implementation Notes)

This document describes how ACPG should provide provable, runtime policy compliance for agentic workflows (in addition to static code compliance).

## Goals

- Produce a **logically explainable** and **cryptographically signed** compliance decision that can be audited in regulated settings (pharma, banking).
- Ensure agents remain safe at runtime by enforcing policy constraints **before**, **during**, and **after** actions (tool calls, file writes, network access, etc.).
- Keep the decision procedure conservative and deterministic by default (AUTO semantics -> grounded).

## Current Implementation (This PR)

- LangGraph orchestration now records an append-only `runtime_events` trace and returns it from `/graph/enforce`.
- Proof bundles assembled via LangGraph include the runtime trace as evidence:
  - `Evidence.rule_id="RUNTIME"`, `Evidence.type="runtime_trace"`, `Evidence.tool="langgraph"`.
- LangGraph endpoints accept an optional `semantics` parameter, and the adjudicator uses it when deciding compliance (AUTO -> grounded).

## What “Runtime Compliance” Means Here

Static compliance answers: "Is the code artifact compliant with policy P?"

Runtime compliance answers: "Is the *agent execution* compliant with policy P, given what it actually did (and attempted to do)?"

In ACPG terms, runtime compliance is built from:

- **Runtime Trace**: structured events emitted by the orchestrator/agents.
- **Runtime Policy Rules**: constraints on actions (e.g., "No network", "Only allow read-only filesystem", "No secrets exfiltration", "Tool X requires approval").
- **Argumentation Adjudication**: resolve conflicts/exceptions/waivers and produce a proof-carrying explanation.

## Proposed Architecture

### 1) Observe (Instrumentation)

Instrument agent steps and tool calls to emit `runtime_events`:

- node lifecycle: start/end/error
- tool call: name, inputs summary, outputs summary, allow/deny decision
- LLM call: provider/model, safety settings, response metadata
- data access: file paths accessed, network destinations (normalized), secrets classification (if enabled)

### 2) Normalize (Event Schema)

Events should be normalized into a small stable schema for policy evaluation. Today ACPG uses:

- `timestamp`, `node`, `kind`, `iteration`, `details`

Next: formalize `kind` and required `details` per kind (and add redaction/hashing rules).

### 3) Evaluate (Runtime Policy Checks)

Introduce a runtime policy compiler that turns policy rules into check functions over events, producing violations like static checks do:

- `Violation.rule_id`
- `Violation.description`
- `Violation.evidence` (event excerpt / hash / reference)
- `Violation.severity`

### 4) Adjudicate (Abstract Argumentation)

Feed runtime violations into the existing adjudicator:

- Default decision procedure: **grounded** (skeptical, deterministic).
- Secondary evidence (optional): stable/preferred if solver available.
- Joint attacks (Nielsen–Parsons style) remain important for real-world policy governance:
  - example: `{approved_by_human, ticket_exists} attacks violation(network_call)` only jointly.

### 5) Prove (Proof Bundle)

Extend proof bundle evidence to include:

- runtime trace (already implemented)
- tool allow/deny decisions
- approvals/attestations (human or system)
- policy versions and rule hashes used for the decision

### 6) Enforce (Guards)

Runtime enforcement should support:

- hard deny (block action)
- soft deny (require approval / degrade capability)
- allow with monitoring (record evidence, raise risk score)

## Dynamic Analysis Roadmap (Safe-by-Default)

Dynamic analysis is powerful but dangerous if it executes untrusted code. The recommended approach is staged and opt-in:

1. **Sandboxed execution** (container/jail) with strict time/memory/network/fs controls.
2. **Property-based tests** (Hypothesis) generated from function signatures or user-provided specs.
3. **Invariant checks** tied to policy (e.g., "no outbound network calls", "no file writes outside workspace", "no subprocess").
4. **Runtime evidence**: store test seeds, failing counterexamples, environment hash, and sandbox config in proof bundle.

## Known Limitations

- Joint attacks are currently supported in grounded computation. Solver-backed stable/preferred semantics do not yet model joint attacks.
- `runtime_events` currently capture node-level decisions; fine-grained tool-call instrumentation is the next step.

