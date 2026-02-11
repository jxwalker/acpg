# Next Steps

Last refreshed: **February 11, 2026**

## Next Implementation Slice

### 1) Runtime Policy Compiler

Goal:
- Evaluate runtime events (`runtime_events`) against runtime policy rules.

Deliverables:
- Runtime policy schema
- Runtime evaluator service
- Violations emitted from runtime checks
- Tests covering pass/fail/edge cases

### 2) Enforcement Decision Layer

Goal:
- Support graded runtime enforcement outcomes.

Deliverables:
- Outcome model: `deny`, `require_approval`, `allow_with_monitoring`
- Event/evidence mapping
- UI/API visibility of enforcement decisions

### 3) Dynamic Analysis MVP (Sandboxed)

Goal:
- Add safe runtime checks without executing untrusted code unsafely.

Deliverables:
- Sandbox runner with resource/time limits
- Deterministic evidence output
- Integration into prosecutor/adjudicator pipeline

### 4) Proof Evidence Enhancements

Goal:
- Increase auditability for regulated review.

Deliverables:
- Policy version hashes in proof bundles
- Explicit evidence provenance fields
- Better machine-verifiable export contract

## Acceptance Criteria

- Full test suite green locally and in CI
- No regression in core analyze/enforce/proof APIs
- Runtime compliance evidence round-trips through proof generation and verification
