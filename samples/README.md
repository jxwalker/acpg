> [!NOTE]
> Documentation Refresh Note (February 11, 2026): this file is retained as specialized or historical context.
> For current product behavior and authoritative guidance, start at /Users/James/code/GAD/apcg/README.md and /Users/James/code/GAD/apcg/docs/README.md.

# ACPG Sample Code Files

This directory contains sample code files demonstrating various security policy violations for testing the ACPG system.

## Sample Files

### 12_tool_demo.py
**Purpose**: Demonstrates static analysis tool findings and the complete tool integration workflow.

**Expected Tool Findings**:
- `B608` - SQL injection (mapped to SQL-001) → Will appear as violation
- `B105` - Hardcoded password (mapped to SEC-001) → Will appear as violation  
- `B307` - Use of eval (mapped to SEC-003) → Will appear as violation
- `B601` - Shell injection (mapped to SQL-001) → Will appear as violation
- `B602` - Shell injection (mapped to SEC-003) → Will appear as violation
- `B104` - Bind to all interfaces (mapped to SEC-001) → Will appear as violation
- `B102` - Use of exec (unmapped) → Will show in tool execution status
- `B101` - Use of assert (unmapped) → Will show in tool execution status

**Workflow Test**:
1. Load this sample in the editor
2. Go to Tools → Browse Rules → Select "bandit"
3. See that B608, B105, B307, B601, B602, B104 are mapped
4. See that B102, B101 are unmapped
5. Click "Analyze" to run tools
6. Check "Tool Execution" panel:
   - See bandit ran successfully
   - See 8 findings total (6 mapped, 2 unmapped)
   - Expand to see unmapped findings (B102, B101)
7. Check "Violations" panel:
   - See 6 violations with [bandit] badges
   - SQL-001 (B608, B601), SEC-001 (B105, B104), SEC-003 (B307, B602)
8. Expand tool execution to see unmapped findings (B102, B101)
9. Optionally create mappings for B102, B101 if desired
10. Re-analyze to see new violations appear

## Sample Files

| File | Description | Violations |
|------|-------------|------------|
| `01_hardcoded_secrets.py` | Embedded credentials and API keys | SEC-001 |
| `02_sql_injection.py` | SQL injection vulnerabilities | SQL-001 |
| `03_dangerous_functions.py` | eval(), exec(), pickle usage | SEC-003 |
| `04_weak_crypto.py` | MD5, SHA1, weak random | CRYPTO-001 |
| `05_insecure_http.py` | HTTP instead of HTTPS | SEC-004 |
| `06_mixed_vulnerabilities.py` | Multiple violation types | Mixed |
| `07_owasp_top10.py` | OWASP Top 10 vulnerabilities | OWASP-* |
| `08_strict_policies.py` | **Strict policies** - no exceptions possible | SEC-001, SEC-003, SQL-001, CRYPTO-001 |
| `09_defeasible_policies.py` | **Defeasible policies** - with valid exceptions | INPUT-001, ERR-001, LOG-001 |
| `10_argumentation_conflict.py` | **Conflict resolution** - competing arguments | Multiple |
| `11_severity_priority.py` | **Priority ordering** - severity-based triage | Multiple |
| `12_tool_demo.py` | **Tool mapping** - mapped vs unmapped tool findings | SQL-001, SEC-001, SEC-003 |
| `13_semantics_stable_vs_grounded.py` | **Semantics comparison** - grounded vs stable/preferred | SEC-003, CRYPTO-001, NIST-SC-13 |
| `14_joint_attack_nelson_parsons.py` | **Joint attack demo** - Nielsen-Parsons style policy conflict | SEC-001, SEC-003, SQL-001 |
| `15_runtime_policy_events.py` | **Runtime governance demo** - tool/network/filesystem event set | SEC-004 |
| `16_dynamic_analysis_replay.py` | **Dynamic replay demo** - deterministic runtime artifacts | SEC-003, CRYPTO-001 |

## Usage

### Analyze a Sample

```bash
cd backend
python cli.py check --input ../samples/01_hardcoded_secrets.py
```

### Fix a Sample

```bash
python cli.py enforce --input ../samples/02_sql_injection.py \
  --output ../samples/02_sql_injection_fixed.py \
  --proof ../samples/02_proof.json
```

### Batch Analysis

```bash
for file in ../samples/*.py; do
  echo "=== $file ==="
  python cli.py check --input "$file"
done
```

## Violation Summary

### SEC-001: Hardcoded Credentials
- Passwords in source code
- API keys embedded
- OAuth secrets visible

### SEC-003: Dangerous Functions
- `eval()` on user input
- `exec()` for dynamic code
- `pickle.loads()` untrusted data
- `yaml.load()` without safe loader

### SEC-004: Insecure HTTP
- HTTP for API calls
- HTTP for payment processing
- HTTP for authentication

### SQL-001: SQL Injection
- String concatenation in queries
- F-string SQL construction
- `.format()` in queries

### CRYPTO-001: Weak Cryptography
- MD5 for password hashing
- SHA1 for security tokens
- `random` module for secrets

## Expected Results

Each sample file should trigger specific violations when analyzed:

```
01_hardcoded_secrets.py: 6 violations (SEC-001)
02_sql_injection.py: 6 violations (SQL-001)
03_dangerous_functions.py: 10 violations (SEC-003)
04_weak_crypto.py: 8 violations (CRYPTO-001)
05_insecure_http.py: 10 violations (SEC-004)
06_mixed_vulnerabilities.py: 12+ violations (Mixed)
07_owasp_top10.py: 15+ violations (Multiple)
```

## Argumentation Framework Samples (08-11)

These samples demonstrate ACPG's formal argumentation logic using **Dung's Abstract Argumentation Framework**:

### Strict vs Defeasible Policies

| Type | Definition | Exception Possible? | Example |
|------|------------|---------------------|---------|
| **Strict** | Absolute security requirements | ❌ No | SQL injection, hardcoded secrets |
| **Defeasible** | Context-dependent requirements | ✅ Yes | Input validation, error handling |

### Argumentation Structure

```
Arguments:
  C_RULE: "Artifact complies with RULE"
  V_RULE: "Artifact violates RULE" → attacks C_RULE
  E_RULE: "Exception applies" → attacks V_RULE (defeasible only)

Grounded Extension:
  - Unattacked arguments are ACCEPTED
  - Arguments attacked by ACCEPTED are REJECTED
  - Iterate until no changes (fixpoint)
```

### Key Concepts Demonstrated

1. **08_strict_policies.py**: Violations that cannot be defeated
   - `V → C` with no counter-attacks
   - All violations remain in grounded extension

2. **09_defeasible_policies.py**: Violations with valid exceptions
   - `E → V → C` chains
   - Exception defeats violation, restoring compliance

3. **10_argumentation_conflict.py**: Complex resolution scenarios
   - Multiple violations, partial exceptions
   - Chain of attacks (exceptions to exceptions)
   - Symmetric attacks (undecidable conflicts)

4. **11_severity_priority.py**: Priority-based ordering
   - Critical > High > Medium > Low
   - Affects fix ordering and threshold compliance

5. **13_semantics_stable_vs_grounded.py**: Semantics behavior comparison
   - Run under grounded, auto, stable, preferred
   - Compare accepted/rejected argument sets and final compliance outcome

6. **14_joint_attack_nelson_parsons.py**: Joint-attack narrative
   - Illustrates multi-condition mitigation arguments
   - Useful for demos of set-attack reasoning and policy conflict discussions

7. **15_runtime_policy_events.py**: Runtime policy channel demo
   - Pairs with runtime policy evaluate endpoints/UI
   - Demonstrates allow/deny/monitor event decisions as proof evidence

8. **16_dynamic_analysis_replay.py**: Dynamic analysis + replay evidence
   - Demonstrates deterministic dynamic artifact generation
   - Shows replay-linked evidence in history and proof bundle views

## For Patent Demonstration

These samples demonstrate ACPG's ability to:
1. Detect multiple categories of security violations
2. Provide detailed evidence for each violation
3. Auto-fix code using AI
4. Generate cryptographically signed compliance proofs
5. **Use formal argumentation to resolve policy conflicts**
6. **Support defeasible reasoning with contextual exceptions**
