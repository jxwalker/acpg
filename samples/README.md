# ACPG Sample Code Files

This directory contains sample code files demonstrating various security policy violations for testing the ACPG system.

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

## For Patent Demonstration

These samples demonstrate ACPG's ability to:
1. Detect multiple categories of security violations
2. Provide detailed evidence for each violation
3. Auto-fix code using AI
4. Generate cryptographically signed compliance proofs

