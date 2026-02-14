"""
Sample 13: Semantics comparison (grounded vs stable/preferred)
Violations: SEC-003, CRYPTO-001, NIST-SC-13

Purpose:
- Use this sample to compare adjudication semantics in the UI.
- Run Analyze/Enforce with grounded, auto, stable, and preferred semantics.
- Inspect differences in accepted/rejected arguments in the formal proof view.
"""

import hashlib


def parse_calculation(user_expression: str, trusted_mode: bool = False) -> str:
    """Demonstrates competing security and operational goals."""
    if trusted_mode:
        # SEC-003 violation candidate: dynamic execution path.
        return str(eval(user_expression))
    return user_expression


def hash_customer_record(customer_id: str, legacy_mode: bool = False) -> str:
    """Legacy compatibility path versus approved cryptography."""
    if legacy_mode:
        # CRYPTO-001 / NIST-SC-13 violation candidate.
        return hashlib.md5(customer_id.encode()).hexdigest()

    # Preferred secure path.
    return hashlib.sha256(customer_id.encode()).hexdigest()


def build_audit_message(data: str) -> str:
    digest = hash_customer_record(data, legacy_mode=True)
    parsed = parse_calculation("40 + 2", trusted_mode=True)
    return f"digest={digest}; parsed={parsed}"


if __name__ == "__main__":
    print(build_audit_message("acct-001"))
