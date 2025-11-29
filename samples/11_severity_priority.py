"""
Sample 11: Severity-Based Priority in Argumentation
Demonstrating how policy severity affects argument priority.

Severity Levels (highest to lowest):
- CRITICAL: System compromise, data breach, injection attacks
- HIGH: Credential exposure, weak crypto, insecure communication
- MEDIUM: Error handling, logging issues, code quality
- LOW: Style, documentation, minor best practices

Priority arguments (H) can attack lower-severity violations when
resources are limited and triage is needed.
"""

import hashlib
import logging
import sqlite3
import requests
from typing import Optional

# =============================================================================
# MULTI-SEVERITY VIOLATION EXAMPLE
# =============================================================================
"""
This class has violations at multiple severity levels.
In the argumentation framework, violations are ordered by priority.

Severity affects:
1. Fix ordering - critical issues addressed first
2. Priority attacks - higher severity can override lower in conflicts
3. Compliance thresholds - some policies may allow low-severity violations
"""

class VulnerablePaymentService:
    """
    Payment service with multiple severity levels of violations.
    
    Argumentation Order (by severity):
    1. CRITICAL: SQL-001 (SQL injection - system compromise)
    2. HIGH: SEC-001 (hardcoded credentials - data breach)
    3. HIGH: CRYPTO-001 (weak hashing - password recovery)
    4. HIGH: SEC-004 (HTTP - credential interception)
    5. MEDIUM: ERR-001 (exception handling - information leak)
    """
    
    def __init__(self):
        # HIGH: SEC-001 - Hardcoded credentials
        # Severity: HIGH (credential exposure)
        self.api_key = "pk_live_payment_key_12345"
        
        # HIGH: SEC-004 - Insecure HTTP
        # Severity: HIGH (credential interception possible)
        self.gateway_url = "http://payments.example.com/api"
        
        self.db = sqlite3.connect("payments.db")
        self.logger = logging.getLogger("payments")
    
    def process_payment(self, user_id: str, card_number: str, amount: float) -> dict:
        """
        Multiple violations at different severity levels.
        
        Argumentation graph will include:
        - V_SQL-001_0 (CRITICAL) - highest priority
        - V_SEC-001_0 (HIGH)
        - V_CRYPTO-001_0 (HIGH)
        - V_SEC-004_0 (HIGH)
        - V_ERR-001_0 (MEDIUM) - lowest priority
        
        When generating fixes, CRITICAL addressed first.
        """
        
        # CRITICAL: SQL-001 - SQL Injection
        # Priority: CRITICAL (full database compromise possible)
        cursor = self.db.cursor()
        query = f"SELECT credit_limit FROM users WHERE id = '{user_id}'"
        cursor.execute(query)
        limit = cursor.fetchone()
        
        if amount > limit[0]:
            return {"error": "Over credit limit"}
        
        # HIGH: CRYPTO-001 - Weak cryptography for transaction ID
        # Priority: HIGH (transaction forgery possible)
        tx_id = hashlib.md5(f"{user_id}{amount}".encode()).hexdigest()
        
        try:
            # HIGH: SEC-004 - HTTP for payment (already set in __init__)
            # Priority: HIGH (payment credentials exposed)
            response = requests.post(
                self.gateway_url,  # HTTP not HTTPS!
                json={
                    "tx_id": tx_id,
                    "card": card_number,
                    "amount": amount,
                    "api_key": self.api_key  # Hardcoded key
                }
            )
            return response.json()
            
        except Exception as e:
            # MEDIUM: ERR-001 - Exposing internal error details
            # Priority: MEDIUM (information disclosure)
            return {"error": str(e), "details": repr(e)}
    
    def get_transaction_history(self, user_id: str) -> list:
        """
        Additional CRITICAL violation.
        
        V_SQL-001_1: Another SQL injection point
        Even with other violations, CRITICAL ones are prioritized.
        """
        cursor = self.db.cursor()
        # CRITICAL: SQL-001 - SQL Injection
        query = "SELECT * FROM transactions WHERE user_id = '" + user_id + "'"
        cursor.execute(query)
        return cursor.fetchall()


# =============================================================================
# PRIORITY-BASED FIX ORDERING
# =============================================================================
"""
When generating fixes, the adjudicator orders by severity:

GUIDANCE OUTPUT:
================================================================================
COMPLIANCE GUIDANCE:
========================================

Found 6 violation(s) to address:

1. [CRITICAL] [STRICT] SQL-001
   Issue: SQL injection via string concatenation
   Location: Line 45, Line 78
   Evidence: f"SELECT credit_limit FROM users WHERE id = '{user_id}'"
   Suggested Fix: Use parameterized queries with prepared statements

2. [HIGH] [STRICT] SEC-001
   Issue: Hardcoded API key
   Location: Line 30
   Evidence: self.api_key = "pk_live_payment_key_12345"
   Suggested Fix: Use environment variables or secure vault

3. [HIGH] [STRICT] CRYPTO-001
   Issue: MD5 used for transaction ID
   Location: Line 53
   Evidence: hashlib.md5(...)
   Suggested Fix: Use SHA-256 or stronger

4. [HIGH] [STRICT] SEC-004
   Issue: HTTP instead of HTTPS for payment
   Location: Line 35
   Evidence: "http://payments.example.com/api"
   Suggested Fix: Replace HTTP with HTTPS

5. [MEDIUM] [STRICT] ERR-001
   Issue: Internal error details exposed
   Location: Line 72
   Evidence: {"error": str(e), "details": repr(e)}
   Suggested Fix: Return user-friendly error, log details internally

========================================
Address violations in order of priority (highest severity first).
"""


# =============================================================================
# THRESHOLD-BASED COMPLIANCE
# =============================================================================
"""
Some compliance frameworks allow threshold-based decisions:
- "No CRITICAL or HIGH violations"
- "Maximum 2 MEDIUM violations allowed"
- "LOW violations require remediation plan but don't block deployment"

This can be modeled with meta-arguments that attack based on thresholds:

    THRESHOLD_ARG ──attacks──► V_LOW (if within acceptable count)
    
This allows graduated compliance rather than binary pass/fail.
"""

class ComplianceThresholds:
    """Model for threshold-based compliance decisions."""
    
    # Define acceptable thresholds by severity
    THRESHOLDS = {
        "critical": 0,  # Zero tolerance
        "high": 0,      # Zero tolerance
        "medium": 2,    # Up to 2 allowed
        "low": 5        # Up to 5 allowed with remediation plan
    }
    
    @classmethod
    def check_threshold_compliance(cls, violations: list) -> dict:
        """
        Check if violations are within acceptable thresholds.
        
        Returns compliance decision with details about
        which thresholds are met/exceeded.
        """
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for v in violations:
            severity = v.get("severity", "medium").lower()
            counts[severity] = counts.get(severity, 0) + 1
        
        exceeded = []
        for severity, count in counts.items():
            if count > cls.THRESHOLDS.get(severity, 0):
                exceeded.append({
                    "severity": severity,
                    "count": count,
                    "threshold": cls.THRESHOLDS[severity]
                })
        
        return {
            "compliant": len(exceeded) == 0,
            "counts": counts,
            "exceeded_thresholds": exceeded,
            "recommendation": cls._get_recommendation(exceeded)
        }
    
    @classmethod
    def _get_recommendation(cls, exceeded: list) -> str:
        if not exceeded:
            return "All thresholds met. Deployment approved."
        
        critical_high = [e for e in exceeded 
                        if e["severity"] in ["critical", "high"]]
        
        if critical_high:
            return "BLOCKED: Critical/High violations must be fixed before deployment."
        else:
            return "WARNING: Medium/Low thresholds exceeded. Create remediation plan."


# =============================================================================
# FORMAL PRIORITY SEMANTICS
# =============================================================================
"""
Priority in Dung's framework can be modeled as:

1. PREFERENCE-BASED ARGUMENTATION:
   - Define priority ordering: critical > high > medium > low
   - Higher priority arguments have "meta-attacks" on lower
   - H(critical) attacks V(low) when resources are limited

2. VALUE-BASED ARGUMENTATION:
   - Each argument promotes a "value" (security, availability, etc.)
   - Value ordering determines which attacks succeed
   - V_SQL-001 (security) defeats V_PERF-001 (performance) if security > performance

3. WEIGHTED ARGUMENTATION:
   - Assign numeric weights to arguments
   - Attack succeeds only if attacker weight > target weight
   - Critical=100, High=75, Medium=50, Low=25

ACPG uses a combination:
- Violations are sorted by severity for fix ordering
- Strict policies cannot be defeated regardless of priority
- Priority affects guidance generation and remediation planning
"""

if __name__ == "__main__":
    print("Severity-Based Priority Demo")
    print("=" * 50)
    print()
    print("Severity levels (highest to lowest):")
    print("  CRITICAL → HIGH → MEDIUM → LOW")
    print()
    print("Priority affects:")
    print("  1. Fix ordering (critical first)")
    print("  2. Conflict resolution (higher wins)")
    print("  3. Threshold compliance (graduated pass/fail)")
    print()
    
    # Example threshold check
    sample_violations = [
        {"rule_id": "SQL-001", "severity": "critical"},
        {"rule_id": "SEC-001", "severity": "high"},
    ]
    
    result = ComplianceThresholds.check_threshold_compliance(sample_violations)
    print(f"Sample compliance check: {result['recommendation']}")

