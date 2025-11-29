"""
Sample 10: Argumentation Conflict Resolution
Demonstrating how competing arguments are resolved using grounded semantics.

This sample shows complex argumentation scenarios:
1. Multiple violations attacking the same compliance claim
2. Exception arguments defeating specific violations
3. Priority-based resolution between conflicting rules
4. Mutual attacks (symmetric conflicts)

Dung's Grounded Semantics:
- Start with unattacked arguments (must be accepted)
- Arguments attacked by accepted arguments are rejected
- Iterate until fixpoint (no more changes)
- Result: minimal complete extension
"""

import os
import hashlib
import logging
from dataclasses import dataclass
from typing import Optional

# =============================================================================
# SCENARIO 1: Multiple Violations, One Exception
# =============================================================================
"""
Argumentation Graph:

    E_INPUT-001 ──attacks──► V_INPUT-001_0
                                  │
                                  │attacks
                                  ▼
                            C_INPUT-001 ◄──attacks── V_INPUT-001_1
                            
Grounded Extension Computation:
1. E_INPUT-001 is unattacked → ACCEPTED
2. E_INPUT-001 attacks V_INPUT-001_0 → V_INPUT-001_0 REJECTED
3. V_INPUT-001_1 is unattacked → ACCEPTED  
4. V_INPUT-001_1 attacks C_INPUT-001 → C_INPUT-001 REJECTED

Result: {E_INPUT-001, V_INPUT-001_1} accepted
        C_INPUT-001 remains violated due to V_INPUT-001_1
"""

class MixedInputHandler:
    """Handler with both excepted and non-excepted input violations."""
    
    def __init__(self):
        # @internal_trusted_source - this has an exception
        self.internal_client = InternalServiceProxy()
    
    def process_mixed_inputs(self, internal_data: dict, external_query: str) -> dict:
        """
        Two input sources, only one has exception:
        
        V_INPUT-001_0: internal_data unvalidated
          - DEFEATED by E_INPUT-001 (trusted internal source)
          
        V_INPUT-001_1: external_query unvalidated  
          - NOT defeated (no exception for external input)
          - Violation STANDS
        
        RESULT: NON-COMPLIANT
        The exception only defeats ONE violation.
        Other violations maintain non-compliance.
        """
        # Exception applies here - internal trusted source
        user_id = internal_data.get("user_id")
        
        # No exception here - external input, violation stands
        search_term = external_query  # Should validate!
        
        return self._search(user_id, search_term)
    
    def _search(self, user_id: str, term: str) -> dict:
        return {"user": user_id, "results": [term]}


class InternalServiceProxy:
    """Proxy for internal service calls."""
    pass


# =============================================================================
# SCENARIO 2: Priority-Based Resolution
# =============================================================================
"""
When two policies conflict, the higher-priority (severity) wins.

Argumentation Graph:

    H_PRIORITY ──attacks──► V_LOW_SEVERITY
         │
         │ attacks
         ▼
    C_SECURITY ◄──attacks── V_HIGH_SEVERITY
    
Priority argument H attacks lower-severity violations when they
conflict with higher-severity requirements.

Example: "Logging for debugging" (low) vs "No sensitive data exposure" (high)
The high-severity policy wins.
"""

DEBUG = os.getenv("DEBUG", "false").lower() == "true"

class ConflictingRequirements:
    """
    Demonstrates priority resolution between conflicting policies.
    
    Conflict:
    - Low priority: LOG-DEBUG requires verbose logging for troubleshooting
    - High priority: SEC-002 prohibits logging sensitive data
    
    Resolution:
    - Priority argument H attacks V_LOG-DEBUG when it conflicts with SEC-002
    - SEC-002 (high severity) overrides LOG-DEBUG (low severity)
    """
    
    def authenticate(self, username: str, password: str) -> bool:
        """
        Conflicting requirements in authentication logging.
        
        V_LOG-DEBUG: "Should log all auth attempts for debugging"
        V_SEC-002: "Must not log passwords"
        
        Priority Resolution:
        - H_PRIORITY attacks V_LOG-DEBUG
        - V_SEC-002 (critical) overrides V_LOG-DEBUG (low)
        
        RESULT: Password must NOT be logged, regardless of debug needs.
        """
        if DEBUG:
            # This would violate SEC-002 (high priority)
            # logging.debug(f"Auth attempt: {username}/{password}")  # WRONG!
            
            # Correct: Log without sensitive data (SEC-002 wins)
            logging.debug(f"Auth attempt for user: {username}")
        
        return self._check_credentials(username, password)
    
    def _check_credentials(self, username: str, password: str) -> bool:
        # Simplified credential check
        return username == "admin" and password == "correct"


# =============================================================================
# SCENARIO 3: Chain of Attacks
# =============================================================================
"""
Argumentation can form chains where acceptance propagates:

    E2 ──attacks──► E1 ──attacks──► V ──attacks──► C

Grounded Extension:
1. E2 is unattacked → ACCEPTED
2. E2 attacks E1 → E1 REJECTED
3. V is unattacked (E1 was rejected) → V ACCEPTED
4. V attacks C → C REJECTED

The exception E1 was itself defeated by counter-exception E2!
This models "exceptions to exceptions" in legal/policy reasoning.
"""

@dataclass
class SecurityContext:
    """Security context for request processing."""
    user_role: str
    is_internal: bool
    audit_mode: bool
    emergency_access: bool

def process_sensitive_operation(data: dict, context: SecurityContext) -> dict:
    """
    Complex argumentation with chained attacks.
    
    Arguments:
    - C_ACCESS: "Access to sensitive data is permitted"
    - V_ACCESS: "Unauthorized access attempt" attacks C_ACCESS
    - E_INTERNAL: "Internal user exception" attacks V_ACCESS
    - E2_AUDIT: "Audit mode disables exceptions" attacks E_INTERNAL
    - E3_EMERGENCY: "Emergency access overrides audit" attacks E2_AUDIT
    
    Grounded Extension depends on context flags:
    
    Case 1: External user
      → V_ACCESS accepted → NON-COMPLIANT
      
    Case 2: Internal user, no audit
      → E_INTERNAL defeats V_ACCESS → COMPLIANT
      
    Case 3: Internal user, audit mode, no emergency
      → E2_AUDIT defeats E_INTERNAL → V_ACCESS accepted → NON-COMPLIANT
      
    Case 4: Internal user, audit mode, emergency
      → E3_EMERGENCY defeats E2_AUDIT → E_INTERNAL defeats V_ACCESS → COMPLIANT
    """
    
    # Build argument chain based on context
    has_violation = True  # Accessing sensitive data
    has_internal_exception = context.is_internal
    audit_defeats_exception = context.audit_mode
    emergency_defeats_audit = context.emergency_access
    
    # Resolve argumentation chain
    if emergency_defeats_audit:
        # E3 → E2, so E2 rejected, E1 can defeat V
        exception_applies = has_internal_exception
    elif audit_defeats_exception:
        # E2 → E1, so E1 rejected, V stands
        exception_applies = False
    else:
        # E1 → V (if internal)
        exception_applies = has_internal_exception
    
    if exception_applies:
        # Exception defeated the violation
        return {"access": "granted", "reason": "exception_applied"}
    elif has_violation:
        # Violation stands
        raise PermissionError("Access denied - violation not defeated")
    else:
        # No violation
        return {"access": "granted", "reason": "no_violation"}


# =============================================================================
# SCENARIO 4: Symmetric Attack (Odd Cycle)
# =============================================================================
"""
Some arguments attack each other symmetrically:

    A ←──attacks──► B

In grounded semantics, neither is accepted (undecided).
This represents genuine policy conflicts with no clear winner.

Example: Privacy vs Transparency
- A: "User data should be anonymized for privacy"
- B: "User data should be visible for transparency"

Neither defeats the other - requires human judgment.
"""

class PolicyConflict:
    """
    Demonstrates symmetric attack (undecidable conflict).
    
    This models real-world policy tensions that cannot be
    automatically resolved by formal argumentation alone.
    """
    
    def handle_data_request(self, user_id: str, requester: str) -> dict:
        """
        Symmetric policy conflict:
        
        V_PRIVACY: "Must anonymize user data for GDPR"
        V_TRANSPARENCY: "Must provide full data for FOIA"
        
        Attack relation: V_PRIVACY ↔ V_TRANSPARENCY
        
        Grounded Extension: ∅ (empty - neither accepted)
        
        RESULT: UNDECIDED - requires human adjudication
        """
        # In symmetric conflicts, system escalates to human review
        return {
            "status": "pending_review",
            "conflict": ["PRIVACY", "TRANSPARENCY"],
            "message": "Symmetric policy conflict - manual review required"
        }


# =============================================================================
# FORMAL LOGIC SUMMARY
# =============================================================================
"""
GROUNDED SEMANTICS ALGORITHM:

function grounded_extension(Args, Attacks):
    accepted = ∅
    rejected = ∅
    
    repeat:
        changed = false
        for each arg in Args:
            if arg ∈ accepted ∪ rejected:
                continue
            
            # Check if all attackers are rejected
            if ∀ attacker of arg: attacker ∈ rejected:
                accepted = accepted ∪ {arg}
                changed = true
                
                # Reject everything this arg attacks
                for each target attacked by arg:
                    if target ∉ rejected:
                        rejected = rejected ∪ {target}
                        changed = true
    
    until not changed
    return accepted

PROPERTIES:
- Uniqueness: Exactly one grounded extension exists
- Minimality: Contains only necessarily accepted arguments
- Skeptical: Only accepts undeniably defensible positions
- Conflict-free: No accepted argument attacks another accepted argument
- Admissible: Accepted arguments defend themselves against all attacks

APPLICATION TO COMPLIANCE:
- If ∃ accepted violation V: artifact is NON-COMPLIANT for rule R
- If ∀ compliance C_R ∈ accepted: artifact is COMPLIANT for rule R
- If V and C are both outside accepted: UNDECIDED (escalate)
"""

if __name__ == "__main__":
    print("Argumentation Conflict Resolution Demo")
    print("=" * 50)
    print()
    print("Scenarios demonstrated:")
    print("1. Multiple violations with partial exception coverage")
    print("2. Priority-based resolution (severity ranking)")
    print("3. Chain of attacks (exceptions to exceptions)")
    print("4. Symmetric attacks (undecidable conflicts)")
    print()
    print("Grounded semantics provides:")
    print("- Unique, deterministic resolution")
    print("- Minimal accepted set (skeptical reasoning)")
    print("- Formal justification for compliance decisions")

