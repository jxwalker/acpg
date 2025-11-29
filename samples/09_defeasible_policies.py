"""
Sample 9: Defeasible Policy Violations with Potential Exceptions
Demonstrating policies that CAN be defeated by valid exceptions.

In Dung's Argumentation Framework for DEFEASIBLE policies:
- Violation argument V attacks Compliance argument C
- Exception argument E CAN attack V (defeating the violation)
- If E is accepted, V is rejected → compliance restored

Defeasible policies represent contextual requirements:
- INPUT-001: User input validation (exceptions for trusted internal sources)
- ERR-001: Exception handling (exceptions for development/debug modes)
- LOG-001: Sensitive data logging (exceptions for audit requirements)

The argumentation graph may show: E → V → C
If E defeats V, then C is accepted despite the apparent violation.
"""

import os
import logging
from typing import Optional

# =============================================================================
# DEFEASIBLE VIOLATION: INPUT-001 - Input Validation
# WITH VALID EXCEPTION
# =============================================================================
# Argumentation:
#   C_INPUT-001: "Code complies with INPUT-001 (input validation)"
#   V_INPUT-001_0: "Violation: unvalidated input used" → attacks C_INPUT-001
#   E_INPUT-001_0: "Exception: input from trusted internal service" → attacks V
#
# Result: E_INPUT-001_0 defeats V_INPUT-001_0
#         V_INPUT-001_0 is REJECTED
#         C_INPUT-001 is ACCEPTED
#         Policy is SATISFIED despite apparent violation

class InternalServiceClient:
    """
    Client for internal microservice communication.
    
    EXCEPTION CONDITION: @internal_trusted_source
    - Input from authenticated internal services is pre-validated
    - Service-to-service authentication provides trust boundary
    - Exception E defeats violation V in argumentation
    """
    
    def __init__(self, service_url: str):
        # @internal_trusted_source: Internal service registry URL
        self.service_url = service_url
        self.auth_token = os.getenv("INTERNAL_SERVICE_TOKEN")
    
    def get_user_data(self, user_id: str) -> dict:
        """
        Fetch user data from internal identity service.
        
        INPUT VALIDATION EXCEPTION:
        - user_id comes from authenticated internal service
        - Internal service has already validated the ID format
        - Exception argument E_INPUT-001 attacks violation V_INPUT-001
        
        Argumentation result: COMPLIANT (exception defeats violation)
        """
        # @exception:INPUT-001 - trusted internal source, pre-validated
        # No additional validation needed - internal service contract guarantees format
        return {"user_id": user_id, "source": "internal_identity_service"}
    
    def process_internal_event(self, event_payload: dict) -> None:
        """
        Process event from internal message queue.
        
        Exception: Events from internal queue are schema-validated at ingestion.
        The message broker enforces schema compliance before delivery.
        """
        # @exception:INPUT-001 - internal message queue with schema validation
        action = event_payload.get("action")
        target = event_payload.get("target_id")
        self._execute_action(action, target)
    
    def _execute_action(self, action: str, target: str) -> None:
        """Internal action executor - inputs already validated by caller."""
        print(f"Executing {action} on {target}")


# =============================================================================
# DEFEASIBLE VIOLATION: INPUT-001 - Input Validation  
# WITHOUT VALID EXCEPTION (VIOLATION STANDS)
# =============================================================================
# Argumentation:
#   C_INPUT-001: "Code complies with INPUT-001"
#   V_INPUT-001_1: "Violation: unvalidated external input" → attacks C_INPUT-001
#   (No exception argument exists)
#
# Result: V_INPUT-001_1 is ACCEPTED
#         C_INPUT-001 is REJECTED
#         Policy is VIOLATED

class ExternalAPIHandler:
    """
    Handler for external/public API requests.
    
    NO EXCEPTION: External input must always be validated.
    No trust boundary exists with external callers.
    """
    
    def search(self, query: str) -> list:
        """
        DEFEASIBLE VIOLATION (NO EXCEPTION):
        - Query comes from external HTTP request
        - No pre-validation from trusted source
        - No exception argument E exists to attack V
        - V_INPUT-001_1 is ACCEPTED → NON-COMPLIANT
        """
        # This SHOULD validate: len, format, allowed chars, etc.
        # Violation stands because external input has no trust exception
        return self._db_search(query)
    
    def _db_search(self, query: str) -> list:
        # Simplified - would normally use parameterized queries
        return [f"result for: {query}"]


# =============================================================================
# DEFEASIBLE VIOLATION: ERR-001 - Exception Handling
# WITH DEVELOPMENT MODE EXCEPTION
# =============================================================================
# Argumentation:
#   C_ERR-001: "Code complies with ERR-001 (proper error handling)"
#   V_ERR-001_0: "Violation: stack trace exposed" → attacks C_ERR-001
#   E_ERR-001_0: "Exception: development mode enabled" → attacks V_ERR-001_0
#
# In development: Exception defeats violation → COMPLIANT
# In production: No exception applies → VIOLATION STANDS

DEBUG_MODE = os.getenv("DEBUG", "false").lower() == "true"

def process_request(data: dict) -> dict:
    """
    Request processor with conditional error handling.
    
    EXCEPTION CONDITION: @development_mode
    - In DEBUG_MODE, full stack traces aid debugging
    - Exception E_ERR-001 attacks violation V_ERR-001
    - In production, exception does not apply → violation stands
    """
    try:
        result = complex_operation(data)
        return {"success": True, "result": result}
    except Exception as e:
        if DEBUG_MODE:
            # @exception:ERR-001 - development mode allows detailed errors
            # Exception argument defeats violation in dev environment
            import traceback
            return {
                "success": False, 
                "error": str(e),
                "stack_trace": traceback.format_exc()  # OK in debug mode
            }
        else:
            # Production: proper error handling, no exception applies
            logging.error(f"Operation failed: {e}")
            return {"success": False, "error": "An error occurred"}

def complex_operation(data: dict) -> dict:
    """Simulated complex operation that might fail."""
    if not data:
        raise ValueError("Empty data provided")
    return {"processed": True}


# =============================================================================
# DEFEASIBLE VIOLATION: LOG-001 - Sensitive Data Logging
# WITH AUDIT COMPLIANCE EXCEPTION
# =============================================================================
# Argumentation:
#   C_LOG-001: "Code complies with LOG-001 (no sensitive data in logs)"
#   V_LOG-001_0: "Violation: user data logged" → attacks C_LOG-001  
#   E_LOG-001_0: "Exception: PCI-DSS audit requirement" → attacks V_LOG-001_0
#
# Certain regulatory frameworks REQUIRE logging for audit trails.
# The compliance exception defeats the sensitive logging violation.

class AuditLogger:
    """
    Compliant audit logging for regulatory requirements.
    
    EXCEPTION: @regulatory_audit_requirement
    - PCI-DSS, SOX, HIPAA may require transaction audit trails
    - Audit logs are encrypted and access-controlled
    - Exception E defeats violation V for audit-specific logging
    """
    
    def __init__(self):
        self.logger = logging.getLogger("audit")
        # Audit logs go to secure, encrypted, access-controlled storage
        self.audit_storage = SecureAuditStorage()
    
    def log_transaction(self, user_id: str, amount: float, 
                        card_last_four: str) -> None:
        """
        Log financial transaction for PCI-DSS compliance.
        
        EXCEPTION: Regulatory audit requirement
        - PCI-DSS 10.2.1 requires logging of all cardholder data access
        - Card number is masked (last 4 only)
        - Exception E_LOG-001 attacks violation V_LOG-001
        - Result: COMPLIANT (regulatory exception applies)
        """
        # @exception:LOG-001 - PCI-DSS audit requirement, data masked
        audit_entry = {
            "timestamp": self._get_timestamp(),
            "user_id": user_id,  # Required for audit trail
            "amount": amount,
            "card_masked": f"****-****-****-{card_last_four}",
            "action": "payment_processed"
        }
        self.audit_storage.write(audit_entry)
    
    def log_access(self, user_id: str, resource: str, action: str) -> None:
        """
        Log resource access for SOX compliance.
        
        Exception: SOX 404 requires access logging to financial systems.
        """
        # @exception:LOG-001 - SOX compliance requirement
        self.audit_storage.write({
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "timestamp": self._get_timestamp()
        })
    
    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.utcnow().isoformat()

class SecureAuditStorage:
    """Simulated secure audit storage with encryption and access control."""
    def write(self, entry: dict) -> None:
        # In reality: encrypt, sign, write to immutable audit log
        pass


# =============================================================================
# COMPARATIVE ANALYSIS: STRICT vs DEFEASIBLE
# =============================================================================
"""
FORMAL LOGIC COMPARISON:

STRICT POLICY (e.g., SQL-001):
  Arguments: {C_SQL-001, V_SQL-001}
  Attacks: {V_SQL-001 → C_SQL-001}
  Grounded Extension: {V_SQL-001}
  Decision: NON-COMPLIANT (no exceptions possible)

DEFEASIBLE POLICY WITH EXCEPTION (e.g., INPUT-001 internal):
  Arguments: {C_INPUT-001, V_INPUT-001, E_INPUT-001}
  Attacks: {V_INPUT-001 → C_INPUT-001, E_INPUT-001 → V_INPUT-001}
  Grounded Extension: {E_INPUT-001, C_INPUT-001}
  Decision: COMPLIANT (exception defeats violation)

DEFEASIBLE POLICY WITHOUT EXCEPTION (e.g., INPUT-001 external):
  Arguments: {C_INPUT-001, V_INPUT-001}
  Attacks: {V_INPUT-001 → C_INPUT-001}
  Grounded Extension: {V_INPUT-001}
  Decision: NON-COMPLIANT (no applicable exception)

KEY INSIGHT:
  Defeasible policies check for exception conditions.
  If an exception argument E exists and attacks V,
  then V is rejected and C can be accepted.
  
  This enables nuanced compliance decisions that account
  for legitimate contextual requirements while maintaining
  security standards.
"""

if __name__ == "__main__":
    print("Defeasible Policy Demo")
    print("=" * 50)
    print("Some violations can be defeated by valid exceptions.")
    print()
    print("Examples of valid exceptions:")
    print("  - Internal service input (pre-validated at trust boundary)")
    print("  - Development mode (debug features acceptable)")
    print("  - Regulatory requirements (audit logging mandated)")

