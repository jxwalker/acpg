"""
Sample 8: Strict Policy Violations
Demonstrating policies that CANNOT be defeated by exceptions.

In Dung's Argumentation Framework:
- Violation argument V attacks Compliance argument C
- NO exception argument E exists to attack V
- Result: V is ACCEPTED in grounded extension → NON-COMPLIANT

Strict policies represent absolute security requirements:
- SEC-001: No hardcoded credentials (STRICT)
- SEC-003: No eval/exec (STRICT)  
- SQL-001: No SQL injection (STRICT)
- CRYPTO-001: No weak crypto (STRICT)

Even with justifications in comments, these violations stand.
The argumentation graph will show V → C with no counter-attacks.
"""

import hashlib
import sqlite3

# =============================================================================
# STRICT VIOLATION: SEC-001 - Hardcoded Credentials
# =============================================================================
# Argumentation:
#   C_SEC-001: "Code complies with SEC-001 (no hardcoded credentials)"
#   V_SEC-001_0: "Violation: hardcoded password on line 28" → attacks C_SEC-001
#   
# No exception can defeat this. Even "temporary" or "test" credentials in code
# represent a strict violation. The grounded extension ACCEPTS V_SEC-001_0.

DATABASE_PASSWORD = "ProductionPassword123!"  # STRICT VIOLATION - no exceptions

# Even with a comment explaining it's for testing - still a strict violation
TEST_API_KEY = "sk_test_ABC123XYZ"  # "Just for testing" - STILL STRICT VIOLATION


# =============================================================================
# STRICT VIOLATION: SEC-003 - Dangerous Functions
# =============================================================================
# Argumentation:
#   C_SEC-003: "Code complies with SEC-003 (no dangerous functions)"
#   V_SEC-003_0: "Violation: eval() used on line 48" → attacks C_SEC-003
#
# eval() is ALWAYS dangerous. No context makes it safe.
# Even "sanitized" input to eval is a strict violation.

def calculate_expression(expr):
    """
    Developer justification: "Input is validated to only contain digits and operators"
    
    ARGUMENTATION RESULT: Justification does NOT defeat violation
    - V_SEC-003 remains ACCEPTED
    - The "validation" claim creates no exception argument
    - Strict policy = no exceptions in formal logic
    """
    # Even with claimed validation, eval is strictly prohibited
    sanitized = ''.join(c for c in expr if c in '0123456789+-*/(). ')
    return eval(sanitized)  # STRICT VIOLATION - always dangerous


# =============================================================================
# STRICT VIOLATION: SQL-001 - SQL Injection
# =============================================================================
# Argumentation:
#   C_SQL-001: "Code complies with SQL-001 (parameterized queries)"
#   V_SQL-001_0: "Violation: string concatenation in SQL" → attacks C_SQL-001
#
# SQL injection is NEVER acceptable. Parameterized queries are always required.

def get_user_by_name(username):
    """
    Developer justification: "This is an internal admin tool"
    
    ARGUMENTATION RESULT: "Internal tool" is NOT an exception
    - SQL injection allows privilege escalation regardless of context
    - V_SQL-001 remains ACCEPTED in grounded extension
    """
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    # STRICT VIOLATION - no exceptions for SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


def search_products(category, min_price):
    """Even parameterizing some values doesn't fix string concat for others."""
    db = sqlite3.connect("products.db")
    cursor = db.cursor()
    # STRICT VIOLATION - partial parameterization is still injection
    query = "SELECT * FROM products WHERE category = '" + category + "' AND price > ?"
    cursor.execute(query, (min_price,))
    return cursor.fetchall()


# =============================================================================
# STRICT VIOLATION: CRYPTO-001 - Weak Cryptography
# =============================================================================
# Argumentation:
#   C_CRYPTO-001: "Code complies with CRYPTO-001 (strong crypto)"
#   V_CRYPTO-001_0: "Violation: MD5 used for password" → attacks C_CRYPTO-001
#
# MD5/SHA1 are cryptographically broken. No use case makes them acceptable
# for security purposes.

def hash_password(password):
    """
    Developer justification: "MD5 is fast for our high-volume login system"
    
    ARGUMENTATION RESULT: Performance is NOT a valid exception
    - Weak crypto enables password cracking attacks
    - V_CRYPTO-001 remains ACCEPTED
    - Use bcrypt/argon2 with appropriate work factors instead
    """
    # STRICT VIOLATION - MD5 is broken for password hashing
    return hashlib.md5(password.encode()).hexdigest()


def create_session_token(user_id):
    """SHA1 collision attacks are practical - not suitable for security tokens."""
    import time
    # STRICT VIOLATION - SHA1 is deprecated for security
    data = f"{user_id}:{time.time()}"
    return hashlib.sha1(data.encode()).hexdigest()


# =============================================================================
# FORMAL LOGIC SUMMARY
# =============================================================================
"""
ARGUMENTATION FRAMEWORK ANALYSIS:

Arguments (A):
  - C_SEC-001: Compliance claim for credentials policy
  - C_SEC-003: Compliance claim for dangerous functions policy  
  - C_SQL-001: Compliance claim for SQL injection policy
  - C_CRYPTO-001: Compliance claim for cryptography policy
  - V_SEC-001_0, V_SEC-001_1: Violation arguments for credentials
  - V_SEC-003_0: Violation argument for eval()
  - V_SQL-001_0, V_SQL-001_1: Violation arguments for SQL injection
  - V_CRYPTO-001_0, V_CRYPTO-001_1: Violation arguments for weak crypto

Attacks (→):
  - V_SEC-001_* → C_SEC-001
  - V_SEC-003_* → C_SEC-003
  - V_SQL-001_* → C_SQL-001
  - V_CRYPTO-001_* → C_CRYPTO-001

Grounded Extension (minimal defensible set):
  - All violation arguments V_* are ACCEPTED (unattacked)
  - All compliance arguments C_* are REJECTED (attacked by accepted V)

Decision: NON-COMPLIANT
  - ∃ accepted violation arguments
  - No exceptions possible for strict policies
  - All violations must be remediated before compliance
"""

if __name__ == "__main__":
    # Demonstrate strict violations
    print("Strict Policy Violations Demo")
    print("=" * 50)
    print("These violations CANNOT be defeated by exceptions.")
    print("In the argumentation framework, no E attacks V.")

