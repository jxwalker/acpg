"""
DEMO: Compliant Code Sample
This code follows all security policies and best practices.
"""
import os
import hashlib
from typing import Optional, Dict, Any


def authenticate_user(username: str, user_password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate a user following security best practices.
    
    This code is COMPLIANT with all ACPG policies:
    - No hardcoded credentials (uses environment variables)
    - No sensitive data in logs
    - Parameterized SQL queries
    - No eval/exec usage
    - HTTPS for external calls
    - Strong cryptographic algorithms
    """
    
    # COMPLIANT: Get credentials from environment
    admin_password_hash = os.environ.get("ADMIN_PASSWORD_HASH")
    api_key = os.environ.get("API_KEY")
    
    # COMPLIANT: No sensitive data in logs
    print(f"Attempting login for user: {username}")
    
    # COMPLIANT: Parameterized SQL query
    query = "SELECT * FROM users WHERE username = ?"
    user_data = db.execute(query, (username,))
    
    # COMPLIANT: Safe data retrieval (no eval)
    user_data = get_user_safely(username)
    
    # COMPLIANT: Using HTTPS
    response = requests.get("https://api.example.com/validate")
    
    # COMPLIANT: Using strong hash algorithm (SHA-256)
    password_hash = hashlib.sha256(user_password.encode()).hexdigest()
    
    if verify_password(password_hash, admin_password_hash):
        return {"status": "authenticated", "user": username}
    return None


def process_payment(card_number: str, amount: float) -> Dict[str, str]:
    """
    Process a payment following security best practices.
    
    COMPLIANT with all security policies.
    """
    
    # COMPLIANT: Get secret from environment
    secret_key = os.environ.get("PAYMENT_SECRET_KEY")
    
    # COMPLIANT: Parameterized SQL query
    query = "INSERT INTO payments (card_hash, amount) VALUES (?, ?)"
    card_hash = hashlib.sha256(card_number.encode()).hexdigest()
    db.execute(query, (card_hash, amount))
    
    return {"status": "processed"}

