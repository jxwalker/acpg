"""
DEMO: Vulnerable Code Sample
This code contains multiple security policy violations for demonstration.
"""

def authenticate_user(username, user_password):
    """Authenticate a user - THIS CODE HAS SECURITY ISSUES!"""
    
    # VIOLATION: SEC-001 - Hardcoded credentials
    admin_password = "super_secret_123"
    api_key = "sk-prod-abc123xyz789"
    
    # VIOLATION: SEC-002 - Logging sensitive data
    print(f"Attempting login for {username} with password {user_password}")
    
    # VIOLATION: SQL-001 - SQL injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    
    # VIOLATION: SEC-003 - Using dangerous eval
    user_data = eval(f"get_user('{username}')")
    
    # VIOLATION: SEC-004 - Using HTTP instead of HTTPS
    response = requests.get("http://api.example.com/validate")
    
    # VIOLATION: CRYPTO-001 - Using weak hash algorithm
    import hashlib
    password_hash = hashlib.md5(user_password.encode()).hexdigest()
    
    return user_data


def process_payment(card_number, amount):
    """Process a payment - MORE SECURITY ISSUES!"""
    
    # VIOLATION: SEC-001 - Hardcoded secret
    secret_key = "payment_secret_key_12345"
    
    # VIOLATION: SQL-001 - SQL injection
    query = f"INSERT INTO payments VALUES ('{card_number}', {amount})"
    
    return {"status": "processed"}

