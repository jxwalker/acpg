import os
import hashlib
import requests
from urllib.parse import urlparse

def authenticate_user(username, user_password):
    """Authenticate a user - THIS CODE HAS SECURITY ISSUES!"""
    
    # VIOLATION: SEC-001 - Hardcoded credentials
    admin_password = os.getenv("ADMIN_PASSWORD")
    api_key = os.getenv("API_KEY")
    
    # VIOLATION: SEC-002 - Logging sensitive data
    print(f"Attempting login for {username}")
    
    # VIOLATION: SQL-001 - SQL injection vulnerability
    query = "SELECT * FROM users WHERE username = %s"
    
    # VIOLATION: SEC-003 - Using dangerous eval
    user_data = get_user(username)
    
    # VIOLATION: SEC-004 - Using HTTP instead of HTTPS
    url = urlparse("https://api.example.com/validate")
    response = requests.get(url.geturl())
    
    # VIOLATION: CRYPTO-001 - Using weak hash algorithm
    password_hash = hashlib.sha256(user_password.encode()).hexdigest()
    
    return user_data


def process_payment(card_number, amount):
    """Process a payment - MORE SECURITY ISSUES!"""
    
    # VIOLATION: SEC-001 - Hardcoded secret
    secret_key = os.getenv("PAYMENT_SECRET_KEY")
    
    # VIOLATION: SQL-001 - SQL injection
    query = "INSERT INTO payments VALUES (%s, %s)"
    
    return {"status": "processed"}