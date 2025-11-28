"""
Sample 1: Hardcoded Secrets
Violations: SEC-001 (Hardcoded credentials)

This code demonstrates the most common security anti-pattern:
embedding secrets directly in source code.
"""

# Database configuration with hardcoded credentials
DATABASE_CONFIG = {
    "host": "db.production.internal",
    "port": 5432,
    "username": "admin",
    "password": "SuperSecret123!",  # SEC-001: Hardcoded password
    "database": "customers"
}

# API keys embedded in code
STRIPE_API_KEY = "sk_live_abc123xyz789"  # SEC-001: Hardcoded API key
SENDGRID_KEY = "SG.abcdefghijklmnop"  # SEC-001: Hardcoded API key
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # SEC-001

# OAuth credentials
OAUTH_CONFIG = {
    "client_id": "my-app-client",
    "client_secret": "oauth_secret_do_not_share_123",  # SEC-001
    "redirect_uri": "https://myapp.com/callback"
}


def connect_to_database():
    """Connect using hardcoded credentials - BAD PRACTICE."""
    import psycopg2
    return psycopg2.connect(
        host=DATABASE_CONFIG["host"],
        user=DATABASE_CONFIG["username"],
        password=DATABASE_CONFIG["password"],
        database=DATABASE_CONFIG["database"]
    )


def send_payment(amount, customer_id):
    """Process payment with hardcoded API key - BAD PRACTICE."""
    import stripe
    stripe.api_key = STRIPE_API_KEY
    return stripe.Charge.create(
        amount=amount,
        currency="usd",
        customer=customer_id
    )

