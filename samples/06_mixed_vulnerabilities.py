"""
Sample 6: Mixed Vulnerabilities
Multiple violation types in a realistic application.

Violations:
- SEC-001: Hardcoded credentials
- SEC-003: Dangerous eval
- SQL-001: SQL injection
- CRYPTO-001: Weak hashing
- SEC-004: HTTP connections
"""

import hashlib
import sqlite3
import requests


# SEC-001: Hardcoded credentials
DB_PASSWORD = "admin123"
API_SECRET = "sk_live_secretkey123"


class UserService:
    """User service with multiple security issues."""
    
    def __init__(self):
        # SEC-004: HTTP connection
        self.auth_url = "http://auth.internal.com/verify"
        self.db = sqlite3.connect("users.db")
    
    def authenticate(self, username, password):
        """Multiple vulnerabilities in authentication."""
        # CRYPTO-001: MD5 for password hashing
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        # SQL-001: SQL injection vulnerability
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
        
        cursor = self.db.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            # SEC-004: HTTP for token verification
            response = requests.post(self.auth_url, json={"user_id": user[0]})
            return response.json().get("token")
        
        return None
    
    def search_users(self, query_string):
        """Search with SQL injection."""
        # SQL-001: Direct string concatenation
        sql = "SELECT * FROM users WHERE name LIKE '%" + query_string + "%'"
        cursor = self.db.cursor()
        cursor.execute(sql)
        return cursor.fetchall()
    
    def execute_admin_command(self, command):
        """Dangerous command execution."""
        # SEC-003: eval for command processing
        return eval(command)
    
    def calculate_discount(self, formula):
        """Dynamic pricing with eval."""
        # SEC-003: eval for calculations
        base_price = 100
        return eval(formula)


class PaymentProcessor:
    """Payment processor with security issues."""
    
    def __init__(self):
        # SEC-001: Hardcoded API key
        self.api_key = "pk_live_payment_key_xyz"
        # SEC-004: HTTP endpoint
        self.gateway_url = "http://payments.gateway.com/process"
    
    def process_payment(self, card_number, amount, user_id):
        """Process payment with multiple issues."""
        # CRYPTO-001: MD5 for transaction ID
        tx_id = hashlib.md5(f"{card_number}{amount}".encode()).hexdigest()
        
        # SEC-004: HTTP for payment processing
        response = requests.post(self.gateway_url, json={
            "card": card_number,
            "amount": amount,
            "api_key": self.api_key,
            "tx_id": tx_id
        })
        
        # SQL-001: Logging with SQL injection
        self._log_transaction(user_id, amount, tx_id)
        
        return response.json()
    
    def _log_transaction(self, user_id, amount, tx_id):
        """Log transaction with SQL injection."""
        db = sqlite3.connect("transactions.db")
        cursor = db.cursor()
        # SQL-001: String concatenation
        query = f"INSERT INTO logs VALUES ('{user_id}', {amount}, '{tx_id}')"
        cursor.execute(query)
        db.commit()


def main():
    """Main function demonstrating all vulnerabilities."""
    # SEC-001: Using hardcoded password
    service = UserService()
    service.authenticate("admin", DB_PASSWORD)
    
    # SEC-003: User-controlled eval
    processor = PaymentProcessor()
    processor.process_payment("4111111111111111", 99.99, "user123")


if __name__ == "__main__":
    main()

