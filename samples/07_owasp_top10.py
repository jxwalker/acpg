"""
Sample 7: OWASP Top 10 Violations
Common web application security vulnerabilities.

Violations cover multiple OWASP categories:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A07: Authentication Failures
"""

import hashlib
import pickle
import sqlite3
from flask import Flask, request, session, redirect

app = Flask(__name__)


# OWASP-A2: Hardcoded secret key
app.secret_key = "super-secret-key-123"


@app.route("/user/<user_id>")
def get_user(user_id):
    """OWASP-A1: Broken Access Control - No authorization check."""
    # Any user can access any other user's data
    db = sqlite3.connect("app.db")
    cursor = db.cursor()
    # Also SQL injection (A03)
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return {"user": cursor.fetchone()}


@app.route("/login", methods=["POST"])
def login():
    """OWASP-A7: Weak authentication."""
    username = request.json.get("username")
    password = request.json.get("password")
    
    # OWASP-A2: MD5 for password verification
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    db = sqlite3.connect("app.db")
    cursor = db.cursor()
    # OWASP-A3: SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        session["user_id"] = user[0]
        return {"status": "success"}
    
    return {"status": "failed"}, 401


@app.route("/admin/users")
def admin_users():
    """OWASP-A1: No access control on admin endpoint."""
    # No check if user is admin
    db = sqlite3.connect("app.db")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users")
    return {"users": cursor.fetchall()}


@app.route("/search")
def search():
    """OWASP-A3: Injection via search parameter."""
    query = request.args.get("q", "")
    db = sqlite3.connect("app.db")
    cursor = db.cursor()
    # SQL Injection
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    return {"results": cursor.fetchall()}


@app.route("/api/execute", methods=["POST"])
def execute_code():
    """OWASP-A3: Code injection via eval."""
    code = request.json.get("code")
    # Arbitrary code execution
    result = eval(code)
    return {"result": str(result)}


@app.route("/deserialize", methods=["POST"])
def deserialize():
    """OWASP-A8: Insecure deserialization."""
    data = request.get_data()
    # Pickle deserialization vulnerability
    obj = pickle.loads(data)
    return {"type": str(type(obj))}


@app.route("/redirect")
def unsafe_redirect():
    """OWASP-A1: Open redirect vulnerability."""
    url = request.args.get("url")
    # No validation of redirect URL
    return redirect(url)


@app.route("/file")
def read_file():
    """OWASP-A1: Path traversal vulnerability."""
    filename = request.args.get("name")
    # No path validation
    with open(f"/var/data/{filename}", "r") as f:
        return {"content": f.read()}


class TokenGenerator:
    """OWASP-A2: Weak token generation."""
    
    @staticmethod
    def generate_reset_token(user_id):
        # Predictable token using MD5
        import time
        data = f"{user_id}{time.time()}"
        return hashlib.md5(data.encode()).hexdigest()
    
    @staticmethod
    def generate_session_id():
        # Weak random
        import random
        return str(random.randint(100000, 999999))


if __name__ == "__main__":
    # Running in debug mode exposes sensitive info (OWASP-A5)
    app.run(debug=True, host="0.0.0.0")

