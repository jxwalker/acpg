"""
Sample 4: Weak Cryptography
Violations: CRYPTO-001 (Weak hash algorithms)

This code demonstrates use of deprecated and weak
cryptographic algorithms.
"""

import hashlib
import random


def hash_password_md5(password):
    """VULNERABLE: Using MD5 for password hashing."""
    # CRYPTO-001: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password):
    """VULNERABLE: Using SHA1 for password hashing."""
    # CRYPTO-001: SHA1 is deprecated for security use
    return hashlib.sha1(password.encode()).hexdigest()


def verify_file_integrity_md5(filepath):
    """VULNERABLE: Using MD5 for integrity checking."""
    # CRYPTO-001: MD5 is vulnerable to collision attacks
    with open(filepath, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def generate_token():
    """VULNERABLE: Using weak random for security tokens."""
    # CRYPTO-001: random module is not cryptographically secure
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(32))


def create_session_id():
    """VULNERABLE: Predictable session ID generation."""
    # CRYPTO-001: random.randint is predictable
    return str(random.randint(100000, 999999))


def simple_hash(data):
    """VULNERABLE: Custom weak hash function."""
    # CRYPTO-001: Custom crypto is almost always wrong
    hash_value = 0
    for char in data:
        hash_value = (hash_value * 31 + ord(char)) % (2**32)
    return hex(hash_value)


class PasswordManager:
    """VULNERABLE: Password manager using weak hashing."""
    
    def __init__(self):
        self.passwords = {}
    
    def store_password(self, username, password):
        # CRYPTO-001: MD5 for password storage
        hashed = hashlib.md5(password.encode()).hexdigest()
        self.passwords[username] = hashed
    
    def verify_password(self, username, password):
        # CRYPTO-001: MD5 comparison
        hashed = hashlib.md5(password.encode()).hexdigest()
        return self.passwords.get(username) == hashed


def encrypt_sensitive_data(data, key):
    """VULNERABLE: XOR 'encryption' - not real encryption."""
    # CRYPTO-001: XOR is not encryption
    encrypted = ""
    for i, char in enumerate(data):
        encrypted += chr(ord(char) ^ ord(key[i % len(key)]))
    return encrypted

