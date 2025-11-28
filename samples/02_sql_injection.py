"""
Sample 2: SQL Injection Vulnerabilities
Violations: SQL-001 (String concatenation in SQL)

This code demonstrates SQL injection vulnerabilities through
unsafe query construction.
"""

import sqlite3


def get_user_unsafe(username):
    """VULNERABLE: Direct string concatenation in SQL."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # SQL-001: String concatenation allows injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    return cursor.fetchone()


def search_products_unsafe(search_term, category):
    """VULNERABLE: F-string SQL query construction."""
    conn = sqlite3.connect("products.db")
    cursor = conn.cursor()
    
    # SQL-001: F-string allows injection
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%' AND category = '{category}'"
    cursor.execute(query)
    
    return cursor.fetchall()


def update_user_unsafe(user_id, new_email):
    """VULNERABLE: Format string SQL query."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # SQL-001: .format() allows injection
    query = "UPDATE users SET email = '{}' WHERE id = {}".format(new_email, user_id)
    cursor.execute(query)
    conn.commit()


def delete_order_unsafe(order_id):
    """VULNERABLE: Percent formatting in SQL."""
    conn = sqlite3.connect("orders.db")
    cursor = conn.cursor()
    
    # SQL-001: % formatting allows injection
    query = "DELETE FROM orders WHERE order_id = '%s'" % order_id
    cursor.execute(query)
    conn.commit()


def complex_query_unsafe(filters):
    """VULNERABLE: Building complex queries unsafely."""
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    
    # SQL-001: Dynamic query building
    query = "SELECT * FROM transactions WHERE 1=1"
    
    if filters.get("user_id"):
        query += " AND user_id = '" + filters["user_id"] + "'"
    
    if filters.get("status"):
        query += " AND status = '" + filters["status"] + "'"
    
    if filters.get("min_amount"):
        query += " AND amount >= " + str(filters["min_amount"])
    
    cursor.execute(query)
    return cursor.fetchall()

