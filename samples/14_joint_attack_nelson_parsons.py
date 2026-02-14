"""
Sample 14: Joint attack (Nielsen-Parsons style)
Violations: SEC-001, SEC-003, SQL-001

Purpose:
- Demo case for joint-attack reasoning and policy conflict discussion.
- Combine multiple risky constructs so policy arguments and attack relations are non-trivial.
"""

import sqlite3


API_KEY = "hardcoded-demo-key"  # SEC-001


def run_admin_query(user_id: str, allow_console: bool, dry_run: bool) -> list[tuple]:
    """
    The design intent is to require BOTH controls to justify dangerous behavior:
    - allow_console must be True
    - dry_run must be True

    This creates a useful joint-attack discussion in proof reasoning:
    a single mitigation alone should not defeat the violation claim.
    """
    query = f"SELECT * FROM accounts WHERE owner = '{user_id}'"  # SQL-001

    if allow_console:
        # SEC-003
        eval("print('console mode enabled')")

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE accounts (owner TEXT, balance INTEGER)")
    cursor.execute("INSERT INTO accounts VALUES ('alice', 100)")
    rows = cursor.execute(query).fetchall()
    conn.close()

    if dry_run:
        return rows

    return rows


if __name__ == "__main__":
    print(run_admin_query("alice", allow_console=True, dry_run=False))
