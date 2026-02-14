"""
Sample 12: Tool Mapping and Unmapped Findings Workflow
Violations: SQL-001, SEC-001, SEC-003

This file contains various security issues that tools like Bandit can detect.
Use this to test the tool integration workflow:
1. Browse rules in Tools → Browse Rules
2. Create mappings for unmapped rules
3. Analyze this code
4. See violations appear with tool badges
5. Check tool execution status to see unmapped findings
"""

# B608 - SQL injection via string formatting (should be mapped to SQL-001)
def get_user_data(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)

# B105 - Hardcoded password (should be mapped to SEC-001)
def login(username, password):
    stored_password = "supersecret123"  # Hardcoded password
    if password == stored_password:
        return True
    return False

# B307 - Use of eval (should be mapped to SEC-003)
def process_user_input(user_input):
    result = eval(user_input)  # Dangerous eval usage
    return result

# B601 - Shell injection (mapped to SQL-001)
def run_command(command):
    import subprocess
    subprocess.call(command, shell=True)  # Shell injection risk

# B602 - Shell injection via os.system (mapped to SEC-003)
def execute_system_command(cmd):
    import os
    os.system(cmd)  # Shell injection risk

# B104 - Hardcoded bind to all interfaces (mapped to SEC-001)
def start_server():
    import socket
    s = socket.socket()
    s.bind(('0.0.0.0', 8080))  # Binds to all interfaces
    s.listen(5)

# B102 - Use of exec (unmapped - will show in tool execution status)
def dynamic_code_execution(code):
    exec(code)  # Dangerous exec usage

# B101 - Use of assert (low severity, unmapped - will show in tool execution status)
def validate_input(value):
    assert value is not None  # Assert used in production code
    return value
