"""Registry of known rules for static analysis tools."""
from typing import Dict, List, Optional, Any

# Known rules for common static analysis tools
# This allows users to browse available rules before creating mappings

TOOL_RULES_REGISTRY: Dict[str, Dict[str, Dict[str, Any]]] = {
    "bandit": {
        "B101": {
            "id": "B101",
            "name": "assert_used",
            "description": "Use of assert detected. The enclosed code will be removed when compiling to optimized byte code.",
            "severity": "low",
            "test_id": "assert_used"
        },
        "B102": {
            "id": "B102",
            "name": "exec_used",
            "description": "Use of exec detected.",
            "severity": "high",
            "test_id": "exec_used"
        },
        "B103": {
            "id": "B103",
            "name": "set_bad_file_permissions",
            "description": "Standard library function to set file permissions found, insecure file permissions set.",
            "severity": "medium",
            "test_id": "set_bad_file_permissions"
        },
        "B104": {
            "id": "B104",
            "name": "hardcoded_bind_all_interfaces",
            "description": "Possible binding to all interfaces.",
            "severity": "medium",
            "test_id": "hardcoded_bind_all_interfaces"
        },
        "B105": {
            "id": "B105",
            "name": "hardcoded_password_string",
            "description": "Possible hardcoded password: {match}",
            "severity": "high",
            "test_id": "hardcoded_password_string"
        },
        "B106": {
            "id": "B106",
            "name": "hardcoded_password_funcarg",
            "description": "Possible hardcoded password: {match}",
            "severity": "high",
            "test_id": "hardcoded_password_funcarg"
        },
        "B107": {
            "id": "B107",
            "name": "hardcoded_password_default",
            "description": "Possible hardcoded password: {match}",
            "severity": "high",
            "test_id": "hardcoded_password_default"
        },
        "B201": {
            "id": "B201",
            "name": "flask_debug_true",
            "description": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
            "severity": "high",
            "test_id": "flask_debug_true"
        },
        "B301": {
            "id": "B301",
            "name": "blacklist_calls",
            "description": "Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.",
            "severity": "high",
            "test_id": "blacklist_calls"
        },
        "B302": {
            "id": "B302",
            "name": "blacklist_imports",
            "description": "Import of {module} module detected.",
            "severity": "high",
            "test_id": "blacklist_imports"
        },
        "B303": {
            "id": "B303",
            "name": "blacklist_calls",
            "description": "Use of insecure MD2, MD4, MD5, or SHA1 hash function.",
            "severity": "high",
            "test_id": "blacklist_calls"
        },
        "B304": {
            "id": "B304",
            "name": "blacklist_calls",
            "description": "Use of insecure cipher mode.",
            "severity": "high",
            "test_id": "blacklist_calls"
        },
        "B305": {
            "id": "B305",
            "name": "blacklist_calls",
            "description": "Use of insecure cipher. Upgrade to a known secure cipher such as AES.",
            "severity": "high",
            "test_id": "blacklist_calls"
        },
        "B306": {
            "id": "B306",
            "name": "blacklist_calls",
            "description": "Use of insecure cipher mode.",
            "severity": "high",
            "test_id": "blacklist_calls"
        },
        "B307": {
            "id": "B307",
            "name": "blacklist_calls",
            "description": "Use of possibly insecure function - consider using safer ast.literal_eval.",
            "severity": "high",
            "test_id": "blacklist_calls"
        },
        "B308": {
            "id": "B308",
            "name": "blacklist_calls",
            "description": "Use of insecure cipher mode.",
            "severity": "high",
            "test_id": "blacklist_calls"
        },
        "B309": {
            "id": "B309",
            "name": "blacklist_calls",
            "description": "Use of insecure cipher mode.",
            "severity": "high",
            "test_id": "blacklist_calls"
        },
        "B310": {
            "id": "B310",
            "name": "blacklist_imports",
            "description": "Import of {module} module detected.",
            "severity": "high",
            "test_id": "blacklist_imports"
        },
        "B311": {
            "id": "B311",
            "name": "blacklist_calls",
            "description": "Use of insecure random number generator.",
            "severity": "high",
            "test_id": "blacklist_calls"
        },
        "B312": {
            "id": "B312",
            "name": "blacklist_calls",
            "description": "Use of insecure cipher mode.",
            "severity": "high",
            "test_id": "blacklist_calls"
        },
        "B313": {
            "id": "B313",
            "name": "blacklist_calls",
            "description": "Use of insecure cipher mode.",
            "severity": "high",
            "test_id": "blacklist_calls"
        },
        "B401": {
            "id": "B401",
            "name": "import_telnetlib",
            "description": "A telnet-related module is being imported. Telnet is considered insecure. Use SSH instead.",
            "severity": "high",
            "test_id": "import_telnetlib"
        },
        "B402": {
            "id": "B402",
            "name": "import_ftplib",
            "description": "A FTP-related module is being imported. FTP is considered insecure. Use SFTP instead.",
            "severity": "high",
            "test_id": "import_ftplib"
        },
        "B403": {
            "id": "B403",
            "name": "import_xmlrpc",
            "description": "An XMLRPC module is being imported. XMLRPC is vulnerable to remote code execution.",
            "severity": "high",
            "test_id": "import_xmlrpc"
        },
        "B501": {
            "id": "B501",
            "name": "request_with_no_cert_validation",
            "description": "Requests call with verify=False disabling SSL certificate checks, security issue.",
            "severity": "high",
            "test_id": "request_with_no_cert_validation"
        },
        "B502": {
            "id": "B502",
            "name": "request_with_no_cert_validation",
            "description": "Requests call with verify=False disabling SSL certificate checks, security issue.",
            "severity": "high",
            "test_id": "request_with_no_cert_validation"
        },
        "B503": {
            "id": "B503",
            "name": "ssl_with_bad_version",
            "description": "SSL connection with insecure version. It's recommended to use SSL version >= TLS 1.2",
            "severity": "high",
            "test_id": "ssl_with_bad_version"
        },
        "B504": {
            "id": "B504",
            "name": "ssl_with_bad_defaults",
            "description": "SSL connection with insecure default settings. It's recommended to use SSLContext with secure defaults.",
            "severity": "high",
            "test_id": "ssl_with_bad_defaults"
        },
        "B505": {
            "id": "B505",
            "name": "weak_cryptographic_key",
            "description": "Use of weak cryptographic key. Increase key size.",
            "severity": "high",
            "test_id": "weak_cryptographic_key"
        },
        "B506": {
            "id": "B506",
            "name": "yaml_load",
            "description": "Use of unsafe yaml load. Allows arbitrary code execution. Use yaml.safe_load instead.",
            "severity": "high",
            "test_id": "yaml_load"
        },
        "B601": {
            "id": "B601",
            "name": "shell_injection_subprocess",
            "description": "Possible shell injection via {name}",
            "severity": "critical",
            "test_id": "shell_injection_subprocess"
        },
        "B602": {
            "id": "B602",
            "name": "shell_injection",
            "description": "Possible shell injection via {name}",
            "severity": "high",
            "test_id": "shell_injection"
        },
        "B603": {
            "id": "B603",
            "name": "subprocess_without_shell_equals_true",
            "description": "subprocess call - check for execution of untrusted input.",
            "severity": "high",
            "test_id": "subprocess_without_shell_equals_true"
        },
        "B604": {
            "id": "B604",
            "name": "any_other_function_with_shell_equals_true",
            "description": "Function call with shell=True parameter identified, security issue.",
            "severity": "high",
            "test_id": "any_other_function_with_shell_equals_true"
        },
        "B605": {
            "id": "B605",
            "name": "start_process_with_a_shell",
            "description": "Starting a process with a shell: True. See docs for security concerns.",
            "severity": "high",
            "test_id": "start_process_with_a_shell"
        },
        "B606": {
            "id": "B606",
            "name": "start_process_with_no_shell",
            "description": "Starting a process without a shell.",
            "severity": "low",
            "test_id": "start_process_with_no_shell"
        },
        "B607": {
            "id": "B607",
            "name": "start_process_with_partial_path",
            "description": "Starting a process with a partial executable path.",
            "severity": "medium",
            "test_id": "start_process_with_partial_path"
        },
        "B608": {
            "id": "B608",
            "name": "hardcoded_sql_expressions",
            "description": "Possible SQL injection vector through string-based query construction.",
            "severity": "critical",
            "test_id": "hardcoded_sql_expressions"
        },
        "B609": {
            "id": "B609",
            "name": "linux_commands_wildcard_injection",
            "description": "Possible wildcard injection in call to {name}",
            "severity": "high",
            "test_id": "linux_commands_wildcard_injection"
        },
        "B610": {
            "id": "B610",
            "name": "django_sql_injection",
            "description": "Possible SQL injection vector through string-based query construction.",
            "severity": "critical",
            "test_id": "django_sql_injection"
        },
        "B611": {
            "id": "B611",
            "name": "shell_injection",
            "description": "Possible shell injection via {name}",
            "severity": "high",
            "test_id": "shell_injection"
        }
    },
    "eslint": {
        "no-eval": {
            "id": "no-eval",
            "name": "no-eval",
            "description": "Disallow the use of eval()",
            "severity": "high",
            "category": "Possible Errors"
        },
        "no-implied-eval": {
            "id": "no-implied-eval",
            "name": "no-implied-eval",
            "description": "Disallow the use of eval()-like methods",
            "severity": "high",
            "category": "Possible Errors"
        },
        "no-new-func": {
            "id": "no-new-func",
            "name": "no-new-func",
            "description": "Disallow the use of the Function constructor",
            "severity": "high",
            "category": "Possible Errors"
        },
        "no-script-url": {
            "id": "no-script-url",
            "name": "no-script-url",
            "description": "Disallow script URLs",
            "severity": "medium",
            "category": "Best Practices"
        },
        "no-proto": {
            "id": "no-proto",
            "name": "no-proto",
            "description": "Disallow the use of __proto__",
            "severity": "medium",
            "category": "Best Practices"
        },
        "no-iterator": {
            "id": "no-iterator",
            "name": "no-iterator",
            "description": "Disallow the use of __iterator__",
            "severity": "low",
            "category": "Best Practices"
        },
        "no-caller": {
            "id": "no-caller",
            "name": "no-caller",
            "description": "Disallow the use of arguments.caller or arguments.callee",
            "severity": "medium",
            "category": "Best Practices"
        }
    },
    "pylint": {
        "eval-used": {
            "id": "eval-used",
            "name": "eval-used",
            "description": "Used eval (dangerous)",
            "severity": "high",
            "category": "Security"
        },
        "exec-used": {
            "id": "exec-used",
            "name": "exec-used",
            "description": "Used exec (dangerous)",
            "severity": "high",
            "category": "Security"
        }
    },
    "safety": {
        "vulnerability": {
            "id": "vulnerability",
            "name": "vulnerability",
            "description": "Known security vulnerability in dependency",
            "severity": "high",
            "category": "Security"
        }
    }
}


def get_tool_rules(tool_name: str) -> Dict[str, Dict[str, Any]]:
    """Get all known rules for a tool."""
    return TOOL_RULES_REGISTRY.get(tool_name, {})


def get_all_tool_rules() -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Get all known rules for all tools."""
    return TOOL_RULES_REGISTRY.copy()


def get_tool_rule(tool_name: str, rule_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific rule for a tool."""
    tool_rules = TOOL_RULES_REGISTRY.get(tool_name, {})
    return tool_rules.get(rule_id)

