"""
Sample 3: Dangerous Function Usage
Violations: SEC-003 (eval/exec usage)

This code demonstrates dangerous use of eval(), exec(),
and other code execution functions.
"""

import pickle
import yaml


def calculate_expression(user_input):
    """VULNERABLE: Using eval on user input."""
    # SEC-003: eval() can execute arbitrary code
    result = eval(user_input)
    return result


def run_dynamic_code(code_string):
    """VULNERABLE: Using exec on dynamic code."""
    # SEC-003: exec() executes arbitrary code
    exec(code_string)


def process_config(config_string):
    """VULNERABLE: Using eval for config parsing."""
    # SEC-003: eval() for parsing is dangerous
    config = eval(config_string)
    return config


def deserialize_data(data_bytes):
    """VULNERABLE: Pickle deserialization of untrusted data."""
    # SEC-003: pickle.loads can execute arbitrary code
    return pickle.loads(data_bytes)


def load_yaml_config(yaml_string):
    """VULNERABLE: Unsafe YAML loading."""
    # SEC-003: yaml.load without Loader can execute code
    return yaml.load(yaml_string)


def dynamic_import(module_name):
    """VULNERABLE: Dynamic code execution via __import__."""
    # SEC-003: Can be used to import malicious modules
    module = __import__(module_name)
    return module


def compile_and_run(source_code, filename="<dynamic>"):
    """VULNERABLE: Compiling and executing user code."""
    # SEC-003: compile + exec is very dangerous
    code = compile(source_code, filename, "exec")
    exec(code)


def math_evaluator(expression, variables):
    """VULNERABLE: Trying to 'safely' eval math - still dangerous."""
    # SEC-003: Even with locals, eval is dangerous
    return eval(expression, {"__builtins__": {}}, variables)


class DynamicProcessor:
    """VULNERABLE: Class using eval for method dispatch."""
    
    def process(self, method_name, data):
        # SEC-003: Using eval for method calls
        return eval(f"self._{method_name}(data)")
    
    def _transform(self, data):
        return data.upper()
    
    def _validate(self, data):
        return len(data) > 0

