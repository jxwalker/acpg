"""Tests for the Policy Compiler service."""
import pytest
import json
import tempfile
from pathlib import Path

# Add backend to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from backend.app.services.policy_compiler import PolicyCompiler
from backend.app.models.schemas import PolicyRule, PolicyCheck


@pytest.fixture
def sample_policies_json():
    """Create a temporary policies JSON file."""
    policies = {
        "policies": [
            {
                "id": "TEST-001",
                "description": "Test policy for regex matching",
                "type": "strict",
                "severity": "high",
                "check": {
                    "type": "regex",
                    "pattern": "password\\s*=",
                    "languages": ["python"]
                },
                "fix_suggestion": "Use environment variables"
            },
            {
                "id": "TEST-002",
                "description": "Defeasible test policy",
                "type": "defeasible",
                "severity": "medium",
                "check": {
                    "type": "manual",
                    "message": "Manual review required",
                    "languages": ["python"]
                }
            }
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(policies, f)
        return Path(f.name)


@pytest.fixture
def compiler(sample_policies_json):
    """Create a PolicyCompiler with sample policies."""
    c = PolicyCompiler()
    c.load_policies(sample_policies_json)
    return c


def test_policy_compiler_init():
    """Test PolicyCompiler initialization."""
    compiler = PolicyCompiler()
    assert compiler._policies == {}
    assert compiler._compiled_checks == {}


def test_load_policies(compiler):
    """Test loading policies from JSON."""
    policies = compiler.get_all_policies()
    assert len(policies) == 2
    assert policies[0].id == "TEST-001"
    assert policies[1].id == "TEST-002"


def test_validate_rule_valid():
    """Test validation of a valid rule."""
    compiler = PolicyCompiler()
    rule = PolicyRule(
        id="VALID-001",
        description="Valid test rule",
        type="strict",
        severity="high",
        check=PolicyCheck(type="regex", pattern="test.*pattern")
    )
    assert compiler.validate_rule(rule) is True


def test_validate_rule_invalid_regex():
    """Test validation fails for invalid regex."""
    compiler = PolicyCompiler()
    rule = PolicyRule(
        id="INVALID-001",
        description="Invalid regex rule",
        type="strict",
        severity="high",
        check=PolicyCheck(type="regex", pattern="[invalid(regex")
    )
    with pytest.raises(ValueError, match="Invalid regex"):
        compiler.validate_rule(rule)


def test_run_check_finds_violation(compiler):
    """Test that regex check finds violations."""
    code = '''
def login(user, pwd):
    password = "secret123"
    return auth(user, password)
'''
    violations = compiler.run_check("TEST-001", code, "python")
    assert len(violations) == 1
    assert violations[0].rule_id == "TEST-001"
    assert violations[0].line == 3


def test_run_check_no_violation(compiler):
    """Test that clean code has no violations."""
    code = '''
import os

def login(user, pwd):
    secret = os.environ.get("PASSWORD")
    return auth(user, secret)
'''
    violations = compiler.run_check("TEST-001", code, "python")
    assert len(violations) == 0


def test_run_all_checks(compiler):
    """Test running all policy checks."""
    code = 'password = "test"'
    violations = compiler.run_all_checks(code, "python")
    assert len(violations) >= 1


def test_get_strict_policies(compiler):
    """Test getting strict policies only."""
    strict = compiler.get_strict_policies()
    assert len(strict) == 1
    assert strict[0].id == "TEST-001"


def test_get_defeasible_policies(compiler):
    """Test getting defeasible policies only."""
    defeasible = compiler.get_defeasible_policies()
    assert len(defeasible) == 1
    assert defeasible[0].id == "TEST-002"


def test_get_knowledge_base(compiler):
    """Test getting the full knowledge base."""
    kb = compiler.get_knowledge_base()
    assert 'policies' in kb
    assert 'strict_rules' in kb
    assert 'defeasible_rules' in kb
    assert 'severity_order' in kb
    assert 'TEST-001' in kb['strict_rules']
    assert 'TEST-002' in kb['defeasible_rules']


def test_language_filtering(compiler):
    """Test that checks respect language filtering."""
    code = 'password = "test"'
    
    # Should find violation for Python
    py_violations = compiler.run_check("TEST-001", code, "python")
    assert len(py_violations) == 1
    
    # Should NOT find violation for JavaScript (not in languages list)
    # Actually this policy includes python only, so js should have no violations
    js_violations = compiler.run_check("TEST-001", code, "javascript")
    assert len(js_violations) == 0

