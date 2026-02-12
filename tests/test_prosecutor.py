"""Tests for the Prosecutor service."""
from pathlib import Path

# Add backend to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def test_prosecutor_analyze():
    """Test basic prosecutor analysis."""
    # Import here to avoid import issues before path setup
    from backend.app.services.prosecutor import Prosecutor
    from backend.app.services.policy_compiler import PolicyCompiler
    
    # Create a fresh compiler and prosecutor
    compiler = PolicyCompiler()
    compiler.load_policies()
    
    prosecutor = Prosecutor()
    prosecutor.policy_compiler = compiler
    
    # Test code with hardcoded password
    code = '''
def login(username, pwd):
    password = "secret123"
    api_key = "sk-12345"
    return authenticate(username, password)
'''
    
    result = prosecutor.analyze(code, "python")
    
    assert result.artifact_id is not None
    assert len(result.violations) > 0
    
    # Should find SEC-001 (hardcoded credentials)
    rule_ids = [v.rule_id for v in result.violations]
    assert "SEC-001" in rule_ids


def test_prosecutor_clean_code():
    """Test that clean code has no violations."""
    from backend.app.services.prosecutor import Prosecutor
    from backend.app.services.policy_compiler import PolicyCompiler
    
    compiler = PolicyCompiler()
    compiler.load_policies()
    
    prosecutor = Prosecutor()
    prosecutor.policy_compiler = compiler
    
    # Clean code using environment variables
    code = '''
import os

def login(username, pwd):
    secret = os.environ.get("PASSWORD")
    return authenticate(username, secret)
'''
    
    result = prosecutor.analyze(code, "python")
    
    # Should have no policy violations from our checks
    # (Bandit might find other things, but policy checks should pass)
    # Depending on policies, this might still have some
    # The main thing is no SEC-001
    sec001_violations = [v for v in result.violations if v.rule_id == "SEC-001"]
    assert len(sec001_violations) == 0


def test_prosecutor_sql_injection():
    """Test SQL injection detection."""
    from backend.app.services.prosecutor import Prosecutor
    from backend.app.services.policy_compiler import PolicyCompiler
    
    compiler = PolicyCompiler()
    compiler.load_policies()
    
    prosecutor = Prosecutor()
    prosecutor.policy_compiler = compiler
    
    # Code with SQL injection vulnerability
    code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
'''
    
    result = prosecutor.analyze(code, "python")
    
    # Should find SQL-001
    rule_ids = [v.rule_id for v in result.violations]
    assert "SQL-001" in rule_ids


def test_prosecutor_eval_detection():
    """Test dangerous function detection."""
    from backend.app.services.prosecutor import Prosecutor
    from backend.app.services.policy_compiler import PolicyCompiler
    
    compiler = PolicyCompiler()
    compiler.load_policies()
    
    prosecutor = Prosecutor()
    prosecutor.policy_compiler = compiler
    
    code = '''
def run_command(cmd):
    result = eval(cmd)
    return result
'''
    
    result = prosecutor.analyze(code, "python")
    
    # Should find SEC-003 (eval/exec)
    rule_ids = [v.rule_id for v in result.violations]
    assert "SEC-003" in rule_ids


def test_violation_summary():
    """Test violation summary generation."""
    from backend.app.services.prosecutor import Prosecutor
    from backend.app.models.schemas import Violation
    
    prosecutor = Prosecutor()
    
    violations = [
        Violation(rule_id="SEC-001", description="Test", severity="high", detector="regex"),
        Violation(rule_id="SEC-001", description="Test2", severity="high", detector="regex"),
        Violation(rule_id="SEC-003", description="Test3", severity="critical", detector="bandit"),
    ]
    
    summary = prosecutor.get_violation_summary(violations)
    
    assert summary['total'] == 3
    assert summary['by_severity']['high'] == 2
    assert summary['by_severity']['critical'] == 1
    assert summary['by_rule']['SEC-001'] == 2
    assert summary['by_rule']['SEC-003'] == 1


def test_prosecutor_records_runtime_guard_violation(monkeypatch):
    """Prosecutor should convert denied runtime guard decisions into violations."""
    from backend.app.services.prosecutor import Prosecutor
    from backend.app.services.tool_executor import ToolExecutionResult

    prosecutor = Prosecutor()

    denied = ToolExecutionResult(
        tool_name="bandit",
        success=False,
        error="blocked by runtime policy",
        policy_decision={
            "allowed": False,
            "rule_id": "RUNTIME-TOOL-DENYLIST",
            "severity": "high",
            "message": "Runtime policy denied tool 'bandit'.",
            "evidence": "tool=bandit",
        },
    )

    monkeypatch.setattr(
        prosecutor.tool_executor,
        "execute_tools_for_language",
        lambda **kwargs: [denied],
    )

    violations, tool_info = prosecutor.run_static_analysis_tools("print('x')", "python")

    assert len(violations) == 1
    assert violations[0].rule_id == "RUNTIME-TOOL-DENYLIST"
    assert violations[0].detector == "runtime_guard"
    assert "bandit" in tool_info
    assert tool_info["bandit"].policy_decision is not None
    assert tool_info["bandit"].policy_decision["allowed"] is False


def test_prosecutor_dynamic_analysis_violation(monkeypatch):
    """Prosecutor should include dynamic sandbox violations when enabled."""
    from backend.app.core.config import settings
    from backend.app.services.dynamic_analyzer import DynamicAnalyzer
    from backend.app.services.prosecutor import Prosecutor

    original_dynamic = settings.ENABLE_DYNAMIC_TESTING
    original_static = settings.ENABLE_STATIC_ANALYSIS
    original_timeout = settings.DYNAMIC_SANDBOX_TIMEOUT_SECONDS
    try:
        settings.ENABLE_DYNAMIC_TESTING = True
        settings.ENABLE_STATIC_ANALYSIS = False
        settings.DYNAMIC_SANDBOX_TIMEOUT_SECONDS = 2

        prosecutor = Prosecutor()
        prosecutor.dynamic_analyzer = DynamicAnalyzer()
        result = prosecutor.analyze("raise RuntimeError('x')", "python")

        assert result.dynamic_analysis is not None
        assert result.dynamic_analysis.executed is True
        assert any(v.detector == "dynamic_sandbox" for v in result.violations)
    finally:
        settings.ENABLE_DYNAMIC_TESTING = original_dynamic
        settings.ENABLE_STATIC_ANALYSIS = original_static
        settings.DYNAMIC_SANDBOX_TIMEOUT_SECONDS = original_timeout
