"""Tests for sandboxed dynamic analyzer."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def test_dynamic_analyzer_disabled(monkeypatch):
    """Dynamic analyzer should skip execution when feature flag is disabled."""
    from backend.app.core.config import settings
    from backend.app.services.dynamic_analyzer import DynamicAnalyzer

    monkeypatch.setattr(settings, "ENABLE_DYNAMIC_TESTING", False)
    analyzer = DynamicAnalyzer()
    result = analyzer.analyze("print('ok')", "python", "artifact123")

    assert result.executed is False
    assert result.violations == []
    assert result.artifacts == []


def test_dynamic_analyzer_exception_violation(monkeypatch):
    """Unhandled exception in sandboxed run should produce DYN-EXEC-EXCEPTION."""
    from backend.app.core.config import settings
    from backend.app.services.dynamic_analyzer import DynamicAnalyzer

    monkeypatch.setattr(settings, "ENABLE_DYNAMIC_TESTING", True)
    monkeypatch.setattr(settings, "DYNAMIC_SANDBOX_TIMEOUT_SECONDS", 2)
    analyzer = DynamicAnalyzer()

    code = "raise ValueError('boom')"
    result = analyzer.analyze(code, "python", "artifact456")

    assert result.executed is True
    assert len(result.artifacts) >= 2
    assert all(artifact.replay.deterministic_fingerprint for artifact in result.artifacts)
    suite_ids = {artifact.suite_id for artifact in result.artifacts}
    assert "direct_execution" in suite_ids
    assert "import_execution" in suite_ids
    assert any(v.rule_id == "DYN-EXEC-EXCEPTION" for v in result.violations)


def test_dynamic_analyzer_timeout_violation(monkeypatch):
    """Execution beyond timeout should produce DYN-EXEC-TIMEOUT."""
    from backend.app.core.config import settings
    from backend.app.services.dynamic_analyzer import DynamicAnalyzer

    monkeypatch.setattr(settings, "ENABLE_DYNAMIC_TESTING", True)
    monkeypatch.setattr(settings, "DYNAMIC_SANDBOX_TIMEOUT_SECONDS", 1)
    analyzer = DynamicAnalyzer()

    code = "import time\ntime.sleep(3)\nprint('late')"
    result = analyzer.analyze(code, "python", "artifact789")

    assert result.executed is True
    assert any(artifact.timed_out for artifact in result.artifacts)
    assert any(v.rule_id == "DYN-EXEC-TIMEOUT" for v in result.violations)


def test_dynamic_analyzer_entrypoint_suite(monkeypatch):
    """Analyzer should add entrypoint suite for deterministic call surfaces."""
    from backend.app.core.config import settings
    from backend.app.services.dynamic_analyzer import DynamicAnalyzer

    monkeypatch.setattr(settings, "ENABLE_DYNAMIC_TESTING", True)
    monkeypatch.setattr(settings, "DYNAMIC_SANDBOX_TIMEOUT_SECONDS", 2)
    analyzer = DynamicAnalyzer()

    code = "def main():\n    return 'ok'\n"
    result = analyzer.analyze(code, "python", "artifact_entry")

    suite_ids = {artifact.suite_id for artifact in result.artifacts}
    assert "entrypoint_main" in suite_ids
