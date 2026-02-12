"""Tests for runtime policy guards."""
from pathlib import Path
import sys

# Add backend to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def test_runtime_guard_denylist():
    """Guard should deny tools in denylist."""
    from backend.app.core.config import settings
    from backend.app.services.runtime_guard import RuntimeGuard

    original_enabled = settings.ENABLE_RUNTIME_GUARDS
    original_denylist = settings.RUNTIME_TOOL_DENYLIST
    original_allowlist = settings.RUNTIME_TOOL_ALLOWLIST
    try:
        settings.ENABLE_RUNTIME_GUARDS = True
        settings.RUNTIME_TOOL_ALLOWLIST = []
        settings.RUNTIME_TOOL_DENYLIST = ["bandit"]

        decision = RuntimeGuard().evaluate_tool("bandit", ["bandit", "-f", "json"], "python")

        assert decision.allowed is False
        assert decision.action == "deny"
        assert decision.rule_id == "RUNTIME-TOOL-DENYLIST"
    finally:
        settings.ENABLE_RUNTIME_GUARDS = original_enabled
        settings.RUNTIME_TOOL_DENYLIST = original_denylist
        settings.RUNTIME_TOOL_ALLOWLIST = original_allowlist


def test_tool_executor_short_circuits_on_runtime_guard():
    """Tool executor should return denied result before running subprocess."""
    from backend.app.core.config import settings
    from backend.app.core.static_analyzers import ToolConfig
    from backend.app.services.tool_executor import ToolExecutor

    original_enabled = settings.ENABLE_RUNTIME_GUARDS
    original_denylist = settings.RUNTIME_TOOL_DENYLIST
    original_allowlist = settings.RUNTIME_TOOL_ALLOWLIST
    try:
        settings.ENABLE_RUNTIME_GUARDS = True
        settings.RUNTIME_TOOL_ALLOWLIST = []
        settings.RUNTIME_TOOL_DENYLIST = ["forbidden-tool"]

        executor = ToolExecutor()
        cfg = ToolConfig(
            name="forbidden-tool",
            command=["forbidden-tool", "--version"],
            parser="text",
            enabled=True,
            requires_file=False,
            output_format="text",
            languages=["python"],
        )

        result = executor.execute_tool(cfg, content="print('ok')", use_cache=False)

        assert result.success is False
        assert result.policy_decision is not None
        assert result.policy_decision["allowed"] is False
        assert result.policy_decision["action"] == "deny"
        assert result.policy_decision["rule_id"] == "RUNTIME-TOOL-DENYLIST"
    finally:
        settings.ENABLE_RUNTIME_GUARDS = original_enabled
        settings.RUNTIME_TOOL_DENYLIST = original_denylist
        settings.RUNTIME_TOOL_ALLOWLIST = original_allowlist


def test_runtime_guard_monitoring_action():
    """Configured monitoring rule should allow execution with monitoring metadata."""
    from backend.app.services.runtime_guard import RuntimeGuard

    decision = RuntimeGuard().evaluate_tool("safety", ["safety", "--version"], "python")

    assert decision.allowed is True
    assert decision.action in {"allow", "allow_with_monitoring"}
