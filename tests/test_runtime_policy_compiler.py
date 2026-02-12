"""Tests for runtime policy compiler decisions."""
import json
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def test_runtime_policy_compiler_deny_rule(tmp_path):
    """Compiler should apply deny action when a matching high-priority rule exists."""
    from backend.app.services.runtime_policy_compiler import RuntimePolicyCompiler

    policy_file = tmp_path / "runtime_policies.json"
    policy_file.write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "id": "RUNTIME-DENY-CURL",
                        "description": "deny curl tools",
                        "event_type": "tool",
                        "action": "deny",
                        "priority": 200,
                        "conditions": {"tool_names": ["curl"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    compiler = RuntimePolicyCompiler(policy_path=policy_file)
    decision = compiler.evaluate_tool("curl", ["curl", "https://example.com"], "python")

    assert decision.allowed is False
    assert decision.action == "deny"
    assert decision.rule_id == "RUNTIME-DENY-CURL"


def test_runtime_policy_compiler_priority_order(tmp_path):
    """Higher-priority matching rule should be selected deterministically."""
    from backend.app.services.runtime_policy_compiler import RuntimePolicyCompiler

    policy_file = tmp_path / "runtime_policies.json"
    policy_file.write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "id": "LOW-PRIORITY-MONITOR",
                        "description": "monitor python tools",
                        "event_type": "tool",
                        "action": "allow_with_monitoring",
                        "priority": 10,
                        "conditions": {"languages": ["python"]},
                    },
                    {
                        "id": "HIGH-PRIORITY-DENY",
                        "description": "deny specific command",
                        "event_type": "tool",
                        "action": "deny",
                        "priority": 100,
                        "conditions": {"command_contains": ["pip install"]},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    compiler = RuntimePolicyCompiler(policy_path=policy_file)
    decision = compiler.evaluate_tool("python", ["python", "-m", "pip", "install", "x"], "python")

    assert decision.rule_id == "HIGH-PRIORITY-DENY"
    assert decision.action == "deny"
    assert decision.allowed is False
    assert "LOW-PRIORITY-MONITOR" in decision.matched_policies


def test_runtime_policy_compiler_require_approval(tmp_path):
    """Require-approval should block execution until explicit approval exists."""
    from backend.app.services.runtime_policy_compiler import RuntimePolicyCompiler

    policy_file = tmp_path / "runtime_policies.json"
    policy_file.write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "id": "APPROVAL-INSTALL",
                        "description": "require approval for installs",
                        "event_type": "tool",
                        "action": "require_approval",
                        "priority": 50,
                        "conditions": {"command_contains": ["npm install"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    compiler = RuntimePolicyCompiler(policy_path=policy_file)
    decision = compiler.evaluate_tool("npm", ["npm", "install", "left-pad"], "javascript")

    assert decision.allowed is False
    assert decision.action == "require_approval"
    assert decision.rule_id == "APPROVAL-INSTALL"


def test_runtime_policy_compiler_legacy_lists(monkeypatch, tmp_path):
    """Legacy allowlist/denylist settings should remain supported."""
    from backend.app.core.config import settings
    from backend.app.services.runtime_policy_compiler import RuntimePolicyCompiler

    monkeypatch.setattr(settings, "RUNTIME_TOOL_ALLOWLIST", ["bandit"])
    monkeypatch.setattr(settings, "RUNTIME_TOOL_DENYLIST", ["eslint"])

    compiler = RuntimePolicyCompiler(policy_path=tmp_path / "does-not-exist.json")

    denied_allowlist = compiler.evaluate_tool("safety", ["safety", "--version"], "python")
    denied_denylist = compiler.evaluate_tool("eslint", ["eslint", "--version"], "javascript")
    allowed = compiler.evaluate_tool("bandit", ["bandit", "--version"], "python")

    assert denied_allowlist.allowed is False
    assert denied_allowlist.rule_id == "RUNTIME-TOOL-ALLOWLIST"
    assert denied_denylist.allowed is False
    assert denied_denylist.rule_id == "RUNTIME-TOOL-DENYLIST"
    assert allowed.allowed is True
