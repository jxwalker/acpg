"""Runtime policy guard for agent/tool actions."""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.config import settings
from .runtime_policy_compiler import get_runtime_policy_compiler


@dataclass
class RuntimeGuardDecision:
    """Decision returned by runtime guard evaluation."""

    allowed: bool
    message: str
    action: str = "allow"
    rule_id: Optional[str] = None
    severity: str = "high"
    evidence: Optional[str] = None
    requires_approval: bool = False
    monitoring: bool = False
    matched_policies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "message": self.message,
            "action": self.action,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "evidence": self.evidence,
            "requires_approval": self.requires_approval,
            "monitoring": self.monitoring,
            "matched_policies": self.matched_policies,
            "metadata": self.metadata,
        }


class RuntimeGuard:
    """Evaluate runtime policies for tool invocations."""

    def __init__(self):
        self.runtime_policy_compiler = get_runtime_policy_compiler()

    def evaluate_tool(
        self,
        tool_name: str,
        command: Optional[list[str]] = None,
        language: Optional[str] = None,
    ) -> RuntimeGuardDecision:
        if not settings.ENABLE_RUNTIME_GUARDS:
            return RuntimeGuardDecision(allowed=True, message="Runtime guards disabled")

        # Keep legacy env-based lists in sync with runtime compiler defaults.
        # If callers mutate settings in tests/runtime, reload to pick it up.
        self.runtime_policy_compiler.reload()
        policy_decision = self.runtime_policy_compiler.evaluate_tool(
            tool_name=tool_name,
            command=command,
            language=language,
        )

        action = policy_decision.action
        monitoring = action == "allow_with_monitoring"
        requires_approval = action == "require_approval"

        # Ensure messages are explicit for auditors and operators.
        if action == "deny":
            message = f"Runtime policy denied tool '{tool_name}'."
        elif action == "require_approval":
            message = f"Runtime policy requires approval for tool '{tool_name}'."
        elif action == "allow_with_monitoring":
            message = f"Runtime policy allowed tool '{tool_name}' with monitoring."
        else:
            message = f"Runtime policy allowed tool '{tool_name}'."

        if policy_decision.message:
            message = f"{message} {policy_decision.message}".strip()

        return RuntimeGuardDecision(
            allowed=policy_decision.allowed,
            message=message,
            action=action,
            rule_id=policy_decision.rule_id,
            severity=policy_decision.severity,
            evidence=policy_decision.evidence,
            requires_approval=requires_approval,
            monitoring=monitoring,
            matched_policies=policy_decision.matched_policies,
            metadata=policy_decision.metadata,
        )


_runtime_guard: Optional[RuntimeGuard] = None


def get_runtime_guard() -> RuntimeGuard:
    """Get runtime guard singleton."""
    global _runtime_guard
    if _runtime_guard is None:
        _runtime_guard = RuntimeGuard()
    return _runtime_guard
