"""Runtime policy guard for agent/tool actions."""
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Set

from ..core.config import settings


def _normalize_tool_set(values: Optional[Iterable[str] | str]) -> Set[str]:
    """Normalize tool names to a lowercase set."""
    if not values:
        return set()
    if isinstance(values, str):
        items = [part.strip() for part in values.split(",")]
    else:
        items = [str(part).strip() for part in values]
    return {item.lower() for item in items if item}


@dataclass
class RuntimeGuardDecision:
    """Decision returned by runtime guard evaluation."""

    allowed: bool
    message: str
    rule_id: Optional[str] = None
    severity: str = "high"
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "message": self.message,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "evidence": self.evidence,
        }


class RuntimeGuard:
    """Evaluate runtime policies for tool invocations."""

    def evaluate_tool(
        self,
        tool_name: str,
        command: Optional[list[str]] = None,
        language: Optional[str] = None,
    ) -> RuntimeGuardDecision:
        if not settings.ENABLE_RUNTIME_GUARDS:
            return RuntimeGuardDecision(allowed=True, message="Runtime guards disabled")

        normalized_tool = (tool_name or "").strip().lower()
        allowlist = _normalize_tool_set(settings.RUNTIME_TOOL_ALLOWLIST)
        denylist = _normalize_tool_set(settings.RUNTIME_TOOL_DENYLIST)
        command_str = " ".join(command or [])
        evidence = (
            f"tool={normalized_tool}; language={language or 'unknown'}; command={command_str}"
        )

        if allowlist and normalized_tool not in allowlist:
            return RuntimeGuardDecision(
                allowed=False,
                rule_id="RUNTIME-TOOL-ALLOWLIST",
                severity="high",
                message=(
                    f"Runtime policy denied tool '{tool_name}': "
                    "tool is not in runtime allowlist."
                ),
                evidence=evidence,
            )

        if normalized_tool in denylist:
            return RuntimeGuardDecision(
                allowed=False,
                rule_id="RUNTIME-TOOL-DENYLIST",
                severity="high",
                message=(
                    f"Runtime policy denied tool '{tool_name}': "
                    "tool is in runtime denylist."
                ),
                evidence=evidence,
            )

        return RuntimeGuardDecision(
            allowed=True,
            message=f"Runtime policy allowed tool '{tool_name}'.",
            evidence=evidence,
        )


_runtime_guard: Optional[RuntimeGuard] = None


def get_runtime_guard() -> RuntimeGuard:
    """Get runtime guard singleton."""
    global _runtime_guard
    if _runtime_guard is None:
        _runtime_guard = RuntimeGuard()
    return _runtime_guard

