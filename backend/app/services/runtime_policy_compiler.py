"""Runtime policy compiler for deterministic event-time policy decisions."""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional

from ..core.config import settings

logger = logging.getLogger(__name__)

RuntimeEventType = Literal["tool", "network", "filesystem", "*"]
RuntimeAction = Literal["allow", "deny", "require_approval", "allow_with_monitoring"]


def _as_lower_list(value: Any) -> List[str]:
    """Normalize a scalar/list value to lowercase strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip().lower()] if value.strip() else []
    result: List[str] = []
    for item in value:
        text = str(item).strip().lower()
        if text:
            result.append(text)
    return result


def _normalize_command(command: Optional[Iterable[str]]) -> str:
    return " ".join(str(part) for part in (command or [])).strip()


@dataclass
class RuntimePolicyRule:
    """Compiled runtime policy rule."""

    id: str
    description: str
    event_type: RuntimeEventType
    action: RuntimeAction = "allow"
    severity: str = "medium"
    priority: int = 0
    enabled: bool = True
    message: Optional[str] = None
    conditions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RuntimePolicyDecision:
    """Result from runtime policy evaluation."""

    action: RuntimeAction
    allowed: bool
    rule_id: Optional[str] = None
    severity: str = "medium"
    message: str = "Runtime policy allowed event."
    evidence: Optional[str] = None
    matched_policies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class RuntimePolicyCompiler:
    """Load and evaluate runtime policies for tool/network/filesystem events."""

    def __init__(self, policy_path: Optional[Path] = None):
        self.policy_path = Path(policy_path) if policy_path else Path(settings.RUNTIME_POLICIES_FILE)
        self._rules: List[RuntimePolicyRule] = []
        self.reload()

    def reload(self) -> None:
        """Reload policy rules from disk, preserving compatibility defaults."""
        self._rules = []
        self._rules.extend(self._legacy_tool_rules())
        if not self.policy_path.exists():
            self._rules.sort(key=lambda rule: (-rule.priority, rule.id))
            return

        try:
            with open(self.policy_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception as exc:
            logger.warning("Failed to load runtime policy file %s: %s", self.policy_path, exc)
            return

        raw_rules = payload.get("policies", [])
        if not isinstance(raw_rules, list):
            logger.warning("Runtime policy file %s has invalid shape; expected policies list", self.policy_path)
            return

        for raw in raw_rules:
            try:
                parsed = self._parse_rule(raw)
            except Exception as exc:
                logger.warning("Skipping invalid runtime policy rule: %s", exc)
                continue
            self._rules.append(parsed)

        self._rules.sort(key=lambda rule: (-rule.priority, rule.id))

    def list_rules(self) -> List[RuntimePolicyRule]:
        """Return compiled runtime policy rules in deterministic order."""
        return list(self._rules)

    def evaluate_tool(
        self,
        tool_name: str,
        command: Optional[Iterable[str]] = None,
        language: Optional[str] = None,
    ) -> RuntimePolicyDecision:
        """Evaluate a tool-invocation event."""
        context = {
            "tool_name": (tool_name or "").strip(),
            "command": list(command or []),
            "command_text": _normalize_command(command),
            "language": (language or "").strip(),
        }
        return self.evaluate("tool", context)

    def evaluate_network(
        self,
        host: str,
        method: str = "GET",
        protocol: str = "https",
    ) -> RuntimePolicyDecision:
        """Evaluate a network event."""
        context = {"host": host, "method": method, "protocol": protocol}
        return self.evaluate("network", context)

    def evaluate_filesystem(
        self,
        path: str,
        operation: str,
    ) -> RuntimePolicyDecision:
        """Evaluate a filesystem event."""
        context = {"path": path, "operation": operation}
        return self.evaluate("filesystem", context)

    def evaluate(self, event_type: RuntimeEventType, context: Dict[str, Any]) -> RuntimePolicyDecision:
        """Evaluate a runtime event against compiled rules."""
        candidates = [
            rule
            for rule in self._rules
            if rule.enabled and self._matches_event_type(rule, event_type) and self._matches_conditions(rule, context)
        ]
        evidence = self._build_evidence(event_type, context)
        if not candidates:
            return RuntimePolicyDecision(
                action="allow",
                allowed=True,
                severity="low",
                message=f"Runtime policy allowed {event_type} event.",
                evidence=evidence,
            )

        selected = candidates[0]
        allowed = selected.action in ("allow", "allow_with_monitoring")
        action_label = selected.action.replace("_", " ")
        message = selected.message or (
            f"Runtime policy rule {selected.id} applied action '{action_label}' to {event_type} event."
        )
        return RuntimePolicyDecision(
            action=selected.action,
            allowed=allowed,
            rule_id=selected.id,
            severity=selected.severity,
            message=message,
            evidence=evidence,
            matched_policies=[rule.id for rule in candidates],
            metadata={
                "event_type": event_type,
                "selected_priority": selected.priority,
                "matched_count": len(candidates),
                "selected_description": selected.description,
                **selected.metadata,
            },
        )

    def _parse_rule(self, raw: Dict[str, Any]) -> RuntimePolicyRule:
        if not isinstance(raw, dict):
            raise ValueError("Rule must be an object.")
        rule_id = str(raw.get("id", "")).strip()
        if not rule_id:
            raise ValueError("Rule is missing required id.")

        action = str(raw.get("action", "allow")).strip().lower()
        if action not in {"allow", "deny", "require_approval", "allow_with_monitoring"}:
            raise ValueError(f"Rule {rule_id} has invalid action '{action}'.")

        event_type = str(raw.get("event_type", "tool")).strip().lower()
        if event_type not in {"tool", "network", "filesystem", "*"}:
            raise ValueError(f"Rule {rule_id} has invalid event_type '{event_type}'.")

        return RuntimePolicyRule(
            id=rule_id,
            description=str(raw.get("description", rule_id)),
            event_type=event_type,  # type: ignore[arg-type]
            action=action,  # type: ignore[arg-type]
            severity=str(raw.get("severity", "medium")).lower(),
            priority=int(raw.get("priority", 0)),
            enabled=bool(raw.get("enabled", True)),
            message=raw.get("message"),
            conditions=raw.get("conditions", {}) or {},
            metadata=raw.get("metadata", {}) or {},
        )

    def _legacy_tool_rules(self) -> List[RuntimePolicyRule]:
        rules: List[RuntimePolicyRule] = []
        allowlist = _as_lower_list(settings.RUNTIME_TOOL_ALLOWLIST)
        denylist = _as_lower_list(settings.RUNTIME_TOOL_DENYLIST)

        if allowlist:
            rules.append(
                RuntimePolicyRule(
                    id="RUNTIME-TOOL-ALLOWLIST",
                    description="Only allow explicitly approved tool invocations.",
                    event_type="tool",
                    action="deny",
                    severity="high",
                    priority=1000,
                    conditions={"tool_not_in": allowlist},
                    message="Runtime policy denied tool invocation because tool is not in allowlist.",
                )
            )
        if denylist:
            rules.append(
                RuntimePolicyRule(
                    id="RUNTIME-TOOL-DENYLIST",
                    description="Block explicitly denied tool invocations.",
                    event_type="tool",
                    action="deny",
                    severity="high",
                    priority=1001,
                    conditions={"tool_names": denylist},
                    message="Runtime policy denied tool invocation because tool is in denylist.",
                )
            )
        return rules

    def _matches_event_type(self, rule: RuntimePolicyRule, event_type: RuntimeEventType) -> bool:
        return rule.event_type in (event_type, "*")

    def _matches_conditions(self, rule: RuntimePolicyRule, context: Dict[str, Any]) -> bool:
        conditions = rule.conditions or {}
        for key, value in conditions.items():
            if key == "tool_names":
                tool = str(context.get("tool_name", "")).lower()
                if tool not in _as_lower_list(value):
                    return False
                continue
            if key == "tool_not_in":
                tool = str(context.get("tool_name", "")).lower()
                if tool in _as_lower_list(value):
                    return False
                continue
            if key == "languages":
                language = str(context.get("language", "")).lower()
                if language not in _as_lower_list(value):
                    return False
                continue
            if key == "command_pattern":
                command_text = str(context.get("command_text", ""))
                if not re.search(str(value), command_text):
                    return False
                continue
            if key == "command_contains":
                command_text = str(context.get("command_text", "")).lower()
                phrases = _as_lower_list(value)
                if not any(phrase in command_text for phrase in phrases):
                    return False
                continue
            if key == "hosts":
                host = str(context.get("host", "")).lower()
                if host not in _as_lower_list(value):
                    return False
                continue
            if key == "host_suffixes":
                host = str(context.get("host", "")).lower()
                suffixes = _as_lower_list(value)
                if suffixes and not any(host.endswith(suffix) for suffix in suffixes):
                    return False
                continue
            if key == "path_prefixes":
                path = str(context.get("path", ""))
                prefixes = [str(item) for item in value] if isinstance(value, list) else [str(value)]
                if prefixes and not any(path.startswith(prefix) for prefix in prefixes):
                    return False
                continue
            if key == "path_pattern":
                path = str(context.get("path", ""))
                if not re.search(str(value), path):
                    return False
                continue
            if key == "operations":
                op = str(context.get("operation", "")).lower()
                if op not in _as_lower_list(value):
                    return False
                continue
            if key == "methods":
                method = str(context.get("method", "")).lower()
                if method not in _as_lower_list(value):
                    return False
                continue
            # Generic deterministic exact match fallback.
            expected = value
            actual = context.get(key)
            if isinstance(expected, list):
                normalized_expected = [str(item).lower() for item in expected]
                if str(actual).lower() not in normalized_expected:
                    return False
            else:
                if str(actual).lower() != str(expected).lower():
                    return False
        return True

    def _build_evidence(self, event_type: RuntimeEventType, context: Dict[str, Any]) -> str:
        # Keep this stable for reproducible proofs.
        fields: List[tuple[str, str]] = [("event", event_type)]
        for key in sorted(context.keys()):
            value = context[key]
            if isinstance(value, list):
                rendered = ",".join(str(item) for item in value)
            else:
                rendered = str(value)
            fields.append((key, rendered))
        return "; ".join(f"{key}={value}" for key, value in fields)


_runtime_policy_compiler: Optional[RuntimePolicyCompiler] = None


def get_runtime_policy_compiler() -> RuntimePolicyCompiler:
    """Get or create the global runtime policy compiler singleton."""
    global _runtime_policy_compiler
    if _runtime_policy_compiler is None:
        _runtime_policy_compiler = RuntimePolicyCompiler()
    return _runtime_policy_compiler
