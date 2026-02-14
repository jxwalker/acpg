"""
Sample 15: Runtime policy events simulation target
Violations: SEC-004

Purpose:
- Use this sample alongside Runtime Policy evaluate endpoints/UI.
- Demonstrates representative agent actions for tool/network/filesystem policy checks.
"""

from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class AgentAction:
    kind: str
    payload: Dict[str, Any]


RUNTIME_ACTIONS: List[AgentAction] = [
    AgentAction(
        kind="tool",
        payload={"tool_name": "safety", "command": ["safety", "check"], "language": "python"},
    ),
    AgentAction(
        kind="tool",
        payload={"tool_name": "pip", "command": ["pip", "install", "requests"], "language": "python"},
    ),
    AgentAction(
        kind="network",
        payload={"host": "api.internal.local", "method": "GET", "protocol": "https", "path": "/health"},
    ),
    AgentAction(
        kind="network",
        payload={"host": "legacy.example.com", "method": "GET", "protocol": "http", "path": "/v1/data"},
    ),
    AgentAction(
        kind="filesystem",
        payload={"path": "/tmp/acpg-output.json", "operation": "write"},
    ),
]


def describe_actions() -> str:
    lines = []
    for idx, action in enumerate(RUNTIME_ACTIONS, start=1):
        lines.append(f"{idx}. {action.kind}: {action.payload}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("Runtime policy simulation actions:")
    print(describe_actions())
