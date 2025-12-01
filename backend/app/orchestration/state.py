"""State definitions for ACPG LangGraph orchestration."""
from typing import TypedDict, List, Optional, Annotated
from datetime import datetime, timezone
import operator


class Violation(TypedDict):
    """A policy violation."""
    rule_id: str
    description: str
    line: Optional[int]
    evidence: Optional[str]
    severity: str


class AgentMessage(TypedDict):
    """Message from an agent."""
    agent: str
    action: str
    content: str
    timestamp: str


class ComplianceState(TypedDict):
    """
    State object passed through the ACPG compliance graph.
    
    This maintains all information needed across agent invocations.
    """
    # Input
    original_code: str
    current_code: str
    language: str
    policy_ids: Optional[List[str]]
    max_iterations: int
    
    # Analysis state
    artifact_hash: str
    violations: List[Violation]
    
    # Adjudication state  
    compliant: bool
    satisfied_rules: List[str]
    unsatisfied_rules: List[str]
    reasoning: List[dict]
    
    # Iteration tracking
    iteration: Annotated[int, operator.add]  # Accumulates across iterations
    violations_fixed: Annotated[List[str], operator.add]  # Accumulates
    
    # Agent communication log
    messages: Annotated[List[AgentMessage], operator.add]
    
    # Output
    proof_bundle: Optional[dict]
    error: Optional[str]
    
    # Metadata
    started_at: str
    completed_at: Optional[str]


def create_initial_state(
    code: str,
    language: str = "python",
    policy_ids: Optional[List[str]] = None,
    max_iterations: int = 3
) -> ComplianceState:
    """Create initial state for a compliance check."""
    return ComplianceState(
        original_code=code,
        current_code=code,
        language=language,
        policy_ids=policy_ids,
        max_iterations=max_iterations,
        artifact_hash="",
        violations=[],
        compliant=False,
        satisfied_rules=[],
        unsatisfied_rules=[],
        reasoning=[],
        iteration=0,
        violations_fixed=[],
        messages=[],
        proof_bundle=None,
        error=None,
        started_at=datetime.now(timezone.utc).isoformat(),
        completed_at=None
    )

