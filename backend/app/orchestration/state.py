"""State definitions for ACPG LangGraph orchestration."""
from typing import TypedDict, List, Optional, Annotated, Dict, Any
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


class RuntimeEvent(TypedDict, total=False):
    """Runtime trace event emitted by a graph node."""
    timestamp: str
    node: str
    kind: str
    iteration: int
    details: Dict[str, Any]


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
    semantics: str  # grounded, stable, preferred, auto
    solver_decision_mode: str  # auto, skeptical, credulous
    
    # Analysis state
    artifact_hash: str
    violations: List[Violation]
    
    # Adjudication state  
    compliant: bool
    satisfied_rules: List[str]
    unsatisfied_rules: List[str]
    reasoning: List[dict]
    secondary_semantics: Optional[Dict[str, Any]]
    
    # Iteration tracking
    iteration: Annotated[int, operator.add]  # Accumulates across iterations
    violations_fixed: Annotated[List[str], operator.add]  # Accumulates
    
    # Agent communication log
    messages: Annotated[List[AgentMessage], operator.add]
    runtime_events: Annotated[List[RuntimeEvent], operator.add]
    
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
    max_iterations: int = 3,
    semantics: str = "auto",
    solver_decision_mode: str = "auto",
) -> ComplianceState:
    """Create initial state for a compliance check."""
    return ComplianceState(
        original_code=code,
        current_code=code,
        language=language,
        policy_ids=policy_ids,
        max_iterations=max_iterations,
        semantics=semantics,
        solver_decision_mode=solver_decision_mode,
        artifact_hash="",
        violations=[],
        compliant=False,
        satisfied_rules=[],
        unsatisfied_rules=[],
        reasoning=[],
        secondary_semantics=None,
        iteration=0,
        violations_fixed=[],
        messages=[],
        runtime_events=[],
        proof_bundle=None,
        error=None,
        started_at=datetime.now(timezone.utc).isoformat(),
        completed_at=None
    )
