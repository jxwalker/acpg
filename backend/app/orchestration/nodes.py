"""Agent nodes for the ACPG LangGraph compliance workflow."""
from datetime import datetime, timezone
from typing import Dict, Any

from .state import ComplianceState, AgentMessage, Violation, RuntimeEvent


def _runtime_event(state: ComplianceState, node: str, kind: str, details: Dict[str, Any]) -> RuntimeEvent:
    return RuntimeEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        node=node,
        kind=kind,
        iteration=state.get("iteration", 0),
        details=details,
    )


def prosecutor_node(state: ComplianceState) -> Dict[str, Any]:
    """
    Prosecutor Agent Node
    
    Analyzes code for policy violations using static analysis
    and pattern matching.
    """
    from ..services import get_prosecutor
    
    prosecutor = get_prosecutor()
    
    # Run analysis
    result = prosecutor.analyze(
        code=state["current_code"],
        language=state["language"],
        policy_ids=state["policy_ids"]
    )
    
    # Convert violations to dict format
    violations = [
        Violation(
            rule_id=v.rule_id,
            description=v.description,
            line=v.line,
            evidence=v.evidence,
            severity=v.severity
        )
        for v in result.violations
    ]
    
    message = AgentMessage(
        agent="prosecutor",
        action="analyze",
        content=f"Found {len(violations)} violation(s)",
        timestamp=datetime.now(timezone.utc).isoformat()
    )

    runtime_events = [
        _runtime_event(
            state,
            node="prosecutor",
            kind="analysis",
            details={
                "artifact_hash": result.artifact_id,
                "violations_count": len(violations),
            },
        )
    ]

    for tool_name, tool_info in (result.tool_execution or {}).items():
        decision = getattr(tool_info, "policy_decision", None)
        if decision and not decision.get("allowed", True):
            runtime_events.append(
                _runtime_event(
                    state,
                    node="prosecutor",
                    kind="runtime_guard_violation",
                    details={
                        "tool": tool_name,
                        "rule_id": decision.get("rule_id"),
                        "severity": decision.get("severity"),
                        "message": decision.get("message"),
                    },
                )
            )
    
    return {
        "artifact_hash": result.artifact_id,
        "violations": violations,
        "messages": [message],
        "runtime_events": runtime_events,
    }


def adjudicator_node(state: ComplianceState) -> Dict[str, Any]:
    """
    Adjudicator Agent Node
    
    Uses formal argumentation to determine compliance status
    based on violations found by the prosecutor.
    """
    from ..services import get_adjudicator
    from ..models.schemas import AnalysisResult, Violation as ViolationModel
    
    adjudicator = get_adjudicator()
    
    # Convert state violations to model format
    violations = [
        ViolationModel(
            rule_id=v["rule_id"],
            description=v["description"],
            line=v.get("line"),
            evidence=v.get("evidence"),
            detector="prosecutor",
            severity=v["severity"]
        )
        for v in state["violations"]
    ]
    
    analysis = AnalysisResult(
        artifact_id=state["artifact_hash"],
        violations=violations
    )
    
    # Run adjudication
    requested_semantics = state.get("semantics", "auto")
    result = adjudicator.adjudicate(analysis, state["policy_ids"], semantics=requested_semantics)
    
    decision = "COMPLIANT" if result.compliant else "NON-COMPLIANT"
    message = AgentMessage(
        agent="adjudicator",
        action="adjudicate",
        content=f"Decision: {decision} ({len(result.unsatisfied_rules)} unsatisfied rules)",
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    
    return {
        # Update semantics to the semantics actually used for the decision (AUTO -> grounded).
        "semantics": result.semantics or requested_semantics,
        "secondary_semantics": result.secondary_semantics,
        "compliant": result.compliant,
        "satisfied_rules": result.satisfied_rules,
        "unsatisfied_rules": result.unsatisfied_rules,
        "reasoning": result.reasoning,
        "messages": [message],
        "runtime_events": [
            _runtime_event(
                state,
                node="adjudicator",
                kind="adjudication",
                details={
                    "requested_semantics": requested_semantics,
                    "used_semantics": result.semantics or requested_semantics,
                    "compliant": result.compliant,
                    "unsatisfied_rules": result.unsatisfied_rules,
                },
            )
        ],
    }


def generator_node(state: ComplianceState) -> Dict[str, Any]:
    """
    Generator Agent Node
    
    Uses AI to fix code based on violations found.
    Only called when code is non-compliant.
    """
    from ..services import get_generator
    from ..models.schemas import Violation as ViolationModel
    
    generator = get_generator()
    
    # Convert violations to model format
    violations = [
        ViolationModel(
            rule_id=v["rule_id"],
            description=v["description"],
            line=v.get("line"),
            evidence=v.get("evidence"),
            detector="prosecutor",
            severity=v["severity"]
        )
        for v in state["violations"]
    ]
    
    # Attempt to fix
    try:
        fixed_code = generator.fix_violations(
            code=state["current_code"],
            violations=violations,
            language=state["language"]
        )
        
        violations_fixed = [v["rule_id"] for v in state["violations"]]
        
        message = AgentMessage(
            agent="generator",
            action="fix",
            content=f"Attempted to fix {len(violations)} violation(s)",
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        return {
            "current_code": fixed_code,
            "violations_fixed": violations_fixed,
            "iteration": 1,  # Will be added to current iteration
            "messages": [message],
            "runtime_events": [
                _runtime_event(
                    state,
                    node="generator",
                    kind="fix_attempt",
                    details={
                        "violations_count": len(violations),
                        "violations_fixed": violations_fixed,
                    },
                )
            ],
        }
    
    except Exception as e:
        message = AgentMessage(
            agent="generator",
            action="error",
            content=f"Fix failed: {str(e)}",
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        return {
            "error": str(e),
            "iteration": 1,
            "messages": [message],
            "runtime_events": [
                _runtime_event(
                    state,
                    node="generator",
                    kind="error",
                    details={"error": str(e)},
                )
            ],
        }


def proof_assembler_node(state: ComplianceState) -> Dict[str, Any]:
    """
    Proof Assembler Node
    
    Generates a cryptographically-signed proof bundle
    for compliant code.
    """
    from ..services import get_proof_assembler
    from ..models.schemas import AnalysisResult, AdjudicationResult
    
    proof_assembler = get_proof_assembler()
    
    # Reconstruct analysis result (empty violations for compliant code)
    analysis = AnalysisResult(
        artifact_id=state["artifact_hash"],
        violations=[]
    )
    
    # Reconstruct adjudication result
    adjudication = AdjudicationResult(
        semantics=state.get("semantics"),
        secondary_semantics=state.get("secondary_semantics"),
        compliant=True,
        satisfied_rules=state["satisfied_rules"],
        unsatisfied_rules=[],
        reasoning=state["reasoning"]
    )
    
    # Generate proof
    proof = proof_assembler.assemble_proof(
        code=state["current_code"],
        analysis=analysis,
        adjudication=adjudication,
        language=state["language"],
        runtime_events=state.get("runtime_events"),
    )
    
    message = AgentMessage(
        agent="proof_assembler",
        action="generate_proof",
        content=f"Proof bundle generated: {proof.artifact.hash[:16]}...",
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    
    return {
        "proof_bundle": proof.model_dump(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "messages": [message],
        "runtime_events": [
            _runtime_event(
                state,
                node="proof_assembler",
                kind="proof_bundle",
                details={"artifact_hash": proof.artifact.hash},
            )
        ],
    }


def finalize_node(state: ComplianceState) -> Dict[str, Any]:
    """
    Finalization Node
    
    Called when workflow completes (either success or max iterations).
    """
    message = AgentMessage(
        agent="orchestrator",
        action="finalize",
        content=f"Workflow complete. Compliant: {state['compliant']}, Iterations: {state['iteration']}",
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    
    return {
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "messages": [message],
        "runtime_events": [
            _runtime_event(
                state,
                node="finalize",
                kind="finalize",
                details={"compliant": state["compliant"], "iterations": state["iteration"]},
            )
        ],
    }
