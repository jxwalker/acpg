"""Agent nodes for the ACPG LangGraph compliance workflow."""
from datetime import datetime
from typing import Dict, Any

from .state import ComplianceState, AgentMessage, Violation


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
        timestamp=datetime.utcnow().isoformat()
    )
    
    return {
        "artifact_hash": result.artifact_id,
        "violations": violations,
        "messages": [message]
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
    result = adjudicator.adjudicate(analysis, state["policy_ids"])
    
    decision = "COMPLIANT" if result.compliant else "NON-COMPLIANT"
    message = AgentMessage(
        agent="adjudicator",
        action="adjudicate",
        content=f"Decision: {decision} ({len(result.unsatisfied_rules)} unsatisfied rules)",
        timestamp=datetime.utcnow().isoformat()
    )
    
    return {
        "compliant": result.compliant,
        "satisfied_rules": result.satisfied_rules,
        "unsatisfied_rules": result.unsatisfied_rules,
        "reasoning": result.reasoning,
        "messages": [message]
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
            timestamp=datetime.utcnow().isoformat()
        )
        
        return {
            "current_code": fixed_code,
            "violations_fixed": violations_fixed,
            "iteration": 1,  # Will be added to current iteration
            "messages": [message]
        }
    
    except Exception as e:
        message = AgentMessage(
            agent="generator",
            action="error",
            content=f"Fix failed: {str(e)}",
            timestamp=datetime.utcnow().isoformat()
        )
        
        return {
            "error": str(e),
            "iteration": 1,
            "messages": [message]
        }


def proof_assembler_node(state: ComplianceState) -> Dict[str, Any]:
    """
    Proof Assembler Node
    
    Generates a cryptographically-signed proof bundle
    for compliant code.
    """
    from ..services import get_proof_assembler, get_adjudicator
    from ..models.schemas import AnalysisResult, AdjudicationResult, Violation as ViolationModel
    
    proof_assembler = get_proof_assembler()
    
    # Reconstruct analysis result (empty violations for compliant code)
    analysis = AnalysisResult(
        artifact_id=state["artifact_hash"],
        violations=[]
    )
    
    # Reconstruct adjudication result
    adjudication = AdjudicationResult(
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
        language=state["language"]
    )
    
    message = AgentMessage(
        agent="proof_assembler",
        action="generate_proof",
        content=f"Proof bundle generated: {proof.artifact.hash[:16]}...",
        timestamp=datetime.utcnow().isoformat()
    )
    
    return {
        "proof_bundle": proof.model_dump(),
        "completed_at": datetime.utcnow().isoformat(),
        "messages": [message]
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
        timestamp=datetime.utcnow().isoformat()
    )
    
    return {
        "completed_at": datetime.utcnow().isoformat(),
        "messages": [message]
    }

