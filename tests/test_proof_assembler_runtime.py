"""Tests for runtime policy evidence in proof bundles."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def test_proof_includes_runtime_policy_monitoring_evidence():
    """Proof bundle should contain runtime monitoring evidence from tool policy decisions."""
    from backend.app.models.schemas import (
        AnalysisResult,
        AdjudicationResult,
        ToolExecutionInfo,
    )
    from backend.app.services.proof_assembler import ProofAssembler

    analysis = AnalysisResult(
        artifact_id="abc123",
        violations=[],
        tool_execution={
            "safety": ToolExecutionInfo(
                tool_name="safety",
                success=True,
                policy_decision={
                    "allowed": True,
                    "action": "allow_with_monitoring",
                    "rule_id": "RUNTIME-TOOL-MONITOR-SAFETY",
                    "message": "Monitored run",
                    "evidence": "event=tool; tool_name=safety",
                },
            )
        },
    )
    adjudication = AdjudicationResult(
        compliant=True,
        satisfied_rules=[],
        unsatisfied_rules=[],
        reasoning=[],
        semantics="grounded",
    )

    proof = ProofAssembler().assemble_proof(
        code="print('ok')",
        analysis=analysis,
        adjudication=adjudication,
        language="python",
    )

    runtime_evidence = [e for e in proof.evidence if e.type == "runtime_policy_monitoring"]
    assert runtime_evidence
    assert runtime_evidence[0].rule_id == "RUNTIME-TOOL-MONITOR-SAFETY"


def test_proof_includes_runtime_policy_enforcement_evidence():
    """Denied/approval-required runtime decisions should be captured as enforcement evidence."""
    from backend.app.models.schemas import (
        AnalysisResult,
        AdjudicationResult,
        ToolExecutionInfo,
        Violation,
    )
    from backend.app.services.proof_assembler import ProofAssembler

    analysis = AnalysisResult(
        artifact_id="abc456",
        violations=[
            Violation(
                rule_id="RUNTIME-TOOL-REQUIRE-APPROVAL-INSTALL-CMDS",
                description="Install command blocked pending approval",
                detector="runtime_guard",
                severity="high",
            )
        ],
        tool_execution={
            "pip": ToolExecutionInfo(
                tool_name="pip",
                success=False,
                policy_decision={
                    "allowed": False,
                    "action": "require_approval",
                    "rule_id": "RUNTIME-TOOL-REQUIRE-APPROVAL-INSTALL-CMDS",
                    "message": "Needs approval",
                    "evidence": "event=tool; tool_name=pip; command_text=pip install requests",
                },
            )
        },
    )
    adjudication = AdjudicationResult(
        compliant=False,
        satisfied_rules=[],
        unsatisfied_rules=["RUNTIME-TOOL-REQUIRE-APPROVAL-INSTALL-CMDS"],
        reasoning=[],
        semantics="grounded",
    )

    proof = ProofAssembler().assemble_proof(
        code="print('pending approval')",
        analysis=analysis,
        adjudication=adjudication,
        language="python",
    )

    runtime_evidence = [e for e in proof.evidence if e.type == "runtime_policy_enforcement"]
    assert runtime_evidence
    assert runtime_evidence[0].rule_id == "RUNTIME-TOOL-REQUIRE-APPROVAL-INSTALL-CMDS"
