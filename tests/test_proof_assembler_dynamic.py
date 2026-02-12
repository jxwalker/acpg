"""Tests for dynamic-analysis evidence in proof bundles."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def test_proof_includes_dynamic_replay_evidence():
    """Proof should carry deterministic replay artifacts from dynamic analysis."""
    from backend.app.models.schemas import (
        AnalysisResult,
        AdjudicationResult,
        DynamicAnalysisResult,
        DynamicExecutionArtifact,
        DynamicReplayArtifact,
    )
    from backend.app.services.proof_assembler import ProofAssembler

    dynamic = DynamicAnalysisResult(
        executed=True,
        runner="python_subprocess_isolated",
        timeout_seconds=2,
        artifacts=[
            DynamicExecutionArtifact(
                artifact_id="DYN-abc123-1",
                suite_id="direct_execution",
                suite_name="Direct Script Execution",
                duration_seconds=0.1,
                return_code=0,
                timed_out=False,
                stdout="ok",
                stderr="",
                replay=DynamicReplayArtifact(
                    runner="python_subprocess_isolated",
                    suite_id="direct_execution",
                    suite_name="Direct Script Execution",
                    command=["python", "-I", "-B", "artifact.py"],
                    timeout_seconds=2,
                    deterministic_fingerprint="f" * 64,
                    language="python",
                ),
            )
        ],
        violations=[],
    )

    analysis = AnalysisResult(
        artifact_id="abc123",
        violations=[],
        dynamic_analysis=dynamic,
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

    replay_evidence = [e for e in proof.evidence if e.type == "dynamic_replay_artifact"]
    analysis_evidence = [e for e in proof.evidence if e.type == "dynamic_analysis"]
    assert replay_evidence
    assert analysis_evidence
