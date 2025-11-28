"""Tests for the Adjudicator service."""
import pytest
from pathlib import Path

# Add backend to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from backend.app.models.schemas import Violation, AnalysisResult, Argument, Attack, ArgumentationGraph


def test_adjudicator_compliant():
    """Test adjudication of compliant code (no violations)."""
    from backend.app.services.adjudicator import Adjudicator
    from backend.app.services.policy_compiler import PolicyCompiler
    
    compiler = PolicyCompiler()
    compiler.load_policies()
    
    adjudicator = Adjudicator()
    adjudicator.policy_compiler = compiler
    
    # Analysis with no violations
    analysis = AnalysisResult(
        artifact_id="test123",
        violations=[]
    )
    
    result = adjudicator.adjudicate(analysis)
    
    assert result.compliant is True
    assert len(result.unsatisfied_rules) == 0
    assert len(result.satisfied_rules) > 0


def test_adjudicator_non_compliant():
    """Test adjudication with violations."""
    from backend.app.services.adjudicator import Adjudicator
    from backend.app.services.policy_compiler import PolicyCompiler
    
    compiler = PolicyCompiler()
    compiler.load_policies()
    
    adjudicator = Adjudicator()
    adjudicator.policy_compiler = compiler
    
    # Analysis with a violation
    analysis = AnalysisResult(
        artifact_id="test123",
        violations=[
            Violation(
                rule_id="SEC-001",
                description="Hardcoded password",
                line=5,
                evidence="password = 'secret'",
                detector="regex",
                severity="high"
            )
        ]
    )
    
    result = adjudicator.adjudicate(analysis)
    
    assert result.compliant is False
    assert "SEC-001" in result.unsatisfied_rules


def test_build_argumentation_graph():
    """Test building an argumentation graph."""
    from backend.app.services.adjudicator import Adjudicator
    from backend.app.services.policy_compiler import PolicyCompiler
    
    compiler = PolicyCompiler()
    compiler.load_policies()
    
    adjudicator = Adjudicator()
    adjudicator.policy_compiler = compiler
    
    violations = [
        Violation(
            rule_id="SEC-001",
            description="Hardcoded password",
            line=5,
            evidence="password = 'secret'",
            detector="regex",
            severity="high"
        )
    ]
    
    graph = adjudicator.build_argumentation_graph(violations)
    
    # Should have compliance arguments for policies + violation argument
    assert len(graph.arguments) > 0
    
    # Should have attacks (violation attacks compliance)
    assert len(graph.attacks) > 0
    
    # Find the compliance and violation arguments
    compliance_args = [a for a in graph.arguments if a.type == "compliance"]
    violation_args = [a for a in graph.arguments if a.type == "violation"]
    
    assert len(compliance_args) > 0
    assert len(violation_args) == 1


def test_grounded_extension_simple():
    """Test grounded extension computation."""
    from backend.app.services.adjudicator import Adjudicator
    
    adjudicator = Adjudicator()
    
    # Simple graph: A attacks B
    # A should be accepted (unattacked), B should be rejected
    graph = ArgumentationGraph(
        arguments=[
            Argument(id="A", rule_id="R1", type="compliance"),
            Argument(id="B", rule_id="R2", type="violation"),
        ],
        attacks=[
            Attack(attacker="A", target="B")
        ]
    )
    
    accepted = adjudicator.compute_grounded_extension(graph)
    
    assert "A" in accepted
    assert "B" not in accepted


def test_grounded_extension_chain():
    """Test grounded extension with attack chain."""
    from backend.app.services.adjudicator import Adjudicator
    
    adjudicator = Adjudicator()
    
    # Chain: A attacks B, B attacks C
    # A is unattacked -> accepted
    # B is attacked by A (accepted) -> rejected
    # C is attacked by B (rejected) -> accepted
    graph = ArgumentationGraph(
        arguments=[
            Argument(id="A", rule_id="R1", type="compliance"),
            Argument(id="B", rule_id="R2", type="violation"),
            Argument(id="C", rule_id="R3", type="compliance"),
        ],
        attacks=[
            Attack(attacker="A", target="B"),
            Attack(attacker="B", target="C"),
        ]
    )
    
    accepted = adjudicator.compute_grounded_extension(graph)
    
    assert "A" in accepted
    assert "B" not in accepted
    assert "C" in accepted


def test_generate_guidance():
    """Test guidance generation for violations."""
    from backend.app.services.adjudicator import Adjudicator
    from backend.app.services.policy_compiler import PolicyCompiler
    
    compiler = PolicyCompiler()
    compiler.load_policies()
    
    adjudicator = Adjudicator()
    adjudicator.policy_compiler = compiler
    
    analysis = AnalysisResult(
        artifact_id="test123",
        violations=[
            Violation(
                rule_id="SEC-001",
                description="Hardcoded password",
                line=5,
                evidence="password = 'secret'",
                detector="regex",
                severity="high"
            ),
            Violation(
                rule_id="SEC-003",
                description="Eval usage",
                line=10,
                evidence="eval(cmd)",
                detector="regex",
                severity="critical"
            )
        ]
    )
    
    guidance = adjudicator.generate_guidance(analysis)
    
    assert "COMPLIANCE GUIDANCE" in guidance
    assert "SEC-001" in guidance
    assert "SEC-003" in guidance
    # Critical should come before high
    assert guidance.index("SEC-003") < guidance.index("SEC-001")


def test_reasoning_trace():
    """Test that adjudication produces reasoning trace."""
    from backend.app.services.adjudicator import Adjudicator
    from backend.app.services.policy_compiler import PolicyCompiler
    
    compiler = PolicyCompiler()
    compiler.load_policies()
    
    adjudicator = Adjudicator()
    adjudicator.policy_compiler = compiler
    
    analysis = AnalysisResult(
        artifact_id="test123",
        violations=[
            Violation(
                rule_id="SEC-001",
                description="Test",
                severity="high",
                detector="regex"
            )
        ]
    )
    
    result = adjudicator.adjudicate(analysis)
    
    assert len(result.reasoning) > 0
    # Should have conclusion in reasoning
    conclusions = [r for r in result.reasoning if 'conclusion' in r]
    assert len(conclusions) > 0

