"""Tests for LangGraph orchestration."""
import pytest
from pathlib import Path
import sys

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import os
os.environ.setdefault("OPENAI_API_KEY", "test-key")


def test_create_initial_state():
    """Test initial state creation."""
    from backend.app.orchestration.state import create_initial_state
    
    state = create_initial_state(
        code="x = 1",
        language="python",
        max_iterations=3
    )
    
    assert state["original_code"] == "x = 1"
    assert state["current_code"] == "x = 1"
    assert state["language"] == "python"
    assert state["max_iterations"] == 3
    assert state["iteration"] == 0
    assert state["compliant"] == False
    assert state["violations"] == []
    assert state["semantics"] == "auto"
    assert state["runtime_events"] == []


def test_prosecutor_node():
    """Test prosecutor node execution."""
    from backend.app.orchestration.nodes import prosecutor_node
    from backend.app.orchestration.state import create_initial_state
    
    state = create_initial_state(
        code="password = 'secret123'",
        language="python"
    )
    
    result = prosecutor_node(state)
    
    assert "violations" in result
    assert "artifact_hash" in result
    assert "messages" in result
    assert "runtime_events" in result
    assert len(result["violations"]) > 0
    assert result["violations"][0]["rule_id"] == "SEC-001"


def test_adjudicator_node_non_compliant():
    """Test adjudicator node with violations."""
    from backend.app.orchestration.nodes import adjudicator_node
    from backend.app.orchestration.state import create_initial_state, Violation
    
    state = create_initial_state(code="x = 1", language="python")
    state["artifact_hash"] = "test123"
    state["violations"] = [
        Violation(
            rule_id="SEC-001",
            description="Hardcoded secret",
            line=1,
            evidence="password = 'x'",
            severity="high"
        )
    ]
    
    result = adjudicator_node(state)
    
    assert result["compliant"] == False
    assert "SEC-001" in result["unsatisfied_rules"]
    assert len(result["messages"]) > 0
    assert result.get("semantics") is not None
    assert "runtime_events" in result


def test_adjudicator_node_compliant():
    """Test adjudicator node without violations."""
    from backend.app.orchestration.nodes import adjudicator_node
    from backend.app.orchestration.state import create_initial_state
    
    state = create_initial_state(
        code="import os\nvalue = os.environ.get('SECRET')",
        language="python"
    )
    state["artifact_hash"] = "test123"
    state["violations"] = []
    
    result = adjudicator_node(state)
    
    assert result["compliant"] == True
    assert len(result["unsatisfied_rules"]) == 0
    assert result.get("semantics") is not None


def test_should_continue_compliant():
    """Test routing when compliant."""
    from backend.app.orchestration.graph import should_continue
    from backend.app.orchestration.state import create_initial_state
    
    state = create_initial_state(code="x = 1", language="python")
    state["compliant"] = True
    state["iteration"] = 1
    
    result = should_continue(state)
    
    assert result == "proof"


def test_should_continue_non_compliant_with_iterations():
    """Test routing when non-compliant with iterations left."""
    from backend.app.orchestration.graph import should_continue
    from backend.app.orchestration.state import create_initial_state
    
    state = create_initial_state(code="x = 1", language="python", max_iterations=3)
    state["compliant"] = False
    state["iteration"] = 1
    
    result = should_continue(state)
    
    assert result == "generator"


def test_should_continue_max_iterations():
    """Test routing when max iterations reached."""
    from backend.app.orchestration.graph import should_continue
    from backend.app.orchestration.state import create_initial_state
    
    state = create_initial_state(code="x = 1", language="python", max_iterations=3)
    state["compliant"] = False
    state["iteration"] = 3
    
    result = should_continue(state)
    
    assert result == "finalize"


def test_graph_visualization():
    """Test graph visualization."""
    from backend.app.orchestration.graph import get_graph_visualization
    
    viz = get_graph_visualization()
    
    assert "Prosecutor" in viz
    assert "Adjudicator" in viz
    assert "Generator" in viz
    assert "Proof Bundle" in viz


def test_sync_compliance_check_clean_code():
    """Test synchronous compliance check with clean code."""
    from backend.app.orchestration.graph import run_compliance_check_sync
    
    clean_code = """
import os
value = os.environ.get('SECRET')
"""
    
    result = run_compliance_check_sync(
        code=clean_code,
        language="python",
        max_iterations=1
    )
    
    assert result["compliant"] == True
    assert result["iteration"] == 0
    assert result["proof_bundle"] is not None


def test_sync_compliance_check_dirty_code():
    """Test synchronous compliance check with violations."""
    from backend.app.orchestration.graph import run_compliance_check_sync
    
    dirty_code = "password = 'secret123'"
    
    result = run_compliance_check_sync(
        code=dirty_code,
        language="python",
        max_iterations=1  # Only 1 iteration
    )
    
    # The code may be fixed by the LLM if available, or remain non-compliant
    # Either way, we should have violations initially and messages
    assert len(result["messages"]) > 0
    
    # If LLM fixed it, it will be compliant; otherwise it won't be
    # Both outcomes are valid for this test
    if result["compliant"]:
        # LLM successfully fixed the code
        assert len(result["violations_fixed"]) > 0
    else:
        # Code remains non-compliant (LLM unavailable or failed)
        assert len(result["violations"]) > 0
