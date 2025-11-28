"""LangGraph compliance workflow for ACPG.

This module defines the agentic workflow as a state machine graph:

    ┌─────────────────────────────────────────────────────────┐
    │                                                         │
    ▼                                                         │
[START] → [Prosecutor] → [Adjudicator] ──Compliant──→ [Proof] → [END]
                              │                          
                              │ Non-compliant            
                              │ & iterations < max       
                              ▼                          
                         [Generator] ────────────────────┘
                              │
                              │ iterations >= max
                              ▼
                          [Finalize] → [END]
"""
from typing import Literal, Optional, Dict, Any
from datetime import datetime

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from .state import ComplianceState, create_initial_state
from .nodes import (
    prosecutor_node,
    adjudicator_node,
    generator_node,
    proof_assembler_node,
    finalize_node
)


def should_continue(state: ComplianceState) -> Literal["generator", "proof", "finalize"]:
    """
    Conditional edge: determine next node after adjudication.
    
    Routes to:
    - "proof": If compliant → generate proof bundle
    - "generator": If not compliant AND more iterations allowed → try to fix
    - "finalize": If not compliant AND max iterations reached → end
    """
    if state["compliant"]:
        return "proof"
    
    if state["iteration"] < state["max_iterations"]:
        return "generator"
    
    return "finalize"


def after_generator(state: ComplianceState) -> Literal["prosecutor", "finalize"]:
    """
    Conditional edge: determine next node after generator.
    
    Routes to:
    - "prosecutor": If no error → re-analyze fixed code
    - "finalize": If error occurred → end workflow
    """
    if state.get("error"):
        return "finalize"
    
    return "prosecutor"


def create_compliance_graph(checkpointer: Optional[MemorySaver] = None) -> StateGraph:
    """
    Create the ACPG compliance workflow graph.
    
    The graph implements a cyclic workflow where:
    1. Prosecutor analyzes code for violations
    2. Adjudicator determines compliance
    3. If non-compliant, Generator attempts fixes
    4. Repeat until compliant or max iterations
    5. If compliant, generate signed proof bundle
    
    Args:
        checkpointer: Optional memory saver for state persistence
        
    Returns:
        Compiled StateGraph ready for execution
    """
    # Create the graph
    workflow = StateGraph(ComplianceState)
    
    # Add nodes (agents)
    workflow.add_node("prosecutor", prosecutor_node)
    workflow.add_node("adjudicator", adjudicator_node)
    workflow.add_node("generator", generator_node)
    workflow.add_node("proof", proof_assembler_node)
    workflow.add_node("finalize", finalize_node)
    
    # Set entry point
    workflow.set_entry_point("prosecutor")
    
    # Add edges
    # Prosecutor always goes to Adjudicator
    workflow.add_edge("prosecutor", "adjudicator")
    
    # Adjudicator has conditional routing
    workflow.add_conditional_edges(
        "adjudicator",
        should_continue,
        {
            "proof": "proof",
            "generator": "generator",
            "finalize": "finalize"
        }
    )
    
    # Generator has conditional routing (back to prosecutor or end)
    workflow.add_conditional_edges(
        "generator",
        after_generator,
        {
            "prosecutor": "prosecutor",
            "finalize": "finalize"
        }
    )
    
    # Proof and Finalize are terminal nodes
    workflow.add_edge("proof", END)
    workflow.add_edge("finalize", END)
    
    # Compile with optional checkpointer
    if checkpointer:
        return workflow.compile(checkpointer=checkpointer)
    
    return workflow.compile()


async def run_compliance_check(
    code: str,
    language: str = "python",
    policy_ids: Optional[list] = None,
    max_iterations: int = 3,
    thread_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run the full compliance check workflow.
    
    This is the main entry point for using the LangGraph orchestration.
    
    Args:
        code: Source code to check
        language: Programming language
        policy_ids: Optional list of policy IDs to check
        max_iterations: Maximum fix attempts
        thread_id: Optional thread ID for checkpointing
        
    Returns:
        Final state dict with compliance results
    """
    # Create checkpointer for state persistence
    checkpointer = MemorySaver()
    
    # Create the graph
    graph = create_compliance_graph(checkpointer)
    
    # Create initial state
    initial_state = create_initial_state(
        code=code,
        language=language,
        policy_ids=policy_ids,
        max_iterations=max_iterations
    )
    
    # Configuration
    config = {"configurable": {"thread_id": thread_id or "default"}}
    
    # Run the graph
    final_state = await graph.ainvoke(initial_state, config)
    
    return final_state


def run_compliance_check_sync(
    code: str,
    language: str = "python",
    policy_ids: Optional[list] = None,
    max_iterations: int = 3
) -> Dict[str, Any]:
    """
    Synchronous version of run_compliance_check.
    
    For use in non-async contexts.
    """
    # Create the graph without checkpointer for sync execution
    graph = create_compliance_graph()
    
    # Create initial state
    initial_state = create_initial_state(
        code=code,
        language=language,
        policy_ids=policy_ids,
        max_iterations=max_iterations
    )
    
    # Run the graph synchronously
    final_state = graph.invoke(initial_state)
    
    return final_state


def get_graph_visualization() -> str:
    """
    Get a text representation of the compliance graph.
    
    Returns:
        ASCII art representation of the graph
    """
    return """
    ACPG Compliance Workflow Graph
    ==============================
    
    ┌─────────────────────────────────────────────────────────┐
    │                                                         │
    │  ┌───────────┐    ┌─────────────┐    ┌───────────────┐ │
    │  │           │    │             │    │               │ │
    │  │ Prosecutor├───►│ Adjudicator ├───►│ Proof Bundle  │ │
    │  │           │    │             │    │               │ │
    │  └───────────┘    └──────┬──────┘    └───────┬───────┘ │
    │        ▲                 │                   │         │
    │        │                 │ Non-compliant     │         │
    │        │                 ▼                   │         │
    │        │           ┌───────────┐             │         │
    │        │           │           │             │         │
    │        └───────────┤ Generator │             │         │
    │                    │           │             │         │
    │                    └─────┬─────┘             │         │
    │                          │                   │         │
    │                          │ Max iterations    │         │
    │                          ▼                   ▼         │
    │                    ┌───────────┐       ┌─────────┐     │
    │                    │ Finalize  │       │   END   │     │
    │                    └───────────┘       └─────────┘     │
    │                                                         │
    └─────────────────────────────────────────────────────────┘
    
    Nodes:
    - Prosecutor: Analyzes code for policy violations
    - Adjudicator: Determines compliance using argumentation
    - Generator: AI-powered code fixing
    - Proof Bundle: Generates signed compliance certificate
    - Finalize: Handles max iterations reached
    
    Edges:
    - Prosecutor → Adjudicator (always)
    - Adjudicator → Proof (if compliant)
    - Adjudicator → Generator (if non-compliant, iterations < max)
    - Adjudicator → Finalize (if non-compliant, iterations >= max)
    - Generator → Prosecutor (if no error)
    - Generator → Finalize (if error)
    """

