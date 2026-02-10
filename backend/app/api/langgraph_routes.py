"""LangGraph-based API routes for ACPG."""
from typing import Optional, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime

router = APIRouter(prefix="/graph", tags=["LangGraph Orchestration"])


class GraphEnforceRequest(BaseModel):
    """Request for graph-based enforcement."""
    code: str
    language: str = "python"
    max_iterations: int = 3
    policies: Optional[List[str]] = None


class AgentMessageResponse(BaseModel):
    """Agent message in response."""
    agent: str
    action: str
    content: str
    timestamp: str


class GraphEnforceResponse(BaseModel):
    """Response from graph-based enforcement."""
    original_code: str
    final_code: str
    compliant: bool
    iterations: int
    violations_fixed: List[str]
    satisfied_rules: List[str]
    unsatisfied_rules: List[str]
    messages: List[AgentMessageResponse]
    proof_bundle: Optional[dict] = None
    error: Optional[str] = None
    duration_ms: float


@router.post("/enforce", response_model=GraphEnforceResponse)
async def graph_enforce(request: GraphEnforceRequest):
    """
    Run compliance enforcement using LangGraph orchestration.
    
    This endpoint uses the graph-based multi-agent workflow:
    1. Prosecutor analyzes code
    2. Adjudicator determines compliance
    3. Generator fixes violations (if needed)
    4. Repeat until compliant or max iterations
    5. Generate proof bundle if compliant
    
    The response includes the full agent message trail for transparency.
    """
    from ..orchestration import run_compliance_check
    
    start_time = datetime.utcnow()
    
    try:
        final_state = await run_compliance_check(
            code=request.code,
            language=request.language,
            policy_ids=request.policies,
            max_iterations=request.max_iterations
        )
        
        end_time = datetime.utcnow()
        duration_ms = (end_time - start_time).total_seconds() * 1000
        
        return GraphEnforceResponse(
            original_code=final_state["original_code"],
            final_code=final_state["current_code"],
            compliant=final_state["compliant"],
            iterations=final_state["iteration"],
            violations_fixed=final_state["violations_fixed"],
            satisfied_rules=final_state["satisfied_rules"],
            unsatisfied_rules=final_state["unsatisfied_rules"],
            messages=[
                AgentMessageResponse(**msg) 
                for msg in final_state["messages"]
            ],
            proof_bundle=final_state.get("proof_bundle"),
            error=final_state.get("error"),
            duration_ms=duration_ms
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Graph execution failed: {str(e)}"
        )


@router.get("/visualize")
async def visualize_graph():
    """
    Get a visualization of the compliance workflow graph.
    """
    from ..orchestration.graph import get_graph_visualization
    
    return {
        "graph": get_graph_visualization(),
        "nodes": [
            {"name": "prosecutor", "description": "Analyzes code for policy violations"},
            {"name": "adjudicator", "description": "Determines compliance using argumentation"},
            {"name": "generator", "description": "AI-powered code fixing"},
            {"name": "proof", "description": "Generates signed compliance certificate"},
            {"name": "finalize", "description": "Handles workflow completion"},
        ],
        "edges": [
            {"from": "START", "to": "prosecutor", "condition": "always"},
            {"from": "prosecutor", "to": "adjudicator", "condition": "always"},
            {"from": "adjudicator", "to": "proof", "condition": "compliant"},
            {"from": "adjudicator", "to": "generator", "condition": "non-compliant AND iterations < max"},
            {"from": "adjudicator", "to": "finalize", "condition": "non-compliant AND iterations >= max"},
            {"from": "generator", "to": "prosecutor", "condition": "no error"},
            {"from": "generator", "to": "finalize", "condition": "error"},
            {"from": "proof", "to": "END", "condition": "always"},
            {"from": "finalize", "to": "END", "condition": "always"},
        ]
    }


class StreamingEnforceRequest(BaseModel):
    """Request for streaming enforcement."""
    code: str
    language: str = "python"
    max_iterations: int = 3
    policies: Optional[List[str]] = None


@router.post("/enforce/stream")
async def graph_enforce_stream(request: StreamingEnforceRequest):
    """
    Run compliance enforcement with streaming updates.
    
    Returns Server-Sent Events (SSE) with agent messages as they occur.
    
    Event types:
    - agent_message: Message from an agent
    - state_update: State change notification
    - complete: Final result
    - error: Error occurred
    """
    from fastapi.responses import StreamingResponse
    from ..orchestration.state import create_initial_state
    from ..orchestration.graph import create_compliance_graph
    import json
    import asyncio
    
    async def event_generator():
        try:
            graph = create_compliance_graph()
            initial_state = create_initial_state(
                code=request.code,
                language=request.language,
                policy_ids=request.policies,
                max_iterations=request.max_iterations
            )
            
            # Stream state updates
            async for event in graph.astream(initial_state):
                for node_name, node_output in event.items():
                    if "messages" in node_output:
                        for msg in node_output["messages"]:
                            yield f"event: agent_message\ndata: {json.dumps(msg)}\n\n"
                    
                    # Send state update
                    update = {
                        "node": node_name,
                        "compliant": node_output.get("compliant"),
                        "iteration": node_output.get("iteration"),
                    }
                    yield f"event: state_update\ndata: {json.dumps(update)}\n\n"
                    
                    await asyncio.sleep(0.01)  # Small delay for client processing
            
            yield f"event: complete\ndata: {json.dumps({'status': 'done'})}\n\n"
            
        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )

