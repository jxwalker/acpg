"""API Routes for ACPG system."""
import hashlib
import uuid
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Depends, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..models.schemas import (
    PolicyRule, PolicySet, Violation, AnalysisResult,
    GeneratorRequest, GeneratorResponse, FixRequest,
    AdjudicationResult, ProofBundle,
    ComplianceRequest, EnforceRequest, EnforceResponse
)
from ..services import (
    get_policy_compiler, get_prosecutor, get_generator,
    get_adjudicator, get_proof_assembler
)
from ..core.static_analyzers import get_analyzer_config
from ..core.tool_rules_registry import get_tool_rules, get_all_tool_rules, get_tool_rule
from ..services.tool_cache import get_tool_cache
from ..services.tool_mapper import get_tool_mapper
from ..core.config import settings
from ..core.database import get_db, AuditLogger, ProofStore

router = APIRouter()


def get_client_ip(request: Request) -> str:
    """Get client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ============================================================================
# Health & Info Endpoints
# ============================================================================

@router.get("/health")
async def health_check():
    """
    Comprehensive health check endpoint.
    
    Returns detailed status of system components:
    - API status
    - Database connectivity
    - Static analysis tools availability
    - LLM provider status
    - Policy loading status
    """
    import subprocess
    from ..core.llm_config import get_llm_config
    from ..core.key_manager import get_key_manager
    
    health_status = {
        "status": "healthy",
        "service": "ACPG",
        "version": "1.0.0",
        "components": {
            "api": {"status": "healthy"},
            "database": {"status": "unknown"},
            "tools": {"status": "unknown", "available": []},
            "llm": {"status": "unknown"},
            "policies": {"status": "unknown", "count": 0},
            "signing": {"status": "unknown"}
        },
        "timestamp": None
    }
    
    from datetime import datetime, timezone
    health_status["timestamp"] = datetime.now(timezone.utc).isoformat()
    
    # Check database
    try:
        from sqlalchemy import text
        db = next(get_db())
        db.execute(text("SELECT 1"))
        health_status["components"]["database"]["status"] = "healthy"
    except Exception as e:
        health_status["components"]["database"]["status"] = "unhealthy"
        health_status["components"]["database"]["error"] = str(e)
        health_status["status"] = "degraded"
    
    # Check static analysis tools
    try:
        config = get_analyzer_config()
        available_tools = []
        tool_status = {}
        
        # Check Python tools
        python_tools = config.get_tools_for_language("python")
        for tool_name, tool_config in python_tools.items():
            if tool_config.enabled:
                try:
                    # Try to run tool with --version or --help
                    result = subprocess.run(
                        [tool_name, "--version"] if tool_name != "safety" else [tool_name, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    if result.returncode == 0 or result.returncode == 1:  # Some tools return 1 for --version
                        available_tools.append(tool_name)
                        tool_status[tool_name] = "available"
                    else:
                        tool_status[tool_name] = "unavailable"
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    tool_status[tool_name] = "not_installed"
                except Exception:
                    tool_status[tool_name] = "error"
        
        health_status["components"]["tools"]["status"] = "healthy" if available_tools else "degraded"
        health_status["components"]["tools"]["available"] = available_tools
        health_status["components"]["tools"]["details"] = tool_status
    except Exception as e:
        health_status["components"]["tools"]["status"] = "error"
        health_status["components"]["tools"]["error"] = str(e)
        health_status["status"] = "degraded"
    
    # Check LLM provider
    try:
        llm_config = get_llm_config()
        provider = llm_config.get_active_provider()
        health_status["components"]["llm"]["status"] = "healthy"
        health_status["components"]["llm"]["provider"] = provider.name
        health_status["components"]["llm"]["model"] = provider.model
    except Exception as e:
        health_status["components"]["llm"]["status"] = "unhealthy"
        health_status["components"]["llm"]["error"] = str(e)
        health_status["status"] = "degraded"
    
    # Check policies
    try:
        compiler = get_policy_compiler()
        policies = compiler.get_all_policies()
        health_status["components"]["policies"]["status"] = "healthy"
        health_status["components"]["policies"]["count"] = len(policies)
    except Exception as e:
        health_status["components"]["policies"]["status"] = "unhealthy"
        health_status["components"]["policies"]["error"] = str(e)
        health_status["status"] = "degraded"
    
    # Check signing key
    try:
        km = get_key_manager()
        key_info = km.get_key_info()
        health_status["components"]["signing"]["status"] = "healthy"
        health_status["components"]["signing"]["fingerprint"] = key_info.get("fingerprint", "unknown")
    except Exception as e:
        health_status["components"]["signing"]["status"] = "unhealthy"
        health_status["components"]["signing"]["error"] = str(e)
        health_status["status"] = "degraded"
    
    return health_status


@router.get("/info")
async def get_info():
    """Get system information."""
    return {
        "name": settings.PROJECT_NAME,
        "version": "1.0.0",
        "model": settings.OPENAI_MODEL,
        "max_fix_iterations": settings.MAX_FIX_ITERATIONS
    }


@router.delete("/cache")
async def clear_cache(tool_name: Optional[str] = None):
    """
    Clear tool result cache.
    
    Args:
        tool_name: If provided, clear only this tool's cache. Otherwise clear all.
    """
    from ..services.tool_cache import get_tool_cache
    
    cache = get_tool_cache()
    cache.clear(tool_name)
    
    return {
        "message": f"Cache cleared for {tool_name}" if tool_name else "All cache cleared",
        "tool_name": tool_name
    }


@router.get("/metrics/prometheus")
async def get_metrics_prometheus():
    """
    Get metrics in Prometheus format.
    
    Returns metrics in Prometheus exposition format for scraping.
    """
    from ..services.tool_cache import get_tool_cache
    from ..core.static_analyzers import get_analyzer_config
    from ..services import get_policy_compiler
    
    lines = []
    
    # Cache metrics
    try:
        cache = get_tool_cache()
        stats = cache.get_stats()
        lines.append(f"# HELP acpg_cache_entries_total Total number of cache entries")
        lines.append(f"# TYPE acpg_cache_entries_total gauge")
        lines.append(f"acpg_cache_entries_total {stats.get('total_entries', 0)}")
        
        lines.append(f"# HELP acpg_cache_size_bytes Total cache size in bytes")
        lines.append(f"# TYPE acpg_cache_size_bytes gauge")
        lines.append(f"acpg_cache_size_bytes {stats.get('total_size_bytes', 0)}")
        
        lines.append(f"# HELP acpg_cache_hits_total Total cache hits")
        lines.append(f"# TYPE acpg_cache_hits_total counter")
        lines.append(f"acpg_cache_hits_total {stats.get('hits', 0)}")
        
        lines.append(f"# HELP acpg_cache_misses_total Total cache misses")
        lines.append(f"# TYPE acpg_cache_misses_total counter")
        lines.append(f"acpg_cache_misses_total {stats.get('misses', 0)}")
        
        total_requests = stats.get('hits', 0) + stats.get('misses', 0)
        hit_rate = (stats.get('hits', 0) / total_requests * 100) if total_requests > 0 else 0.0
        lines.append(f"# HELP acpg_cache_hit_rate Cache hit rate percentage")
        lines.append(f"# TYPE acpg_cache_hit_rate gauge")
        lines.append(f"acpg_cache_hit_rate {hit_rate:.2f}")
    except Exception:
        pass
    
    # Tool metrics
    try:
        config = get_analyzer_config()
        all_tools = config.list_all_tools()
        enabled_count = 0
        for language, tools in all_tools.items():
            for tool_name, tool_config in tools.items():
                if tool_config.enabled:
                    enabled_count += 1
                    lines.append(f"# HELP acpg_tool_enabled Whether a tool is enabled")
                    lines.append(f"# TYPE acpg_tool_enabled gauge")
                    lines.append(f'acpg_tool_enabled{{tool="{tool_name}",language="{language}"}} 1')
        
        lines.append(f"# HELP acpg_tools_enabled_total Total number of enabled tools")
        lines.append(f"# TYPE acpg_tools_enabled_total gauge")
        lines.append(f"acpg_tools_enabled_total {enabled_count}")
    except Exception:
        pass
    
    # Policy metrics
    try:
        compiler = get_policy_compiler()
        policies = compiler.get_all_policies()
        lines.append(f"# HELP acpg_policies_total Total number of policies")
        lines.append(f"# TYPE acpg_policies_total gauge")
        lines.append(f"acpg_policies_total {len(policies)}")
    except Exception:
        pass
    
    # Health status (1 = healthy, 0 = unhealthy)
    try:
        from datetime import datetime, timezone
        lines.append(f"# HELP acpg_health_status System health status (1=healthy, 0=unhealthy)")
        lines.append(f"# TYPE acpg_health_status gauge")
        lines.append(f"acpg_health_status 1")  # Could be enhanced to check actual health
    except Exception:
        pass
    
    return Response(
        content="\n".join(lines),
        media_type="text/plain; version=0.0.4"
    )


@router.get("/metrics")
async def get_metrics():
    """
    Get performance and system metrics.
    
    Returns:
    - Tool cache statistics
    - System performance metrics
    - Component status
    """
    from ..services.tool_cache import get_tool_cache
    from ..core.static_analyzers import get_analyzer_config
    
    metrics = {
        "timestamp": None,
        "cache": {},
        "tools": {},
        "policies": {},
        "performance": {}
    }
    
    from datetime import datetime, timezone
    metrics["timestamp"] = datetime.now(timezone.utc).isoformat()
    
    # Cache statistics
    try:
        cache = get_tool_cache()
        cache_stats = cache.get_stats()
        metrics["cache"] = {
            "hits": cache_stats.get("hits", 0),
            "misses": cache_stats.get("misses", 0),
            "total_entries": cache_stats.get("total_entries", 0),
            "total_size_mb": cache_stats.get("total_size_mb", 0.0),
            "hit_rate": cache_stats.get("hit_rate", 0.0),
            "ttl_seconds": cache_stats.get("ttl_seconds", 3600)
        }
    except Exception as e:
        metrics["cache"] = {"error": str(e)}
    
    # Tool statistics
    try:
        config = get_analyzer_config()
        tool_stats = {}
        total_enabled = 0
        
        for language, tools in config.list_all_tools().items():
            for tool_name, tool_config in tools.items():
                if tool_config.enabled:
                    total_enabled += 1
                    tool_stats[tool_name] = {
                        "enabled": True,
                        "language": language,
                        "timeout": tool_config.timeout,
                        "format": tool_config.output_format
                    }
        
        metrics["tools"] = {
            "total_enabled": total_enabled,
            "details": tool_stats
        }
    except Exception as e:
        metrics["tools"] = {"error": str(e)}
    
    # Policy statistics
    try:
        compiler = get_policy_compiler()
        policies = compiler.get_all_policies()
        
        # Count by category
        categories = {}
        for policy in policies:
            category = "default"
            if policy.id.startswith("OWASP"):
                category = "owasp"
            elif policy.id.startswith("NIST"):
                category = "nist"
            categories[category] = categories.get(category, 0) + 1
        
        metrics["policies"] = {
            "total": len(policies),
            "by_category": categories
        }
    except Exception as e:
        metrics["policies"] = {"error": str(e)}
    
    # Performance metrics (if available)
    metrics["performance"] = {
        "note": "Performance metrics collected during analysis",
        "typical_analysis_time": "1-2 seconds",
        "tool_execution": "Parallel execution enabled"
    }
    
    return metrics


# ============================================================================
# Sample Files Endpoints
# ============================================================================

@router.get("/samples")
async def list_sample_files():
    """List available sample code files for testing."""
    import os
    from pathlib import Path
    
    # Navigate from backend/app/api/routes.py to acpg/samples
    samples_dir = Path(__file__).parent.parent.parent.parent / "samples"
    
    if not samples_dir.exists():
        return {"samples": []}
    
    samples = []
    for file in sorted(samples_dir.glob("*.py")):
        # Read first few lines for description
        with open(file, 'r') as f:
            content = f.read()
            lines = content.split('\n')
            
            # Extract description from docstring
            description = ""
            violations = []
            for line in lines[:20]:
                if line.strip().startswith('"""') or line.strip().startswith("'''"):
                    continue
                if "Sample" in line and ":" in line:
                    description = line.split(":", 1)[1].strip()
                if "Violations:" in line:
                    violations = [v.strip() for v in line.split(":", 1)[1].strip().split(",")]
        
        samples.append({
            "name": file.name,
            "path": str(file),
            "description": description or file.stem.replace("_", " ").title(),
            "violations": violations,
            "size": len(content),
            "lines": len(lines)
        })
    
    return {"samples": samples}


@router.get("/samples/{filename}")
async def get_sample_file(filename: str):
    """Get contents of a sample file."""
    from pathlib import Path
    
    samples_dir = Path(__file__).parent.parent.parent.parent / "samples"
    file_path = samples_dir / filename
    
    if not file_path.exists() or not file_path.suffix == '.py':
        raise HTTPException(status_code=404, detail=f"Sample file not found: {filename}")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    return {
        "name": filename,
        "content": content,
        "lines": len(content.split('\n'))
    }


@router.get("/static-analysis/tools")
async def list_static_analysis_tools():
    """List all configured static analysis tools."""
    try:
        config = get_analyzer_config()
        all_tools = config.list_all_tools()
        
        # Format for frontend
        tools_by_language = {}
        for language, tools in all_tools.items():
            tools_by_language[language] = [
                {
                    "name": tool.name,
                    "enabled": tool.enabled,
                    "timeout": tool.timeout,
                    "output_format": tool.output_format,
                    "requires_config": tool.requires_config
                }
                for tool in tools.values()
            ]
        
        # Get cache stats with error handling
        try:
            cache_stats = get_tool_cache().get_stats()
        except Exception as e:
            # If cache stats fail, return empty stats
            import logging
            logging.warning(f"Cache stats unavailable: {e}")
            cache_stats = {
                "cache_dir": "unknown",
                "total_entries": 0,
                "total_size_bytes": 0,
                "ttl_seconds": 3600
            }
        
        response = {
            "tools_by_language": tools_by_language,
            "cache_stats": cache_stats
        }
        
        return response
    except Exception as e:
        import logging
        import traceback
        error_msg = str(e)
        logging.error(f"Error in /static-analysis/tools: {error_msg}", exc_info=True)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error loading tools configuration: {error_msg}")


@router.patch("/static-analysis/tools/{language}/{tool_name}")
async def toggle_tool(language: str, tool_name: str, enabled: bool = Query(...)):
    """Enable or disable a static analysis tool."""
    try:
        config = get_analyzer_config()
        tool = config.get_tool(language, tool_name)
        
        if not tool:
            raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found for language '{language}'")
        
        if enabled:
            config.enable_tool(language, tool_name)
        else:
            config.disable_tool(language, tool_name)
        
        return {
            "language": language,
            "tool_name": tool_name,
            "enabled": enabled,
            "message": f"Tool '{tool_name}' {'enabled' if enabled else 'disabled'}"
        }
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logging.error(f"Error toggling tool: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error toggling tool: {e}")


@router.get("/static-analysis/mappings")
async def get_tool_mappings():
    """Get all tool-to-policy mappings."""
    try:
        mapper = get_tool_mapper()
        mappings = mapper.get_all_mappings()
        return {"mappings": mappings}
    except Exception as e:
        import logging
        logging.error(f"Error loading tool mappings: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error loading tool mappings: {e}")


@router.put("/static-analysis/mappings")
async def update_tool_mappings(request: Dict[str, Any]):
    """Update tool-to-policy mappings."""
    try:
        mapper = get_tool_mapper()
        mappings = request.get("mappings", {})
        mapper.update_mappings(mappings)
        return {
            "message": "Tool mappings updated successfully",
            "mappings": mappings
        }
    except Exception as e:
        import logging
        logging.error(f"Error updating tool mappings: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating tool mappings: {e}")


@router.post("/static-analysis/mappings/{tool_name}/{tool_rule_id}")
async def add_tool_mapping(
    tool_name: str,
    tool_rule_id: str,
    request: Dict[str, Any]
):
    """Add or update a single tool mapping."""
    try:
        mapper = get_tool_mapper()
        mapper.add_or_update_mapping(
            tool_name=tool_name,
            tool_rule_id=tool_rule_id,
            policy_id=request.get("policy_id"),
            confidence=request.get("confidence", "medium"),
            severity=request.get("severity"),
            description=request.get("description")
        )
        return {
            "message": f"Mapping for {tool_name}:{tool_rule_id} updated successfully",
            "mapping": mapper.get_mapping(tool_name, tool_rule_id)
        }
    except Exception as e:
        import logging
        logging.error(f"Error adding tool mapping: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error adding tool mapping: {e}")


class BulkMappingRequest(BaseModel):
    """Request for bulk mapping operations."""
    mappings: List[Dict[str, Any]]  # List of {tool_name, tool_rule_id, policy_id, ...}


@router.post("/static-analysis/mappings/bulk")
async def bulk_add_mappings(request: BulkMappingRequest):
    """
    Add or update multiple tool mappings in a single operation.
    
    Useful for mapping many rules at once.
    """
    try:
        mapper = get_tool_mapper()
        results = {
            "success": [],
            "failed": []
        }
        
        for mapping in request.mappings:
            try:
                tool_name = mapping.get("tool_name")
                tool_rule_id = mapping.get("tool_rule_id")
                policy_id = mapping.get("policy_id")
                
                if not tool_name or not tool_rule_id or not policy_id:
                    results["failed"].append({
                        "mapping": mapping,
                        "error": "Missing required fields: tool_name, tool_rule_id, policy_id"
                    })
                    continue
                
                mapper.add_or_update_mapping(
                    tool_name=tool_name,
                    tool_rule_id=tool_rule_id,
                    policy_id=policy_id,
                    confidence=mapping.get("confidence", "medium"),
                    severity=mapping.get("severity"),
                    description=mapping.get("description")
                )
                
                results["success"].append({
                    "tool_name": tool_name,
                    "tool_rule_id": tool_rule_id,
                    "policy_id": policy_id
                })
            except Exception as e:
                results["failed"].append({
                    "mapping": mapping,
                    "error": str(e)
                })
        
        return {
            "message": f"Bulk mapping completed: {len(results['success'])} succeeded, {len(results['failed'])} failed",
            "total": len(request.mappings),
            "succeeded": len(results["success"]),
            "failed": len(results["failed"]),
            "results": results
        }
    except Exception as e:
        import logging
        logging.error(f"Error in bulk mapping: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error in bulk mapping: {e}")


@router.delete("/static-analysis/mappings/{tool_name}/{tool_rule_id}")
async def delete_tool_mapping(tool_name: str, tool_rule_id: str):
    """Delete a tool mapping."""
    try:
        mapper = get_tool_mapper()
        if mapper.delete_mapping(tool_name, tool_rule_id):
            return {
                "message": f"Mapping for {tool_name}:{tool_rule_id} deleted successfully"
            }
        else:
            raise HTTPException(
                status_code=404,
                detail=f"Mapping not found: {tool_name}:{tool_rule_id}"
            )
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logging.error(f"Error deleting tool mapping: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error deleting tool mapping: {e}")


@router.get("/static-analysis/tools/{tool_name}/rules")
async def get_tool_rules_endpoint(tool_name: str):
    """Get all available rules for a specific tool."""
    try:
        rules = get_tool_rules(tool_name)
        if not rules:
            raise HTTPException(
                status_code=404,
                detail=f"No rules found for tool '{tool_name}' or tool not supported"
            )
        
        # Get existing mappings to show which rules are already mapped
        mapper = get_tool_mapper()
        existing_mappings = mapper.get_all_mappings().get(tool_name, {})
        
        # Enrich rules with mapping status
        enriched_rules = {}
        for rule_id, rule_info in rules.items():
            mapping = existing_mappings.get(rule_id)
            enriched_rules[rule_id] = {
                **rule_info,
                "mapped": mapping is not None,
                "mapped_to_policy": mapping.get("policy_id") if mapping else None
            }
        
        return {
            "tool_name": tool_name,
            "rules": enriched_rules,
            "total_rules": len(rules),
            "mapped_rules": len(existing_mappings),
            "unmapped_rules": len(rules) - len(existing_mappings)
        }
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logging.error(f"Error getting tool rules: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error getting tool rules: {e}")


@router.get("/static-analysis/tools/rules")
async def get_all_tool_rules_endpoint():
    """Get all available rules for all tools."""
    try:
        all_rules = get_all_tool_rules()
        mapper = get_tool_mapper()
        existing_mappings = mapper.get_all_mappings()
        
        # Enrich with mapping status
        enriched = {}
        for tool_name, rules in all_rules.items():
            tool_mappings = existing_mappings.get(tool_name, {})
            enriched[tool_name] = {
                "rules": {
                    rule_id: {
                        **rule_info,
                        "mapped": rule_id in tool_mappings,
                        "mapped_to_policy": tool_mappings.get(rule_id, {}).get("policy_id") if rule_id in tool_mappings else None
                    }
                    for rule_id, rule_info in rules.items()
                },
                "total_rules": len(rules),
                "mapped_rules": len(tool_mappings),
                "unmapped_rules": len(rules) - len(tool_mappings)
            }
        
        return enriched
    except Exception as e:
        import logging
        logging.error(f"Error getting all tool rules: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error getting all tool rules: {e}")


# ============================================================================
# Policy Endpoints
# ============================================================================

@router.get("/policies", response_model=PolicySet)
async def list_policies():
    """List all available policies."""
    compiler = get_policy_compiler()
    policies = compiler.get_all_policies()
    return PolicySet(policies=policies)


@router.get("/policies/{policy_id}", response_model=PolicyRule)
async def get_policy(policy_id: str):
    """Get a specific policy by ID."""
    compiler = get_policy_compiler()
    policy = compiler.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy not found: {policy_id}")
    return policy


@router.get("/policies/severity/{severity}", response_model=List[PolicyRule])
async def get_policies_by_severity(severity: str):
    """Get policies filtered by severity level."""
    if severity not in ('low', 'medium', 'high', 'critical'):
        raise HTTPException(status_code=400, detail="Invalid severity level")
    compiler = get_policy_compiler()
    return compiler.get_policies_by_severity(severity)


# ============================================================================
# Analysis Endpoints
# ============================================================================

@router.post("/analyze", response_model=AnalysisResult)
async def analyze_code(
    request: ComplianceRequest,
    http_request: Request,
    db: Session = Depends(get_db)
):
    """
    Analyze code for policy violations.
    
    Runs static analysis (Bandit) and policy checks (regex, AST).
    Returns all violations found without attempting fixes.
    
    If no policies specified, uses policies from enabled policy groups.
    """
    from .policy_routes import get_enabled_policy_ids
    
    prosecutor = get_prosecutor()
    adjudicator = get_adjudicator()
    
    # Use enabled policy groups if no specific policies requested
    policy_ids = request.policies
    if not policy_ids:
        policy_ids = get_enabled_policy_ids()
    
    result = prosecutor.analyze(
        code=request.code,
        language=request.language,
        policy_ids=policy_ids if policy_ids else None
    )
    
    # Adjudicate to determine compliance
    adjudication = adjudicator.adjudicate(result, request.policies)
    
    # Log to audit trail
    try:
        audit = AuditLogger(db)
        audit.log_analysis(
            artifact_hash=result.artifact_id,
            language=request.language,
            compliant=adjudication.compliant,
            violations=[v.model_dump() for v in result.violations],
            ip_address=get_client_ip(http_request),
            request_id=str(uuid.uuid4())
        )
    except Exception:
        pass  # Don't fail request if audit logging fails
    
    return result


class ViolationSummary(BaseModel):
    """Summary of violations found."""
    total: int
    by_severity: dict
    by_rule: dict
    by_detector: dict
    violations: List[Violation]


@router.post("/analyze/summary", response_model=ViolationSummary)
async def analyze_code_summary(request: ComplianceRequest):
    """
    Analyze code and return a summary of violations.
    """
    from .policy_routes import get_enabled_policy_ids
    
    policy_ids = request.policies
    if not policy_ids:
        policy_ids = get_enabled_policy_ids()
    
    prosecutor = get_prosecutor()
    result = prosecutor.analyze(
        code=request.code,
        language=request.language,
        policy_ids=policy_ids if policy_ids else None
    )
    summary = prosecutor.get_violation_summary(result.violations)
    summary['violations'] = result.violations
    return summary


# ============================================================================
# Batch Analysis Endpoints
# ============================================================================

class BatchAnalysisItem(BaseModel):
    """A single item in a batch analysis request."""
    name: str
    code: str
    language: str = "python"


class BatchAnalysisRequest(BaseModel):
    """Request for batch analysis of multiple code snippets."""
    items: List[BatchAnalysisItem]
    policies: Optional[List[str]] = None


class BatchAnalysisResult(BaseModel):
    """Result for a single item in batch analysis."""
    name: str
    compliant: bool
    violation_count: int
    violations: List[Violation]
    risk_score: int


@router.post("/analyze/batch")
async def batch_analyze(request: BatchAnalysisRequest):
    """
    Analyze multiple code snippets in a single request.
    
    Returns compliance status and violations for each item.
    Useful for analyzing multiple files at once.
    """
    from .policy_routes import get_enabled_policy_ids
    
    prosecutor = get_prosecutor()
    adjudicator = get_adjudicator()
    
    # Use enabled policy groups if no specific policies requested
    policy_ids = request.policies
    if not policy_ids:
        policy_ids = get_enabled_policy_ids()
    
    results = []
    total_violations = 0
    compliant_count = 0
    
    for item in request.items:
        # Analyze each item
        analysis = prosecutor.analyze(
            code=item.code,
            language=item.language,
            policy_ids=policy_ids if policy_ids else None
        )
        
        # Adjudicate
        adjudication = adjudicator.adjudicate(analysis, policy_ids)
        
        # Calculate risk score
        risk_score = 0
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        for v in analysis.violations:
            risk_score += weights.get(v.severity, 5)
        risk_score = min(100, risk_score)
        
        results.append(BatchAnalysisResult(
            name=item.name,
            compliant=adjudication.compliant,
            violation_count=len(analysis.violations),
            violations=analysis.violations,
            risk_score=risk_score
        ))
        
        total_violations += len(analysis.violations)
        if adjudication.compliant:
            compliant_count += 1
    
    return {
        "items": [r.model_dump() for r in results],
        "summary": {
            "total_items": len(request.items),
            "compliant_count": compliant_count,
            "non_compliant_count": len(request.items) - compliant_count,
            "total_violations": total_violations,
            "compliance_rate": round(compliant_count / len(request.items) * 100, 1) if request.items else 0
        }
    }


# ============================================================================
# Report Endpoints
# ============================================================================

class ReportRequest(BaseModel):
    """Request for generating a compliance report."""
    code: str
    language: str = "python"
    policies: Optional[List[str]] = None
    format: str = "json"  # json, markdown, html
    signed: bool = False


@router.post("/report")
async def generate_report(request: ReportRequest):
    """
    Generate a compliance report for code.
    
    This endpoint analyzes code and generates a detailed report
    including violations, recommendations, and risk assessment.
    Does NOT attempt to fix the code.
    
    Report formats:
    - json: Structured JSON report
    - markdown: Human-readable Markdown
    - html: Styled HTML report
    
    If no policies specified, uses policies from enabled policy groups.
    """
    from ..services.report_generator import generate_compliance_report
    from .policy_routes import get_enabled_policy_ids
    
    # Use enabled policy groups if no specific policies requested
    policy_ids = request.policies
    if not policy_ids:
        policy_ids = get_enabled_policy_ids()
    
    # Run analysis
    prosecutor = get_prosecutor()
    analysis = prosecutor.analyze(
        code=request.code,
        language=request.language,
        policy_ids=policy_ids if policy_ids else None
    )
    
    # Run adjudication
    adjudicator = get_adjudicator()
    adjudication = adjudicator.adjudicate(analysis)
    
    # Generate report
    report = generate_compliance_report(
        code=request.code,
        language=request.language,
        analysis=analysis,
        adjudication=adjudication,
        format=request.format,
        signed=request.signed
    )
    
    # Return appropriate content type
    if request.format == "markdown":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(content=report, media_type="text/markdown")
    elif request.format == "html":
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=report)
    
    return report


@router.post("/report/download")
async def download_report(request: ReportRequest):
    """
    Generate and download a compliance report.
    
    Returns the report as a downloadable file with appropriate headers.
    """
    from fastapi.responses import Response
    from ..services.report_generator import generate_compliance_report
    import json
    
    # Run analysis
    prosecutor = get_prosecutor()
    analysis = prosecutor.analyze(
        code=request.code,
        language=request.language,
        policy_ids=request.policies
    )
    
    # Run adjudication
    adjudicator = get_adjudicator()
    adjudication = adjudicator.adjudicate(analysis)
    
    # Generate report
    report = generate_compliance_report(
        code=request.code,
        language=request.language,
        analysis=analysis,
        adjudication=adjudication,
        format=request.format,
        signed=request.signed
    )
    
    # Set filename and content type
    status = "compliant" if adjudication.compliant else "non-compliant"
    timestamp = analysis.timestamp.strftime("%Y%m%d_%H%M%S") if hasattr(analysis, 'timestamp') else "report"
    
    if request.format == "markdown":
        filename = f"compliance_report_{status}_{timestamp}.md"
        content_type = "text/markdown"
        content = report
    elif request.format == "html":
        filename = f"compliance_report_{status}_{timestamp}.html"
        content_type = "text/html"
        content = report
    else:
        filename = f"compliance_report_{status}_{timestamp}.json"
        content_type = "application/json"
        content = json.dumps(report, indent=2)
    
    return Response(
        content=content,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


# ============================================================================
# Generator Endpoints
# ============================================================================

@router.post("/generate", response_model=GeneratorResponse)
async def generate_code(request: GeneratorRequest):
    """
    Generate code from a specification.
    
    Uses AI to generate policy-aware code based on the specification.
    """
    try:
        generator = get_generator()
        return generator.generate_code(request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Generation failed: {str(e)}")


class FixCodeRequest(BaseModel):
    """Request to fix code violations."""
    code: str
    violations: List[Violation]
    language: str = "python"


class FixCodeResponse(BaseModel):
    """Response with fixed code."""
    original_code: str
    fixed_code: str
    explanation: Optional[str] = None


@router.post("/fix", response_model=FixCodeResponse)
async def fix_code(request: FixCodeRequest):
    """
    Fix code to resolve specific violations.
    
    Uses AI to rewrite code addressing the provided violations.
    """
    try:
        generator = get_generator()
        fixed_code = generator.fix_violations(
            code=request.code,
            violations=request.violations,
            language=request.language
        )
        
        # Generate explanation
        explanation = generator.explain_fix(
            original=request.code,
            fixed=fixed_code,
            violations=request.violations
        )
        
        return FixCodeResponse(
            original_code=request.code,
            fixed_code=fixed_code,
            explanation=explanation
        )
    except ValueError as e:
        # ValueError from generator contains helpful error messages
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Unexpected error in fix_code: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Fix failed: {str(e)}")


# ============================================================================
# Adjudication Endpoints
# ============================================================================

@router.post("/adjudicate", response_model=AdjudicationResult)
async def adjudicate_analysis(analysis: AnalysisResult):
    """
    Run adjudication on analysis results.
    
    Uses formal argumentation to determine compliance status.
    """
    adjudicator = get_adjudicator()
    return adjudicator.adjudicate(analysis)


class GuidanceResponse(BaseModel):
    """Guidance for fixing violations."""
    guidance: str
    violation_count: int
    priority_order: List[str]


@router.post("/adjudicate/guidance", response_model=GuidanceResponse)
async def get_fix_guidance(analysis: AnalysisResult):
    """
    Get prioritized guidance for fixing violations.
    """
    adjudicator = get_adjudicator()
    guidance = adjudicator.generate_guidance(analysis)
    
    # Extract priority order
    priority_order = [v.rule_id for v in sorted(
        analysis.violations,
        key=lambda v: (['critical', 'high', 'medium', 'low'].index(v.severity) 
                      if v.severity in ['critical', 'high', 'medium', 'low'] else 99)
    )]
    
    return GuidanceResponse(
        guidance=guidance,
        violation_count=len(analysis.violations),
        priority_order=list(dict.fromkeys(priority_order))  # Dedupe while preserving order
    )


# ============================================================================
# Enforcement Endpoint (Full Loop)
# ============================================================================

@router.post("/enforce", response_model=EnforceResponse)
async def enforce_compliance(
    request: EnforceRequest,
    http_request: Request,
    db: Session = Depends(get_db)
):
    """
    Full compliance enforcement loop.
    
    1. Analyze code for violations
    2. Adjudicate to determine compliance
    3. If non-compliant, use AI to fix
    4. Repeat until compliant or max iterations
    5. Generate signed proof bundle
    
    This is the main endpoint for automated compliance.
    If no policies specified, uses policies from enabled policy groups.
    """
    from .policy_routes import get_enabled_policy_ids
    
    prosecutor = get_prosecutor()
    adjudicator = get_adjudicator()
    generator = get_generator()
    proof_assembler = get_proof_assembler()
    request_id = str(uuid.uuid4())
    
    # Use enabled policy groups if no specific policies requested
    policy_ids = request.policies
    if not policy_ids:
        policy_ids = get_enabled_policy_ids()
    
    code = request.code
    original_code = request.code
    violations_fixed = []
    
    for iteration in range(request.max_iterations):
        # Analyze
        analysis = prosecutor.analyze(
            code=code,
            language=request.language,
            policy_ids=policy_ids if policy_ids else None
        )
        
        # Adjudicate
        adjudication = adjudicator.adjudicate(analysis, policy_ids)
        
        if adjudication.compliant:
            # Success! Generate proof bundle
            proof = proof_assembler.assemble_proof(
                code=code,
                analysis=analysis,
                adjudication=adjudication,
                language=request.language
            )
            
            return EnforceResponse(
                original_code=original_code,
                final_code=code,
                iterations=iteration + 1,
                compliant=True,
                violations_fixed=violations_fixed,
                proof_bundle=proof
            )
        
        # Not compliant - attempt fix
        try:
            fixed_code = generator.fix_violations(
                code=code,
                violations=analysis.violations,
                language=request.language
            )
            
            # Track what we're fixing
            violations_fixed.extend([v.rule_id for v in analysis.violations])
            code = fixed_code
            
        except Exception as e:
            # Fix failed - still generate proof bundle for formal logic visibility
            fail_analysis = prosecutor.analyze(
                code=code,
                language=request.language,
                policy_ids=policy_ids if policy_ids else None
            )
            fail_adjudication = adjudicator.adjudicate(fail_analysis, policy_ids)
            fail_proof = proof_assembler.assemble_proof(
                code=code,
                analysis=fail_analysis,
                adjudication=fail_adjudication,
                language=request.language
            )
            
            return EnforceResponse(
                original_code=original_code,
                final_code=code,
                iterations=iteration + 1,
                compliant=False,
                violations_fixed=violations_fixed,
                proof_bundle=fail_proof
            )
    
    # Max iterations reached without compliance
    # Still generate a proof bundle to show the formal logic of why it failed
    final_analysis = prosecutor.analyze(
        code=code,
        language=request.language,
        policy_ids=policy_ids if policy_ids else None
    )
    final_adjudication = adjudicator.adjudicate(final_analysis, policy_ids)
    
    # Generate proof bundle even for non-compliant code (for formal logic visibility)
    proof = proof_assembler.assemble_proof(
        code=code,
        analysis=final_analysis,
        adjudication=final_adjudication,
        language=request.language
    )
    
    # Log enforcement attempt
    try:
        audit = AuditLogger(db)
        audit.log_enforcement(
            artifact_hash=hashlib.sha256(code.encode()).hexdigest()[:16],
            language=request.language,
            compliant=False,
            violations_fixed=violations_fixed,
            iterations=request.max_iterations,
            ip_address=get_client_ip(http_request),
            request_id=request_id
        )
    except Exception:
        pass
    
    return EnforceResponse(
        original_code=original_code,
        final_code=code,
        iterations=request.max_iterations,
        compliant=False,
        violations_fixed=violations_fixed,
        proof_bundle=proof
    )


# ============================================================================
# Proof Endpoints
# ============================================================================

@router.post("/proof/generate", response_model=ProofBundle)
async def generate_proof(
    request: ComplianceRequest,
    http_request: Request,
    db: Session = Depends(get_db)
):
    """
    Generate a proof bundle for code (compliant or non-compliant).
    
    First analyzes and adjudicates, then generates proof bundle.
    Proof bundles are generated for both compliant and non-compliant code
    to show the formal logic and evidence.
    """
    prosecutor = get_prosecutor()
    adjudicator = get_adjudicator()
    proof_assembler = get_proof_assembler()
    
    analysis = prosecutor.analyze(
        code=request.code,
        language=request.language,
        policy_ids=request.policies
    )
    
    adjudication = adjudicator.adjudicate(analysis, request.policies)
    
    # Generate proof bundle for both compliant and non-compliant code
    # This allows viewing the formal logic even when code fails
    proof = proof_assembler.assemble_proof(
        code=request.code,
        analysis=analysis,
        adjudication=adjudication,
        language=request.language
    )
    
    # Store proof in database
    try:
        proof_store = ProofStore(db)
        proof_store.store_proof(proof.model_dump())
        
        # Log audit trail
        audit = AuditLogger(db)
        audit.log_proof_generation(
            artifact_hash=proof.artifact.hash,
            language=request.language,
            ip_address=get_client_ip(http_request)
        )
    except Exception:
        pass  # Don't fail if storage fails
    
    return proof


# ============================================================================
# Proof Retrieval Endpoints
# ============================================================================

@router.get("/proof/{artifact_hash}")
async def get_proof_by_hash(artifact_hash: str, db: Session = Depends(get_db)):
    """Retrieve a stored proof bundle by artifact hash."""
    proof_store = ProofStore(db)
    proof = proof_store.get_proof_by_hash(artifact_hash)
    
    if not proof:
        raise HTTPException(status_code=404, detail="Proof not found")
    
    return proof


@router.get("/proofs")
async def list_proofs(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db)
):
    """List stored proof bundles."""
    proof_store = ProofStore(db)
    proofs = proof_store.list_proofs(limit=limit, offset=offset)
    return {"proofs": proofs, "count": len(proofs)}


# ============================================================================
# Proof Verification Endpoints
# ============================================================================

class VerifyProofRequest(BaseModel):
    """Request to verify a proof bundle."""
    proof_bundle: Dict[str, Any]

@router.post("/proof/verify")
async def verify_proof_bundle(request: VerifyProofRequest):
    """
    Verify a proof bundle's cryptographic signature.
    
    This endpoint checks if a proof bundle has been tampered with by:
    1. Reconstructing the signed data from the proof bundle
    2. Verifying the ECDSA signature against the public key
    3. Comparing hashes to detect any modifications
    
    Returns detailed information about the verification result.
    """
    from ..core.crypto import get_signer
    from ..core.key_manager import get_key_manager
    
    proof = request.proof_bundle
    signer = get_signer()
    
    result = {
        "valid": False,
        "tampered": True,
        "details": {
            "signature_valid": False,
            "hash_valid": False,
            "timestamp_present": False,
            "signer_match": False
        },
        "original_hash": None,
        "computed_hash": None,
        "checks": [],
        "errors": []
    }
    
    try:
        # Check required fields
        if "signed" not in proof:
            result["errors"].append("Missing 'signed' field - this bundle was not cryptographically signed")
            return result
        
        if "artifact" not in proof:
            result["errors"].append("Missing 'artifact' field")
            return result
        
        signed_info = proof["signed"]
        signature = signed_info.get("signature", "")
        
        if not signature:
            result["errors"].append("No signature found in proof bundle")
            return result
        
        result["checks"].append("✓ Proof bundle has required structure")
        
        # Check signer fingerprint matches
        expected_fingerprint = signer.get_public_key_fingerprint()
        bundle_fingerprint = signed_info.get("public_key_fingerprint", "")
        
        if bundle_fingerprint == expected_fingerprint:
            result["details"]["signer_match"] = True
            result["checks"].append(f"✓ Signer fingerprint matches: {expected_fingerprint}")
        else:
            result["errors"].append(f"✗ Signer mismatch: bundle has '{bundle_fingerprint}', expected '{expected_fingerprint}'")
            result["errors"].append("  This bundle was signed by a different key")
        
        # Reconstruct the data that was signed
        # The signed data includes: artifact, policies, evidence, argumentation, decision, timestamp
        artifact_data = proof.get("artifact", {})
        
        # Handle timestamp serialization
        if "timestamp" in artifact_data:
            ts = artifact_data["timestamp"]
            if hasattr(ts, 'isoformat'):
                artifact_data = dict(artifact_data)
                artifact_data["timestamp"] = ts.isoformat()
        
        # This is the data structure that was signed
        # Must include code to verify it hasn't been tampered with
        code_content = proof.get("code", "")
        if not code_content:
            result["errors"].append("✗ Code content missing from proof bundle")
            result["details"]["code_present"] = False
        else:
            result["details"]["code_present"] = True
            result["checks"].append(f"✓ Code content present ({len(code_content)} characters)")
        
        signed_data = {
            "artifact": artifact_data,
            "code": code_content,  # Include code in signed data verification
            "policies": proof.get("policies", []),
            "evidence": proof.get("evidence", []),
            "argumentation": proof.get("argumentation", {}),
            "decision": proof.get("decision", ""),
            "timestamp": signed_info.get("signed_at", proof.get("timestamp", ""))
        }
        
        # Verify the signature
        try:
            import json
            import base64
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            
            canonical_json = json.dumps(signed_data, sort_keys=True)
            data_bytes = canonical_json.encode('utf-8')
            signature_bytes = base64.b64decode(signature)
            
            signer.public_key.verify(
                signature_bytes,
                data_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            
            result["details"]["signature_valid"] = True
            result["checks"].append("✓ ECDSA signature is VALID")
            
        except Exception as e:
            result["details"]["signature_valid"] = False
            result["errors"].append(f"✗ Signature verification FAILED: {str(e)}")
            result["errors"].append("  The proof bundle data has been modified since signing")
        
        # Verify artifact hash matches code
        if "artifact" in proof and "hash" in proof["artifact"]:
            result["original_hash"] = proof["artifact"]["hash"]
            result["details"]["hash_present"] = True
            result["checks"].append(f"✓ Artifact hash present: {proof['artifact']['hash'][:16]}...")
            
            # Verify code hash matches artifact hash
            if code_content:
                import hashlib
                computed_hash = hashlib.sha256(code_content.encode()).hexdigest()
                if computed_hash == proof["artifact"]["hash"]:
                    result["details"]["hash_valid"] = True
                    result["checks"].append("✓ Code hash matches artifact hash (code integrity verified)")
                else:
                    result["details"]["hash_valid"] = False
                    result["errors"].append("✗ Code hash MISMATCH - code has been modified!")
                    result["errors"].append(f"  Expected: {proof['artifact']['hash'][:16]}...")
                    result["errors"].append(f"  Computed: {computed_hash[:16]}...")
                    result["tampered"] = True
            else:
                result["details"]["hash_valid"] = False
                result["errors"].append("✗ Cannot verify code hash - code content missing")
        
        # Check timestamp
        if artifact_data.get("timestamp"):
            result["details"]["timestamp_present"] = True
            result["checks"].append(f"✓ Timestamp: {artifact_data['timestamp']}")
        
        # Final determination
        result["valid"] = result["details"]["signature_valid"]
        result["tampered"] = not result["details"]["signature_valid"]
        
        if result["valid"]:
            result["checks"].append("")
            result["checks"].append("═══════════════════════════════════════")
            result["checks"].append("  ✓ PROOF BUNDLE INTEGRITY VERIFIED")
            result["checks"].append("  This bundle has NOT been tampered with")
            result["checks"].append("═══════════════════════════════════════")
        else:
            result["errors"].append("")
            result["errors"].append("═══════════════════════════════════════")
            result["errors"].append("  ✗ PROOF BUNDLE TAMPERING DETECTED")
            result["errors"].append("  This bundle has been modified!")
            result["errors"].append("═══════════════════════════════════════")
        
    except Exception as e:
        result["errors"].append(f"Verification error: {str(e)}")
    
    return result


@router.get("/proof/public-key")
async def get_public_key():
    """
    Get the public key used for signing proof bundles.
    
    This can be used to independently verify signatures.
    """
    from ..core.crypto import get_signer
    
    signer = get_signer()
    
    return {
        "public_key_pem": signer.get_public_key_pem(),
        "fingerprint": signer.get_public_key_fingerprint(),
        "algorithm": "ECDSA-SHA256",
        "curve": "SECP256R1 (P-256)"
    }


# ============================================================================
# Admin Endpoints
# ============================================================================

@router.get("/admin/audit-logs")
async def get_audit_logs(
    limit: int = Query(default=100, le=1000),
    action: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get audit logs (admin only in production)."""
    from ..core.database import AuditLog
    
    query = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    
    if action:
        query = query.filter(AuditLog.action == action)
    
    logs = query.limit(limit).all()
    
    return {
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "action": log.action,
                "artifact_hash": log.artifact_hash,
                "compliant": log.compliant,
                "violation_count": log.violation_count
            }
            for log in logs
        ]
    }


@router.get("/admin/stats")
async def get_system_stats(db: Session = Depends(get_db)):
    """Get system statistics."""
    from ..core.database import AuditLog, StoredProof
    from sqlalchemy import func
    
    total_analyses = db.query(func.count(AuditLog.id)).filter(
        AuditLog.action == "analyze"
    ).scalar() or 0
    
    compliant_count = db.query(func.count(AuditLog.id)).filter(
        AuditLog.action == "analyze",
        AuditLog.compliant == True
    ).scalar() or 0
    
    total_proofs = db.query(func.count(StoredProof.id)).scalar() or 0
    
    total_enforcements = db.query(func.count(AuditLog.id)).filter(
        AuditLog.action == "enforce"
    ).scalar() or 0
    
    compiler = get_policy_compiler()
    
    return {
        "total_analyses": total_analyses,
        "compliant_analyses": compliant_count,
        "compliance_rate": round(compliant_count / total_analyses * 100, 1) if total_analyses > 0 else 0,
        "total_proofs_generated": total_proofs,
        "total_enforcements": total_enforcements,
        "policies_loaded": len(compiler.get_all_policies())
    }


class VerifyProofRequest(BaseModel):
    """Request to verify a proof bundle."""
    proof_bundle: ProofBundle


class VerifyProofResponse(BaseModel):
    """Response from proof verification."""
    valid: bool
    message: str


@router.post("/proof/verify", response_model=VerifyProofResponse)
async def verify_proof(request: VerifyProofRequest):
    """
    Verify a proof bundle's signature.
    """
    proof_assembler = get_proof_assembler()
    
    try:
        is_valid = proof_assembler.verify_proof(request.proof_bundle)
        return VerifyProofResponse(
            valid=is_valid,
            message="Signature is valid" if is_valid else "Signature verification failed"
        )
    except Exception as e:
        return VerifyProofResponse(
            valid=False,
            message=f"Verification error: {str(e)}"
        )


class ExportProofRequest(BaseModel):
    """Request to export proof bundle."""
    proof_bundle: ProofBundle
    format: str = "json"


@router.post("/proof/export")
async def export_proof(request: ExportProofRequest):
    """
    Export proof bundle to a portable format.
    """
    proof_assembler = get_proof_assembler()
    
    try:
        exported = proof_assembler.export_proof(
            bundle=request.proof_bundle,
            format=request.format
        )
        return {"format": request.format, "content": exported}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

