"""API Routes for ACPG system."""
import json
import hashlib
import re
import uuid
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, Literal
from fastapi import APIRouter, HTTPException, Query, Depends, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..models.schemas import (
    PolicyRule, PolicySet, Violation, AnalysisResult,
    GeneratorRequest, GeneratorResponse, AdjudicationResult, ProofBundle,
    ComplianceRequest, EnforceRequest, EnforceResponse
)
from ..services import (
    get_policy_compiler, get_prosecutor, get_generator,
    get_adjudicator, get_proof_assembler, get_runtime_policy_compiler
)
from ..core.static_analyzers import get_analyzer_config
from ..core.tool_rules_registry import get_tool_rules, get_all_tool_rules, get_tool_rule
from ..services.tool_cache import get_tool_cache
from ..services.tool_mapper import get_tool_mapper
from ..core.config import settings
from ..core.database import get_db, AuditLogger, ProofStore, TestCaseStore, TestCase
from ..core.auth import AuthContext, require_permission

router = APIRouter()


def get_client_ip(request: Request) -> str:
    """Get client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _auth_actor(auth: Optional[AuthContext]) -> Optional[str]:
    if not auth:
        return None
    key_name = auth.key_name or "anonymous"
    tenant = auth.tenant_id or "global"
    return f"{tenant}:{key_name}"


def _redact_database_url(url: str) -> str:
    if "@" not in url or "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    if "@" not in rest:
        return url
    credentials, host = rest.split("@", 1)
    if ":" in credentials:
        user = credentials.split(":", 1)[0]
        return f"{scheme}://{user}:***@{host}"
    return f"{scheme}://***@{host}"


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
        db_gen = get_db()
        db = next(db_gen)
        try:
            db.execute(text("SELECT 1"))
            health_status["components"]["database"]["status"] = "healthy"
        finally:
            # Ensure the database session is closed
            try:
                next(db_gen, None)  # Advance generator to finally block
            except StopIteration:
                pass
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


class RuntimePolicyEvaluateRequest(BaseModel):
    """Ad-hoc runtime policy evaluation request."""

    event_type: Literal["tool", "network", "filesystem"]
    tool_name: Optional[str] = None
    command: Optional[List[str]] = None
    language: Optional[str] = None
    host: Optional[str] = None
    method: Optional[str] = "GET"
    protocol: Optional[str] = "https"
    path: Optional[str] = None
    operation: Optional[str] = None


@router.get("/runtime/policies")
async def list_runtime_policies():
    """List compiled runtime policies in evaluation order."""
    compiler = get_runtime_policy_compiler()
    compiler.reload()
    rules = [
        {
            "id": rule.id,
            "description": rule.description,
            "event_type": rule.event_type,
            "action": rule.action,
            "severity": rule.severity,
            "priority": rule.priority,
            "enabled": rule.enabled,
            "conditions": rule.conditions,
            "message": rule.message,
            "metadata": rule.metadata,
        }
        for rule in compiler.list_rules()
    ]
    return {
        "policy_file": str(compiler.policy_path),
        "count": len(rules),
        "rules": rules,
    }


@router.post("/runtime/policies/reload")
async def reload_runtime_policies():
    """Reload runtime policy compiler from disk."""
    compiler = get_runtime_policy_compiler()
    compiler.reload()
    return {"ok": True, "count": len(compiler.list_rules())}


@router.post("/runtime/policies/evaluate")
async def evaluate_runtime_policy(request: RuntimePolicyEvaluateRequest):
    """Evaluate a runtime policy decision for a synthetic event."""
    compiler = get_runtime_policy_compiler()
    compiler.reload()

    if request.event_type == "tool":
        decision = compiler.evaluate_tool(
            tool_name=request.tool_name or "",
            command=request.command,
            language=request.language,
        )
    elif request.event_type == "network":
        if not request.host:
            raise HTTPException(status_code=400, detail="host is required for network events")
        decision = compiler.evaluate_network(
            host=request.host,
            method=request.method or "GET",
            protocol=request.protocol or "https",
        )
    elif request.event_type == "filesystem":
        if not request.path or not request.operation:
            raise HTTPException(
                status_code=400,
                detail="path and operation are required for filesystem events",
            )
        decision = compiler.evaluate_filesystem(
            path=request.path,
            operation=request.operation,
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported event type: {request.event_type}")

    return {
        "event_type": request.event_type,
        "decision": {
            "allowed": decision.allowed,
            "action": decision.action,
            "rule_id": decision.rule_id,
            "severity": decision.severity,
            "message": decision.message,
            "evidence": decision.evidence,
            "matched_policies": decision.matched_policies,
            "metadata": decision.metadata,
        },
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
        lines.append("# HELP acpg_cache_entries_total Total number of cache entries")
        lines.append("# TYPE acpg_cache_entries_total gauge")
        lines.append(f"acpg_cache_entries_total {stats.get('total_entries', 0)}")
        
        lines.append("# HELP acpg_cache_size_bytes Total cache size in bytes")
        lines.append("# TYPE acpg_cache_size_bytes gauge")
        lines.append(f"acpg_cache_size_bytes {stats.get('total_size_bytes', 0)}")
        
        lines.append("# HELP acpg_cache_hits_total Total cache hits")
        lines.append("# TYPE acpg_cache_hits_total counter")
        lines.append(f"acpg_cache_hits_total {stats.get('hits', 0)}")
        
        lines.append("# HELP acpg_cache_misses_total Total cache misses")
        lines.append("# TYPE acpg_cache_misses_total counter")
        lines.append(f"acpg_cache_misses_total {stats.get('misses', 0)}")
        
        total_requests = stats.get('hits', 0) + stats.get('misses', 0)
        hit_rate = (stats.get('hits', 0) / total_requests * 100) if total_requests > 0 else 0.0
        lines.append("# HELP acpg_cache_hit_rate Cache hit rate percentage")
        lines.append("# TYPE acpg_cache_hit_rate gauge")
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
                    lines.append("# HELP acpg_tool_enabled Whether a tool is enabled")
                    lines.append("# TYPE acpg_tool_enabled gauge")
                    lines.append(f'acpg_tool_enabled{{tool="{tool_name}",language="{language}"}} 1')
        
        lines.append("# HELP acpg_tools_enabled_total Total number of enabled tools")
        lines.append("# TYPE acpg_tools_enabled_total gauge")
        lines.append(f"acpg_tools_enabled_total {enabled_count}")
    except Exception:
        pass
    
    # Policy metrics
    try:
        compiler = get_policy_compiler()
        policies = compiler.get_all_policies()
        lines.append("# HELP acpg_policies_total Total number of policies")
        lines.append("# TYPE acpg_policies_total gauge")
        lines.append(f"acpg_policies_total {len(policies)}")
    except Exception:
        pass
    
    # Health status (1 = healthy, 0 = unhealthy)
    try:
        lines.append("# HELP acpg_health_status System health status (1=healthy, 0=unhealthy)")
        lines.append("# TYPE acpg_health_status gauge")
        lines.append("acpg_health_status 1")  # Could be enhanced to check actual health
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


class TestCaseItem(BaseModel):
    """Unified test case item from DB or file source."""
    id: str
    source: Literal["db", "file"]
    name: str
    description: Optional[str] = None
    language: str = "python"
    tags: List[str] = []
    violations: List[str] = []
    read_only: bool = False
    code: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class CreateTestCaseRequest(BaseModel):
    """Create a DB-backed test case."""
    name: str
    description: Optional[str] = None
    language: str = "python"
    code: str
    tags: List[str] = []


class UpdateTestCaseRequest(BaseModel):
    """Update a DB-backed test case."""
    name: Optional[str] = None
    description: Optional[str] = None
    language: Optional[str] = None
    code: Optional[str] = None
    tags: Optional[List[str]] = None
    is_active: Optional[bool] = None


class ImportTestCaseItem(BaseModel):
    """Import payload item for DB-backed test cases."""
    id: Optional[str] = None
    name: str
    description: Optional[str] = None
    language: str = "python"
    code: str
    tags: List[str] = []
    is_active: Optional[bool] = True


class ImportTestCasesRequest(BaseModel):
    """Bulk import request for DB test cases."""
    cases: List[ImportTestCaseItem]
    overwrite: bool = False
    match_by: Literal["name_language", "id"] = "name_language"


def _get_samples_dir() -> Path:
    import os
    return Path(os.environ.get("SAMPLES_DIR", Path(__file__).parent.parent.parent.parent / "samples"))


_POLICY_ID_RE = re.compile(r"\b[A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)*-\d{1,4}\b")
_SAMPLE_TITLE_RE = re.compile(r"^\s*Sample(?:\s+\d+)?\s*:\s*(.+?)\s*$", re.IGNORECASE)
_MAPPED_POLICY_RE = re.compile(r"mapped to\s+([A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)*-\d{1,4})", re.IGNORECASE)


def _dedupe_preserving_order(values: List[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _extract_sample_metadata(lines: List[str], stem_fallback: str) -> Dict[str, Any]:
    description = ""
    violations: List[str] = []

    for line in lines[:40]:
        stripped = line.strip()
        normalized = stripped.strip("# ").strip("'\"")
        if not normalized:
            continue

        title_match = _SAMPLE_TITLE_RE.match(normalized)
        if title_match and not description:
            description = title_match.group(1).strip()

        if "violations" in normalized.lower() and ":" in normalized:
            tail = normalized.split(":", 1)[1]
            violations.extend(_POLICY_ID_RE.findall(tail))

    if not description:
        for line in lines[:40]:
            normalized = line.strip().strip("# ").strip("'\"")
            if not normalized:
                continue
            if normalized.lower() in {"sample", "violations"}:
                continue
            if normalized.lower().startswith("sample "):
                description = normalized
            else:
                description = normalized.rstrip(".")
            break

    if not violations:
        preview = "\n".join(lines[:240])
        mapped = _MAPPED_POLICY_RE.findall(preview)
        if mapped:
            violations.extend(mapped)
        else:
            violations.extend(_POLICY_ID_RE.findall(preview))

    return {
        "description": description or stem_fallback,
        "violations": _dedupe_preserving_order(violations),
    }


def _parse_file_test_case(file_path: Path, include_code: bool = False) -> Dict[str, Any]:
    content = file_path.read_text()
    lines = content.split('\n')
    fallback_description = file_path.stem.replace("_", " ").title()
    metadata = _extract_sample_metadata(lines, fallback_description)

    item: Dict[str, Any] = {
        "id": f"file:{file_path.name}",
        "source": "file",
        "name": file_path.name,
        "description": metadata["description"],
        "language": "python",
        "tags": ["file-sample"],
        "violations": metadata["violations"],
        "read_only": True,
        "created_at": None,
        "updated_at": None,
    }
    if include_code:
        item["code"] = content
    return item


def _db_case_to_item(case: Any, include_code: bool = False) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "id": f"db:{case.id}",
        "source": "db",
        "name": case.name,
        "description": case.description,
        "language": case.language or "python",
        "tags": case.tags or [],
        "violations": [],
        "read_only": False,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
    }
    if include_code:
        item["code"] = case.code
    return item


def _normalize_tags(tags: Optional[List[str]]) -> List[str]:
    normalized: List[str] = []
    seen = set()
    for raw in tags or []:
        tag = str(raw).strip().lower()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        normalized.append(tag)
    return normalized


@router.get("/test-cases", response_model=Dict[str, List[TestCaseItem]])
async def list_test_cases(
    source: Literal["all", "db", "file"] = Query("all"),
    language: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """List test cases from DB and/or file samples."""
    items: List[Dict[str, Any]] = []
    normalized_tag = tag.strip().lower() if tag else None

    if source in ("all", "db"):
        store = TestCaseStore(db)
        for case in store.list_cases(include_inactive=False, language=language):
            item = _db_case_to_item(case, include_code=False)
            if normalized_tag and normalized_tag not in item.get("tags", []):
                continue
            items.append(item)

    if source in ("all", "file"):
        samples_dir = _get_samples_dir()
        if samples_dir.exists():
            for file in sorted(samples_dir.glob("*.py")):
                if language and language != "python":
                    continue
                item = _parse_file_test_case(file, include_code=False)
                if normalized_tag and normalized_tag not in item.get("tags", []):
                    continue
                items.append(item)

    return {"cases": items}


@router.get("/test-cases/tags")
async def list_test_case_tags(
    source: Literal["all", "db", "file"] = Query("all"),
    language: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """List available tags with usage counts across test case sources."""
    tag_counts: Dict[str, int] = {}

    if source in ("all", "db"):
        store = TestCaseStore(db)
        for case in store.list_cases(include_inactive=False, language=language):
            for tag in _normalize_tags(case.tags):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

    if source in ("all", "file"):
        samples_dir = _get_samples_dir()
        if samples_dir.exists() and (not language or language == "python"):
            for file in sorted(samples_dir.glob("*.py")):
                item = _parse_file_test_case(file, include_code=False)
                for tag in _normalize_tags(item.get("tags", [])):
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1

    tags = [{"tag": tag, "count": count} for tag, count in sorted(tag_counts.items())]
    return {"tags": tags, "count": len(tags)}


@router.get("/test-cases/export")
async def export_test_cases(
    include_inactive: bool = Query(False),
    language: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Export DB-backed test cases as a portable JSON payload."""
    store = TestCaseStore(db)
    cases = store.list_cases(include_inactive=include_inactive, language=language)
    payload = []
    for case in cases:
        payload.append(
            {
                "id": f"db:{case.id}",
                "name": case.name,
                "description": case.description,
                "language": case.language or "python",
                "code": case.code,
                "tags": _normalize_tags(case.tags),
                "is_active": bool(case.is_active),
                "created_at": case.created_at.isoformat() if case.created_at else None,
                "updated_at": case.updated_at.isoformat() if case.updated_at else None,
            }
        )

    return {
        "version": "1",
        "exported_at": datetime.now(tz=timezone.utc).isoformat(),
        "count": len(payload),
        "cases": payload,
    }


@router.post("/test-cases/import")
async def import_test_cases(request: ImportTestCasesRequest, db: Session = Depends(get_db)):
    """Bulk import DB-backed test cases, with optional overwrite behavior."""
    if not request.cases:
        raise HTTPException(status_code=400, detail="cases is required")

    store = TestCaseStore(db)
    created_ids: List[str] = []
    updated_ids: List[str] = []
    skipped_ids: List[str] = []
    errors: List[Dict[str, Any]] = []

    for index, item in enumerate(request.cases):
        name = item.name.strip()
        code = item.code.strip()
        if not name:
            errors.append({"index": index, "id": item.id, "error": "name is required"})
            continue
        if not code:
            errors.append({"index": index, "id": item.id, "error": "code is required"})
            continue

        existing: Optional[TestCase] = None
        if request.match_by == "id" and item.id:
            raw_id = str(item.id).strip()
            if raw_id.startswith("db:"):
                raw_id = raw_id.split(":", 1)[1]
            if raw_id.isdigit():
                existing = store.get_case(int(raw_id))
        if existing is None:
            existing = (
                db.query(TestCase)
                .filter(TestCase.name == name, TestCase.language == item.language)
                .first()
            )

        normalized_tags = _normalize_tags(item.tags)
        if existing:
            existing_id = f"db:{existing.id}"
            if not request.overwrite:
                skipped_ids.append(existing_id)
                continue
            updated = store.update_case(
                existing,
                name=name,
                description=item.description,
                language=item.language,
                code=code,
                tags=normalized_tags,
                is_active=item.is_active if item.is_active is not None else existing.is_active,
            )
            updated_ids.append(f"db:{updated.id}")
            continue

        created = store.create_case(
            name=name,
            description=item.description,
            language=item.language,
            code=code,
            tags=normalized_tags,
            is_active=True if item.is_active is None else bool(item.is_active),
        )
        created_ids.append(f"db:{created.id}")

    return {
        "success": len(errors) == 0,
        "summary": {
            "requested": len(request.cases),
            "created": len(created_ids),
            "updated": len(updated_ids),
            "skipped": len(skipped_ids),
            "errors": len(errors),
        },
        "created_ids": created_ids,
        "updated_ids": updated_ids,
        "skipped_ids": skipped_ids,
        "errors": errors,
    }


@router.get("/test-cases/{case_id}", response_model=TestCaseItem)
async def get_test_case(case_id: str, db: Session = Depends(get_db)):
    """Get full test case content by ID (db:<id> or file:<filename>)."""
    if case_id.startswith("db:"):
        try:
            db_id = int(case_id.split(":", 1)[1])
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid DB test case id")
        store = TestCaseStore(db)
        case = store.get_case(db_id)
        if not case or not case.is_active:
            raise HTTPException(status_code=404, detail=f"Test case not found: {case_id}")
        return TestCaseItem(**_db_case_to_item(case, include_code=True))

    if case_id.startswith("file:"):
        filename = case_id.split(":", 1)[1]
        samples_dir = _get_samples_dir()
        samples_root = samples_dir.resolve()
        file_path = (samples_dir / filename).resolve()
        if (
            not samples_dir.exists()
            or not str(file_path).startswith(str(samples_root))
            or not file_path.exists()
            or file_path.suffix != ".py"
        ):
            raise HTTPException(status_code=404, detail=f"Test case not found: {case_id}")
        return TestCaseItem(**_parse_file_test_case(file_path, include_code=True))

    raise HTTPException(status_code=400, detail="Unsupported test case id format")


@router.post("/test-cases", response_model=TestCaseItem)
async def create_test_case(request: CreateTestCaseRequest, db: Session = Depends(get_db)):
    """Create a DB-backed test case."""
    if not request.name.strip():
        raise HTTPException(status_code=400, detail="name is required")
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="code is required")

    store = TestCaseStore(db)
    case = store.create_case(
        name=request.name.strip(),
        description=request.description,
        language=request.language,
        code=request.code,
        tags=_normalize_tags(request.tags),
    )
    return TestCaseItem(**_db_case_to_item(case, include_code=True))


@router.put("/test-cases/{case_id}", response_model=TestCaseItem)
async def update_test_case(case_id: str, request: UpdateTestCaseRequest, db: Session = Depends(get_db)):
    """Update a DB-backed test case."""
    if not case_id.startswith("db:"):
        raise HTTPException(status_code=400, detail="Only DB-backed test cases are editable")
    try:
        db_id = int(case_id.split(":", 1)[1])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid DB test case id")

    store = TestCaseStore(db)
    case = store.get_case(db_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Test case not found: {case_id}")

    updated = store.update_case(
        case,
        name=request.name,
        description=request.description,
        language=request.language,
        code=request.code,
        tags=_normalize_tags(request.tags) if request.tags is not None else None,
        is_active=request.is_active,
    )
    return TestCaseItem(**_db_case_to_item(updated, include_code=True))


@router.delete("/test-cases/{case_id}")
async def delete_test_case(case_id: str, db: Session = Depends(get_db)):
    """Delete a DB-backed test case."""
    if not case_id.startswith("db:"):
        raise HTTPException(status_code=400, detail="Only DB-backed test cases are deletable")
    try:
        db_id = int(case_id.split(":", 1)[1])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid DB test case id")

    store = TestCaseStore(db)
    case = store.get_case(db_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Test case not found: {case_id}")
    store.delete_case(case)
    return {"success": True, "message": f"Deleted {case_id}"}

@router.get("/samples")
async def list_sample_files():
    """List available sample code files for testing."""
    samples_dir = _get_samples_dir()
    
    if not samples_dir.exists():
        return {"samples": [], "error": f"Samples directory not found: {samples_dir}"}
    
    samples = []
    for file in sorted(samples_dir.glob("*.py")):
        item = _parse_file_test_case(file, include_code=False)
        content = file.read_text()
        lines = content.split('\n')
        samples.append({
            "name": item["name"],
            "path": str(file),
            "description": item["description"],
            "violations": item["violations"],
            "size": len(content),
            "lines": len(lines)
        })
    
    return {"samples": samples}


@router.get("/samples/{filename}")
async def get_sample_file(filename: str):
    """Get contents of a sample file."""
    samples_dir = _get_samples_dir()
    samples_root = samples_dir.resolve()
    file_path = (samples_dir / filename).resolve()
    
    if (
        not str(file_path).startswith(str(samples_root))
        or not file_path.exists()
        or file_path.suffix != '.py'
    ):
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


@router.get("/static-analysis/tools/{tool_name}/rules/{rule_id}")
async def get_single_tool_rule(tool_name: str, rule_id: str):
    """Get a specific rule for a tool with its details."""
    try:
        rule = get_tool_rule(tool_name, rule_id)
        if not rule:
            raise HTTPException(
                status_code=404,
                detail=f"Rule '{rule_id}' not found for tool '{tool_name}'"
            )
        
        # Get mapping status
        mapper = get_tool_mapper()
        existing_mappings = mapper.get_all_mappings().get(tool_name, {})
        mapping = existing_mappings.get(rule_id)
        
        return {
            "tool_name": tool_name,
            "rule_id": rule_id,
            **rule,
            "mapped": mapping is not None,
            "mapped_to_policy": mapping.get("policy_id") if mapping else None
        }
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logging.error(f"Error getting tool rule: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error getting tool rule: {e}")


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
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("analyze")),
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
            user_id=_auth_actor(auth),
            ip_address=get_client_ip(http_request),
            request_id=str(uuid.uuid4())
        )
    except Exception:
        pass  # Don't fail request if audit logging fails
    
    # Save to analysis history
    try:
        severity_breakdown = {}
        rule_breakdown = {}
        for v in result.violations:
            severity_breakdown[v.severity] = severity_breakdown.get(v.severity, 0) + 1
            rule_breakdown[v.rule_id] = rule_breakdown.get(v.rule_id, 0) + 1

        dynamic_artifacts: List[Dict[str, Any]] = []
        if result.dynamic_analysis and result.dynamic_analysis.executed:
            for artifact in result.dynamic_analysis.artifacts:
                first_rule = next(
                    (
                        violation.rule_id
                        for violation in result.dynamic_analysis.violations
                        if violation.detector.endswith(artifact.suite_id)
                    ),
                    None,
                )
                dynamic_artifacts.append(
                    {
                        "artifact_id": artifact.artifact_id,
                        "suite_id": artifact.suite_id,
                        "suite_name": artifact.suite_name,
                        "return_code": artifact.return_code,
                        "timed_out": artifact.timed_out,
                        "duration_seconds": artifact.duration_seconds,
                        "replay_fingerprint": artifact.replay.deterministic_fingerprint,
                        "violation_rule_id": first_rule,
                    }
                )
        
        await add_to_history(
            code=request.code,
            language=request.language,
            compliant=adjudication.compliant,
            violations_count=len(result.violations),
            policies_passed=len(adjudication.satisfied_rules),
            severity_breakdown=severity_breakdown,
            rule_breakdown=rule_breakdown,
            dynamic_executed=bool(result.dynamic_analysis and result.dynamic_analysis.executed),
            dynamic_runner=result.dynamic_analysis.runner if result.dynamic_analysis else None,
            dynamic_artifacts=dynamic_artifacts,
            tenant_id=auth.tenant_id,
            auth=auth,
        )
    except Exception:
        pass  # Don't fail if history save fails
    
    return result


class ViolationSummary(BaseModel):
    """Summary of violations found."""
    total: int
    by_severity: dict
    by_rule: dict
    by_detector: dict
    violations: List[Violation]


@router.post("/analyze/summary", response_model=ViolationSummary)
async def analyze_code_summary(
    request: ComplianceRequest,
    auth: AuthContext = Depends(require_permission("analyze")),
):
    """
    Analyze code and return a summary of violations.
    """
    _ = auth
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
async def batch_analyze(
    request: BatchAnalysisRequest,
    auth: AuthContext = Depends(require_permission("analyze")),
):
    """
    Analyze multiple code snippets in a single request.
    
    Returns compliance status and violations for each item.
    Useful for analyzing multiple files at once.
    """
    _ = auth
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
async def generate_report(
    request: ReportRequest,
    auth: AuthContext = Depends(require_permission("analyze")),
):
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
    _ = auth
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
        
        # Generate explanation (optional - don't fail if this errors)
        explanation = None
        try:
            explanation = generator.explain_fix(
                original=request.code,
                fixed=fixed_code,
                violations=request.violations
            )
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to generate explanation: {e}")
            # Continue without explanation rather than failing
        
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
async def adjudicate_analysis(
    analysis: AnalysisResult,
    semantics: Literal["grounded", "auto", "stable", "preferred"] = Query(
        "grounded",
        description="Argumentation semantics: grounded, auto, stable, preferred",
    ),
    solver_mode: Literal["auto", "skeptical", "credulous"] = Query(
        "auto",
        description="Solver decision mode for stable/preferred semantics: auto, skeptical, credulous",
    ),
    auth: AuthContext = Depends(require_permission("adjudicate")),
):
    """
    Run adjudication on analysis results.
    
    Uses formal argumentation to determine compliance status.
    """
    _ = auth
    adjudicator = get_adjudicator()
    return adjudicator.adjudicate(
        analysis,
        semantics=semantics,
        solver_decision_mode=solver_mode,
    )


class GuidanceResponse(BaseModel):
    """Guidance for fixing violations."""
    guidance: str
    violation_count: int
    priority_order: List[str]


@router.post("/adjudicate/guidance", response_model=GuidanceResponse)
async def get_fix_guidance(
    analysis: AnalysisResult,
    auth: AuthContext = Depends(require_permission("adjudicate")),
):
    """
    Get prioritized guidance for fixing violations.
    """
    _ = auth
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
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("enforce")),
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
    generator.reset_usage_tracking()
    
    # Use enabled policy groups if no specific policies requested
    policy_ids = request.policies
    if not policy_ids:
        policy_ids = get_enabled_policy_ids()
    
    semantics = request.semantics or "grounded"
    code = request.code
    original_code = request.code
    violations_fixed = []
    run_started = time.perf_counter()
    analysis_total_seconds = 0.0
    adjudication_total_seconds = 0.0
    fix_total_seconds = 0.0
    proof_total_seconds = 0.0
    iteration_metrics: List[Dict[str, Any]] = []
    stopped_early_reason: Optional[str] = None
    seen_code_hashes = {hashlib.sha256(code.encode()).hexdigest()}
    prev_violation_fingerprint: Optional[tuple[str, ...]] = None
    prev_violation_count: Optional[int] = None
    consecutive_unchanged_fixes = 0
    last_fix_changed: Optional[bool] = None

    def _build_performance() -> Dict[str, Any]:
        return {
            "total_seconds": round(time.perf_counter() - run_started, 6),
            "analysis_seconds": round(analysis_total_seconds, 6),
            "adjudication_seconds": round(adjudication_total_seconds, 6),
            "fix_seconds": round(fix_total_seconds, 6),
            "proof_seconds": round(proof_total_seconds, 6),
            "stopped_early_reason": stopped_early_reason,
            "iterations": iteration_metrics,
        }
    
    for iteration in range(request.max_iterations):
        iter_num = iteration + 1
        iter_metrics: Dict[str, Any] = {
            "iteration": iter_num,
            "violation_count": 0,
            "compliant": False,
            "analysis_seconds": 0.0,
            "adjudication_seconds": 0.0,
            "fix_attempted": False,
            "semantics_used": None,
        }

        # Analyze
        analysis_started = time.perf_counter()
        analysis = prosecutor.analyze(
            code=code,
            language=request.language,
            policy_ids=policy_ids if policy_ids else None
        )
        analysis_seconds = time.perf_counter() - analysis_started
        analysis_total_seconds += analysis_seconds
        iter_metrics["analysis_seconds"] = round(analysis_seconds, 6)
        iter_metrics["violation_count"] = len(analysis.violations)
        
        # Adjudicate
        adjudication_started = time.perf_counter()
        adjudication = adjudicator.adjudicate(
            analysis,
            policy_ids,
            semantics=semantics,
            solver_decision_mode=request.solver_decision_mode,
        )
        adjudication_seconds = time.perf_counter() - adjudication_started
        adjudication_total_seconds += adjudication_seconds
        iter_metrics["adjudication_seconds"] = round(adjudication_seconds, 6)
        iter_metrics["compliant"] = adjudication.compliant
        iter_metrics["semantics_used"] = adjudication.semantics
        iteration_metrics.append(iter_metrics)
        
        if adjudication.compliant:
            # Success! Generate proof bundle
            proof_started = time.perf_counter()
            proof = proof_assembler.assemble_proof(
                code=code,
                analysis=analysis,
                adjudication=adjudication,
                language=request.language
            )
            proof_total_seconds += time.perf_counter() - proof_started
            
            return EnforceResponse(
                original_code=original_code,
                final_code=code,
                iterations=iter_num,
                compliant=True,
                violations_fixed=violations_fixed,
                llm_usage=generator.get_usage_summary(),
                performance=_build_performance(),
                proof_bundle=proof
            )

        current_fingerprint = tuple(sorted(v.rule_id for v in analysis.violations))
        if (
            request.stop_on_stagnation
            and last_fix_changed is not False
            and prev_violation_fingerprint is not None
            and current_fingerprint == prev_violation_fingerprint
            and prev_violation_count is not None
            and len(analysis.violations) >= prev_violation_count
        ):
            stopped_early_reason = "stagnation_no_violation_reduction"
            break
        
        # Not compliant - attempt fix
        try:
            iter_metrics["fix_attempted"] = True
            fix_started = time.perf_counter()
            fixed_code = generator.fix_violations(
                code=code,
                violations=analysis.violations,
                language=request.language
            )
            fix_seconds = time.perf_counter() - fix_started
            fix_total_seconds += fix_seconds
            iter_metrics["fix_seconds"] = round(fix_seconds, 6)
            
            # Track what we're fixing
            violations_fixed.extend([v.rule_id for v in analysis.violations])
            next_code = fixed_code
            if next_code.strip() == code.strip():
                iter_metrics["fix_changed"] = False
                consecutive_unchanged_fixes += 1
                last_fix_changed = False
                prev_violation_fingerprint = current_fingerprint
                prev_violation_count = len(analysis.violations)
                if request.stop_on_stagnation and consecutive_unchanged_fixes >= 2:
                    stopped_early_reason = "fix_returned_unchanged_code"
                    break
                continue

            next_hash = hashlib.sha256(next_code.encode()).hexdigest()
            iter_metrics["fix_changed"] = True
            consecutive_unchanged_fixes = 0
            last_fix_changed = True
            if request.stop_on_stagnation and next_hash in seen_code_hashes:
                code = next_code
                stopped_early_reason = "fix_cycle_detected"
                break
            seen_code_hashes.add(next_hash)
            code = next_code
            prev_violation_fingerprint = current_fingerprint
            prev_violation_count = len(analysis.violations)
            
        except Exception as e:
            iter_metrics["fix_attempted"] = True
            iter_metrics["fix_error"] = str(e)
            iter_metrics["fix_changed"] = False
            # Fix failed - still generate proof bundle for formal logic visibility
            fail_analysis_started = time.perf_counter()
            fail_analysis = prosecutor.analyze(
                code=code,
                language=request.language,
                policy_ids=policy_ids if policy_ids else None
            )
            analysis_total_seconds += time.perf_counter() - fail_analysis_started
            fail_adjudication_started = time.perf_counter()
            fail_adjudication = adjudicator.adjudicate(
                fail_analysis,
                policy_ids,
                semantics=semantics,
                solver_decision_mode=request.solver_decision_mode,
            )
            adjudication_total_seconds += time.perf_counter() - fail_adjudication_started
            fail_proof_started = time.perf_counter()
            fail_proof = proof_assembler.assemble_proof(
                code=code,
                analysis=fail_analysis,
                adjudication=fail_adjudication,
                language=request.language
            )
            proof_total_seconds += time.perf_counter() - fail_proof_started
            stopped_early_reason = "fix_error"
            
            return EnforceResponse(
                original_code=original_code,
                final_code=code,
                iterations=iter_num,
                compliant=False,
                violations_fixed=violations_fixed,
                llm_usage=generator.get_usage_summary(),
                performance=_build_performance(),
                proof_bundle=fail_proof
            )
    
    final_analysis_started = time.perf_counter()
    final_analysis = prosecutor.analyze(
        code=code,
        language=request.language,
        policy_ids=policy_ids if policy_ids else None
    )
    analysis_total_seconds += time.perf_counter() - final_analysis_started
    final_adjudication_started = time.perf_counter()
    final_adjudication = adjudicator.adjudicate(
        final_analysis,
        policy_ids,
        semantics=semantics,
        solver_decision_mode=request.solver_decision_mode,
    )
    adjudication_total_seconds += time.perf_counter() - final_adjudication_started
    
    # Generate proof bundle even for non-compliant code (for formal logic visibility)
    proof_started = time.perf_counter()
    proof = proof_assembler.assemble_proof(
        code=code,
        analysis=final_analysis,
        adjudication=final_adjudication,
        language=request.language
    )
    proof_total_seconds += time.perf_counter() - proof_started
    
    # Log enforcement attempt
    try:
        audit = AuditLogger(db)
        audit.log_enforcement(
            artifact_hash=hashlib.sha256(code.encode()).hexdigest()[:16],
            language=request.language,
            compliant=final_adjudication.compliant,
            violations_fixed=violations_fixed,
            iterations=len(iteration_metrics) if iteration_metrics else request.max_iterations,
            user_id=_auth_actor(auth),
            ip_address=get_client_ip(http_request),
            request_id=request_id
        )
    except Exception:
        pass

    if not final_adjudication.compliant and stopped_early_reason is None:
        stopped_early_reason = "max_iterations_reached"
    
    return EnforceResponse(
        original_code=original_code,
        final_code=code,
        iterations=len(iteration_metrics) if iteration_metrics else request.max_iterations,
        compliant=final_adjudication.compliant,
        violations_fixed=violations_fixed,
        llm_usage=generator.get_usage_summary(),
        performance=_build_performance(),
        proof_bundle=proof
    )


# ============================================================================
# Proof Endpoints
# ============================================================================

@router.post("/proof/generate", response_model=ProofBundle)
async def generate_proof(
    request: ComplianceRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    semantics: str = Query(
        "grounded",
        description="Argumentation semantics: grounded, auto, stable, preferred",
    ),
    solver_mode: Literal["auto", "skeptical", "credulous"] = Query(
        "auto",
        description="Solver decision mode for stable/preferred semantics: auto, skeptical, credulous",
    ),
    auth: AuthContext = Depends(require_permission("proof:generate")),
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
    
    adjudication = adjudicator.adjudicate(
        analysis,
        request.policies,
        semantics=semantics,
        solver_decision_mode=solver_mode,
    )
    
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
            user_id=_auth_actor(auth),
            ip_address=get_client_ip(http_request)
        )
    except Exception:
        pass  # Don't fail if storage fails
    
    return proof


# ============================================================================
# Proof Retrieval Endpoints
# ============================================================================

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


@router.get("/proof/{artifact_hash}")
async def get_proof_by_hash(
    artifact_hash: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("proof:read")),
):
    """Retrieve a stored proof bundle by artifact hash."""
    _ = auth
    proof_store = ProofStore(db)
    proof = proof_store.get_proof_by_hash(artifact_hash)
    
    if not proof:
        raise HTTPException(status_code=404, detail="Proof not found")
    
    return proof


@router.get("/proofs")
async def list_proofs(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("proof:read")),
):
    """List stored proof bundles."""
    _ = auth
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
async def verify_proof_bundle(
    request: VerifyProofRequest,
    auth: AuthContext = Depends(require_permission("proof:read")),
):
    """
    Verify a proof bundle's cryptographic signature.
    
    This endpoint checks if a proof bundle has been tampered with by:
    1. Reconstructing the signed data from the proof bundle
    2. Verifying the ECDSA signature against the public key
    3. Comparing hashes to detect any modifications
    
    Returns detailed information about the verification result.
    """
    _ = auth
    from ..core.crypto import get_signer
    
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


# ============================================================================
# Admin Endpoints
# ============================================================================

@router.get("/admin/audit-logs")
async def get_audit_logs(
    limit: int = Query(default=100, le=1000),
    action: Optional[str] = None,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("admin:read")),
):
    """Get audit logs (admin only in production)."""
    _ = auth
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
async def get_system_stats(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("admin:read")),
):
    """Get system statistics."""
    _ = auth
    from ..core.database import AuditLog, StoredProof
    from sqlalchemy import func
    
    total_analyses = db.query(func.count(AuditLog.id)).filter(
        AuditLog.action == "analyze"
    ).scalar() or 0
    
    compliant_count = db.query(func.count(AuditLog.id)).filter(
        AuditLog.action == "analyze",
        AuditLog.compliant.is_(True)
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


@router.get("/admin/database/diagnostics")
async def get_database_diagnostics(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("admin:read")),
):
    """Return database connectivity and pool diagnostics for operations."""
    from sqlalchemy import text
    from ..core.database import DATABASE_URL, engine

    _ = auth
    started = time.perf_counter()
    db.execute(text("SELECT 1"))
    latency_ms = round((time.perf_counter() - started) * 1000, 3)

    return {
        "dialect": engine.dialect.name,
        "driver": engine.dialect.driver,
        "database_url": _redact_database_url(DATABASE_URL),
        "pool_class": engine.pool.__class__.__name__,
        "pool_status": engine.pool.status() if hasattr(engine.pool, "status") else "n/a",
        "connectivity": {
            "healthy": True,
            "latency_ms": latency_ms,
        },
    }


class VerifyProofRequest(BaseModel):
    """Request to verify a proof bundle."""
    proof_bundle: ProofBundle


class VerifyProofResponse(BaseModel):
    """Response from proof verification."""
    valid: bool
    message: str


@router.post("/proof/verify", response_model=VerifyProofResponse)
async def verify_proof(
    request: VerifyProofRequest,
    auth: AuthContext = Depends(require_permission("proof:read")),
):
    """
    Verify a proof bundle's signature.
    """
    _ = auth
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
async def export_proof(
    request: ExportProofRequest,
    auth: AuthContext = Depends(require_permission("proof:read")),
):
    """
    Export proof bundle to a portable format.
    """
    _ = auth
    proof_assembler = get_proof_assembler()
    
    try:
        exported = proof_assembler.export_proof(
            bundle=request.proof_bundle,
            format=request.format
        )
        return {"format": request.format, "content": exported}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============================================================================
# Analysis History
# ============================================================================

HISTORY_FILE = settings.DATA_DIR / "analysis_history.json" if hasattr(settings, 'DATA_DIR') else Path("data/analysis_history.json")


def load_history() -> list:
    """Load analysis history from file."""
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    return []


def save_history(history: list):
    """Save analysis history to file."""
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Keep only last 100 entries
    history = history[-100:]
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2, default=str)


class HistoryEntry(BaseModel):
    """A history entry for analysis results."""
    id: str
    timestamp: str
    code_preview: str
    language: str
    compliant: bool
    violations_count: int
    policies_passed: int
    severity_breakdown: dict
    rule_breakdown: dict = {}
    code_hash: str
    tenant_id: Optional[str] = None
    dynamic_executed: bool = False
    dynamic_runner: Optional[str] = None
    dynamic_artifacts: List[Dict[str, Any]] = []


def _history_entry_tenant(entry: Dict[str, Any]) -> str:
    return str(entry.get("tenant_id") or "global")


def _history_visible(entry: Dict[str, Any], auth: AuthContext) -> bool:
    if auth.is_master:
        return True
    auth_tenant = auth.tenant_id or "global"
    return _history_entry_tenant(entry) == auth_tenant


@router.get("/history")
async def get_analysis_history(
    limit: int = Query(20, ge=1, le=100),
    auth: AuthContext = Depends(require_permission("history:read")),
):
    """Get recent analysis history."""
    history = load_history()
    visible = [entry for entry in history if _history_visible(entry, auth)]
    return {
        "history": visible[-limit:][::-1],  # Most recent first
        "total": len(visible)
    }


@router.post("/history")
async def add_to_history(
    code: str,
    language: str = "python",
    compliant: bool = False,
    violations_count: int = 0,
    policies_passed: int = 0,
    severity_breakdown: dict = None,
    rule_breakdown: dict = None,
    tenant_id: Optional[str] = None,
    dynamic_executed: bool = False,
    dynamic_runner: Optional[str] = None,
    dynamic_artifacts: Optional[List[Dict[str, Any]]] = None,
    auth: AuthContext = Depends(require_permission("history:write")),
):
    """Add an analysis result to history."""
    history = load_history()
    effective_tenant_id = tenant_id if auth.is_master else (auth.tenant_id or tenant_id)
    normalized_tenant_id = (effective_tenant_id or "global").strip()
    
    # Create code hash for deduplication
    # Use a non-cryptographic identifier for dedupe; avoid weak hashes to satisfy security scans.
    code_hash = hashlib.sha256(code.encode()).hexdigest()[:8]
    
    # Check if this exact code was just analyzed (avoid duplicates)
    if (
        history
        and history[-1].get('code_hash') == code_hash
        and _history_entry_tenant(history[-1]) == normalized_tenant_id
    ):
        return {"message": "Duplicate entry skipped", "id": history[-1]['id']}
    
    entry = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "code_preview": code[:100] + ("..." if len(code) > 100 else ""),
        "language": language,
        "compliant": compliant,
        "violations_count": violations_count,
        "policies_passed": policies_passed,
        "severity_breakdown": severity_breakdown or {},
        "rule_breakdown": rule_breakdown or {},
        "code_hash": code_hash,
        "tenant_id": normalized_tenant_id,
        "dynamic_executed": dynamic_executed,
        "dynamic_runner": dynamic_runner,
        "dynamic_artifacts": dynamic_artifacts or [],
    }
    
    history.append(entry)
    save_history(history)
    
    return {"message": "Added to history", "id": entry['id']}


@router.get("/history/dynamic-artifacts")
async def get_dynamic_artifact_index(
    limit: int = Query(50, ge=1, le=500),
    violations_only: bool = Query(False),
    suite_id: Optional[str] = Query(None),
    violation_rule_id: Optional[str] = Query(None),
    language: Optional[str] = Query(None),
    compliant: Optional[bool] = Query(None),
    auth: AuthContext = Depends(require_permission("history:read")),
):
    """List recent dynamic replay artifacts across analysis history entries."""
    history = load_history()
    indexed: List[Dict[str, Any]] = []
    normalized_suite = suite_id.strip().lower() if suite_id else None
    normalized_rule = violation_rule_id.strip().upper() if violation_rule_id else None
    normalized_language = language.strip().lower() if language else None

    for entry in reversed(history):
        if not _history_visible(entry, auth):
            continue
        if normalized_language and str(entry.get("language", "")).lower() != normalized_language:
            continue
        if compliant is not None and bool(entry.get("compliant")) != compliant:
            continue
        artifacts = entry.get("dynamic_artifacts") or []
        if not artifacts:
            continue
        for artifact in artifacts:
            if normalized_suite and str(artifact.get("suite_id", "")).lower() != normalized_suite:
                continue
            if violations_only and not artifact.get("violation_rule_id"):
                continue
            if normalized_rule and str(artifact.get("violation_rule_id", "")).upper() != normalized_rule:
                continue
            indexed.append(
                {
                    "history_id": entry.get("id"),
                    "timestamp": entry.get("timestamp"),
                    "language": entry.get("language"),
                    "compliant": entry.get("compliant"),
                    **artifact,
                }
            )
            if len(indexed) >= limit:
                return {"artifacts": indexed, "total": len(indexed)}

    return {"artifacts": indexed, "total": len(indexed)}


def _parse_history_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


@router.get("/history/trends")
async def get_history_trends(
    days: int = Query(30, ge=1, le=365),
    auth: AuthContext = Depends(require_permission("history:read")),
):
    """Aggregate compliance trends from analysis history for audit dashboards."""
    history = load_history()
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)

    selected = []
    for entry in history:
        if not _history_visible(entry, auth):
            continue
        ts = _parse_history_timestamp(entry.get("timestamp"))
        if ts is None or ts < cutoff:
            continue
        selected.append((ts, entry))

    total_runs = len(selected)
    compliant_runs = 0
    total_violations = 0
    total_policies_passed = 0
    dynamic_runs = 0
    dynamic_issue_runs = 0
    severity_totals: Dict[str, int] = {}
    rule_totals: Dict[str, int] = {}
    buckets: Dict[str, Dict[str, Any]] = {}

    for ts, entry in selected:
        compliant = bool(entry.get("compliant"))
        compliant_runs += 1 if compliant else 0
        violations_count = int(entry.get("violations_count") or 0)
        total_violations += violations_count
        total_policies_passed += int(entry.get("policies_passed") or 0)

        if entry.get("dynamic_executed"):
            dynamic_runs += 1
            has_dynamic_issue = any(
                artifact.get("violation_rule_id")
                for artifact in (entry.get("dynamic_artifacts") or [])
            )
            if has_dynamic_issue:
                dynamic_issue_runs += 1

        for severity, count in (entry.get("severity_breakdown") or {}).items():
            severity_totals[severity] = severity_totals.get(severity, 0) + int(count or 0)

        for rule_id, count in (entry.get("rule_breakdown") or {}).items():
            normalized_rule = str(rule_id).strip()
            if not normalized_rule:
                continue
            rule_totals[normalized_rule] = rule_totals.get(normalized_rule, 0) + int(count or 0)

        bucket_key = ts.date().isoformat()
        bucket = buckets.setdefault(
            bucket_key,
            {"date": bucket_key, "runs": 0, "compliant": 0, "non_compliant": 0, "violations_total": 0},
        )
        bucket["runs"] += 1
        bucket["compliant"] += 1 if compliant else 0
        bucket["non_compliant"] += 0 if compliant else 1
        bucket["violations_total"] += violations_count

    series = []
    for key in sorted(buckets.keys()):
        bucket = buckets[key]
        runs = bucket["runs"] or 1
        series.append(
            {
                "date": bucket["date"],
                "runs": bucket["runs"],
                "compliant": bucket["compliant"],
                "non_compliant": bucket["non_compliant"],
                "avg_violations": round(bucket["violations_total"] / runs, 3),
            }
        )

    compliance_rate = round((compliant_runs / total_runs) * 100, 2) if total_runs else 0.0
    dynamic_issue_rate = round((dynamic_issue_runs / dynamic_runs) * 100, 2) if dynamic_runs else 0.0

    top_violated_rules = [
        {"rule_id": rule_id, "count": count}
        for rule_id, count in sorted(rule_totals.items(), key=lambda item: item[1], reverse=True)[:10]
    ]

    return {
        "window_days": days,
        "total_runs": total_runs,
        "compliant_runs": compliant_runs,
        "non_compliant_runs": total_runs - compliant_runs,
        "compliance_rate": compliance_rate,
        "avg_violations": round((total_violations / total_runs), 3) if total_runs else 0.0,
        "avg_policies_passed": round((total_policies_passed / total_runs), 3) if total_runs else 0.0,
        "dynamic_runs": dynamic_runs,
        "dynamic_issue_runs": dynamic_issue_runs,
        "dynamic_issue_rate": dynamic_issue_rate,
        "severity_totals": severity_totals,
        "top_violated_rules": top_violated_rules,
        "series": series,
    }


@router.delete("/history/{entry_id}")
async def delete_history_entry(
    entry_id: str,
    auth: AuthContext = Depends(require_permission("history:write")),
):
    """Delete a specific history entry."""
    history = load_history()
    original_len = len(history)
    history = [
        h for h in history
        if not (h.get('id') == entry_id and _history_visible(h, auth))
    ]
    
    if len(history) == original_len:
        raise HTTPException(status_code=404, detail="Entry not found")
    
    save_history(history)
    return {"message": "Entry deleted"}


@router.delete("/history")
async def clear_history(auth: AuthContext = Depends(require_permission("history:write"))):
    """Clear all analysis history."""
    history = load_history()
    if auth.is_master:
        save_history([])
        return {"message": "History cleared"}

    remaining = [entry for entry in history if not _history_visible(entry, auth)]
    save_history(remaining)
    return {"message": "Tenant history cleared"}
