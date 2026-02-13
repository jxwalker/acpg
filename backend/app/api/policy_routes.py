"""Policy CRUD API Routes - Create, Read, Update, Delete policies."""
import json
from typing import List, Optional, Dict, Any
from datetime import datetime

from fastapi import APIRouter, HTTPException, Body, Depends, Request, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.auth import require_permission
from ..core.config import settings
from ..core.database import get_db, PolicyHistoryStore, TestCaseStore
from ..services.policy_compiler import get_policy_compiler


router = APIRouter(
    prefix="/policies",
    tags=["Policy Management"],
    dependencies=[Depends(require_permission("policy:read"))],
)
groups_router = APIRouter(
    prefix="/policies/groups",
    tags=["Policy Groups"],
    dependencies=[Depends(require_permission("policy:read"))],
)


# Models for API requests/responses
class PolicyCheckInput(BaseModel):
    """Input model for policy check definition."""
    type: str = Field(..., description="Check type: regex, ast, or manual")
    pattern: Optional[str] = Field(None, description="Regex pattern for regex checks")
    function: Optional[str] = Field(None, description="Function name for ast checks")
    target: Optional[str] = Field(None, description="Target pattern for ast checks")
    message: Optional[str] = Field(None, description="Message for manual checks")
    languages: List[str] = Field(default=["python"], description="Applicable languages")


class PolicyInput(BaseModel):
    """Input model for creating/updating a policy."""
    id: str = Field(..., description="Unique policy identifier (e.g., SEC-001)")
    description: str = Field(..., description="Human-readable description")
    type: str = Field("strict", description="Policy type: strict or defeasible")
    severity: str = Field("medium", description="Severity: low, medium, high, critical")
    check: PolicyCheckInput
    fix_suggestion: Optional[str] = Field(None, description="Suggested fix for violations")
    category: Optional[str] = Field(None, description="Policy category")


class PolicyFileInfo(BaseModel):
    """Information about a policy file."""
    filename: str
    path: str
    policy_count: int
    last_modified: str


class PolicyExport(BaseModel):
    """Export format for policies."""
    policies: List[dict]
    exported_at: str
    version: str = "1.0"


def _actor_from_request(request: Optional[Request]) -> str:
    if not request:
        return "unknown"
    return (
        request.headers.get("X-User-Id")
        or request.headers.get("X-Actor")
        or request.headers.get("X-Forwarded-User")
        or "unknown"
    )


def _policy_to_dict(policy: PolicyInput) -> dict:
    policy_dict = {
        "id": policy.id,
        "description": policy.description,
        "type": policy.type,
        "severity": policy.severity,
        "check": {
            "type": policy.check.type,
            "pattern": policy.check.pattern,
            "function": policy.check.function,
            "target": policy.check.target,
            "message": policy.check.message,
            "languages": policy.check.languages,
        },
        "fix_suggestion": policy.fix_suggestion,
    }
    if policy.category:
        policy_dict["category"] = policy.category
    return policy_dict


def _normalize_policy_dict(policy: dict) -> dict:
    """Normalize imported/raw policy dict for history/diff stability."""
    return {
        "id": policy.get("id"),
        "description": policy.get("description"),
        "type": policy.get("type", "strict"),
        "severity": policy.get("severity", "medium"),
        "check": {
            "type": (policy.get("check") or {}).get("type", "manual"),
            "pattern": (policy.get("check") or {}).get("pattern"),
            "function": (policy.get("check") or {}).get("function"),
            "target": (policy.get("check") or {}).get("target"),
            "message": (policy.get("check") or {}).get("message"),
            "languages": (policy.get("check") or {}).get("languages", []),
        },
        "fix_suggestion": policy.get("fix_suggestion"),
        "category": policy.get("category"),
    }


# Custom policies storage file
CUSTOM_POLICIES_FILE = settings.POLICIES_DIR / "custom_policies.json"


def load_custom_policies() -> dict:
    """Load custom policies from file."""
    if CUSTOM_POLICIES_FILE.exists():
        with open(CUSTOM_POLICIES_FILE, 'r') as f:
            return json.load(f)
    return {"policies": []}


def save_custom_policies(data: dict):
    """Save custom policies to file."""
    with open(CUSTOM_POLICIES_FILE, 'w') as f:
        json.dump(data, f, indent=2)
        # Keep trailing newline style stable to avoid noisy git diffs.
        f.write("\n\n")


def reload_policies():
    """Reload all policies into the compiler."""
    from ..services import policy_compiler
    policy_compiler._compiler = None
    return get_policy_compiler()


@router.get("/", response_model=dict)
async def list_all_policies():
    """List all loaded policies with their sources."""
    compiler = get_policy_compiler()
    policies = compiler.get_all_policies()
    
    # Group by source file
    policy_files = {}
    for filename in ['default_policies.json', 'owasp_policies.json', 
                     'nist_policies.json', 'javascript_policies.json', 
                     'custom_policies.json']:
        filepath = settings.POLICIES_DIR / filename
        if filepath.exists():
            with open(filepath, 'r') as f:
                data = json.load(f)
                policy_files[filename] = {
                    "count": len(data.get('policies', [])),
                    "policy_ids": [p['id'] for p in data.get('policies', [])]
                }
    
    return {
        "total_policies": len(policies),
        "policies": [p.model_dump() for p in policies],
        "sources": policy_files
    }


@router.get("/files", response_model=List[PolicyFileInfo])
async def list_policy_files():
    """List all policy files in the policies directory."""
    files = []
    for filepath in settings.POLICIES_DIR.glob("*.json"):
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        stat = filepath.stat()
        files.append(PolicyFileInfo(
            filename=filepath.name,
            path=str(filepath),
            policy_count=len(data.get('policies', [])),
            last_modified=datetime.fromtimestamp(stat.st_mtime).isoformat()
        ))
    
    return files


@router.get("/file/{filename}")
async def get_policy_file(filename: str):
    """Get contents of a specific policy file."""
    filepath = settings.POLICIES_DIR / filename
    if not filepath.exists():
        raise HTTPException(status_code=404, detail=f"Policy file not found: {filename}")
    
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    return data


def _format_history_entry(entry) -> dict:
    payload = entry.policy_data or {}
    return {
        "id": entry.id,
        "policy_id": entry.policy_id,
        "action": entry.action,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        "changed_by": entry.changed_by or payload.get("changed_by") or "unknown",
        "version": payload.get("version"),
        "source": payload.get("source"),
        "reason": payload.get("reason"),
        "changed_fields": payload.get("changed_fields", []),
        "summary": (
            f"{entry.action} v{payload.get('version')}"
            if payload.get("version")
            else entry.action
        ),
        "before": payload.get("before"),
        "after": payload.get("after"),
    }


@router.get("/audit/history", response_model=dict)
async def list_policy_history(
    policy_id: Optional[str] = Query(None, description="Optional policy id filter"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List policy history entries for audit and change tracking."""
    store = PolicyHistoryStore(db)
    entries = store.list_history(policy_id=policy_id, limit=limit, offset=offset)
    return {
        "entries": [_format_history_entry(entry) for entry in entries],
        "policy_id": policy_id,
        "count": len(entries),
        "limit": limit,
        "offset": offset,
    }


@router.get("/{policy_id}/audit/history", response_model=dict)
async def get_policy_history(
    policy_id: str,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Get version history for a specific policy id."""
    store = PolicyHistoryStore(db)
    entries = store.list_history(policy_id=policy_id, limit=limit, offset=offset)
    return {
        "policy_id": policy_id,
        "entries": [_format_history_entry(entry) for entry in entries],
        "count": len(entries),
    }


@router.get("/{policy_id}/audit/versions/{version}", response_model=dict)
async def get_policy_version_snapshot(
    policy_id: str,
    version: int,
    db: Session = Depends(get_db),
):
    """Retrieve a specific historical version snapshot for a policy."""
    store = PolicyHistoryStore(db)
    snapshot = store.get_version_snapshot(policy_id, version)
    if snapshot is None:
        raise HTTPException(status_code=404, detail=f"Version {version} not found for policy {policy_id}")
    return {"policy_id": policy_id, "version": version, "snapshot": snapshot}


@router.get("/{policy_id}/audit/diff", response_model=dict)
async def diff_policy_versions(
    policy_id: str,
    from_version: int = Query(..., ge=1),
    to_version: int = Query(..., ge=1),
    db: Session = Depends(get_db),
):
    """Diff two policy versions for auditability."""
    store = PolicyHistoryStore(db)
    before = store.get_version_snapshot(policy_id, from_version)
    after = store.get_version_snapshot(policy_id, to_version)
    if before is None:
        raise HTTPException(status_code=404, detail=f"Version {from_version} not found for policy {policy_id}")
    if after is None:
        raise HTTPException(status_code=404, detail=f"Version {to_version} not found for policy {policy_id}")

    changed_fields: List[str] = []

    def _walk(prefix: str, left, right):
        if isinstance(left, dict) and isinstance(right, dict):
            keys = sorted(set(left.keys()) | set(right.keys()))
            for key in keys:
                path = f"{prefix}.{key}" if prefix else str(key)
                if key not in left or key not in right:
                    changed_fields.append(path)
                else:
                    _walk(path, left[key], right[key])
            return
        if isinstance(left, list) and isinstance(right, list):
            if left != right:
                changed_fields.append(prefix)
            return
        if left != right:
            changed_fields.append(prefix)

    _walk("", before, after)

    return {
        "policy_id": policy_id,
        "from_version": from_version,
        "to_version": to_version,
        "changed_fields": changed_fields,
        "before": before,
        "after": after,
        "before_json": json.dumps(before, indent=2, sort_keys=True),
        "after_json": json.dumps(after, indent=2, sort_keys=True),
    }


@router.get("/{policy_id}")
async def get_policy(policy_id: str):
    """Get a specific policy by ID."""
    compiler = get_policy_compiler()
    policy = compiler.get_policy(policy_id)
    
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy not found: {policy_id}")
    
    # Find source file
    source = "unknown"
    for filename in ['default_policies.json', 'owasp_policies.json', 
                     'nist_policies.json', 'javascript_policies.json',
                     'custom_policies.json']:
        filepath = settings.POLICIES_DIR / filename
        if filepath.exists():
            with open(filepath, 'r') as f:
                data = json.load(f)
                if any(p['id'] == policy_id for p in data.get('policies', [])):
                    source = filename
                    break
    
    return {
        "policy": policy.model_dump(),
        "source": source
    }


@router.post("/", response_model=dict, dependencies=[Depends(require_permission("policy:write"))])
async def create_policy(
    policy: PolicyInput,
    request: Request,
    db: Session = Depends(get_db),
):
    """Create a new custom policy."""
    compiler = get_policy_compiler()
    
    # Check if policy ID already exists
    existing = compiler.get_policy(policy.id)
    if existing:
        raise HTTPException(
            status_code=400, 
            detail=f"Policy with ID '{policy.id}' already exists"
        )
    
    # Load existing custom policies
    data = load_custom_policies()
    
    # Add new policy
    policy_dict = _policy_to_dict(policy)
    
    data['policies'].append(policy_dict)
    save_custom_policies(data)

    history = PolicyHistoryStore(db)
    history.record_change(
        action="add",
        policy_id=policy.id,
        before=None,
        after=_normalize_policy_dict(policy_dict),
        changed_by=_actor_from_request(request),
        source="custom_policies.json",
        reason="Policy created via API",
    )
    
    # Reload policies
    reload_policies()
    
    return {
        "message": f"Policy '{policy.id}' created successfully",
        "policy": policy_dict
    }


@router.put("/{policy_id}", response_model=dict, dependencies=[Depends(require_permission("policy:write"))])
async def update_policy(
    policy_id: str,
    policy: PolicyInput,
    request: Request,
    db: Session = Depends(get_db),
):
    """Update an existing custom policy."""
    # Only allow updating custom policies
    data = load_custom_policies()
    
    # Find the policy
    policy_index = None
    for i, p in enumerate(data.get('policies', [])):
        if p['id'] == policy_id:
            policy_index = i
            break
    
    if policy_index is None:
        raise HTTPException(
            status_code=404,
            detail=f"Custom policy '{policy_id}' not found. Only custom policies can be updated."
        )
    
    before_policy = _normalize_policy_dict(data['policies'][policy_index])
    policy_dict = _policy_to_dict(policy)
    
    data['policies'][policy_index] = policy_dict
    save_custom_policies(data)

    history = PolicyHistoryStore(db)
    history.record_change(
        action="modify",
        policy_id=policy.id,
        before=before_policy,
        after=_normalize_policy_dict(policy_dict),
        changed_by=_actor_from_request(request),
        source="custom_policies.json",
        reason=f"Policy updated via API ({policy_id})",
    )
    
    # Reload policies
    reload_policies()
    
    return {
        "message": f"Policy '{policy_id}' updated successfully",
        "policy": policy_dict
    }


@router.delete("/{policy_id}", response_model=dict, dependencies=[Depends(require_permission("policy:write"))])
async def delete_policy(
    policy_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Delete a custom policy."""
    data = load_custom_policies()
    
    # Find and remove the policy
    original_count = len(data.get('policies', []))
    removed_policy = next((p for p in data.get('policies', []) if p['id'] == policy_id), None)
    data['policies'] = [p for p in data.get('policies', []) if p['id'] != policy_id]
    
    if len(data['policies']) == original_count:
        raise HTTPException(
            status_code=404,
            detail=f"Custom policy '{policy_id}' not found. Only custom policies can be deleted."
        )
    
    save_custom_policies(data)

    history = PolicyHistoryStore(db)
    history.record_change(
        action="delete",
        policy_id=policy_id,
        before=_normalize_policy_dict(removed_policy or {"id": policy_id}),
        after=None,
        changed_by=_actor_from_request(request),
        source="custom_policies.json",
        reason="Policy deleted via API",
    )
    
    # Reload policies
    reload_policies()
    
    return {
        "message": f"Policy '{policy_id}' deleted successfully"
    }


@router.post("/validate", response_model=dict)
async def validate_policy(policy: PolicyInput):
    """Validate a policy definition without saving it."""
    import re
    
    errors = []
    warnings = []
    
    # Validate ID format
    if not re.match(r'^[A-Z]+-\d+$', policy.id):
        warnings.append(f"Policy ID '{policy.id}' doesn't follow recommended format (e.g., SEC-001)")
    
    # Validate type
    if policy.type not in ('strict', 'defeasible'):
        errors.append(f"Invalid type: '{policy.type}'. Must be 'strict' or 'defeasible'")
    
    # Validate severity
    if policy.severity not in ('low', 'medium', 'high', 'critical'):
        errors.append(f"Invalid severity: '{policy.severity}'")
    
    # Validate check type
    if policy.check.type not in ('regex', 'ast', 'manual'):
        errors.append(f"Invalid check type: '{policy.check.type}'")
    
    # Validate regex pattern if provided
    if policy.check.type == 'regex':
        if not policy.check.pattern:
            errors.append("Regex check requires a pattern")
        else:
            try:
                re.compile(policy.check.pattern)
            except re.error as e:
                errors.append(f"Invalid regex pattern: {e}")
    
    # Validate languages
    valid_languages = ['python', 'javascript', 'typescript', 'java', 'go', 'rust']
    for lang in policy.check.languages:
        if lang.lower() not in valid_languages:
            warnings.append(f"Unknown language: '{lang}'")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings
    }


@router.post("/test", response_model=dict)
async def test_policy(
    policy: PolicyInput,
    code: str = Body(..., embed=True),
    language: str = Body("python", embed=True)
):
    """Test a policy against sample code without saving it."""
    import re
    
    if policy.check.type != 'regex':
        return {
            "message": "Only regex policies can be tested directly",
            "violations": []
        }
    
    violations = []
    try:
        pattern = re.compile(policy.check.pattern, re.MULTILINE | re.IGNORECASE)
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            matches = pattern.finditer(line)
            for match in matches:
                violations.append({
                    "line": line_num,
                    "evidence": match.group(0),
                    "column": match.start()
                })
    except re.error as e:
        raise HTTPException(status_code=400, detail=f"Invalid regex: {e}")
    
    return {
        "policy_id": policy.id,
        "violations_found": len(violations),
        "violations": violations
    }


@router.get("/export/all", response_model=PolicyExport)
async def export_all_policies():
    """Export all policies as JSON."""
    compiler = get_policy_compiler()
    policies = compiler.get_all_policies()
    
    return PolicyExport(
        policies=[p.model_dump() for p in policies],
        exported_at=datetime.utcnow().isoformat()
    )


@router.get("/export/custom", response_model=PolicyExport)
async def export_custom_policies():
    """Export only custom policies."""
    data = load_custom_policies()
    
    return PolicyExport(
        policies=data.get('policies', []),
        exported_at=datetime.utcnow().isoformat()
    )


@router.post("/import", response_model=dict, dependencies=[Depends(require_permission("policy:write"))])
async def import_policies(
    request: Request,
    policies: List[dict] = Body(..., embed=True),
    overwrite: bool = Body(False, embed=True),
    db: Session = Depends(get_db),
):
    """Import policies from JSON."""
    data = load_custom_policies()
    existing_ids = {p['id'] for p in data.get('policies', [])}
    
    imported = []
    skipped = []
    history = PolicyHistoryStore(db)
    actor = _actor_from_request(request)
    
    for policy in policies:
        policy_id = policy.get('id')
        if not policy_id:
            continue
        
        if policy_id in existing_ids:
            if overwrite:
                # Remove existing and add new
                previous = next((p for p in data['policies'] if p['id'] == policy_id), None)
                data['policies'] = [p for p in data['policies'] if p['id'] != policy_id]
                data['policies'].append(policy)
                imported.append(policy_id)
                history.record_change(
                    action="modify",
                    policy_id=policy_id,
                    before=_normalize_policy_dict(previous or {"id": policy_id}),
                    after=_normalize_policy_dict(policy),
                    changed_by=actor,
                    source="custom_policies.json",
                    reason="Policy import overwrite",
                )
            else:
                skipped.append(policy_id)
        else:
            data['policies'].append(policy)
            imported.append(policy_id)
            existing_ids.add(policy_id)
            history.record_change(
                action="add",
                policy_id=policy_id,
                before=None,
                after=_normalize_policy_dict(policy),
                changed_by=actor,
                source="custom_policies.json",
                reason="Policy import add",
            )
    
    save_custom_policies(data)
    reload_policies()
    
    return {
        "imported": imported,
        "skipped": skipped,
        "total_imported": len(imported),
        "total_skipped": len(skipped)
    }


@router.post("/reload", response_model=dict, dependencies=[Depends(require_permission("policy:write"))])
async def reload_all_policies():
    """Reload all policies from disk."""
    compiler = reload_policies()
    policies = compiler.get_all_policies()
    
    return {
        "message": "Policies reloaded successfully",
        "total_policies": len(policies)
    }


# ============================================================================
# Policy Groups Management
# ============================================================================

POLICY_GROUPS_FILE = settings.POLICIES_DIR / "policy_groups.json"


class PolicyGroup(BaseModel):
    """A group of policies that can be enabled/disabled together."""
    id: str = Field(..., description="Unique group identifier")
    name: str = Field(..., description="Display name")
    description: str = Field("", description="Group description")
    enabled: bool = Field(True, description="Whether this group is active")
    policies: List[str] = Field(default_factory=list, description="Policy IDs in this group")


class PolicyGroupInput(BaseModel):
    """Input for creating/updating a policy group."""
    id: str
    name: str
    description: str = ""
    enabled: bool = True
    policies: List[str] = []


class RolloutPreviewRequest(BaseModel):
    """Request model for policy group rollout preview."""

    proposed_group_states: Optional[Dict[str, bool]] = Field(
        default=None,
        description="Proposed enabled/disabled state per group id",
    )
    test_case_ids: Optional[List[int]] = Field(
        default=None,
        description="Optional explicit DB test case ids to evaluate",
    )
    include_inactive_cases: bool = Field(False, description="Include inactive test cases")
    limit_cases: int = Field(20, ge=1, le=200, description="Max number of test cases to evaluate")
    semantics: str = Field("auto", description="Adjudication semantics")
    solver_decision_mode: str = Field("auto", description="Solver decision mode")


def load_policy_groups() -> dict:
    """Load policy groups from file."""
    if POLICY_GROUPS_FILE.exists():
        with open(POLICY_GROUPS_FILE, 'r') as f:
            return json.load(f)
    return {"groups": [], "active_profile": "default"}


def save_policy_groups(data: dict):
    """Save policy groups to file."""
    with open(POLICY_GROUPS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def get_enabled_policy_ids() -> List[str]:
    """Get list of policy IDs from all enabled groups."""
    data = load_policy_groups()
    enabled_policies = set()
    
    for group in data.get('groups', []):
        if group.get('enabled', True):
            enabled_policies.update(group.get('policies', []))
    
    return list(enabled_policies)


def _enabled_policy_ids_from_groups(
    groups_data: dict,
    overrides: Optional[Dict[str, bool]] = None,
) -> Dict[str, Any]:
    """Resolve enabled groups and policy IDs, optionally with state overrides."""
    overrides = overrides or {}
    enabled_group_ids: List[str] = []
    enabled_policies = set()
    for group in groups_data.get("groups", []):
        group_id = group.get("id")
        current = bool(group.get("enabled", True))
        proposed = overrides.get(group_id, current)
        if proposed:
            enabled_group_ids.append(group_id)
            enabled_policies.update(group.get("policies", []))
    return {
        "enabled_group_ids": enabled_group_ids,
        "policy_ids": sorted(enabled_policies),
    }


@groups_router.get("/", response_model=dict)
async def list_policy_groups():
    """List all policy groups."""
    data = load_policy_groups()
    
    # Enrich with policy details
    compiler = get_policy_compiler()
    all_policies = {p.id: p for p in compiler.get_all_policies()}
    
    groups_with_details = []
    for group in data.get('groups', []):
        policy_details = []
        for policy_id in group.get('policies', []):
            if policy_id in all_policies:
                p = all_policies[policy_id]
                policy_details.append({
                    "id": p.id,
                    "description": p.description,
                    "severity": p.severity
                })
            else:
                policy_details.append({
                    "id": policy_id,
                    "description": "Policy not found",
                    "severity": "unknown"
                })
        
        groups_with_details.append({
            **group,
            "policy_details": policy_details,
            "policy_count": len(group.get('policies', []))
        })
    
    # Count enabled policies
    enabled_count = sum(
        len(g.get('policies', [])) 
        for g in data.get('groups', []) 
        if g.get('enabled', True)
    )
    
    return {
        "groups": groups_with_details,
        "total_groups": len(data.get('groups', [])),
        "enabled_groups": sum(1 for g in data.get('groups', []) if g.get('enabled', True)),
        "enabled_policies": enabled_count,
        "active_profile": data.get('active_profile', 'default')
    }


@groups_router.get("/export", response_model=dict)
async def export_policy_groups():
    """Export all policy groups as JSON for sharing."""
    data = load_policy_groups()
    return {
        "version": "1.0",
        "exported_at": datetime.now().isoformat(),
        "groups": data.get('groups', []),
        "active_profile": data.get('active_profile', 'default')
    }


@groups_router.post("/import", response_model=dict, dependencies=[Depends(require_permission("policy:write"))])
async def import_policy_groups(
    groups: List[dict] = Body(..., embed=True),
    overwrite: bool = Body(False, embed=True)
):
    """Import policy groups from JSON."""
    data = load_policy_groups()
    existing_ids = {g['id'] for g in data.get('groups', [])}
    
    imported = []
    skipped = []
    
    for group in groups:
        group_id = group.get('id')
        if not group_id:
            continue
        
        if group_id in existing_ids:
            if overwrite:
                data['groups'] = [g for g in data['groups'] if g['id'] != group_id]
                data['groups'].append(group)
                imported.append(group_id)
            else:
                skipped.append(group_id)
        else:
            data['groups'].append(group)
            imported.append(group_id)
            existing_ids.add(group_id)
    
    save_policy_groups(data)
    
    return {
        "imported": imported,
        "skipped": skipped,
        "total_imported": len(imported),
        "total_skipped": len(skipped)
    }


@groups_router.get("/{group_id}")
async def get_policy_group(group_id: str):
    """Get a specific policy group."""
    data = load_policy_groups()
    
    for group in data.get('groups', []):
        if group.get('id') == group_id:
            return group
    
    raise HTTPException(status_code=404, detail=f"Group not found: {group_id}")


@groups_router.post("/", response_model=dict, dependencies=[Depends(require_permission("policy:write"))])
async def create_policy_group(group: PolicyGroupInput):
    """Create a new policy group."""
    data = load_policy_groups()
    
    # Check if group ID already exists
    if any(g.get('id') == group.id for g in data.get('groups', [])):
        raise HTTPException(status_code=400, detail=f"Group '{group.id}' already exists")
    
    new_group = {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "enabled": group.enabled,
        "policies": group.policies
    }
    
    data['groups'].append(new_group)
    save_policy_groups(data)
    
    return {"message": f"Group '{group.id}' created successfully", "group": new_group}


@groups_router.put("/{group_id}", response_model=dict, dependencies=[Depends(require_permission("policy:write"))])
async def update_policy_group(group_id: str, group: PolicyGroupInput):
    """Update a policy group."""
    data = load_policy_groups()
    
    for i, g in enumerate(data.get('groups', [])):
        if g.get('id') == group_id:
            data['groups'][i] = {
                "id": group.id,
                "name": group.name,
                "description": group.description,
                "enabled": group.enabled,
                "policies": group.policies
            }
            save_policy_groups(data)
            return {"message": f"Group '{group_id}' updated successfully", "group": data['groups'][i]}
    
    raise HTTPException(status_code=404, detail=f"Group not found: {group_id}")


@groups_router.delete("/{group_id}", response_model=dict, dependencies=[Depends(require_permission("policy:write"))])
async def delete_policy_group(group_id: str):
    """Delete a policy group."""
    data = load_policy_groups()
    
    original_count = len(data.get('groups', []))
    data['groups'] = [g for g in data.get('groups', []) if g.get('id') != group_id]
    
    if len(data['groups']) == original_count:
        raise HTTPException(status_code=404, detail=f"Group not found: {group_id}")
    
    save_policy_groups(data)
    return {"message": f"Group '{group_id}' deleted successfully"}


@groups_router.patch("/{group_id}/toggle", response_model=dict, dependencies=[Depends(require_permission("policy:write"))])
async def toggle_policy_group(group_id: str):
    """Toggle a policy group's enabled state."""
    data = load_policy_groups()
    
    for group in data.get('groups', []):
        if group.get('id') == group_id:
            group['enabled'] = not group.get('enabled', True)
            save_policy_groups(data)
            return {
                "message": f"Group '{group_id}' {'enabled' if group['enabled'] else 'disabled'}",
                "enabled": group['enabled']
            }
    
    raise HTTPException(status_code=404, detail=f"Group not found: {group_id}")


@groups_router.post("/{group_id}/policies", response_model=dict, dependencies=[Depends(require_permission("policy:write"))])
async def add_policy_to_group(group_id: str, policy_id: str = Body(..., embed=True)):
    """Add a policy to a group."""
    data = load_policy_groups()
    
    for group in data.get('groups', []):
        if group.get('id') == group_id:
            if policy_id not in group.get('policies', []):
                group['policies'].append(policy_id)
                save_policy_groups(data)
            return {"message": f"Policy '{policy_id}' added to group '{group_id}'", "policies": group['policies']}
    
    raise HTTPException(status_code=404, detail=f"Group not found: {group_id}")


@groups_router.delete(
    "/{group_id}/policies/{policy_id}",
    response_model=dict,
    dependencies=[Depends(require_permission("policy:write"))],
)
async def remove_policy_from_group(group_id: str, policy_id: str):
    """Remove a policy from a group."""
    data = load_policy_groups()
    
    for group in data.get('groups', []):
        if group.get('id') == group_id:
            if policy_id in group.get('policies', []):
                group['policies'].remove(policy_id)
                save_policy_groups(data)
            return {"message": f"Policy '{policy_id}' removed from group '{group_id}'", "policies": group['policies']}
    
    raise HTTPException(status_code=404, detail=f"Group not found: {group_id}")


@groups_router.get("/enabled/policies", response_model=dict)
async def get_enabled_policies():
    """Get all policies from enabled groups."""
    enabled_ids = get_enabled_policy_ids()
    
    compiler = get_policy_compiler()
    all_policies = {p.id: p for p in compiler.get_all_policies()}
    
    enabled_policies = []
    for policy_id in enabled_ids:
        if policy_id in all_policies:
            enabled_policies.append(all_policies[policy_id].model_dump())
    
    return {
        "enabled_policy_ids": enabled_ids,
        "policies": enabled_policies,
        "count": len(enabled_policies)
    }


@groups_router.post("/rollout/preview", response_model=dict)
async def preview_policy_group_rollout(
    request: RolloutPreviewRequest,
    db: Session = Depends(get_db),
):
    """
    Preview impact of proposed policy-group states against stored test cases.

    This endpoint does not persist any group changes. It is intended for safe rollout
    planning in regulated regression workflows.
    """
    from ..services import get_prosecutor, get_adjudicator

    groups_data = load_policy_groups()
    baseline = _enabled_policy_ids_from_groups(groups_data)
    proposed = _enabled_policy_ids_from_groups(groups_data, request.proposed_group_states)

    store = TestCaseStore(db)
    if request.test_case_ids:
        selected = []
        for case_id in request.test_case_ids:
            case = store.get_case(case_id)
            if case is not None and (request.include_inactive_cases or case.is_active):
                selected.append(case)
    else:
        selected = store.list_cases(include_inactive=request.include_inactive_cases)[: request.limit_cases]

    prosecutor = get_prosecutor()
    adjudicator = get_adjudicator()

    case_results = []
    baseline_compliant = 0
    proposed_compliant = 0
    changed_cases_count = 0

    for case in selected:
        # Baseline evaluation
        if baseline["policy_ids"]:
            baseline_analysis = prosecutor.analyze(
                code=case.code,
                language=case.language,
                policy_ids=baseline["policy_ids"],
            )
            baseline_adj = adjudicator.adjudicate(
                baseline_analysis,
                baseline["policy_ids"],
                semantics=request.semantics,
                solver_decision_mode=request.solver_decision_mode,
            )
        else:
            baseline_analysis = prosecutor.analyze(
                code=case.code,
                language=case.language,
                policy_ids=[],
            )
            baseline_adj = adjudicator.adjudicate(
                baseline_analysis,
                [],
                semantics=request.semantics,
                solver_decision_mode=request.solver_decision_mode,
            )

        # Proposed evaluation
        if proposed["policy_ids"]:
            proposed_analysis = prosecutor.analyze(
                code=case.code,
                language=case.language,
                policy_ids=proposed["policy_ids"],
            )
            proposed_adj = adjudicator.adjudicate(
                proposed_analysis,
                proposed["policy_ids"],
                semantics=request.semantics,
                solver_decision_mode=request.solver_decision_mode,
            )
        else:
            proposed_analysis = prosecutor.analyze(
                code=case.code,
                language=case.language,
                policy_ids=[],
            )
            proposed_adj = adjudicator.adjudicate(
                proposed_analysis,
                [],
                semantics=request.semantics,
                solver_decision_mode=request.solver_decision_mode,
            )

        baseline_unsat = sorted(set(baseline_adj.unsatisfied_rules))
        proposed_unsat = sorted(set(proposed_adj.unsatisfied_rules))
        newly_violated = sorted(set(proposed_unsat) - set(baseline_unsat))
        resolved = sorted(set(baseline_unsat) - set(proposed_unsat))
        changed = (
            baseline_adj.compliant != proposed_adj.compliant
            or baseline_unsat != proposed_unsat
        )

        if baseline_adj.compliant:
            baseline_compliant += 1
        if proposed_adj.compliant:
            proposed_compliant += 1
        if changed:
            changed_cases_count += 1

        case_results.append(
            {
                "id": case.id,
                "name": case.name,
                "language": case.language,
                "baseline": {
                    "compliant": baseline_adj.compliant,
                    "violations": len(baseline_analysis.violations),
                    "unsatisfied_rules": baseline_unsat,
                },
                "proposed": {
                    "compliant": proposed_adj.compliant,
                    "violations": len(proposed_analysis.violations),
                    "unsatisfied_rules": proposed_unsat,
                },
                "newly_violated_rules": newly_violated,
                "resolved_rules": resolved,
                "changed": changed,
            }
        )

    evaluated = len(case_results)
    return {
        "baseline": {
            "enabled_group_ids": baseline["enabled_group_ids"],
            "policy_ids": baseline["policy_ids"],
            "policy_count": len(baseline["policy_ids"]),
        },
        "proposed": {
            "enabled_group_ids": proposed["enabled_group_ids"],
            "policy_ids": proposed["policy_ids"],
            "policy_count": len(proposed["policy_ids"]),
        },
        "evaluated_cases": evaluated,
        "changed_cases_count": changed_cases_count,
        "summary": {
            "baseline_compliant": baseline_compliant,
            "baseline_non_compliant": evaluated - baseline_compliant,
            "proposed_compliant": proposed_compliant,
            "proposed_non_compliant": evaluated - proposed_compliant,
        },
        "cases": case_results,
    }


# ============================================================================
# Policy Templates - Pre-built policy group configurations
# ============================================================================

POLICY_TEMPLATES = {
    "owasp-top-10": {
        "name": "OWASP Top 10",
        "description": "Essential web application security policies based on OWASP Top 10 vulnerabilities",
        "icon": "🛡️",
        "category": "security",
        "policies": [
            "OWASP-A01", "OWASP-A02", "OWASP-A03", "OWASP-A04", "OWASP-A05",
            "OWASP-A06", "OWASP-A07", "OWASP-A08", "OWASP-A09", "OWASP-A10"
        ]
    },
    "secure-coding": {
        "name": "Secure Coding Basics",
        "description": "Fundamental security practices for any codebase",
        "icon": "🔐",
        "category": "security",
        "policies": [
            "SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005",
            "SEC-006", "SEC-007", "SEC-008"
        ]
    },
    "nist-compliance": {
        "name": "NIST 800-218",
        "description": "Secure Software Development Framework compliance",
        "icon": "📋",
        "category": "compliance",
        "policies": [
            "NIST-AC-3", "NIST-AU-2", "NIST-IA-5", "NIST-SC-8",
            "NIST-SC-12", "NIST-SC-13", "NIST-SI-10", "NIST-SI-11"
        ]
    },
    "injection-prevention": {
        "name": "Injection Prevention",
        "description": "Prevent SQL, command, and code injection attacks",
        "icon": "💉",
        "category": "security",
        "policies": [
            "SEC-002", "SEC-003", "SEC-006", "OWASP-A03"
        ]
    },
    "credential-security": {
        "name": "Credential Security",
        "description": "Protect secrets, API keys, and authentication data",
        "icon": "🔑",
        "category": "security",
        "policies": [
            "SEC-001", "NIST-IA-5", "OWASP-A02", "OWASP-A07"
        ]
    },
    "cryptography": {
        "name": "Cryptography Standards",
        "description": "Enforce strong encryption and secure random generation",
        "icon": "🔒",
        "category": "security",
        "policies": [
            "SEC-004", "SEC-005", "NIST-SC-12", "NIST-SC-13"
        ]
    },
    "input-validation": {
        "name": "Input Validation",
        "description": "Validate and sanitize all user inputs",
        "icon": "✅",
        "category": "security",
        "policies": [
            "NIST-SI-10", "OWASP-A03", "SEC-002", "SEC-003"
        ]
    },
    "javascript-security": {
        "name": "JavaScript Security",
        "description": "Security policies for JavaScript/TypeScript applications",
        "icon": "🟨",
        "category": "language",
        "policies": [
            "JS-001", "JS-002", "JS-003", "JS-004", "JS-005",
            "JS-006", "JS-007", "JS-008", "JS-009", "JS-010"
        ]
    },
    "minimal": {
        "name": "Minimal Security",
        "description": "Basic security checks for quick validation",
        "icon": "⚡",
        "category": "quick",
        "policies": [
            "SEC-001", "SEC-002", "SEC-003"
        ]
    },
    "comprehensive": {
        "name": "Comprehensive Audit",
        "description": "Full security audit with all available policies",
        "icon": "🔍",
        "category": "audit",
        "policies": []  # Will be populated with all policies
    }
}


@groups_router.get("/templates/", response_model=dict)
async def list_policy_templates():
    """List all available policy templates."""
    compiler = get_policy_compiler()
    all_policy_ids = {p.id for p in compiler.get_all_policies()}
    
    templates = []
    for template_id, template in POLICY_TEMPLATES.items():
        # For comprehensive template, include all policies
        if template_id == "comprehensive":
            policies = list(all_policy_ids)
        else:
            # Filter to only existing policies
            policies = [p for p in template["policies"] if p in all_policy_ids]
        
        templates.append({
            "id": template_id,
            "name": template["name"],
            "description": template["description"],
            "icon": template["icon"],
            "category": template["category"],
            "policy_count": len(policies),
            "policies": policies
        })
    
    return {
        "templates": templates,
        "categories": list(set(t["category"] for t in POLICY_TEMPLATES.values()))
    }


@groups_router.post(
    "/templates/{template_id}/apply",
    response_model=dict,
    dependencies=[Depends(require_permission("policy:write"))],
)
async def apply_policy_template(template_id: str, group_name: str = None):
    """Create a policy group from a template."""
    if template_id not in POLICY_TEMPLATES:
        raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")
    
    template = POLICY_TEMPLATES[template_id]
    compiler = get_policy_compiler()
    all_policy_ids = {p.id for p in compiler.get_all_policies()}
    
    # Get valid policies for this template
    if template_id == "comprehensive":
        policies = list(all_policy_ids)
    else:
        policies = [p for p in template["policies"] if p in all_policy_ids]
    
    # Create unique group ID
    data = load_policy_groups()
    base_id = f"template-{template_id}"
    group_id = base_id
    counter = 1
    while any(g.get('id') == group_id for g in data.get('groups', [])):
        group_id = f"{base_id}-{counter}"
        counter += 1
    
    # Create the group
    new_group = {
        "id": group_id,
        "name": group_name or f"{template['icon']} {template['name']}",
        "description": template["description"],
        "enabled": True,
        "policies": policies
    }
    
    data['groups'].append(new_group)
    save_policy_groups(data)
    
    return {
        "message": f"Created group from template '{template['name']}'",
        "group": new_group,
        "policies_added": len(policies)
    }
