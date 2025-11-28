"""Policy CRUD API Routes - Create, Read, Update, Delete policies."""
import json
import os
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel, Field

from ..core.config import settings
from ..services.policy_compiler import get_policy_compiler, PolicyCompiler
from ..models.schemas import PolicyRule, PolicyCheck


router = APIRouter(prefix="/policies", tags=["Policy Management"])


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


@router.post("/", response_model=dict)
async def create_policy(policy: PolicyInput):
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
            "languages": policy.check.languages
        },
        "fix_suggestion": policy.fix_suggestion
    }
    
    if policy.category:
        policy_dict["category"] = policy.category
    
    data['policies'].append(policy_dict)
    save_custom_policies(data)
    
    # Reload policies
    reload_policies()
    
    return {
        "message": f"Policy '{policy.id}' created successfully",
        "policy": policy_dict
    }


@router.put("/{policy_id}", response_model=dict)
async def update_policy(policy_id: str, policy: PolicyInput):
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
    
    # Update policy
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
            "languages": policy.check.languages
        },
        "fix_suggestion": policy.fix_suggestion
    }
    
    if policy.category:
        policy_dict["category"] = policy.category
    
    data['policies'][policy_index] = policy_dict
    save_custom_policies(data)
    
    # Reload policies
    reload_policies()
    
    return {
        "message": f"Policy '{policy_id}' updated successfully",
        "policy": policy_dict
    }


@router.delete("/{policy_id}", response_model=dict)
async def delete_policy(policy_id: str):
    """Delete a custom policy."""
    data = load_custom_policies()
    
    # Find and remove the policy
    original_count = len(data.get('policies', []))
    data['policies'] = [p for p in data.get('policies', []) if p['id'] != policy_id]
    
    if len(data['policies']) == original_count:
        raise HTTPException(
            status_code=404,
            detail=f"Custom policy '{policy_id}' not found. Only custom policies can be deleted."
        )
    
    save_custom_policies(data)
    
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


@router.post("/import", response_model=dict)
async def import_policies(
    policies: List[dict] = Body(..., embed=True),
    overwrite: bool = Body(False, embed=True)
):
    """Import policies from JSON."""
    data = load_custom_policies()
    existing_ids = {p['id'] for p in data.get('policies', [])}
    
    imported = []
    skipped = []
    
    for policy in policies:
        policy_id = policy.get('id')
        if not policy_id:
            continue
        
        if policy_id in existing_ids:
            if overwrite:
                # Remove existing and add new
                data['policies'] = [p for p in data['policies'] if p['id'] != policy_id]
                data['policies'].append(policy)
                imported.append(policy_id)
            else:
                skipped.append(policy_id)
        else:
            data['policies'].append(policy)
            imported.append(policy_id)
            existing_ids.add(policy_id)
    
    save_custom_policies(data)
    reload_policies()
    
    return {
        "imported": imported,
        "skipped": skipped,
        "total_imported": len(imported),
        "total_skipped": len(skipped)
    }


@router.post("/reload", response_model=dict)
async def reload_all_policies():
    """Reload all policies from disk."""
    compiler = reload_policies()
    policies = compiler.get_all_policies()
    
    return {
        "message": "Policies reloaded successfully",
        "total_policies": len(policies)
    }

