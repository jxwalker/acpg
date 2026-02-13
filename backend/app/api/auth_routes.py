"""Tenant-scoped authentication and API key management routes."""
from typing import List, Optional, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.auth import (
    APIKeyManager,
    AuthContext,
    ROLE_PERMISSIONS,
    get_auth_context,
    require_permission,
)
from ..core.database import TenantStore, get_db

router = APIRouter(prefix="/auth", tags=["auth"])


class CreateTenantRequest(BaseModel):
    tenant_id: str = Field(min_length=2, max_length=100)
    name: str = Field(min_length=2, max_length=255)
    description: Optional[str] = None


class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    tenant_id: Optional[str] = None
    role: Literal["viewer", "analyst", "operator", "admin"] = "operator"
    permissions: List[str] = []
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=3650)
    rate_limit: int = Field(default=100, ge=1, le=10000)


@router.get("/me")
async def get_me(auth: AuthContext = Depends(get_auth_context)):
    """Return effective auth context for the caller."""
    return {
        "authenticated": auth.authenticated,
        "is_master": auth.is_master,
        "key_name": auth.key_name,
        "tenant_id": auth.tenant_id,
        "role": auth.role,
        "permissions": auth.permissions,
    }


@router.get("/roles")
async def list_roles():
    """Return supported RBAC roles and default permissions."""
    return {"roles": ROLE_PERMISSIONS}


@router.get("/tenants")
async def list_tenants(
    include_inactive: bool = Query(False),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("tenant:read")),
):
    """List tenants available to this caller."""
    store = TenantStore(db)
    if auth.is_master:
        tenants = store.list_tenants(include_inactive=include_inactive)
    else:
        if not auth.tenant_id:
            return {"tenants": []}
        tenant = store.get_tenant(auth.tenant_id)
        tenants = [tenant] if tenant else []
    return {
        "tenants": [
            {
                "tenant_id": t.tenant_id,
                "name": t.name,
                "description": t.description,
                "is_active": bool(t.is_active),
                "created_at": t.created_at.isoformat() if t.created_at else None,
            }
            for t in tenants
        ]
    }


@router.post("/tenants")
async def create_tenant(
    request: CreateTenantRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("tenant:write")),
):
    """Create a tenant (master/admin only)."""
    _ = auth
    store = TenantStore(db)
    tenant_id = request.tenant_id.strip()
    if store.get_tenant(tenant_id):
        raise HTTPException(status_code=409, detail=f"Tenant already exists: {tenant_id}")
    created = store.create_tenant(
        tenant_id=tenant_id,
        name=request.name.strip(),
        description=request.description,
    )
    return {
        "tenant_id": created.tenant_id,
        "name": created.name,
        "description": created.description,
        "is_active": bool(created.is_active),
    }


@router.get("/keys")
async def list_api_keys(
    tenant_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("key:read")),
):
    """List API keys, scoped by tenant for non-master callers."""
    manager = APIKeyManager(db)
    effective_tenant = tenant_id
    if not auth.is_master:
        effective_tenant = auth.tenant_id
    return {"keys": manager.list_keys(tenant_id=effective_tenant)}


@router.post("/keys")
async def create_api_key(
    request: CreateApiKeyRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("key:write")),
):
    """Create an API key scoped to a tenant with role-based defaults."""
    requested_tenant = (request.tenant_id or "").strip() or None
    if not auth.is_master:
        if auth.tenant_id and requested_tenant and requested_tenant != auth.tenant_id:
            raise HTTPException(status_code=403, detail="Cannot create keys for another tenant")
        requested_tenant = auth.tenant_id

    if request.role == "admin" and not auth.is_master and "*" not in auth.permissions:
        raise HTTPException(status_code=403, detail="Only tenant admins can create admin keys")

    manager = APIKeyManager(db)
    try:
        api_key = manager.create_key(
            name=request.name.strip(),
            permissions=request.permissions,
            expires_in_days=request.expires_in_days,
            rate_limit=request.rate_limit,
            tenant_id=requested_tenant,
            role=request.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "name": request.name.strip(),
        "tenant_id": requested_tenant,
        "role": request.role,
        "api_key": api_key,
    }


@router.post("/keys/{name}/revoke")
async def revoke_api_key(
    name: str,
    tenant_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("key:write")),
):
    """Revoke a key by name (tenant-scoped for non-master users)."""
    manager = APIKeyManager(db)
    effective_tenant = tenant_id
    if not auth.is_master:
        effective_tenant = auth.tenant_id
    revoked = manager.revoke_key(name=name, tenant_id=effective_tenant)
    if not revoked:
        raise HTTPException(status_code=404, detail=f"Key not found: {name}")
    return {"success": True, "name": name, "tenant_id": effective_tenant}
