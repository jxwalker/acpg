"""Authentication and authorization for ACPG API."""
import hashlib
import os
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from .database import APIKey, get_db

# API Key headers
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
TENANT_HEADER = APIKeyHeader(name="X-Tenant-ID", auto_error=False)

# Master API key from environment (for admin operations)
MASTER_API_KEY = os.environ.get("ACPG_MASTER_API_KEY")

# Whether to require authentication (can be disabled for development)
REQUIRE_AUTH = os.environ.get("ACPG_REQUIRE_AUTH", "false").lower() == "true"

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "viewer": [
        "analyze:read",
        "policy:read",
        "llm:read",
        "graph:read",
        "history:read",
        "key:read",
        "tenant:read",
    ],
    "analyst": [
        "analyze",
        "adjudicate",
        "policy:read",
        "llm:read",
        "llm:test",
        "graph:read",
        "graph:enforce",
        "proof:read",
        "history:read",
        "history:write",
        "key:read",
        "tenant:read",
    ],
    "operator": [
        "analyze",
        "adjudicate",
        "enforce",
        "policy:read",
        "policy:write",
        "llm:read",
        "llm:test",
        "llm:switch",
        "llm:write",
        "graph:read",
        "graph:enforce",
        "proof:generate",
        "proof:read",
        "history:read",
        "history:write",
        "key:read",
        "tenant:read",
    ],
    "admin": ["*"],
}


def hash_api_key(key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key() -> str:
    """Generate a new API key."""
    return f"acpg_{secrets.token_urlsafe(32)}"


def role_permissions(role: Optional[str]) -> List[str]:
    """Get default permissions for a role."""
    role_name = (role or "operator").strip().lower()
    return ROLE_PERMISSIONS.get(role_name, ROLE_PERMISSIONS["operator"])


class AuthContext:
    """Context for authenticated requests."""

    def __init__(
        self,
        authenticated: bool = False,
        key_name: Optional[str] = None,
        permissions: List[str] = None,
        is_master: bool = False,
        tenant_id: Optional[str] = None,
        role: Optional[str] = None,
    ):
        self.authenticated = authenticated
        self.key_name = key_name
        self.permissions = permissions or []
        self.is_master = is_master
        self.tenant_id = tenant_id
        self.role = role

    def has_permission(self, permission: str) -> bool:
        """Check if the context has a specific permission."""
        if self.is_master:
            return True
        return permission in self.permissions or "*" in self.permissions


async def get_auth_context(
    request: Request,
    api_key: Optional[str] = Security(API_KEY_HEADER),
    requested_tenant_id: Optional[str] = Security(TENANT_HEADER),
    db: Session = Depends(get_db),
) -> AuthContext:
    """
    Validate API key and return auth context.

    If REQUIRE_AUTH is False, returns a permissive master context for local/dev use.
    """
    _ = request  # Reserved for future request-aware auth decisions.

    # If auth not required, allow everything
    if not REQUIRE_AUTH:
        return AuthContext(
            authenticated=False,
            permissions=["*"],
            is_master=True,
            tenant_id=requested_tenant_id or "global",
            role="system",
        )

    # No API key provided
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Set X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Check master key
    if MASTER_API_KEY and api_key == MASTER_API_KEY:
        return AuthContext(
            authenticated=True,
            key_name="master",
            permissions=["*"],
            is_master=True,
            tenant_id=requested_tenant_id,
            role="master",
        )

    # Look up key in database
    key_hash = hash_api_key(api_key)
    db_key = (
        db.query(APIKey)
        .filter(APIKey.key_hash == key_hash, APIKey.is_active.is_(True))
        .first()
    )

    if not db_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Check expiration
    if db_key.expires_at and db_key.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=401,
            detail="API key has expired",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Enforce tenant scope for non-master keys
    key_tenant_id = (db_key.tenant_id or "").strip() or None
    if requested_tenant_id and key_tenant_id and requested_tenant_id != key_tenant_id:
        raise HTTPException(
            status_code=403,
            detail=f"Tenant scope mismatch for key '{db_key.name}'",
        )

    # Update last used
    db_key.last_used = datetime.utcnow()
    db.commit()

    role_name = (db_key.role or "operator").strip().lower()
    merged_permissions = sorted(set(role_permissions(role_name) + (db_key.permissions or [])))

    return AuthContext(
        authenticated=True,
        key_name=db_key.name,
        permissions=merged_permissions,
        tenant_id=key_tenant_id or requested_tenant_id,
        role=role_name,
    )


def require_permission(permission: str):
    """Dependency factory to require a specific permission."""

    async def permission_checker(auth: AuthContext = Depends(get_auth_context)):
        if not auth.has_permission(permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required: {permission}",
            )
        return auth

    return permission_checker


# ============================================================================
# API Key Management
# ============================================================================


class APIKeyManager:
    """Manage API keys."""

    def __init__(self, db: Session):
        self.db = db

    def create_key(
        self,
        name: str,
        permissions: List[str] = None,
        expires_in_days: Optional[int] = None,
        rate_limit: int = 100,
        tenant_id: Optional[str] = None,
        role: str = "operator",
    ) -> str:
        """Create a new API key."""
        key = generate_api_key()
        key_hash = hash_api_key(key)

        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        role_name = (role or "operator").strip().lower()
        if role_name not in ROLE_PERMISSIONS:
            raise ValueError(f"Unsupported role: {role_name}")

        merged_permissions = sorted(set(role_permissions(role_name) + (permissions or [])))

        db_key = APIKey(
            key_hash=key_hash,
            name=name,
            permissions=merged_permissions,
            expires_at=expires_at,
            rate_limit=rate_limit,
            tenant_id=tenant_id,
            role=role_name,
        )
        self.db.add(db_key)
        self.db.commit()

        return key  # Return unhashed key (only time it's available)

    def revoke_key(self, name: str, tenant_id: Optional[str] = None) -> bool:
        """Revoke an API key by name."""
        query = self.db.query(APIKey).filter(APIKey.name == name)
        if tenant_id is not None:
            query = query.filter(APIKey.tenant_id == tenant_id)
        db_key = query.first()
        if db_key:
            db_key.is_active = False
            self.db.commit()
            return True
        return False

    def list_keys(self, tenant_id: Optional[str] = None) -> List[dict]:
        """List API keys (without hashes)."""
        query = self.db.query(APIKey)
        if tenant_id is not None:
            query = query.filter(APIKey.tenant_id == tenant_id)
        keys = query.order_by(APIKey.created_at.desc()).all()
        return [
            {
                "name": k.name,
                "created_at": k.created_at.isoformat(),
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "is_active": k.is_active,
                "permissions": k.permissions,
                "tenant_id": k.tenant_id,
                "role": k.role,
                "last_used": k.last_used.isoformat() if k.last_used else None,
            }
            for k in keys
        ]
