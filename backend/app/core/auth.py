"""Authentication and authorization for ACPG API."""
import os
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import HTTPException, Security, Depends, Request
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from .database import get_db, APIKey

# API Key header
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Master API key from environment (for admin operations)
MASTER_API_KEY = os.environ.get("ACPG_MASTER_API_KEY")

# Whether to require authentication (can be disabled for development)
REQUIRE_AUTH = os.environ.get("ACPG_REQUIRE_AUTH", "false").lower() == "true"


def hash_api_key(key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key() -> str:
    """Generate a new API key."""
    return f"acpg_{secrets.token_urlsafe(32)}"


class AuthContext:
    """Context for authenticated requests."""
    
    def __init__(
        self,
        authenticated: bool = False,
        key_name: Optional[str] = None,
        permissions: List[str] = None,
        is_master: bool = False
    ):
        self.authenticated = authenticated
        self.key_name = key_name
        self.permissions = permissions or []
        self.is_master = is_master
    
    def has_permission(self, permission: str) -> bool:
        """Check if the context has a specific permission."""
        if self.is_master:
            return True
        return permission in self.permissions or "*" in self.permissions


async def get_auth_context(
    request: Request,
    api_key: Optional[str] = Security(API_KEY_HEADER),
    db: Session = Depends(get_db)
) -> AuthContext:
    """
    Validate API key and return auth context.
    
    If REQUIRE_AUTH is False, returns an unauthenticated context with full access.
    """
    # If auth not required, allow everything
    if not REQUIRE_AUTH:
        return AuthContext(
            authenticated=False,
            permissions=["*"],
            is_master=True
        )
    
    # No API key provided
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Set X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"}
        )
    
    # Check master key
    if MASTER_API_KEY and api_key == MASTER_API_KEY:
        return AuthContext(
            authenticated=True,
            key_name="master",
            permissions=["*"],
            is_master=True
        )
    
    # Look up key in database
    key_hash = hash_api_key(api_key)
    db_key = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True
    ).first()
    
    if not db_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"}
        )
    
    # Check expiration
    if db_key.expires_at and db_key.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=401,
            detail="API key has expired",
            headers={"WWW-Authenticate": "ApiKey"}
        )
    
    # Update last used
    db_key.last_used = datetime.utcnow()
    db.commit()
    
    return AuthContext(
        authenticated=True,
        key_name=db_key.name,
        permissions=db_key.permissions or []
    )


def require_permission(permission: str):
    """Decorator to require a specific permission."""
    async def permission_checker(auth: AuthContext = Depends(get_auth_context)):
        if not auth.has_permission(permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required: {permission}"
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
        rate_limit: int = 100
    ) -> str:
        """Create a new API key."""
        key = generate_api_key()
        key_hash = hash_api_key(key)
        
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        db_key = APIKey(
            key_hash=key_hash,
            name=name,
            permissions=permissions or ["analyze", "enforce", "proof"],
            expires_at=expires_at,
            rate_limit=rate_limit
        )
        self.db.add(db_key)
        self.db.commit()
        
        return key  # Return unhashed key (only time it's available)
    
    def revoke_key(self, name: str) -> bool:
        """Revoke an API key by name."""
        db_key = self.db.query(APIKey).filter(APIKey.name == name).first()
        if db_key:
            db_key.is_active = False
            self.db.commit()
            return True
        return False
    
    def list_keys(self) -> List[dict]:
        """List all API keys (without hashes)."""
        keys = self.db.query(APIKey).all()
        return [
            {
                "name": k.name,
                "created_at": k.created_at.isoformat(),
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "is_active": k.is_active,
                "permissions": k.permissions,
                "last_used": k.last_used.isoformat() if k.last_used else None
            }
            for k in keys
        ]

