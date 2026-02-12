"""Database configuration and models for ACPG."""
import os
from datetime import datetime
from typing import Optional, List
from pathlib import Path

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, JSON
from sqlalchemy.orm import declarative_base, sessionmaker, Session


# Database URL - defaults to SQLite for simplicity
DATABASE_URL = os.environ.get(
    "DATABASE_URL", 
    f"sqlite:///{Path(__file__).parent.parent.parent}/acpg.db"
)

# Create engine
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


# ============================================================================
# Database Models
# ============================================================================

class AuditLog(Base):
    """Audit log for all compliance checks."""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(tz=None), index=True)
    action = Column(String(50), index=True)  # analyze, enforce, generate, proof
    artifact_hash = Column(String(64), index=True)
    language = Column(String(20))
    compliant = Column(Boolean, nullable=True)
    violation_count = Column(Integer, default=0)
    violations = Column(JSON, nullable=True)  # List of violation details
    iterations = Column(Integer, nullable=True)
    user_id = Column(String(100), nullable=True, index=True)  # For future auth
    ip_address = Column(String(45), nullable=True)
    request_id = Column(String(36), nullable=True, index=True)


class StoredProof(Base):
    """Stored proof bundles for retrieval."""
    __tablename__ = "stored_proofs"
    
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=None), index=True)
    artifact_hash = Column(String(64), unique=True, index=True)
    artifact_name = Column(String(255), nullable=True)
    language = Column(String(20))
    decision = Column(String(20))  # Compliant / Non-compliant
    policies_checked = Column(JSON)  # List of policy outcomes
    signature = Column(Text)
    signer = Column(String(100))
    algorithm = Column(String(50))
    public_key_fingerprint = Column(String(32))
    full_bundle = Column(JSON)  # Complete proof bundle


class PolicyHistory(Base):
    """History of policy changes."""
    __tablename__ = "policy_history"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(tz=None))
    action = Column(String(20))  # add, modify, delete
    policy_id = Column(String(50), index=True)
    policy_data = Column(JSON)
    changed_by = Column(String(100), nullable=True)


class APIKey(Base):
    """API keys for authentication."""
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String(64), unique=True, index=True)  # SHA-256 of key
    name = Column(String(100))
    created_at = Column(DateTime, default=lambda: datetime.now(tz=None))
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    permissions = Column(JSON, default=list)  # List of allowed actions
    rate_limit = Column(Integer, default=100)  # Requests per minute
    last_used = Column(DateTime, nullable=True)


class TestCase(Base):
    """Stored test code cases for repeatable analysis/enforcement runs."""
    __tablename__ = "test_cases"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=None), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(tz=None), index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    language = Column(String(20), default="python", index=True)
    code = Column(Text, nullable=False)
    tags = Column(JSON, default=list)
    is_active = Column(Boolean, default=True, index=True)


# ============================================================================
# Database Operations
# ============================================================================

def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class AuditLogger:
    """Helper class for audit logging."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def log_analysis(
        self,
        artifact_hash: str,
        language: str,
        compliant: bool,
        violations: List[dict],
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        request_id: Optional[str] = None
    ):
        """Log an analysis action."""
        log = AuditLog(
            action="analyze",
            artifact_hash=artifact_hash,
            language=language,
            compliant=compliant,
            violation_count=len(violations),
            violations=violations,
            user_id=user_id,
            ip_address=ip_address,
            request_id=request_id
        )
        self.db.add(log)
        self.db.commit()
        return log.id
    
    def log_enforcement(
        self,
        artifact_hash: str,
        language: str,
        compliant: bool,
        violations_fixed: List[str],
        iterations: int,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None
    ):
        """Log an enforcement action."""
        log = AuditLog(
            action="enforce",
            artifact_hash=artifact_hash,
            language=language,
            compliant=compliant,
            violation_count=len(violations_fixed),
            violations={"fixed": violations_fixed},
            iterations=iterations,
            user_id=user_id,
            request_id=request_id
        )
        self.db.add(log)
        self.db.commit()
        return log.id
    
    def log_proof_generation(
        self,
        artifact_hash: str,
        language: str,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None
    ):
        """Log proof generation."""
        log = AuditLog(
            action="proof",
            artifact_hash=artifact_hash,
            language=language,
            compliant=True,  # Only compliant code gets proofs
            user_id=user_id,
            request_id=request_id
        )
        self.db.add(log)
        self.db.commit()
        return log.id


class ProofStore:
    """Helper class for proof storage."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def store_proof(self, proof_bundle: dict) -> int:
        """Store a proof bundle."""
        artifact = proof_bundle.get("artifact", {})
        signed = proof_bundle.get("signed", {})
        
        proof = StoredProof(
            artifact_hash=artifact.get("hash"),
            artifact_name=artifact.get("name"),
            language=artifact.get("language"),
            decision=proof_bundle.get("decision"),
            policies_checked=proof_bundle.get("policies"),
            signature=signed.get("signature"),
            signer=signed.get("signer"),
            algorithm=signed.get("algorithm"),
            public_key_fingerprint=signed.get("public_key_fingerprint"),
            full_bundle=proof_bundle
        )
        self.db.add(proof)
        self.db.commit()
        return proof.id
    
    def get_proof_by_hash(self, artifact_hash: str) -> Optional[dict]:
        """Retrieve a proof by artifact hash."""
        proof = self.db.query(StoredProof).filter(
            StoredProof.artifact_hash == artifact_hash
        ).first()
        return proof.full_bundle if proof else None
    
    def list_proofs(self, limit: int = 100, offset: int = 0) -> List[dict]:
        """List stored proofs."""
        proofs = self.db.query(StoredProof).order_by(
            StoredProof.created_at.desc()
        ).offset(offset).limit(limit).all()
        return [
            {
                "id": p.id,
                "artifact_hash": p.artifact_hash,
                "artifact_name": p.artifact_name,
                "decision": p.decision,
                "created_at": p.created_at.isoformat()
            }
            for p in proofs
        ]


class TestCaseStore:
    """CRUD helper for persisted test code cases."""

    def __init__(self, db: Session):
        self.db = db

    def list_cases(self, *, include_inactive: bool = False, language: Optional[str] = None) -> List[TestCase]:
        query = self.db.query(TestCase)
        if not include_inactive:
            query = query.filter(TestCase.is_active == True)  # noqa: E712
        if language:
            query = query.filter(TestCase.language == language)
        return query.order_by(TestCase.updated_at.desc()).all()

    def get_case(self, case_id: int) -> Optional[TestCase]:
        return self.db.query(TestCase).filter(TestCase.id == case_id).first()

    def create_case(
        self,
        *,
        name: str,
        description: Optional[str],
        language: str,
        code: str,
        tags: Optional[List[str]] = None,
    ) -> TestCase:
        now = datetime.now(tz=None)
        test_case = TestCase(
            name=name,
            description=description,
            language=language,
            code=code,
            tags=tags or [],
            created_at=now,
            updated_at=now,
            is_active=True,
        )
        self.db.add(test_case)
        self.db.commit()
        self.db.refresh(test_case)
        return test_case

    def update_case(
        self,
        case: TestCase,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        language: Optional[str] = None,
        code: Optional[str] = None,
        tags: Optional[List[str]] = None,
        is_active: Optional[bool] = None,
    ) -> TestCase:
        if name is not None:
            case.name = name
        if description is not None:
            case.description = description
        if language is not None:
            case.language = language
        if code is not None:
            case.code = code
        if tags is not None:
            case.tags = tags
        if is_active is not None:
            case.is_active = is_active
        case.updated_at = datetime.now(tz=None)
        self.db.add(case)
        self.db.commit()
        self.db.refresh(case)
        return case

    def delete_case(self, case: TestCase) -> None:
        self.db.delete(case)
        self.db.commit()
