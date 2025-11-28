"""API Routes for ACPG system."""
import hashlib
import uuid
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends, Request
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
    """Health check endpoint."""
    return {"status": "healthy", "service": "ACPG"}


@router.get("/info")
async def get_info():
    """Get system information."""
    return {
        "name": settings.PROJECT_NAME,
        "version": "1.0.0",
        "model": settings.OPENAI_MODEL,
        "max_fix_iterations": settings.MAX_FIX_ITERATIONS
    }


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
    """
    prosecutor = get_prosecutor()
    adjudicator = get_adjudicator()
    
    result = prosecutor.analyze(
        code=request.code,
        language=request.language,
        policy_ids=request.policies
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
    prosecutor = get_prosecutor()
    result = prosecutor.analyze(
        code=request.code,
        language=request.language,
        policy_ids=request.policies
    )
    summary = prosecutor.get_violation_summary(result.violations)
    summary['violations'] = result.violations
    return summary


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
    except Exception as e:
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
    """
    prosecutor = get_prosecutor()
    adjudicator = get_adjudicator()
    generator = get_generator()
    proof_assembler = get_proof_assembler()
    request_id = str(uuid.uuid4())
    
    code = request.code
    original_code = request.code
    violations_fixed = []
    
    for iteration in range(request.max_iterations):
        # Analyze
        analysis = prosecutor.analyze(
            code=code,
            language=request.language,
            policy_ids=request.policies
        )
        
        # Adjudicate
        adjudication = adjudicator.adjudicate(analysis, request.policies)
        
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
            # Fix failed - return current state
            return EnforceResponse(
                original_code=original_code,
                final_code=code,
                iterations=iteration + 1,
                compliant=False,
                violations_fixed=violations_fixed,
                proof_bundle=None
            )
    
    # Max iterations reached without compliance
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
        proof_bundle=None
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
    Generate a proof bundle for compliant code.
    
    First analyzes and adjudicates, then generates proof if compliant.
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
    
    if not adjudication.compliant:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Code is not compliant, cannot generate proof",
                "violations": [v.model_dump() for v in analysis.violations]
            }
        )
    
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

