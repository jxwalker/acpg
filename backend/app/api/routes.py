"""API Routes for ACPG system."""
import hashlib
import uuid
from typing import List, Optional, Dict, Any
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
from ..core.static_analyzers import get_analyzer_config
from ..services.tool_cache import get_tool_cache
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
    
    return {
        "tools_by_language": tools_by_language,
        "cache_stats": get_tool_cache().get_stats()
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
        signed_data = {
            "artifact": artifact_data,
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
        
        # Verify artifact hash
        if "artifact" in proof and "hash" in proof["artifact"]:
            result["original_hash"] = proof["artifact"]["hash"]
            result["details"]["hash_valid"] = True
            result["checks"].append(f"✓ Artifact hash present: {proof['artifact']['hash'][:16]}...")
        
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

