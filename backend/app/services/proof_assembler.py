"""Proof Assembler Service - Compile and sign proof-carrying artifacts."""
from typing import List, Optional, Dict, Any
from datetime import datetime

from ..models.schemas import (
    ProofBundle, ArtifactMetadata, PolicyOutcome, Evidence,
    AnalysisResult, AdjudicationResult, Violation
)
from ..core.crypto import get_signer
from ..core.config import settings
from .policy_compiler import get_policy_compiler


class ProofAssembler:
    """
    Assembles proof bundles for compliant artifacts.
    
    A proof bundle contains:
    - Artifact metadata (hash, language, generator)
    - Policy outcomes (satisfied/violated/waived)
    - Evidence traces (check results, counterexamples)
    - Argumentation trace (decision reasoning)
    - Digital signature (tamper-evidence)
    """
    
    def __init__(self):
        self.signer = get_signer()
        self.policy_compiler = get_policy_compiler()
    
    def assemble_proof(self, 
                       code: str,
                       analysis: AnalysisResult,
                       adjudication: AdjudicationResult,
                       artifact_name: Optional[str] = None,
                       language: str = "python") -> ProofBundle:
        """
        Assemble a complete proof bundle.
        
        Args:
            code: The compliant code artifact
            analysis: Analysis results from prosecutor
            adjudication: Adjudication results from adjudicator
            artifact_name: Optional name for the artifact
            language: Programming language
            
        Returns:
            Signed ProofBundle
        """
        # Create artifact metadata
        artifact = self._create_artifact_metadata(code, language, artifact_name)
        
        # Compile policy outcomes
        policies = self._compile_policy_outcomes(adjudication)
        
        # Gather evidence
        evidence = self._gather_evidence(analysis, adjudication)
        
        # Extract argumentation trace
        argumentation = self._extract_argumentation(adjudication)
        
        # Determine decision
        decision = "Compliant" if adjudication.compliant else "Non-compliant"
        
        # Create unsigned bundle data (serialize datetime to ISO format)
        artifact_dict = artifact.model_dump()
        if 'timestamp' in artifact_dict and hasattr(artifact_dict['timestamp'], 'isoformat'):
            artifact_dict['timestamp'] = artifact_dict['timestamp'].isoformat()
        
        bundle_data = {
            "artifact": artifact_dict,
            "policies": [p.model_dump() for p in policies],
            "evidence": [e.model_dump() for e in evidence],
            "argumentation": argumentation,
            "decision": decision,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Sign the bundle
        signature = self.signer.sign_proof(bundle_data)
        
        signed_info = {
            "signature": signature,
            "signer": settings.SIGNER_NAME,
            "algorithm": settings.SIGNATURE_ALGORITHM,
            "public_key_fingerprint": self.signer.get_public_key_fingerprint()
        }
        
        return ProofBundle(
            artifact=artifact,
            policies=policies,
            evidence=evidence,
            argumentation=argumentation,
            decision=decision,
            signed=signed_info
        )
    
    def verify_proof(self, bundle: ProofBundle) -> bool:
        """
        Verify a proof bundle's signature.
        
        Args:
            bundle: ProofBundle to verify
            
        Returns:
            True if signature is valid
        """
        # Reconstruct the data that was signed
        bundle_data = {
            "artifact": bundle.artifact.model_dump(),
            "policies": [p.model_dump() for p in bundle.policies],
            "evidence": [e.model_dump() for e in bundle.evidence],
            "argumentation": bundle.argumentation,
            "decision": bundle.decision,
            # Note: timestamp would need to be stored/recovered for verification
        }
        
        signature = bundle.signed.get("signature", "")
        return self.signer.verify_signature(bundle_data, signature)
    
    def export_proof(self, bundle: ProofBundle, format: str = "json") -> str:
        """
        Export proof bundle to a portable format.
        
        Args:
            bundle: ProofBundle to export
            format: Export format ('json', 'summary')
            
        Returns:
            Serialized proof bundle
        """
        import json
        
        if format == "json":
            # Convert to JSON with custom serialization for datetime
            data = bundle.model_dump()
            # Handle datetime serialization
            if 'artifact' in data and 'timestamp' in data['artifact']:
                ts = data['artifact']['timestamp']
                if hasattr(ts, 'isoformat'):
                    data['artifact']['timestamp'] = ts.isoformat()
            return json.dumps(data, indent=2, default=str)
        
        elif format == "summary":
            lines = [
                "=" * 60,
                "ACPG PROOF BUNDLE",
                "=" * 60,
                "",
                f"Artifact: {bundle.artifact.name or 'unnamed'}",
                f"Hash: {bundle.artifact.hash}",
                f"Language: {bundle.artifact.language}",
                f"Generator: {bundle.artifact.generator}",
                f"Timestamp: {bundle.artifact.timestamp}",
                "",
                f"Decision: {bundle.decision}",
                "",
                "Policies:",
            ]
            
            for p in bundle.policies:
                status_icon = "✓" if p.result == "satisfied" else "✗" if p.result == "violated" else "○"
                lines.append(f"  {status_icon} {p.id}: {p.result}")
            
            lines.extend([
                "",
                f"Evidence Items: {len(bundle.evidence)}",
                "",
                "Signature:",
                f"  Algorithm: {bundle.signed.get('algorithm', 'unknown')}",
                f"  Signer: {bundle.signed.get('signer', 'unknown')}",
                f"  Fingerprint: {bundle.signed.get('public_key_fingerprint', 'unknown')}",
                "",
                "=" * 60,
            ])
            
            return "\n".join(lines)
        
        else:
            raise ValueError(f"Unknown format: {format}")
    
    def _create_artifact_metadata(self, code: str, language: str,
                                   name: Optional[str]) -> ArtifactMetadata:
        """Create metadata for the artifact."""
        import hashlib
        
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        return ArtifactMetadata(
            name=name,
            hash=code_hash,
            language=language,
            generator=f"ACPG-{settings.OPENAI_MODEL}",
            timestamp=datetime.utcnow()
        )
    
    def _compile_policy_outcomes(self, adjudication: AdjudicationResult) -> List[PolicyOutcome]:
        """Compile policy outcomes from adjudication results."""
        outcomes = []
        
        # Satisfied rules
        for rule_id in adjudication.satisfied_rules:
            policy = self.policy_compiler.get_policy(rule_id)
            description = policy.description if policy else f"Policy {rule_id}"
            outcomes.append(PolicyOutcome(
                id=rule_id,
                description=description,
                result="satisfied"
            ))
        
        # Unsatisfied rules
        for rule_id in adjudication.unsatisfied_rules:
            policy = self.policy_compiler.get_policy(rule_id)
            description = policy.description if policy else f"Policy {rule_id}"
            outcomes.append(PolicyOutcome(
                id=rule_id,
                description=description,
                result="violated"
            ))
        
        return outcomes
    
    def _gather_evidence(self, analysis: AnalysisResult,
                         adjudication: AdjudicationResult) -> List[Evidence]:
        """Gather evidence from analysis and adjudication."""
        evidence_list = []
        
        # Evidence from violations
        for v in analysis.violations:
            evidence_list.append(Evidence(
                rule_id=v.rule_id,
                type="violation",
                tool=v.detector,
                output=f"Line {v.line}: {v.evidence}" if v.evidence else v.description
            ))
        
        # Evidence from satisfied rules (no violations found)
        for rule_id in adjudication.satisfied_rules:
            evidence_list.append(Evidence(
                rule_id=rule_id,
                type="compliance",
                tool="analysis",
                output=f"No violations detected for {rule_id}"
            ))
        
        return evidence_list
    
    def _extract_argumentation(self, adjudication: AdjudicationResult) -> Dict[str, Any]:
        """Extract argumentation trace for the proof."""
        return {
            "reasoning": adjudication.reasoning,
            "compliant": adjudication.compliant,
            "satisfied_count": len(adjudication.satisfied_rules),
            "unsatisfied_count": len(adjudication.unsatisfied_rules)
        }


# Global proof assembler instance
_proof_assembler: Optional[ProofAssembler] = None


def get_proof_assembler() -> ProofAssembler:
    """Get or create the global proof assembler instance."""
    global _proof_assembler
    if _proof_assembler is None:
        _proof_assembler = ProofAssembler()
    return _proof_assembler

