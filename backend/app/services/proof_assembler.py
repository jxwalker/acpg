"""Proof Assembler Service - Compile and sign proof-carrying artifacts."""
from typing import List, Optional, Dict, Any
from datetime import datetime

from ..models.schemas import (
    ProofBundle, ArtifactMetadata, PolicyOutcome, Evidence,
    AnalysisResult, AdjudicationResult, Violation
)
from ..core.crypto import get_signer
from ..core.config import settings
from ..core.llm_config import get_llm_config
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
        
        # Extract argumentation trace (with tool metadata)
        argumentation = self._extract_argumentation(adjudication, analysis)
        
        # Determine decision
        decision = "Compliant" if adjudication.compliant else "Non-compliant"
        
        # Create unsigned bundle data (serialize datetime to ISO format)
        artifact_dict = artifact.model_dump()
        if 'timestamp' in artifact_dict and hasattr(artifact_dict['timestamp'], 'isoformat'):
            artifact_dict['timestamp'] = artifact_dict['timestamp'].isoformat()
        
        signing_timestamp = datetime.utcnow().isoformat()
        
        # Include code in bundle data for tamper detection
        # The signature will cover the code, so any modification will invalidate it
        bundle_data = {
            "artifact": artifact_dict,
            "code": code,  # Include actual code in signed data
            "policies": [p.model_dump() for p in policies],
            "evidence": [e.model_dump() for e in evidence],
            "argumentation": argumentation,
            "decision": decision,
            "timestamp": signing_timestamp
        }
        
        # Sign the bundle (includes code, so tampering with code invalidates signature)
        signature = self.signer.sign_proof(bundle_data)
        
        signed_info = {
            "signature": signature,
            "signer": settings.SIGNER_NAME,
            "algorithm": settings.SIGNATURE_ALGORITHM,
            "public_key_fingerprint": self.signer.get_public_key_fingerprint(),
            "signed_at": signing_timestamp  # Store the timestamp used in signing
        }
        
        return ProofBundle(
            artifact=artifact,
            code=code,  # Include code in bundle
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
        # Must include code to verify it hasn't been tampered with
        artifact_dict = bundle.artifact.model_dump()
        if 'timestamp' in artifact_dict and hasattr(artifact_dict['timestamp'], 'isoformat'):
            artifact_dict['timestamp'] = artifact_dict['timestamp'].isoformat()
        
        bundle_data = {
            "artifact": artifact_dict,
            "code": bundle.code,  # Include code in verification
            "policies": [p.model_dump() for p in bundle.policies],
            "evidence": [e.model_dump() for e in bundle.evidence],
            "argumentation": bundle.argumentation,
            "decision": bundle.decision,
            "timestamp": bundle.signed.get("signed_at", "")  # Use stored timestamp
        }
        
        # Verify signature covers code
        signature = bundle.signed.get("signature", "")
        if not self.signer.verify_signature(bundle_data, signature):
            return False
        
        # Verify code hash matches artifact hash
        import hashlib
        code_hash = hashlib.sha256(bundle.code.encode()).hexdigest()
        if code_hash != bundle.artifact.hash:
            return False  # Code has been modified
        
        return True
    
    def export_proof(self, bundle: ProofBundle, format: str = "json") -> str:
        """
        Export proof bundle to a portable format.
        
        Args:
            bundle: ProofBundle to export
            format: Export format ('json', 'summary', 'markdown', 'html')
            
        Returns:
            Serialized proof bundle
        """
        import json
        from datetime import datetime
        
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
        
        elif format == "markdown":
            return self._export_markdown(bundle)
        
        elif format == "html":
            return self._export_html(bundle)
        
        else:
            raise ValueError(f"Unknown format: {format}. Supported: json, summary, markdown, html")
    
    def _export_markdown(self, bundle: ProofBundle) -> str:
        """Export proof bundle as Markdown."""
        lines = [
            "# ACPG Proof Bundle",
            "",
            "## Artifact Information",
            "",
            f"- **Name**: {bundle.artifact.name or 'unnamed'}",
            f"- **Hash**: `{bundle.artifact.hash}`",
            f"- **Language**: {bundle.artifact.language}",
            f"- **Generator**: {bundle.artifact.generator}",
            f"- **Timestamp**: {bundle.artifact.timestamp}",
            "",
            f"## Decision: {bundle.decision.upper()}",
            "",
            "## Policies",
            "",
        ]
        
        satisfied = [p for p in bundle.policies if p.result == "satisfied"]
        violated = [p for p in bundle.policies if p.result == "violated"]
        
        if satisfied:
            lines.append("### Satisfied Policies")
            lines.append("")
            for p in satisfied:
                lines.append(f"- ✅ **{p.id}**: {p.description}")
            lines.append("")
        
        if violated:
            lines.append("### Violated Policies")
            lines.append("")
            for p in violated:
                lines.append(f"- ❌ **{p.id}**: {p.description}")
            lines.append("")
        
        if bundle.evidence:
            lines.extend([
                "## Evidence",
                "",
            ])
            for i, ev in enumerate(bundle.evidence, 1):
                lines.append(f"### Evidence {i}")
                lines.append(f"- **Type**: {ev.type}")
                lines.append(f"- **Description**: {ev.description}")
                if ev.location:
                    loc = ev.location
                    if 'file' in loc:
                        lines.append(f"- **File**: {loc['file']}")
                    if 'line' in loc:
                        lines.append(f"- **Line**: {loc['line']}")
                lines.append("")
        
        if bundle.argumentation:
            lines.extend([
                "## Argumentation",
                "",
                f"**Summary**: {bundle.argumentation.summary.explanation}",
                "",
            ])
            
            if bundle.argumentation.arguments:
                lines.append("### Arguments")
                lines.append("")
                for arg in bundle.argumentation.arguments:
                    status = "✅ ACCEPTED" if arg.get('accepted', False) else "❌ REJECTED"
                    lines.append(f"- **{arg.get('id', 'unknown')}** ({status}): {arg.get('claim', 'N/A')}")
                lines.append("")
        
        lines.extend([
            "## Cryptographic Signature",
            "",
            f"- **Algorithm**: {bundle.signed.get('algorithm', 'unknown')}",
            f"- **Signer**: {bundle.signed.get('signer', 'unknown')}",
            f"- **Fingerprint**: `{bundle.signed.get('public_key_fingerprint', 'unknown')}`",
            f"- **Signature**: `{bundle.signed.get('signature', 'unknown')[:64]}...`",
            "",
            "---",
            f"*Generated by {bundle.artifact.generator} on {bundle.artifact.timestamp}*",
        ])
        
        return "\n".join(lines)
    
    def _export_html(self, bundle: ProofBundle) -> str:
        """Export proof bundle as HTML."""
        html = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='utf-8'>",
            "<title>ACPG Proof Bundle</title>",
            "<style>",
            "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #0f172a; color: #e2e8f0; }",
            "h1 { color: #10b981; border-bottom: 2px solid #10b981; padding-bottom: 10px; }",
            "h2 { color: #34d399; margin-top: 30px; }",
            "h3 { color: #6ee7b7; }",
            ".decision { font-size: 1.5em; font-weight: bold; padding: 15px; border-radius: 8px; margin: 20px 0; }",
            ".compliant { background: #065f46; color: #6ee7b7; }",
            ".non-compliant { background: #7f1d1d; color: #fca5a5; }",
            ".policy { padding: 10px; margin: 5px 0; border-radius: 5px; border-left: 4px solid; }",
            ".satisfied { background: #064e3b; border-color: #10b981; }",
            ".violated { background: #7f1d1d; border-color: #ef4444; }",
            ".evidence { background: #1e293b; padding: 15px; margin: 10px 0; border-radius: 5px; }",
            ".signature { background: #1e293b; padding: 15px; border-radius: 5px; font-family: monospace; }",
            "code { background: #1e293b; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }",
            ".meta { color: #94a3b8; font-size: 0.9em; }",
            "</style>",
            "</head>",
            "<body>",
            f"<h1>ACPG Proof Bundle</h1>",
            "",
            "<div class='meta'>",
            f"<p><strong>Artifact:</strong> {bundle.artifact.name or 'unnamed'}</p>",
            f"<p><strong>Hash:</strong> <code>{bundle.artifact.hash}</code></p>",
            f"<p><strong>Language:</strong> {bundle.artifact.language}</p>",
            f"<p><strong>Generator:</strong> {bundle.artifact.generator}</p>",
            f"<p><strong>Timestamp:</strong> {bundle.artifact.timestamp}</p>",
            "</div>",
            "",
            f"<div class='decision {'compliant' if bundle.decision == 'compliant' else 'non-compliant'}'>",
            f"Decision: {bundle.decision.upper()}",
            "</div>",
            "",
            "<h2>Policies</h2>",
        ]
        
        satisfied = [p for p in bundle.policies if p.result == "satisfied"]
        violated = [p for p in bundle.policies if p.result == "violated"]
        
        if satisfied:
            html.append("<h3>Satisfied Policies</h3>")
            for p in satisfied:
                html.append(f"<div class='policy satisfied'>✅ <strong>{p.id}</strong>: {p.description}</div>")
        
        if violated:
            html.append("<h3>Violated Policies</h3>")
            for p in violated:
                html.append(f"<div class='policy violated'>❌ <strong>{p.id}</strong>: {p.description}</div>")
        
        if bundle.evidence:
            html.extend([
                "",
                "<h2>Evidence</h2>",
            ])
            for i, ev in enumerate(bundle.evidence, 1):
                html.append(f"<div class='evidence'>")
                html.append(f"<h3>Evidence {i}</h3>")
                html.append(f"<p><strong>Type:</strong> {ev.type}</p>")
                html.append(f"<p><strong>Description:</strong> {ev.description}</p>")
                if ev.location:
                    loc = ev.location
                    if 'file' in loc:
                        html.append(f"<p><strong>File:</strong> {loc['file']}</p>")
                    if 'line' in loc:
                        html.append(f"<p><strong>Line:</strong> {loc['line']}</p>")
                html.append("</div>")
        
        if bundle.argumentation:
            html.extend([
                "",
                "<h2>Argumentation</h2>",
                f"<p>{bundle.argumentation.summary.explanation}</p>",
            ])
            
            if bundle.argumentation.arguments:
                html.append("<h3>Arguments</h3>")
                for arg in bundle.argumentation.arguments:
                    status = "✅ ACCEPTED" if arg.get('accepted', False) else "❌ REJECTED"
                    html.append(f"<p><strong>{arg.get('id', 'unknown')}</strong> ({status}): {arg.get('claim', 'N/A')}</p>")
        
        html.extend([
            "",
            "<h2>Cryptographic Signature</h2>",
            "<div class='signature'>",
            f"<p><strong>Algorithm:</strong> {bundle.signed.get('algorithm', 'unknown')}</p>",
            f"<p><strong>Signer:</strong> {bundle.signed.get('signer', 'unknown')}</p>",
            f"<p><strong>Fingerprint:</strong> <code>{bundle.signed.get('public_key_fingerprint', 'unknown')}</code></p>",
            f"<p><strong>Signature:</strong> <code>{bundle.signed.get('signature', 'unknown')[:64]}...</code></p>",
            "</div>",
            "",
            "<hr>",
            f"<p class='meta'><em>Generated by {bundle.artifact.generator} on {bundle.artifact.timestamp}</em></p>",
            "</body>",
            "</html>",
        ])
        
        return "\n".join(html)
    
    def _create_artifact_metadata(self, code: str, language: str,
                                   name: Optional[str]) -> ArtifactMetadata:
        """Create metadata for the artifact."""
        import hashlib
        
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        # Get the active LLM provider name for the generator field
        try:
            llm_name = get_llm_config().get_active_provider().name
        except Exception:
            llm_name = settings.OPENAI_MODEL  # Fallback to settings
        
        return ArtifactMetadata(
            name=name,
            hash=code_hash,
            language=language,
            generator=f"ACPG-{llm_name}",
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
    
    def _extract_argumentation(self, adjudication: AdjudicationResult, 
                                analysis: Optional[AnalysisResult] = None) -> Dict[str, Any]:
        """Extract full formal argumentation proof for the bundle."""
        # Extract tools used from violations
        tools_used = set()
        tool_versions = {}
        if analysis:
            for violation in analysis.violations:
                if violation.detector and violation.detector != "regex" and violation.detector != "ast":
                    tools_used.add(violation.detector)
        
        # Build the formal proof structure
        formal_proof = {
            "framework": "Dung's Abstract Argumentation Framework",
            "semantics": "Grounded Extension",
            "decision": "Compliant" if adjudication.compliant else "Non-Compliant",
            
            # Tools used in analysis
            "tools_used": sorted(list(tools_used)) if tools_used else [],
            "tool_versions": tool_versions,  # Tool versions extracted from tool execution
            
            # Arguments in the framework
            "arguments": [],
            
            # Attack relations
            "attacks": [],
            
            # Grounded extension computation
            "grounded_extension": {
                "accepted": [],
                "rejected": []
            },
            
            # Detailed reasoning trace
            "reasoning_trace": adjudication.reasoning,
            
            # Summary statistics
            "summary": {
                "total_arguments": 0,
                "accepted_arguments": 0,
                "rejected_arguments": 0,
                "total_attacks": 0,
                "effective_attacks": 0,
                "satisfied_rules": len(adjudication.satisfied_rules),
                "unsatisfied_rules": len(adjudication.unsatisfied_rules)
            },
            
            # Visual graph representation
            "graph_visual": "",
            
            # Plain English explanation
            "explanation": {
                "summary": "",
                "terminology": {
                    "argument": "A claim about the code's compliance status",
                    "C_RULE": "Compliance argument - claims 'code complies with RULE'",
                    "V_RULE": "Violation argument - claims 'code violates RULE' with evidence",
                    "E_RULE": "Exception argument - claims 'exception condition applies, defeating violation'",
                    "attack": "One argument contradicts/defeats another",
                    "grounded_extension": "The set of arguments that are defensibly accepted after resolving all attacks",
                    "accepted": "Argument is in the grounded extension - its claim holds",
                    "rejected": "Argument is defeated by an accepted argument - its claim does not hold"
                },
                "decision_logic": [],
                "step_by_step": []
            }
        }
        
        # Extract arguments and attacks from reasoning trace
        compliance_args = []
        violation_args = []
        exception_args = []
        attack_list = []
        
        for item in adjudication.reasoning:
            if "argument" in item:
                arg_entry = {
                    "id": item["argument"],
                    "type": item.get("type", "unknown"),
                    "rule_id": item.get("rule", ""),
                    "status": item.get("status", "unknown"),
                    "details": item.get("details", ""),
                    "evidence": item.get("evidence", "")
                }
                formal_proof["arguments"].append(arg_entry)
                formal_proof["summary"]["total_arguments"] += 1
                
                # Categorize by type
                if item.get("type") == "compliance":
                    compliance_args.append(arg_entry)
                elif item.get("type") == "violation":
                    violation_args.append(arg_entry)
                elif item.get("type") == "exception":
                    exception_args.append(arg_entry)
                
                if item.get("status") == "accepted":
                    formal_proof["grounded_extension"]["accepted"].append(item["argument"])
                    formal_proof["summary"]["accepted_arguments"] += 1
                else:
                    formal_proof["grounded_extension"]["rejected"].append(item["argument"])
                    formal_proof["summary"]["rejected_arguments"] += 1
                    
            elif "attack" in item:
                attack_entry = {
                    "relation": item["attack"],
                    "attacker": item["attack"].split(" → ")[0] if " → " in item["attack"] else "",
                    "target": item["attack"].split(" → ")[1] if " → " in item["attack"] else "",
                    "effective": item.get("effective", False),
                    "explanation": item.get("explanation", "")
                }
                formal_proof["attacks"].append(attack_entry)
                attack_list.append(attack_entry)
                formal_proof["summary"]["total_attacks"] += 1
                if item.get("effective"):
                    formal_proof["summary"]["effective_attacks"] += 1
                    
            elif "conclusion" in item:
                formal_proof["conclusion"] = {
                    "decision": item["conclusion"],
                    "reason": item.get("reason", ""),
                    "violated_rules": item.get("violations", [])
                }
        
        # Generate visual graph and explanations
        formal_proof["graph_visual"] = self._generate_graph_visual(
            compliance_args, violation_args, exception_args, attack_list
        )
        formal_proof["explanation"] = self._generate_detailed_explanation(
            adjudication, compliance_args, violation_args, exception_args, attack_list
        )
        
        return formal_proof
    
    def _generate_graph_visual(self, compliance_args: List, violation_args: List,
                                exception_args: List, attacks: List) -> Dict[str, Any]:
        """Generate a structured visualization of the argumentation graph for frontend rendering."""
        
        graph = {
            "violations": [],
            "compliant_policies": [],
            "legend": {
                "accepted": "Argument is in the grounded extension (claim holds)",
                "rejected": "Argument is defeated by an accepted attacker (claim does not hold)",
                "attacks": "One argument contradicts/defeats another"
            }
        }
        
        # Group violations by rule
        rules_shown = set()
        
        for v_arg in violation_args:
            rule_id = v_arg.get("rule_id", "UNKNOWN")
            if rule_id in rules_shown:
                continue
            rules_shown.add(rule_id)
            
            # Find corresponding compliance arg
            c_arg = next((c for c in compliance_args if c.get("rule_id") == rule_id), None)
            # Find any exception args
            e_args = [e for e in exception_args if e.get("rule_id") == rule_id]
            
            v_accepted = v_arg.get("status") == "accepted"
            c_accepted = c_arg and c_arg.get("status") == "accepted"
            
            evidence = v_arg.get("evidence", "")
            if not evidence:
                evidence = "(pattern match)"
            
            violation_entry = {
                "rule_id": rule_id,
                "violation": {
                    "id": f"V_{rule_id}",
                    "label": "Violation argument",
                    "accepted": v_accepted,
                    "evidence": evidence
                },
                "compliance": {
                    "id": f"C_{rule_id}",
                    "label": "Compliance argument", 
                    "accepted": c_accepted
                },
                "exception": None
            }
            
            if e_args:
                e_arg = e_args[0]
                e_accepted = e_arg.get("status") == "accepted"
                violation_entry["exception"] = {
                    "id": f"E_{rule_id}",
                    "label": "Exception argument",
                    "accepted": e_accepted
                }
            
            graph["violations"].append(violation_entry)
        
        # Compliant policies (no violations)
        compliant_only = [c for c in compliance_args 
                         if c.get("rule_id") not in rules_shown and c.get("status") == "accepted"]
        graph["compliant_policies"] = [c.get("rule_id", "?") for c in compliant_only]
        
        return graph
    
    def _generate_detailed_explanation(self, adjudication: AdjudicationResult,
                                        compliance_args: List, violation_args: List,
                                        exception_args: List, attacks: List) -> Dict[str, Any]:
        """Generate a detailed plain-English explanation of the argumentation."""
        explanation = {
            "summary": "",
            "terminology": {
                "argument": "A claim about the code's compliance status",
                "C_RULE": "Compliance argument - claims 'this code complies with RULE'",
                "V_RULE": "Violation argument - claims 'this code violates RULE' (with evidence)",
                "E_RULE": "Exception argument - claims 'an exception condition applies, defeating the violation'",
                "attack": "A relationship where one argument contradicts/defeats another",
                "grounded_extension": "The minimal set of arguments that are defensibly accepted after resolving all attacks",
                "accepted": "The argument's claim is upheld - it is in the grounded extension",
                "rejected": "The argument is defeated by an accepted attacker - its claim does not hold"
            },
            "what_happened": [],
            "step_by_step": [],
            "decision_logic": []
        }
        
        accepted_violations = [v for v in violation_args if v.get("status") == "accepted"]
        rejected_violations = [v for v in violation_args if v.get("status") != "accepted"]
        
        # Generate summary
        if adjudication.compliant:
            explanation["summary"] = (
                f"The code is COMPLIANT. All {len(compliance_args)} compliance arguments were accepted "
                f"in the grounded extension. No violation arguments remained undefeated."
            )
        else:
            violated_rules = list(set(v.get("rule_id", "?") for v in accepted_violations))
            explanation["summary"] = (
                f"The code is NON-COMPLIANT. {len(accepted_violations)} violation argument(s) "
                f"were accepted in the grounded extension for policies: {violated_rules}. "
                f"These violations were not defeated by any exception arguments."
            )
        
        # What happened for each violated policy
        for v in accepted_violations:
            rule_id = v.get("rule_id", "UNKNOWN")
            evidence = v.get("evidence") or v.get("details", "").split(": ")[-1] if v.get("details") else "detected pattern"
            
            what = {
                "policy": rule_id,
                "result": "VIOLATED",
                "reason": f"Violation argument V_{rule_id} was ACCEPTED in the grounded extension",
                "evidence": evidence,
                "explanation": (
                    f"The system found evidence that the code violates {rule_id}: '{evidence}'. "
                    f"A violation argument (V_{rule_id}) was created to attack the compliance argument (C_{rule_id}). "
                    f"Since no exception argument existed to defeat V_{rule_id}, it remained unattacked "
                    f"and was therefore ACCEPTED. This means the violation claim holds, and C_{rule_id} was REJECTED."
                )
            }
            explanation["what_happened"].append(what)
        
        # Step by step for the grounded extension
        explanation["step_by_step"] = [
            {
                "step": 1,
                "title": "Initialize",
                "description": "Start with empty sets: accepted = ∅, rejected = ∅"
            },
            {
                "step": 2,
                "title": "Find Unattacked Arguments",
                "description": (
                    f"Identify arguments with no attackers. "
                    f"Violation arguments V_* that have no exception arguments attacking them are unattacked."
                ),
                "result": f"Unattacked: {[v['id'] for v in accepted_violations]}" if accepted_violations else "All violations were defeated"
            },
            {
                "step": 3,
                "title": "Accept Unattacked Arguments",
                "description": "Add unattacked arguments to the accepted set.",
                "result": f"Accepted: {[v['id'] for v in accepted_violations]}" if accepted_violations else "No violations accepted"
            },
            {
                "step": 4,
                "title": "Reject Attacked Arguments",
                "description": "Arguments attacked by accepted arguments are rejected.",
                "result": f"Rejected compliance: {[c['id'] for c in compliance_args if c.get('status') != 'accepted']}"
            },
            {
                "step": 5,
                "title": "Iterate to Fixpoint",
                "description": "Repeat until no changes. The final accepted set is the grounded extension."
            }
        ]
        
        # Decision logic
        explanation["decision_logic"] = [
            "IF ∃ violation argument V in accepted set → code VIOLATES that policy",
            "IF ∀ compliance arguments C in accepted set → code is COMPLIANT",
            f"Result: {'COMPLIANT' if adjudication.compliant else 'NON-COMPLIANT'}"
        ]
        
        if accepted_violations:
            explanation["decision_logic"].append(
                f"Violated policies: {list(set(v.get('rule_id') for v in accepted_violations))}"
            )
        
        return explanation


# Global proof assembler instance
_proof_assembler: Optional[ProofAssembler] = None


def get_proof_assembler() -> ProofAssembler:
    """Get or create the global proof assembler instance."""
    global _proof_assembler
    if _proof_assembler is None:
        _proof_assembler = ProofAssembler()
    return _proof_assembler

