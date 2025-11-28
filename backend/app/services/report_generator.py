"""Report Generator Service - Generate compliance reports for code artifacts."""
from typing import List, Optional, Dict, Any
from datetime import datetime
import json
import hashlib

from ..models.schemas import (
    AnalysisResult, AdjudicationResult, Violation, PolicyRule
)
from ..core.crypto import get_signer
from ..core.config import settings
from .policy_compiler import get_policy_compiler


class ComplianceReport:
    """
    A compliance report detailing analysis results, violations, and recommendations.
    Can be generated for both compliant and non-compliant code.
    """
    
    def __init__(
        self,
        code: str,
        language: str,
        analysis: AnalysisResult,
        adjudication: AdjudicationResult,
        report_type: str = "analysis"  # "analysis", "failure", "compliance"
    ):
        self.code = code
        self.language = language
        self.analysis = analysis
        self.adjudication = adjudication
        self.report_type = report_type
        self.timestamp = datetime.utcnow()
        self.policy_compiler = get_policy_compiler()
        self.signer = get_signer()
    
    def generate(self) -> Dict[str, Any]:
        """Generate the full compliance report."""
        code_hash = hashlib.sha256(self.code.encode()).hexdigest()
        
        report = {
            "report_metadata": {
                "type": self.report_type,
                "generated_at": self.timestamp.isoformat(),
                "generator": "ACPG Report Generator",
                "version": "1.0"
            },
            "artifact": {
                "hash": code_hash,
                "language": self.language,
                "lines_of_code": len(self.code.split('\n')),
                "size_bytes": len(self.code.encode())
            },
            "summary": self._generate_summary(),
            "compliance_status": {
                "compliant": self.adjudication.compliant,
                "status": "PASS" if self.adjudication.compliant else "FAIL",
                "total_violations": len(self.analysis.violations),
                "policies_checked": len(self.adjudication.satisfied_rules) + len(self.adjudication.unsatisfied_rules),
                "policies_satisfied": len(self.adjudication.satisfied_rules),
                "policies_violated": len(self.adjudication.unsatisfied_rules)
            },
            "violations": self._format_violations(),
            "policy_results": self._format_policy_results(),
            "recommendations": self._generate_recommendations(),
            "executive_summary": self._generate_executive_summary(),
            "signature": None  # Will be added if signed
        }
        
        return report
    
    def generate_signed(self) -> Dict[str, Any]:
        """Generate a signed compliance report."""
        report = self.generate()
        
        # Create signature over report content
        report_content = {
            "artifact": report["artifact"],
            "compliance_status": report["compliance_status"],
            "violations": report["violations"],
            "timestamp": report["report_metadata"]["generated_at"]
        }
        
        signature = self.signer.sign_proof(report_content)
        
        report["signature"] = {
            "value": signature,
            "algorithm": settings.SIGNATURE_ALGORITHM,
            "signer": settings.SIGNER_NAME,
            "public_key_fingerprint": self.signer.get_public_key_fingerprint()
        }
        
        return report
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate a summary of findings."""
        violations = self.analysis.violations
        
        # Group by severity
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in violations:
            if v.severity in by_severity:
                by_severity[v.severity] += 1
        
        # Group by category
        by_category = {}
        for v in violations:
            category = v.rule_id.split('-')[0]
            by_category[category] = by_category.get(category, 0) + 1
        
        # Group by detector
        by_detector = {}
        for v in violations:
            by_detector[v.detector] = by_detector.get(v.detector, 0) + 1
        
        return {
            "total_violations": len(violations),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_detector": by_detector,
            "critical_count": by_severity["critical"],
            "high_count": by_severity["high"],
            "risk_score": self._calculate_risk_score(violations)
        }
    
    def _calculate_risk_score(self, violations: List[Violation]) -> int:
        """Calculate a risk score from 0-100."""
        if not violations:
            return 0
        
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        total_score = sum(weights.get(v.severity, 5) for v in violations)
        
        # Cap at 100
        return min(100, total_score)
    
    def _format_violations(self) -> List[Dict[str, Any]]:
        """Format violations with full details and recommendations."""
        formatted = []
        
        for v in self.analysis.violations:
            policy = self.policy_compiler.get_policy(v.rule_id)
            
            violation_entry = {
                "id": v.rule_id,
                "severity": v.severity,
                "description": v.description,
                "location": {
                    "line": v.line,
                    "evidence": v.evidence
                },
                "detector": v.detector,
                "policy_type": policy.type if policy else "unknown",
                "fix_suggestion": policy.fix_suggestion if policy else None,
                "reference": self._get_reference_url(v.rule_id)
            }
            
            formatted.append(violation_entry)
        
        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        formatted.sort(key=lambda x: severity_order.get(x["severity"], 4))
        
        return formatted
    
    def _format_policy_results(self) -> Dict[str, List[Dict[str, Any]]]:
        """Format policy check results."""
        satisfied = []
        violated = []
        
        for rule_id in self.adjudication.satisfied_rules:
            policy = self.policy_compiler.get_policy(rule_id)
            satisfied.append({
                "id": rule_id,
                "description": policy.description if policy else rule_id,
                "type": policy.type if policy else "unknown",
                "severity": policy.severity if policy else "unknown"
            })
        
        for rule_id in self.adjudication.unsatisfied_rules:
            policy = self.policy_compiler.get_policy(rule_id)
            violated.append({
                "id": rule_id,
                "description": policy.description if policy else rule_id,
                "type": policy.type if policy else "unknown",
                "severity": policy.severity if policy else "unknown",
                "fix_suggestion": policy.fix_suggestion if policy else None
            })
        
        return {
            "satisfied": satisfied,
            "violated": violated
        }
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations for fixing violations."""
        recommendations = []
        seen_rules = set()
        
        # Group violations by rule
        violations_by_rule = {}
        for v in self.analysis.violations:
            if v.rule_id not in violations_by_rule:
                violations_by_rule[v.rule_id] = []
            violations_by_rule[v.rule_id].append(v)
        
        # Generate recommendations for each rule
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        
        for rule_id, violations in sorted(
            violations_by_rule.items(),
            key=lambda x: severity_order.get(x[1][0].severity, 4)
        ):
            if rule_id in seen_rules:
                continue
            seen_rules.add(rule_id)
            
            policy = self.policy_compiler.get_policy(rule_id)
            v = violations[0]
            
            recommendation = {
                "priority": len(recommendations) + 1,
                "rule_id": rule_id,
                "severity": v.severity,
                "title": f"Fix {rule_id}: {v.description}",
                "description": policy.description if policy else v.description,
                "occurrences": len(violations),
                "affected_lines": [viol.line for viol in violations if viol.line],
                "action": policy.fix_suggestion if policy else "Review and fix the identified issue",
                "effort": self._estimate_effort(violations),
                "impact": self._estimate_impact(v.severity)
            }
            
            recommendations.append(recommendation)
        
        return recommendations
    
    def _estimate_effort(self, violations: List[Violation]) -> str:
        """Estimate the effort to fix violations."""
        count = len(violations)
        if count <= 2:
            return "Low (< 30 minutes)"
        elif count <= 5:
            return "Medium (30 min - 2 hours)"
        else:
            return "High (> 2 hours)"
    
    def _estimate_impact(self, severity: str) -> str:
        """Estimate the security impact."""
        impacts = {
            "critical": "Critical - Immediate security risk, potential for data breach or system compromise",
            "high": "High - Significant security vulnerability that should be addressed urgently",
            "medium": "Medium - Security weakness that should be addressed in the near term",
            "low": "Low - Minor security improvement recommended"
        }
        return impacts.get(severity, "Unknown impact")
    
    def _get_reference_url(self, rule_id: str) -> Optional[str]:
        """Get reference URL for the rule."""
        prefix = rule_id.split('-')[0]
        
        references = {
            "SEC": "https://owasp.org/www-project-secure-coding-practices/",
            "SQL": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "CRYPTO": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
            "OWASP": "https://owasp.org/www-project-top-ten/",
            "NIST": "https://csrc.nist.gov/publications/detail/sp/800-218/final",
            "INPUT": "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
            "ERR": "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
        }
        
        return references.get(prefix)
    
    def _generate_executive_summary(self) -> str:
        """Generate an executive summary of the report."""
        violations = self.analysis.violations
        
        if self.adjudication.compliant:
            return (
                f"The analyzed code artifact is COMPLIANT with all {len(self.adjudication.satisfied_rules)} "
                f"security policies. No violations were detected. The code meets the required security standards "
                f"and is approved for deployment."
            )
        
        critical = sum(1 for v in violations if v.severity == "critical")
        high = sum(1 for v in violations if v.severity == "high")
        
        summary_parts = [
            f"The analyzed code artifact is NON-COMPLIANT. "
            f"A total of {len(violations)} violation(s) were detected across "
            f"{len(self.adjudication.unsatisfied_rules)} policy rule(s)."
        ]
        
        if critical > 0:
            summary_parts.append(
                f" ⚠️ CRITICAL: {critical} critical severity issue(s) require immediate attention."
            )
        
        if high > 0:
            summary_parts.append(
                f" {high} high severity issue(s) should be addressed urgently."
            )
        
        summary_parts.append(
            " Please review the detailed findings and recommendations below, "
            "and address all violations before proceeding with deployment."
        )
        
        return "".join(summary_parts)
    
    def to_markdown(self) -> str:
        """Export report as Markdown."""
        report = self.generate()
        
        lines = [
            "# Compliance Analysis Report",
            "",
            f"**Generated:** {report['report_metadata']['generated_at']}",
            f"**Status:** {'✅ COMPLIANT' if report['compliance_status']['compliant'] else '❌ NON-COMPLIANT'}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            report['executive_summary'],
            "",
            "---",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Violations | {report['summary']['total_violations']} |",
            f"| Critical | {report['summary']['critical_count']} |",
            f"| High | {report['summary']['high_count']} |",
            f"| Risk Score | {report['summary']['risk_score']}/100 |",
            "",
        ]
        
        if report['violations']:
            lines.extend([
                "---",
                "",
                "## Violations",
                "",
            ])
            
            for v in report['violations']:
                lines.extend([
                    f"### [{v['severity'].upper()}] {v['id']}: {v['description']}",
                    "",
                    f"- **Line:** {v['location']['line']}",
                    f"- **Evidence:** `{v['location']['evidence']}`" if v['location']['evidence'] else "",
                    f"- **Detector:** {v['detector']}",
                    "",
                    f"**Recommendation:** {v['fix_suggestion']}" if v['fix_suggestion'] else "",
                    "",
                ])
        
        if report['recommendations']:
            lines.extend([
                "---",
                "",
                "## Recommendations",
                "",
            ])
            
            for rec in report['recommendations']:
                lines.extend([
                    f"### {rec['priority']}. {rec['title']}",
                    "",
                    f"- **Severity:** {rec['severity']}",
                    f"- **Occurrences:** {rec['occurrences']}",
                    f"- **Effort:** {rec['effort']}",
                    f"- **Impact:** {rec['impact']}",
                    "",
                    f"**Action:** {rec['action']}",
                    "",
                ])
        
        lines.extend([
            "---",
            "",
            "## Policy Results",
            "",
            f"**Satisfied:** {len(report['policy_results']['satisfied'])} policies",
            "",
        ])
        
        for p in report['policy_results']['satisfied']:
            lines.append(f"- ✅ {p['id']}: {p['description']}")
        
        if report['policy_results']['violated']:
            lines.extend([
                "",
                f"**Violated:** {len(report['policy_results']['violated'])} policies",
                "",
            ])
            
            for p in report['policy_results']['violated']:
                lines.append(f"- ❌ {p['id']}: {p['description']}")
        
        lines.extend([
            "",
            "---",
            "",
            f"*Report generated by ACPG - Agentic Compliance and Policy Governor*",
            f"*Artifact Hash: {report['artifact']['hash'][:16]}...*",
        ])
        
        return "\n".join(lines)
    
    def to_html(self) -> str:
        """Export report as HTML."""
        report = self.generate()
        status_class = "compliant" if report['compliance_status']['compliant'] else "non-compliant"
        status_text = "COMPLIANT" if report['compliance_status']['compliant'] else "NON-COMPLIANT"
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Report - ACPG</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
            --accent-blue: #3b82f6;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 40px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}
        h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}
        h2 {{
            font-size: 1.5rem;
            margin-top: 2rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #334155;
        }}
        .status {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: bold;
            margin: 1rem 0;
        }}
        .status.compliant {{
            background: rgba(16, 185, 129, 0.2);
            color: var(--accent-green);
        }}
        .status.non-compliant {{
            background: rgba(239, 68, 68, 0.2);
            color: var(--accent-red);
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin: 1.5rem 0;
        }}
        .summary-card {{
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }}
        .summary-card .value {{
            font-size: 2rem;
            font-weight: bold;
        }}
        .summary-card .label {{
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
        .violation {{
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
            border-left: 4px solid var(--accent-red);
        }}
        .violation.critical {{ border-left-color: #dc2626; }}
        .violation.high {{ border-left-color: #f97316; }}
        .violation.medium {{ border-left-color: #eab308; }}
        .violation.low {{ border-left-color: #6b7280; }}
        .violation-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.5rem;
        }}
        .severity-badge {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{ background: #dc2626; }}
        .severity-badge.high {{ background: #f97316; }}
        .severity-badge.medium {{ background: #eab308; color: #000; }}
        .severity-badge.low {{ background: #6b7280; }}
        .code {{
            background: #0f172a;
            padding: 0.5rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.875rem;
            margin: 0.5rem 0;
        }}
        .recommendation {{
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }}
        .recommendation-number {{
            display: inline-block;
            width: 24px;
            height: 24px;
            background: var(--accent-blue);
            border-radius: 50%;
            text-align: center;
            line-height: 24px;
            font-weight: bold;
            margin-right: 0.5rem;
        }}
        .executive-summary {{
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 8px;
            margin: 1rem 0;
        }}
        .footer {{
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid #334155;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Compliance Analysis Report</h1>
        <p>Generated: {report['report_metadata']['generated_at']}</p>
        
        <div class="status {status_class}">{status_text}</div>
        
        <div class="executive-summary">
            <h3>Executive Summary</h3>
            <p>{report['executive_summary']}</p>
        </div>
        
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="value">{report['summary']['total_violations']}</div>
                <div class="label">Total Violations</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: #dc2626;">{report['summary']['critical_count']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: #f97316;">{report['summary']['high_count']}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card">
                <div class="value">{report['summary']['risk_score']}/100</div>
                <div class="label">Risk Score</div>
            </div>
        </div>
"""
        
        if report['violations']:
            html += """
        <h2>Violations</h2>
"""
            for v in report['violations']:
                html += f"""
        <div class="violation {v['severity']}">
            <div class="violation-header">
                <strong>{v['id']}: {v['description']}</strong>
                <span class="severity-badge {v['severity']}">{v['severity']}</span>
            </div>
            <p>Line: {v['location']['line']}</p>
            <div class="code">{v['location']['evidence'] or 'N/A'}</div>
            {f"<p><strong>Recommendation:</strong> {v['fix_suggestion']}</p>" if v['fix_suggestion'] else ""}
        </div>
"""
        
        if report['recommendations']:
            html += """
        <h2>Recommendations</h2>
"""
            for rec in report['recommendations']:
                html += f"""
        <div class="recommendation">
            <span class="recommendation-number">{rec['priority']}</span>
            <strong>{rec['title']}</strong>
            <p><strong>Severity:</strong> {rec['severity']} | <strong>Occurrences:</strong> {rec['occurrences']} | <strong>Effort:</strong> {rec['effort']}</p>
            <p><strong>Action:</strong> {rec['action']}</p>
        </div>
"""
        
        html += f"""
        <div class="footer">
            <p>Report generated by ACPG - Agentic Compliance and Policy Governor</p>
            <p>Artifact Hash: {report['artifact']['hash'][:16]}...</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html


def generate_compliance_report(
    code: str,
    language: str,
    analysis: AnalysisResult,
    adjudication: AdjudicationResult,
    format: str = "json",
    signed: bool = False
) -> Any:
    """
    Generate a compliance report in the specified format.
    
    Args:
        code: The analyzed code
        language: Programming language
        analysis: Analysis results from prosecutor
        adjudication: Adjudication results
        format: Output format (json, markdown, html)
        signed: Whether to cryptographically sign the report
    
    Returns:
        Report in the requested format
    """
    report_type = "compliance" if adjudication.compliant else "failure"
    report = ComplianceReport(code, language, analysis, adjudication, report_type)
    
    if format == "markdown":
        return report.to_markdown()
    elif format == "html":
        return report.to_html()
    else:
        if signed:
            return report.generate_signed()
        return report.generate()

