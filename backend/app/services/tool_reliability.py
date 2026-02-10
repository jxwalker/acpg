"""Tool reliability checker for creating exception arguments."""
from typing import Optional
from dataclasses import dataclass

from ..models.schemas import Violation


@dataclass
class ReliabilityException:
    """Exception based on tool reliability concerns."""
    reason: str  # Why the tool finding is unreliable
    confidence: str  # "low", "medium", "high" - how confident we are this is a false positive
    details: str  # Detailed explanation


class ToolReliabilityChecker:
    """Checks tool findings for reliability issues."""
    
    # Known false positive patterns
    FALSE_POSITIVE_PATTERNS = {
        "bandit": {
            "B105": [  # Hardcoded password
                "test", "example", "demo", "sample", "placeholder"
            ],
            "B608": [  # SQL injection
                "SELECT.*FROM.*WHERE.*%s",  # Parameterized queries
                "SELECT.*FROM.*WHERE.*\\?",  # Parameterized queries
            ]
        },
        "eslint": {
            "no-eval": [
                "JSON\\.parse",  # JSON.parse is safe
                "Function\\(.*'return'",  # Some safe Function uses
            ]
        }
    }
    
    # Tool versions with known issues
    KNOWN_ISSUES = {
        "bandit": {
            "1.7.0": ["B608 false positives on f-strings"],
            "1.6.0": ["B105 false positives on test files"]
        }
    }
    
    # Low confidence thresholds
    LOW_CONFIDENCE_THRESHOLD = "medium"  # Findings below this are questionable
    
    def check_reliability(
        self,
        violation: Violation,
        tool_name: Optional[str] = None,
        tool_version: Optional[str] = None,
        confidence: Optional[str] = None
    ) -> Optional[ReliabilityException]:
        """
        Check if a violation from a tool should be considered unreliable.
        
        Args:
            violation: The violation to check
            tool_name: Name of the tool that found it
            tool_version: Version of the tool
            confidence: Confidence level from the tool
            
        Returns:
            ReliabilityException if finding is unreliable, None otherwise
        """
        if not tool_name or tool_name in ("regex", "ast"):
            # Only check static analysis tools, not built-in checks
            return None
        
        # Check 1: Low confidence findings
        if confidence and confidence.lower() == "low":
            return ReliabilityException(
                reason="low_confidence",
                confidence="high",
                details=f"Tool {tool_name} reported low confidence for this finding. "
                       f"Rule {violation.rule_id} may be a false positive."
            )
        
        # Check 2: Known false positive patterns
        tool_patterns = self.FALSE_POSITIVE_PATTERNS.get(tool_name, {})
        rule_patterns = tool_patterns.get(violation.rule_id, [])
        
        if violation.evidence:
            evidence_lower = violation.evidence.lower()
            for pattern in rule_patterns:
                import re
                if re.search(pattern, evidence_lower, re.IGNORECASE):
                    return ReliabilityException(
                        reason="false_positive_pattern",
                        confidence="medium",
                        details=f"Finding matches known false positive pattern for {tool_name} "
                               f"rule {violation.rule_id}. Evidence: {violation.evidence[:50]}"
                    )
        
        # Check 3: Tool version known issues
        if tool_version:
            version_issues = self.KNOWN_ISSUES.get(tool_name, {}).get(tool_version, [])
            if version_issues:
                return ReliabilityException(
                    reason="tool_version_issue",
                    confidence="medium",
                    details=f"Tool {tool_name} version {tool_version} has known issues: "
                           f"{', '.join(version_issues)}. This finding may be unreliable."
                )
        
        # Check 4: Test/demo file patterns
        if violation.evidence:
            test_indicators = ["test", "example", "demo", "sample", "mock", "fake"]
            evidence_lower = violation.evidence.lower()
            if any(indicator in evidence_lower for indicator in test_indicators):
                # Lower confidence for test-like code
                if confidence and confidence.lower() in ("low", "medium"):
                    return ReliabilityException(
                        reason="test_code_pattern",
                        confidence="low",
                        details="Finding in code that appears to be test/demo code. "
                               "May be acceptable in non-production context."
                    )
        
        return None


# Global instance
_reliability_checker: Optional[ToolReliabilityChecker] = None


def get_reliability_checker() -> ToolReliabilityChecker:
    """Get the global tool reliability checker instance."""
    global _reliability_checker
    if _reliability_checker is None:
        _reliability_checker = ToolReliabilityChecker()
    return _reliability_checker

