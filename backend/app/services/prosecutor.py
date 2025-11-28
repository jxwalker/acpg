"""Prosecutor Service - Static and dynamic analysis to find policy violations."""
import subprocess
import json
import tempfile
import os
import re
from typing import List, Optional, Dict, Any
from pathlib import Path

from ..models.schemas import Violation, AnalysisResult, PolicyRule
from ..core.config import settings
from .policy_compiler import get_policy_compiler


class Prosecutor:
    """
    The Prosecutor agent finds policy violations in code artifacts.
    
    Uses multiple detection strategies:
    1. Bandit - Python security scanner
    2. Regex pattern matching - From policy definitions
    3. AST analysis - For semantic checks
    4. Dynamic testing - Hypothesis fuzzing (optional)
    """
    
    # Mapping of Bandit test IDs to our policy IDs
    BANDIT_POLICY_MAP = {
        'B105': 'SEC-001',  # hardcoded_password_string
        'B106': 'SEC-001',  # hardcoded_password_funcarg
        'B107': 'SEC-001',  # hardcoded_password_default
        'B108': 'SEC-001',  # hardcoded_tmp_directory (related)
        'B301': 'SEC-003',  # pickle
        'B302': 'SEC-003',  # marshal
        'B303': 'CRYPTO-001',  # md5, sha1
        'B304': 'CRYPTO-001',  # insecure ciphers
        'B305': 'CRYPTO-001',  # insecure cipher modes
        'B306': 'SEC-003',  # mktemp
        'B307': 'SEC-003',  # eval
        'B308': 'SEC-003',  # mark_safe
        'B310': 'SEC-004',  # urllib_urlopen (http)
        'B311': 'CRYPTO-001',  # random
        'B312': 'SEC-004',  # telnetlib
        'B501': 'SEC-004',  # request_with_no_cert_validation
        'B502': 'SEC-004',  # ssl_with_bad_version
        'B503': 'SEC-004',  # ssl_with_bad_defaults
        'B504': 'SEC-004',  # ssl_with_no_version
        'B506': 'SEC-003',  # yaml_load
        'B608': 'SQL-001',  # sql_injection (hardcoded)
        'B609': 'SQL-001',  # linux_commands_wildcard_injection
        'B610': 'SEC-003',  # django_extra_used
        'B611': 'SEC-003',  # django_rawsql_used
    }
    
    def __init__(self):
        self.policy_compiler = get_policy_compiler()
    
    def analyze(self, code: str, language: str = "python", 
                policy_ids: Optional[List[str]] = None) -> AnalysisResult:
        """
        Run full analysis on code artifact.
        
        Args:
            code: Source code to analyze
            language: Programming language
            policy_ids: Optional list of policies to check (None = all)
            
        Returns:
            AnalysisResult with all violations found
        """
        import hashlib
        artifact_id = hashlib.sha256(code.encode()).hexdigest()[:16]
        
        all_violations = []
        
        # Run Bandit for Python code
        if language.lower() == 'python':
            bandit_violations = self.run_bandit(code)
            all_violations.extend(bandit_violations)
        
        # Run policy regex/AST checks
        policy_violations = self.run_policy_checks(code, language, policy_ids)
        all_violations.extend(policy_violations)
        
        # Deduplicate violations (same rule + same line)
        seen = set()
        unique_violations = []
        for v in all_violations:
            key = (v.rule_id, v.line)
            if key not in seen:
                seen.add(key)
                unique_violations.append(v)
        
        return AnalysisResult(
            artifact_id=artifact_id,
            violations=unique_violations
        )
    
    def run_bandit(self, code: str) -> List[Violation]:
        """
        Run Bandit security scanner on Python code.
        
        Args:
            code: Python source code
            
        Returns:
            List of violations detected by Bandit
        """
        violations = []
        
        # Write code to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name
        
        try:
            # Run Bandit with JSON output
            result = subprocess.run(
                ['bandit', '-f', 'json', '-q', temp_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse Bandit output
            if result.stdout:
                try:
                    bandit_output = json.loads(result.stdout)
                    for issue in bandit_output.get('results', []):
                        # Map Bandit test ID to our policy ID
                        test_id = issue.get('test_id', '')
                        policy_id = self.BANDIT_POLICY_MAP.get(test_id, f'BANDIT-{test_id}')
                        
                        # Get severity from Bandit or policy
                        bandit_severity = issue.get('issue_severity', 'MEDIUM').lower()
                        
                        violations.append(Violation(
                            rule_id=policy_id,
                            description=issue.get('issue_text', 'Security issue detected'),
                            line=issue.get('line_number'),
                            evidence=issue.get('code', '').strip(),
                            detector='bandit',
                            severity=bandit_severity
                        ))
                except json.JSONDecodeError:
                    pass  # Bandit didn't produce valid JSON
                    
        except subprocess.TimeoutExpired:
            pass  # Bandit timed out
        except FileNotFoundError:
            # Bandit not installed - skip
            pass
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_path)
            except:
                pass
        
        return violations
    
    def run_policy_checks(self, code: str, language: str = "python",
                          policy_ids: Optional[List[str]] = None) -> List[Violation]:
        """
        Run policy-defined checks (regex and AST).
        
        Args:
            code: Source code to analyze
            language: Programming language
            policy_ids: Optional list of policies to check
            
        Returns:
            List of violations from policy checks
        """
        return self.policy_compiler.run_all_checks(code, language, policy_ids)
    
    def run_hypothesis_tests(self, code: str, function_name: str) -> List[Violation]:
        """
        Run Hypothesis property-based tests (optional dynamic testing).
        
        This is a placeholder for future implementation of fuzzing/property testing.
        """
        if not settings.ENABLE_DYNAMIC_TESTING:
            return []
        
        # TODO: Implement Hypothesis-based dynamic testing
        # This would:
        # 1. Parse the code to find function signatures
        # 2. Generate Hypothesis strategies for input types
        # 3. Run property tests to find counterexamples
        # 4. Report any failures as violations
        
        return []
    
    def synthesize_counterexamples(self, code: str, 
                                    violations: List[Violation]) -> Dict[str, Any]:
        """
        Generate concrete counterexamples for violations.
        
        This provides evidence that can be used in the argumentation framework.
        """
        counterexamples = {}
        
        for violation in violations:
            if violation.evidence:
                counterexamples[violation.rule_id] = {
                    'type': 'code_snippet',
                    'line': violation.line,
                    'evidence': violation.evidence,
                    'explanation': f"Line {violation.line} contains: {violation.evidence}"
                }
        
        return counterexamples
    
    def get_violation_summary(self, violations: List[Violation]) -> Dict[str, Any]:
        """
        Generate a summary of violations for reporting.
        """
        summary = {
            'total': len(violations),
            'by_severity': {},
            'by_rule': {},
            'by_detector': {}
        }
        
        for v in violations:
            # Count by severity
            summary['by_severity'][v.severity] = summary['by_severity'].get(v.severity, 0) + 1
            
            # Count by rule
            summary['by_rule'][v.rule_id] = summary['by_rule'].get(v.rule_id, 0) + 1
            
            # Count by detector
            summary['by_detector'][v.detector] = summary['by_detector'].get(v.detector, 0) + 1
        
        return summary


# Global prosecutor instance
_prosecutor: Optional[Prosecutor] = None


def get_prosecutor() -> Prosecutor:
    """Get or create the global prosecutor instance."""
    global _prosecutor
    if _prosecutor is None:
        _prosecutor = Prosecutor()
    return _prosecutor

