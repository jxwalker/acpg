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
from .language_detector import get_language_detector
from .tool_executor import get_tool_executor
from .tool_mapper import get_tool_mapper
from .parsers import BanditParser, ESLintParser, SarifParser


class Prosecutor:
    """
    The Prosecutor agent finds policy violations in code artifacts.
    
    Uses multiple detection strategies:
    1. Static analysis tools (Bandit, ESLint, etc.) - Configurable
    2. Regex pattern matching - From policy definitions
    3. AST analysis - For semantic checks
    4. Dynamic testing - Hypothesis fuzzing (optional)
    """
    
    def __init__(self):
        self.policy_compiler = get_policy_compiler()
        self.language_detector = get_language_detector()
        self.tool_executor = get_tool_executor()
        self.tool_mapper = get_tool_mapper()
        
        # Parser registry
        self.parsers = {
            "bandit": BanditParser(),
            "eslint": ESLintParser(),
            "sarif": SarifParser()
        }
    
    def analyze(self, code: str, language: Optional[str] = None, 
                policy_ids: Optional[List[str]] = None) -> AnalysisResult:
        """
        Run full analysis on code artifact.
        
        Args:
            code: Source code to analyze
            language: Programming language (auto-detected if None)
            policy_ids: Optional list of policies to check (None = all)
            
        Returns:
            AnalysisResult with all violations found
        """
        import hashlib
        artifact_id = hashlib.sha256(code.encode()).hexdigest()[:16]
        
        # Auto-detect language if not provided
        if language is None:
            language = self.language_detector.detect_from_content(code) or "python"
        
        all_violations = []
        tool_execution_info = {}
        
        # Run static analysis tools if enabled
        if settings.ENABLE_STATIC_ANALYSIS:
            tool_violations, tool_execution_info = self.run_static_analysis_tools(code, language)
            all_violations.extend(tool_violations)
        
        # Run policy regex/AST checks
        policy_violations = self.run_policy_checks(code, language, policy_ids)
        all_violations.extend(policy_violations)
        
        # Deduplicate violations (same rule + same line + same detector)
        seen = set()
        unique_violations = []
        for v in all_violations:
            key = (v.rule_id, v.line, v.detector)
            if key not in seen:
                seen.add(key)
                unique_violations.append(v)
        
        return AnalysisResult(
            artifact_id=artifact_id,
            violations=unique_violations,
            tool_execution=tool_execution_info if tool_execution_info else None
        )
    
    def run_static_analysis_tools(self, code: str, language: str) -> tuple[List[Violation], Dict[str, Any]]:
        """
        Run all enabled static analysis tools for the given language.
        
        Args:
            code: Source code to analyze
            language: Programming language
            
        Returns:
            Tuple of (violations, tool_execution_info)
        """
        from ..models.schemas import ToolExecutionInfo
        
        violations = []
        tool_execution_info = {}
        
        # Execute all enabled tools for this language
        execution_results = self.tool_executor.execute_tools_for_language(
            language=language,
            content=code
        )
        
        for result in execution_results:
            tool_name = result.tool_name
            findings_count = 0
            mapped_count = 0
            unmapped_count = 0
            raw_findings = []
            
            if not result.success:
                # Tool failed - provide helpful error message
                error_msg = result.error or "Tool execution failed"
                
                # Enhance error messages for common issues
                if "No such file or directory" in error_msg or "not found" in error_msg.lower():
                    error_msg = f"Tool '{tool_name}' is not installed. Install it with: pip install {tool_name}"
                elif "timeout" in error_msg.lower():
                    error_msg = f"Tool '{tool_name}' execution timed out. The code may be too large or the tool is slow."
                elif "ModuleNotFoundError" in error_msg or "ImportError" in error_msg:
                    error_msg = f"Tool '{tool_name}' has missing dependencies. Check tool installation."
                
                tool_execution_info[tool_name] = ToolExecutionInfo(
                    tool_name=tool_name,
                    success=False,
                    error=error_msg,
                    execution_time=result.execution_time
                )
                logger.warning(f"Tool {tool_name} failed: {error_msg}")
                continue
            
            if not result.output:
                # Tool succeeded but no output
                tool_execution_info[tool_name] = ToolExecutionInfo(
                    tool_name=tool_name,
                    success=True,
                    findings_count=0,
                    execution_time=result.execution_time
                )
                continue
            
            # Get parser for this tool
            parser = self.parsers.get(tool_name)
            if not parser:
                # Try to determine parser from tool name
                if "bandit" in tool_name.lower():
                    parser = self.parsers["bandit"]
                elif "eslint" in tool_name.lower():
                    parser = self.parsers["eslint"]
                else:
                    # No parser available
                    tool_execution_info[tool_name] = ToolExecutionInfo(
                        tool_name=tool_name,
                        success=True,
                        error=f"No parser available for {tool_name}",
                        execution_time=result.execution_time
                    )
                    continue
            
            # Parse tool output
            try:
                findings = parser.parse(result.output)
                findings_count = len(findings)
            except Exception as e:
                # Log parsing error but continue
                import logging
                logging.warning(f"Error parsing {tool_name} output: {e}")
                tool_execution_info[tool_name] = ToolExecutionInfo(
                    tool_name=tool_name,
                    success=True,
                    error=f"Parsing error: {str(e)}",
                    execution_time=result.execution_time
                )
                continue
            
            # Map findings to violations
            for finding in findings:
                mapping = self.tool_mapper.map_finding_to_policy(tool_name, finding)
                
                is_mapped = mapping is not None
                
                raw_findings.append({
                    "rule_id": finding.tool_rule_id,
                    "line": finding.line_number,
                    "message": finding.message,
                    "severity": finding.severity,
                    "mapped": is_mapped,
                    "policy_id": mapping[0] if mapping else None
                })
                
                if mapping:
                    mapped_count += 1
                    policy_id, metadata = mapping
                    
                    # Create violation
                    violation = Violation(
                        rule_id=policy_id,
                        description=metadata.get("description", finding.message),
                        line=finding.line_number,
                        evidence=finding.message,
                        detector=tool_name,
                        severity=metadata.get("severity", finding.severity)
                    )
                    violations.append(violation)
                else:
                    unmapped_count += 1
            
            # Store execution info for this tool
            tool_execution_info[tool_name] = ToolExecutionInfo(
                tool_name=tool_name,
                success=True,
                findings_count=findings_count,
                mapped_findings=mapped_count,
                unmapped_findings=unmapped_count,
                execution_time=result.execution_time,
                tool_version=getattr(result, 'tool_version', None),  # Extract tool version
                findings=raw_findings if findings_count > 0 else None  # Include all findings for visibility
            )
        
        return violations, tool_execution_info
    
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

