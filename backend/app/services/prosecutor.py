"""Prosecutor Service - Static and dynamic analysis to find policy violations."""
import logging
from typing import List, Optional, Dict, Any

from ..models.schemas import Violation, AnalysisResult
from ..core.config import settings
from .policy_compiler import get_policy_compiler
from .language_detector import get_language_detector
from .tool_executor import get_tool_executor
from .tool_mapper import get_tool_mapper
from .dynamic_analyzer import get_dynamic_analyzer
from .parsers import BanditParser, ESLintParser, SarifParser

logger = logging.getLogger(__name__)


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
        self.dynamic_analyzer = get_dynamic_analyzer()
        
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
        import time
        artifact_id = hashlib.sha256(code.encode()).hexdigest()[:16]
        started_at = time.perf_counter()
        
        # Auto-detect language if not provided
        if language is None:
            language = self.language_detector.detect_from_content(code) or "python"
        
        all_violations = []
        tool_execution_info = {}
        dynamic_analysis_result = None
        static_tools_seconds = 0.0
        policy_checks_seconds = 0.0
        dynamic_analysis_seconds = 0.0
        dedupe_seconds = 0.0
        
        # Run static analysis tools if enabled
        if settings.ENABLE_STATIC_ANALYSIS:
            tool_started = time.perf_counter()
            tool_violations, tool_execution_info = self.run_static_analysis_tools(code, language)
            static_tools_seconds = time.perf_counter() - tool_started
            all_violations.extend(tool_violations)
        
        # Run policy regex/AST checks
        policy_started = time.perf_counter()
        policy_violations = self.run_policy_checks(code, language, policy_ids)
        policy_checks_seconds = time.perf_counter() - policy_started
        all_violations.extend(policy_violations)

        # Run sandboxed dynamic analysis (optional, Python only)
        dynamic_started = time.perf_counter()
        dynamic_analysis_result = self.run_dynamic_analysis(code, language, artifact_id)
        dynamic_analysis_seconds = time.perf_counter() - dynamic_started
        if dynamic_analysis_result and dynamic_analysis_result.violations:
            all_violations.extend(dynamic_analysis_result.violations)
        
        # Deduplicate violations (same rule + same line + same detector)
        dedupe_started = time.perf_counter()
        seen = set()
        unique_violations = []
        for v in all_violations:
            key = (v.rule_id, v.line, v.detector)
            if key not in seen:
                seen.add(key)
                unique_violations.append(v)
        dedupe_seconds = time.perf_counter() - dedupe_started
        total_seconds = time.perf_counter() - started_at
        
        return AnalysisResult(
            artifact_id=artifact_id,
            violations=unique_violations,
            tool_execution=tool_execution_info if tool_execution_info else None,
            dynamic_analysis=dynamic_analysis_result,
            performance={
                "total_seconds": round(total_seconds, 6),
                "static_tools_seconds": round(static_tools_seconds, 6),
                "policy_checks_seconds": round(policy_checks_seconds, 6),
                "dynamic_analysis_seconds": round(dynamic_analysis_seconds, 6),
                "dedupe_seconds": round(dedupe_seconds, 6),
                "tool_count": len(tool_execution_info),
            },
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
            policy_decision = result.policy_decision
            
            if not result.success:
                if policy_decision and not policy_decision.get("allowed", True):
                    violations.append(Violation(
                        rule_id=policy_decision.get("rule_id") or "RUNTIME-GUARD",
                        description=policy_decision.get("message") or "Runtime policy violation",
                        line=None,
                        evidence=policy_decision.get("evidence"),
                        detector="runtime_guard",
                        severity=policy_decision.get("severity") or "high",
                    ))
                    tool_execution_info[tool_name] = ToolExecutionInfo(
                        tool_name=tool_name,
                        success=False,
                        error=policy_decision.get("message") or result.error,
                        execution_time=result.execution_time,
                        tool_version=result.tool_version,
                        policy_decision=policy_decision,
                    )
                    continue

                # Tool failed - provide helpful error message
                error_msg = result.error or "Tool execution failed"
                
                # Categorize and enhance error messages for common issues
                error_category = "unknown"
                enhanced_msg = error_msg
                
                if "No such file or directory" in error_msg or "not found" in error_msg.lower() or "command not found" in error_msg.lower():
                    error_category = "not_installed"
                    enhanced_msg = f"Tool '{tool_name}' is not installed. Install it with: pip install {tool_name}"
                elif "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
                    error_category = "timeout"
                    enhanced_msg = f"Tool '{tool_name}' execution timed out. The code may be too large or the tool is slow. Consider increasing timeout or analyzing smaller code chunks."
                elif "ModuleNotFoundError" in error_msg or "ImportError" in error_msg:
                    error_category = "missing_dependencies"
                    enhanced_msg = f"Tool '{tool_name}' has missing dependencies. Check tool installation: pip install {tool_name}[all]"
                elif "permission denied" in error_msg.lower() or "permission" in error_msg.lower():
                    error_category = "permission"
                    enhanced_msg = f"Tool '{tool_name}' permission denied. Check file permissions and tool installation."
                elif "syntax error" in error_msg.lower() or "parse error" in error_msg.lower():
                    error_category = "syntax_error"
                    enhanced_msg = f"Tool '{tool_name}' encountered a syntax error in the code. This may indicate invalid code being analyzed."
                elif "connection" in error_msg.lower() or "network" in error_msg.lower():
                    error_category = "network"
                    enhanced_msg = f"Tool '{tool_name}' network error. Check your internet connection and tool configuration."
                elif "retry" in error_msg.lower() or "transient" in error_msg.lower():
                    error_category = "transient"
                    enhanced_msg = f"Tool '{tool_name}' failed with a transient error. The system will retry automatically."

                # Optional tools should not fail the overall tool execution status.
                if error_category == "not_installed" and tool_name in {"safety", "pylint"}:
                    tool_execution_info[tool_name] = ToolExecutionInfo(
                        tool_name=tool_name,
                        success=True,
                        findings_count=0,
                        mapped_findings=0,
                        unmapped_findings=0,
                        error=f"Skipped optional tool: {enhanced_msg}",
                        execution_time=result.execution_time,
                        tool_version=result.tool_version,
                        policy_decision=policy_decision,
                    )
                    logger.info(f"Optional tool {tool_name} not installed; skipping.")
                    continue
                
                tool_execution_info[tool_name] = ToolExecutionInfo(
                    tool_name=tool_name,
                    success=False,
                    error=enhanced_msg,
                    execution_time=result.execution_time,
                    tool_version=result.tool_version,
                    policy_decision=policy_decision,
                )
                logger.warning(f"Tool {tool_name} failed ({error_category}): {enhanced_msg}")
                continue
            
            if not result.output:
                # Tool succeeded but no output
                tool_execution_info[tool_name] = ToolExecutionInfo(
                    tool_name=tool_name,
                    success=True,
                    findings_count=0,
                    execution_time=result.execution_time,
                    policy_decision=policy_decision,
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
                        execution_time=result.execution_time,
                        policy_decision=policy_decision,
                    )
                    continue
            
            # Parse tool output
            try:
                findings = parser.parse(result.output)
                findings_count = len(findings)
            except Exception as e:
                # Log parsing error but continue
                logger.warning(f"Error parsing {tool_name} output: {e}")
                tool_execution_info[tool_name] = ToolExecutionInfo(
                    tool_name=tool_name,
                    success=True,
                    error=f"Parsing error: {str(e)}",
                    execution_time=result.execution_time,
                    policy_decision=policy_decision,
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
                    # Ensure severity is never None (default to "medium" if missing)
                    severity = metadata.get("severity") or finding.severity or "medium"
                    
                    violation = Violation(
                        rule_id=policy_id,
                        description=metadata.get("description", finding.message),
                        line=finding.line_number,
                        evidence=finding.message,
                        detector=tool_name,
                        severity=severity
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
                policy_decision=policy_decision,
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
    
    def run_dynamic_analysis(self, code: str, language: str, artifact_id: str):
        """Run constrained dynamic analysis and return detailed artifacts."""
        if not settings.ENABLE_DYNAMIC_TESTING:
            return None
        return self.dynamic_analyzer.analyze(code=code, language=language, artifact_id=artifact_id)
    
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
