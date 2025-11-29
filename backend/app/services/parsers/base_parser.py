"""Base parser for static analysis tool outputs."""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class ParsedFinding:
    """A parsed finding from a static analysis tool."""
    tool_name: str
    tool_rule_id: str  # Tool-specific rule ID (e.g., "B608" for Bandit)
    severity: str  # "low", "medium", "high", "critical"
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    confidence: Optional[str] = None  # "low", "medium", "high"
    raw_data: Optional[Dict[str, Any]] = None  # Original tool output


class BaseParser:
    """Base class for static analysis tool parsers."""
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
    
    def parse(self, output: str) -> List[ParsedFinding]:
        """
        Parse tool output into findings.
        
        Args:
            output: Raw tool output (JSON, XML, text, etc.)
            
        Returns:
            List of parsed findings
        """
        raise NotImplementedError("Subclasses must implement parse()")
    
    def _normalize_severity(self, severity: Any) -> str:
        """
        Normalize severity to standard levels.
        
        Args:
            severity: Tool-specific severity value
            
        Returns:
            Normalized severity: "low", "medium", "high", "critical"
        """
        if isinstance(severity, str):
            severity_lower = severity.lower()
            if severity_lower in ["critical", "error", "high"]:
                return "critical" if "critical" in severity_lower else "high"
            elif severity_lower in ["medium", "warning"]:
                return "medium"
            else:
                return "low"
        elif isinstance(severity, int):
            if severity >= 8:
                return "critical"
            elif severity >= 5:
                return "high"
            elif severity >= 3:
                return "medium"
            else:
                return "low"
        return "medium"  # Default

