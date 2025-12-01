"""Parser for SARIF (Static Analysis Results Interchange Format) output."""
import json
from typing import List, Dict, Any
from .base_parser import BaseParser, ParsedFinding


class SarifParser(BaseParser):
    """Parser for SARIF format output (used by Semgrep, CodeQL, etc.)."""
    
    def __init__(self):
        super().__init__("sarif")
    
    def parse(self, output: str) -> List[ParsedFinding]:
        """
        Parse SARIF JSON output.
        
        SARIF format is complex, but we extract:
        - ruleId from result.ruleId
        - message from result.message.text
        - location from result.locations
        - level from result.level (error, warning, note)
        """
        findings = []
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings
        
        # SARIF format: { "version": "...", "runs": [...] }
        runs = data.get("runs", [])
        
        for run in runs:
            results = run.get("results", [])
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            
            for result in results:
                rule_id = result.get("ruleId", "UNKNOWN")
                message_obj = result.get("message", {})
                message_text = message_obj.get("text", message_obj.get("markdown", ""))
                
                # Get severity from level
                level = result.get("level", "warning")
                severity = self._normalize_severity(level)
                
                # Extract location
                locations = result.get("locations", [])
                file_path = None
                line_number = None
                column_number = None
                
                if locations:
                    location = locations[0]
                    physical_location = location.get("physicalLocation", {})
                    artifact_location = physical_location.get("artifactLocation", {})
                    file_path = artifact_location.get("uri")
                    
                    region = physical_location.get("region", {})
                    line_number = region.get("startLine")
                    column_number = region.get("startColumn")
                
                finding = ParsedFinding(
                    tool_name=tool_name,
                    tool_rule_id=rule_id,
                    severity=severity,
                    message=message_text,
                    file_path=file_path,
                    line_number=line_number,
                    column_number=column_number,
                    confidence="high" if level == "error" else "medium",
                    raw_data=result
                )
                
                findings.append(finding)
        
        return findings

