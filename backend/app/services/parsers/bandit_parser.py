"""Parser for Bandit (Python security linter) output."""
import json
from typing import List
from .base_parser import BaseParser, ParsedFinding


class BanditParser(BaseParser):
    """Parser for Bandit JSON output."""
    
    def __init__(self):
        super().__init__("bandit")
    
    def parse(self, output: str) -> List[ParsedFinding]:
        """
        Parse Bandit JSON output.
        
        Bandit JSON format:
        {
            "errors": [],
            "generated_at": "...",
            "metrics": {...},
            "results": [
                {
                    "code": "...",
                    "col_offset": 0,
                    "end_line_number": 5,
                    "filename": "test.py",
                    "issue_confidence": "HIGH",
                    "issue_severity": "HIGH",
                    "issue_text": "...",
                    "line_number": 5,
                    "line_range": [5],
                    "more_info": "...",
                    "test_id": "B608",
                    "test_name": "hardcoded_sql_expressions"
                }
            ]
        }
        """
        findings = []
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            # If output is not valid JSON, return empty list
            return findings
        
        # Parse results
        results = data.get("results", [])
        
        for result in results:
            test_id = result.get("test_id", "UNKNOWN")
            issue_text = result.get("issue_text", "")
            line_number = result.get("line_number")
            filename = result.get("filename")
            
            # Map Bandit severity/confidence
            issue_severity = result.get("issue_severity", "MEDIUM")
            issue_confidence = result.get("issue_confidence", "MEDIUM")
            
            # Normalize severity
            severity = self._normalize_severity(issue_severity)
            
            # Normalize confidence
            confidence = issue_confidence.lower() if isinstance(issue_confidence, str) else "medium"
            
            finding = ParsedFinding(
                tool_name=self.tool_name,
                tool_rule_id=test_id,
                severity=severity,
                message=issue_text,
                file_path=filename,
                line_number=line_number,
                column_number=result.get("col_offset"),
                confidence=confidence,
                raw_data=result
            )
            
            findings.append(finding)
        
        return findings

