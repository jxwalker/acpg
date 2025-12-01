"""Parser for ESLint output."""
import json
from typing import List, Dict, Any
from .base_parser import BaseParser, ParsedFinding


class ESLintParser(BaseParser):
    """Parser for ESLint JSON output."""
    
    def __init__(self):
        super().__init__("eslint")
    
    def parse(self, output: str) -> List[ParsedFinding]:
        """
        Parse ESLint JSON output.
        
        ESLint JSON format:
        [
            {
                "filePath": "test.js",
                "messages": [
                    {
                        "ruleId": "no-eval",
                        "severity": 2,
                        "message": "eval can be harmful.",
                        "line": 5,
                        "column": 1,
                        "nodeType": "CallExpression",
                        "endLine": 5,
                        "endColumn": 5
                    }
                ],
                "errorCount": 1,
                "warningCount": 0
            }
        ]
        """
        findings = []
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings
        
        # ESLint returns a list of file results
        if not isinstance(data, list):
            return findings
        
        for file_result in data:
            file_path = file_result.get("filePath")
            messages = file_result.get("messages", [])
            
            for message in messages:
                rule_id = message.get("ruleId")
                if not rule_id:
                    continue  # Skip non-rule messages
                
                # ESLint severity: 0=off, 1=warning, 2=error
                eslint_severity = message.get("severity", 1)
                severity = "high" if eslint_severity == 2 else "medium"
                
                finding = ParsedFinding(
                    tool_name=self.tool_name,
                    tool_rule_id=rule_id,
                    severity=severity,
                    message=message.get("message", ""),
                    file_path=file_path,
                    line_number=message.get("line"),
                    column_number=message.get("column"),
                    confidence="high" if eslint_severity == 2 else "medium",
                    raw_data=message
                )
                
                findings.append(finding)
        
        return findings

