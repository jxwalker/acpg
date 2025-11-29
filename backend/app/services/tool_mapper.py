"""Tool-to-policy mapping service."""
import json
from typing import Dict, Optional, Tuple, Any
from pathlib import Path

from ..core.config import settings
from .parsers.base_parser import ParsedFinding


class ToolMapper:
    """Maps tool findings to ACPG policies."""
    
    def __init__(self):
        self._mappings: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._load_mappings()
    
    def _load_mappings(self):
        """Load tool-to-policy mappings from JSON file."""
        mappings_file = settings.POLICIES_DIR / "tool_mappings.json"
        
        if mappings_file.exists():
            try:
                with open(mappings_file, 'r') as f:
                    self._mappings = json.load(f)
            except Exception as e:
                # If mappings file is invalid, use empty dict
                self._mappings = {}
        else:
            self._mappings = {}
    
    def map_finding_to_policy(
        self,
        tool_name: str,
        finding: ParsedFinding
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Map a tool finding to an ACPG policy.
        
        Args:
            tool_name: Name of the tool (e.g., "bandit")
            finding: Parsed finding from the tool
            
        Returns:
            Tuple of (policy_id, metadata) or None if no mapping exists
        """
        tool_mappings = self._mappings.get(tool_name, {})
        rule_mapping = tool_mappings.get(finding.tool_rule_id)
        
        if not rule_mapping:
            return None
        
        policy_id = rule_mapping.get("policy_id")
        if not policy_id:
            return None
        
        metadata = {
            "confidence": rule_mapping.get("confidence", finding.confidence or "medium"),
            "severity": rule_mapping.get("severity", finding.severity),
            "description": rule_mapping.get("description", finding.message),
            "tool_rule_id": finding.tool_rule_id,
            "tool_name": tool_name
        }
        
        return (policy_id, metadata)
    
    def get_mapping(self, tool_name: str, tool_rule_id: str) -> Optional[Dict[str, Any]]:
        """Get mapping for a specific tool rule."""
        return self._mappings.get(tool_name, {}).get(tool_rule_id)
    
    def add_mapping(
        self,
        tool_name: str,
        tool_rule_id: str,
        policy_id: str,
        confidence: str = "medium",
        severity: Optional[str] = None,
        description: Optional[str] = None
    ):
        """Add a custom mapping."""
        if tool_name not in self._mappings:
            self._mappings[tool_name] = {}
        
        self._mappings[tool_name][tool_rule_id] = {
            "policy_id": policy_id,
            "confidence": confidence,
            "severity": severity,
            "description": description
        }
    
    def get_all_mappings(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Get all mappings."""
        return self._mappings.copy()
    
    def update_mappings(self, mappings: Dict[str, Dict[str, Dict[str, Any]]]):
        """Update all mappings."""
        self._mappings = mappings
        self._save_mappings()
    
    def _save_mappings(self):
        """Save mappings to JSON file."""
        mappings_file = settings.POLICIES_DIR / "tool_mappings.json"
        try:
            with open(mappings_file, 'w') as f:
                json.dump(self._mappings, f, indent=2)
        except Exception as e:
            import logging
            logging.error(f"Failed to save tool mappings: {e}")
            raise


# Global instance
_tool_mapper: Optional[ToolMapper] = None


def get_tool_mapper() -> ToolMapper:
    """Get the global tool mapper instance."""
    global _tool_mapper
    if _tool_mapper is None:
        _tool_mapper = ToolMapper()
    return _tool_mapper

