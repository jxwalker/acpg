"""Static analyzer configuration and management."""
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ToolConfig:
    """Configuration for a static analysis tool."""
    name: str
    command: List[str]  # Command template with {target} placeholder
    parser: str  # Parser class name
    enabled: bool = True
    timeout: int = 30  # Timeout in seconds
    requires_file: bool = True  # Whether tool needs file path vs stdin
    output_format: str = "json"  # "json", "sarif", "xml", "text"
    requires_config: Optional[str] = None  # Config file name (e.g., ".eslintrc.json")
    languages: List[str] = None  # Languages this tool supports
    
    def __post_init__(self):
        if self.languages is None:
            self.languages = []


class StaticAnalyzerConfig:
    """Configuration for all static analysis tools."""
    
    def __init__(self):
        self._tools: Dict[str, Dict[str, ToolConfig]] = {}
        self._config_file = Path(__file__).parent.parent.parent.parent / "policies" / "tool_config.json"
        self._load_default_config()
        self._load_saved_config()
    
    def _load_default_config(self):
        """Load default tool configurations."""
        
        # Python tools
        self._tools["python"] = {
            "bandit": ToolConfig(
                name="bandit",
                command=["bandit", "-f", "json", "-ll", "-r", "{target}"],
                parser="bandit_parser",
                enabled=True,
                timeout=30,
                requires_file=True,
                output_format="json",
                languages=["python"]
            ),
            "pylint": ToolConfig(
                name="pylint",
                command=["pylint", "--output-format=json", "{target}"],
                parser="pylint_parser",
                enabled=False,  # Disabled by default
                timeout=60,
                requires_file=True,
                output_format="json",
                languages=["python"]
            ),
            "safety": ToolConfig(
                name="safety",
                command=["safety", "check", "--json", "--file", "{target}"],
                parser="safety_parser",
                enabled=True,
                timeout=20,
                requires_file=True,
                output_format="json",
                languages=["python"]
            )
        }
        
        # JavaScript/TypeScript tools
        self._tools["javascript"] = {
            "eslint": ToolConfig(
                name="eslint",
                command=["eslint", "--format", "json", "{target}"],
                parser="eslint_parser",
                enabled=True,
                timeout=30,
                requires_file=True,
                output_format="json",
                requires_config=".eslintrc.json",
                languages=["javascript", "typescript"]
            )
        }
        
        self._tools["typescript"] = {
            "eslint": ToolConfig(
                name="eslint",
                command=["eslint", "--format", "json", "{target}"],
                parser="eslint_parser",
                enabled=True,
                timeout=30,
                requires_file=True,
                output_format="json",
                requires_config=".eslintrc.json",
                languages=["javascript", "typescript"]
            )
        }
    
    def get_tools_for_language(self, language: str) -> Dict[str, ToolConfig]:
        """Get enabled tools for a given language."""
        tools = self._tools.get(language, {})
        return {name: config for name, config in tools.items() if config.enabled}
    
    def get_tool(self, language: str, tool_name: str) -> Optional[ToolConfig]:
        """Get a specific tool configuration."""
        return self._tools.get(language, {}).get(tool_name)
    
    def enable_tool(self, language: str, tool_name: str):
        """Enable a tool."""
        if language in self._tools and tool_name in self._tools[language]:
            self._tools[language][tool_name].enabled = True
            self._save_config()
    
    def disable_tool(self, language: str, tool_name: str):
        """Disable a tool."""
        if language in self._tools and tool_name in self._tools[language]:
            self._tools[language][tool_name].enabled = False
            self._save_config()
    
    def _load_saved_config(self):
        """Load saved tool enable/disable state from file."""
        if not self._config_file.exists():
            return
        
        try:
            with open(self._config_file, 'r') as f:
                saved_config = json.load(f)
            
            # Apply saved enabled/disabled states
            for language, tools in saved_config.items():
                if language in self._tools:
                    for tool_name, tool_state in tools.items():
                        if tool_name in self._tools[language]:
                            self._tools[language][tool_name].enabled = tool_state.get("enabled", True)
        except Exception as e:
            import logging
            logging.warning(f"Failed to load saved tool config: {e}")
    
    def _save_config(self):
        """Save tool enable/disable state to file."""
        try:
            config_data = {}
            for language, tools in self._tools.items():
                config_data[language] = {}
                for tool_name, tool_config in tools.items():
                    config_data[language][tool_name] = {
                        "enabled": tool_config.enabled
                    }
            
            self._config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
        except Exception as e:
            import logging
            logging.error(f"Failed to save tool config: {e}")
    
    def list_all_tools(self) -> Dict[str, Dict[str, ToolConfig]]:
        """List all configured tools."""
        return self._tools.copy()
    
    def add_tool(self, language: str, tool_config: ToolConfig):
        """Add a custom tool configuration."""
        if language not in self._tools:
            self._tools[language] = {}
        self._tools[language][tool_config.name] = tool_config


# Global instance
_analyzer_config: Optional[StaticAnalyzerConfig] = None


def get_analyzer_config() -> StaticAnalyzerConfig:
    """Get the global static analyzer configuration."""
    global _analyzer_config
    if _analyzer_config is None:
        _analyzer_config = StaticAnalyzerConfig()
    return _analyzer_config

