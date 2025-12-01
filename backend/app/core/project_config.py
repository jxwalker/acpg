"""Project-level configuration for ACPG.

Supports .acpgrc (YAML/JSON) configuration files for per-project settings.
"""
import os
import json
import yaml
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field


@dataclass
class ProjectConfig:
    """Project-level ACPG configuration."""
    
    # Analysis settings
    enabled_policies: List[str] = field(default_factory=list)  # Empty = all policies
    disabled_policies: List[str] = field(default_factory=list)
    policy_groups: List[str] = field(default_factory=list)  # Policy groups to enable
    
    # File patterns
    include_patterns: List[str] = field(default_factory=lambda: ["**/*.py", "**/*.js", "**/*.ts"])
    exclude_patterns: List[str] = field(default_factory=lambda: ["**/node_modules/**", "**/.venv/**", "**/venv/**", "**/__pycache__/**"])
    
    # Severity thresholds
    fail_on_severity: str = "low"  # low, medium, high, critical
    
    # Auto-fix settings
    auto_fix_enabled: bool = False
    max_iterations: int = 3
    
    # API settings
    api_url: str = "http://localhost:8000"
    api_key: Optional[str] = None
    
    # Output settings
    output_format: str = "text"  # text, json, sarif
    proof_bundle: bool = False
    
    # Custom settings
    custom: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProjectConfig':
        """Create config from dictionary."""
        return cls(
            enabled_policies=data.get('enabled_policies', []),
            disabled_policies=data.get('disabled_policies', []),
            policy_groups=data.get('policy_groups', []),
            include_patterns=data.get('include_patterns', ["**/*.py", "**/*.js", "**/*.ts"]),
            exclude_patterns=data.get('exclude_patterns', ["**/node_modules/**", "**/.venv/**"]),
            fail_on_severity=data.get('fail_on_severity', 'low'),
            auto_fix_enabled=data.get('auto_fix_enabled', False),
            max_iterations=data.get('max_iterations', 3),
            api_url=data.get('api_url', 'http://localhost:8000'),
            api_key=data.get('api_key'),
            output_format=data.get('output_format', 'text'),
            proof_bundle=data.get('proof_bundle', False),
            custom=data.get('custom', {})
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'enabled_policies': self.enabled_policies,
            'disabled_policies': self.disabled_policies,
            'policy_groups': self.policy_groups,
            'include_patterns': self.include_patterns,
            'exclude_patterns': self.exclude_patterns,
            'fail_on_severity': self.fail_on_severity,
            'auto_fix_enabled': self.auto_fix_enabled,
            'max_iterations': self.max_iterations,
            'api_url': self.api_url,
            'api_key': self.api_key,
            'output_format': self.output_format,
            'proof_bundle': self.proof_bundle,
            'custom': self.custom
        }


def find_config_file(start_path: Optional[Path] = None) -> Optional[Path]:
    """Find .acpgrc config file by searching up the directory tree."""
    config_names = ['.acpgrc', '.acpgrc.yaml', '.acpgrc.yml', '.acpgrc.json', 'acpg.config.yaml', 'acpg.config.json']
    
    current = Path(start_path or os.getcwd()).resolve()
    
    while current != current.parent:
        for name in config_names:
            config_path = current / name
            if config_path.exists():
                return config_path
        current = current.parent
    
    # Check home directory
    home = Path.home()
    for name in config_names:
        config_path = home / name
        if config_path.exists():
            return config_path
    
    return None


def load_config(config_path: Optional[Path] = None) -> ProjectConfig:
    """Load project configuration.
    
    Args:
        config_path: Explicit path to config file, or None to search
        
    Returns:
        ProjectConfig instance
    """
    if config_path is None:
        config_path = find_config_file()
    
    if config_path is None or not config_path.exists():
        return ProjectConfig()  # Return defaults
    
    try:
        with open(config_path, 'r') as f:
            content = f.read()
        
        # Try YAML first, then JSON
        if config_path.suffix in ['.yaml', '.yml'] or config_path.name == '.acpgrc':
            try:
                data = yaml.safe_load(content) or {}
            except yaml.YAMLError:
                data = json.loads(content)
        else:
            data = json.loads(content)
        
        return ProjectConfig.from_dict(data)
    
    except Exception as e:
        print(f"Warning: Could not load config from {config_path}: {e}")
        return ProjectConfig()


def generate_default_config(output_path: Optional[Path] = None, format: str = 'yaml') -> str:
    """Generate a default .acpgrc configuration file.
    
    Args:
        output_path: Where to write the file (None = return string)
        format: 'yaml' or 'json'
        
    Returns:
        Config content as string
    """
    config = ProjectConfig()
    data = config.to_dict()
    
    # Add comments for YAML
    if format == 'yaml':
        content = """# ACPG Project Configuration
# Place this file in your project root as .acpgrc, .acpgrc.yaml, or acpg.config.yaml

# Policy settings
enabled_policies: []      # Empty = use all policies. Specify IDs to limit: ["SEC-001", "SQL-001"]
disabled_policies: []     # Policies to skip
policy_groups: []         # Enable specific policy groups by name

# File patterns (glob syntax)
include_patterns:
  - "**/*.py"
  - "**/*.js"
  - "**/*.ts"

exclude_patterns:
  - "**/node_modules/**"
  - "**/.venv/**"
  - "**/venv/**"
  - "**/__pycache__/**"

# Severity threshold - fail if violations at or above this level
fail_on_severity: low     # low, medium, high, critical

# Auto-fix settings
auto_fix_enabled: false   # Enable automatic code fixing
max_iterations: 3         # Max fix attempts

# API settings
api_url: http://localhost:8000
api_key: null             # Optional API key for authentication

# Output settings
output_format: text       # text, json, sarif
proof_bundle: false       # Generate cryptographic proof bundles

# Custom project-specific settings
custom: {}
"""
    else:
        content = json.dumps(data, indent=2)
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(content)
    
    return content


# Global config cache
_project_config: Optional[ProjectConfig] = None


def get_project_config(reload: bool = False) -> ProjectConfig:
    """Get the current project configuration (cached)."""
    global _project_config
    if _project_config is None or reload:
        _project_config = load_config()
    return _project_config

