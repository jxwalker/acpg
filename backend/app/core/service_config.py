"""Service configuration loader from YAML."""
import yaml
import os
from pathlib import Path
from typing import Dict, Any

# Default config path
CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config.yaml"


def load_config() -> Dict[str, Any]:
    """Load configuration from YAML file."""
    if not CONFIG_PATH.exists():
        # Return defaults if config doesn't exist
        return {
            "services": {
                "backend": {"base_port": 6000, "auto_find_port": True},
                "frontend": {"base_port": 6001, "auto_find_port": True}
            },
            "api": {
                "base_path": "/api/v1",
                "cors_origins": [
                    "http://localhost:6001",
                    "http://localhost:6002",
                    "http://localhost:6003"
                ]
            }
        }
    
    try:
        with open(CONFIG_PATH, 'r') as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Warning: Could not load config.yaml: {e}")
        return {}


def get_backend_port() -> int:
    """Get backend port from config or environment."""
    # Check environment first (for override)
    if "ACPG_BACKEND_PORT" in os.environ:
        return int(os.environ["ACPG_BACKEND_PORT"])
    
    config = load_config()
    base_port = config.get("services", {}).get("backend", {}).get("base_port", 6000)
    
    # If auto_find_port is enabled, the startup script will handle it
    # For now, just return the base port
    return base_port


def get_cors_origins() -> list:
    """Get CORS origins from config."""
    config = load_config()
    return config.get("api", {}).get("cors_origins", [
        "http://localhost:6001",
        "http://localhost:6002",
        "http://localhost:6003"
    ])

