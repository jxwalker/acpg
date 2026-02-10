"""Configuration management for ACPG."""
import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""
    
    # API Configuration
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "ACPG - Agentic Compliance and Policy Governor"
    
    # OpenAI Configuration (optional if using local LLM)
    OPENAI_API_KEY: str = ""  # Can be empty if using local LLM
    OPENAI_MODEL: str = "gpt-4"
    OPENAI_TEMPERATURE: float = 0.3
    OPENAI_MAX_TOKENS: int = 2000
    
    # Policy Configuration
    POLICIES_DIR: Path = Path(os.environ.get("POLICIES_DIR", Path(__file__).parent.parent.parent.parent / "policies"))
    DEFAULT_POLICIES_FILE: str = "default_policies.json"
    
    # Compliance Configuration
    MAX_FIX_ITERATIONS: int = 3
    ENABLE_DYNAMIC_TESTING: bool = False  # Hypothesis testing (optional)
    
    # Crypto Configuration
    SIGNATURE_ALGORITHM: str = "ECDSA-SHA256"
    SIGNER_NAME: str = "ACPG-Adjudicator"
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    # Static Analysis Configuration
    ENABLE_STATIC_ANALYSIS: bool = True
    STATIC_ANALYSIS_TIMEOUT: int = 30  # Default timeout in seconds
    STATIC_ANALYSIS_CACHE_TTL: int = 3600  # Cache TTL in seconds (1 hour)
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": True
    }


# Global settings instance
settings = Settings()
