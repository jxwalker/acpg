"""LLM Management API routes."""
import yaml
from pathlib import Path
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/llm", tags=["LLM Management"])

# Path to LLM config file
LLM_CONFIG_PATH = Path(__file__).parent.parent.parent / "llm_config.yaml"


class LLMProvider(BaseModel):
    """LLM provider info."""
    id: str
    name: str
    model: str
    is_active: bool


class LLMTestResult(BaseModel):
    """Result of LLM connection test."""
    success: bool
    provider: str
    model: str
    response: Optional[str] = None
    error: Optional[str] = None
    diagnostics: Optional[Dict[str, Any]] = None


class SwitchProviderRequest(BaseModel):
    """Request to switch LLM provider."""
    provider_id: str


class ProviderConfig(BaseModel):
    """Full provider configuration."""
    id: str
    type: str  # openai, openai_compatible, anthropic
    name: str
    base_url: str
    api_key: str  # Can be ${ENV_VAR} or actual key
    model: str
    max_tokens: int = 2000
    temperature: float = 0.3
    context_window: int = 8192


class UpdateProviderRequest(BaseModel):
    """Request to update a provider."""
    name: Optional[str] = None
    type: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    context_window: Optional[int] = None


class CreateProviderRequest(BaseModel):
    """Request to create a new provider."""
    id: str
    type: str
    name: str
    base_url: str
    api_key: str
    model: str
    max_tokens: int = 2000
    temperature: float = 0.3
    context_window: int = 8192


def _load_config() -> Dict[str, Any]:
    """Load the LLM config file."""
    if not LLM_CONFIG_PATH.exists():
        return {"active_provider": "", "providers": {}}
    with open(LLM_CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f) or {"active_provider": "", "providers": {}}


def _save_config(config: Dict[str, Any]):
    """Save the LLM config file."""
    # Add header comment
    header = """# ACPG LLM Server Configuration
# Configure multiple LLM providers and select the active one
# API keys should use ${ENV_VAR} syntax to reference environment variables

"""
    with open(LLM_CONFIG_PATH, 'w') as f:
        f.write(header)
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


@router.get("/providers", response_model=List[LLMProvider])
async def list_llm_providers():
    """
    List all configured LLM providers.
    """
    from ..core.llm_config import get_llm_config
    
    config = get_llm_config()
    full_config = config.load_config()
    active = full_config.get('active_provider')
    providers = full_config.get('providers', {})
    
    return [
        LLMProvider(
            id=provider_id,
            name=data.get('name', provider_id),
            model=data.get('model', 'unknown'),
            is_active=(provider_id == active)
        )
        for provider_id, data in providers.items()
    ]


@router.get("/active")
async def get_active_provider():
    """
    Get the currently active LLM provider.
    """
    from ..core.llm_config import get_llm_config
    
    config = get_llm_config()
    provider = config.get_active_provider()
    
    return {
        "name": provider.name,
        "model": provider.model,
        "base_url": provider.base_url,
        "max_tokens": provider.max_tokens,
        "temperature": provider.temperature,
        "context_window": provider.context_window
    }


@router.post("/test", response_model=LLMTestResult)
async def test_llm_connection():
    """
    Test the connection to the active LLM provider.
    
    Sends a simple prompt and returns the result.
    """
    from ..core.llm_config import get_llm_config
    
    config = get_llm_config()
    result = config.test_connection()
    
    return LLMTestResult(**result)


@router.post("/switch")
async def switch_llm_provider(request: SwitchProviderRequest):
    """
    Switch to a different LLM provider.
    
    Note: This only affects the current process. To persist,
    update the llm_config.yaml file.
    """
    from ..core.llm_config import get_llm_config
    
    config = get_llm_config()
    
    try:
        new_provider = config.switch_provider(request.provider_id)
        
        # Also reset the generator to use the new provider
        from ..services.generator import reset_generator
        reset_generator()
        
        return {
            "success": True,
            "message": f"Switched to {new_provider.name}",
            "provider": {
                "name": new_provider.name,
                "model": new_provider.model,
                "base_url": new_provider.base_url
            }
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/generate-test")
async def test_code_generation():
    """
    Test code generation with the active LLM.
    
    Generates a simple Python function to verify the LLM is working.
    """
    from ..core.llm_config import get_llm_config, get_llm_client
    
    config = get_llm_config()
    client = get_llm_client()
    provider = config.get_active_provider()
    
    try:
        system_prompt = "You are a Python code generator. Generate only code, no explanations."
        user_prompt = "Write a Python function called 'add_numbers' that takes two integers and returns their sum. Include a docstring."

        if provider.type == "anthropic":
            response = client.messages.create(
                model=provider.model,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                max_tokens=200,
                temperature=0.3,
            )
            generated_code = response.content[0].text.strip() if response.content else ""
            tokens_used = None
        else:
            from ..core.llm_text import openai_text

            generated_code = openai_text(
                client,
                model=provider.model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.3,
                max_output_tokens=200,
                max_tokens_fallback=200,
            )
            tokens_used = None
        
        return {
            "success": True,
            "provider": provider.name,
            "model": provider.model,
            "generated_code": generated_code,
            "tokens_used": tokens_used
        }
    
    except Exception as e:
        return {
            "success": False,
            "provider": provider.name,
            "model": provider.model,
            "error": str(e)
        }


@router.post("/fix-test")
async def test_code_fixing():
    """
    Test code fixing with the active LLM.
    
    Attempts to fix a simple security violation.
    """
    from ..services import get_generator
    from ..models.schemas import Violation
    
    test_code = 'password = "secret123"'
    test_violations = [
        Violation(
            rule_id="SEC-001",
            description="Hardcoded password detected",
            line=1,
            evidence='password = "secret123"',
            detector="test",
            severity="high"
        )
    ]
    
    try:
        generator = get_generator()
        fixed_code = generator.fix_violations(test_code, test_violations, "python")
        
        provider = generator.llm_config.get_active_provider()
        
        return {
            "success": True,
            "provider": provider.name,
            "original_code": test_code,
            "fixed_code": fixed_code,
            "violation_fixed": "SEC-001"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


# =============================================================================
# Provider CRUD Operations
# =============================================================================

@router.get("/providers/{provider_id}")
async def get_provider(provider_id: str):
    """Get detailed configuration for a specific provider."""
    config = _load_config()
    providers = config.get('providers', {})
    
    if provider_id not in providers:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found")
    
    provider_data = providers[provider_id]
    return {
        "id": provider_id,
        "is_active": config.get('active_provider') == provider_id,
        **provider_data
    }


@router.post("/providers/")
async def create_provider(request: CreateProviderRequest):
    """Create a new LLM provider configuration."""
    config = _load_config()
    providers = config.get('providers', {})
    
    if request.id in providers:
        raise HTTPException(status_code=400, detail=f"Provider '{request.id}' already exists")
    
    # Create provider entry
    providers[request.id] = {
        "type": request.type,
        "name": request.name,
        "base_url": request.base_url,
        "api_key": request.api_key,
        "model": request.model,
        "max_tokens": request.max_tokens,
        "temperature": request.temperature,
        "context_window": request.context_window
    }
    
    config['providers'] = providers
    _save_config(config)
    
    return {
        "success": True,
        "message": f"Provider '{request.id}' created",
        "provider": {"id": request.id, **providers[request.id]}
    }


@router.put("/providers/{provider_id}")
async def update_provider(provider_id: str, request: UpdateProviderRequest):
    """Update an existing LLM provider configuration."""
    config = _load_config()
    providers = config.get('providers', {})
    
    if provider_id not in providers:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found")
    
    # Update only provided fields
    provider_data = providers[provider_id]
    update_dict = request.model_dump(exclude_unset=True)
    
    for key, value in update_dict.items():
        if value is not None:
            provider_data[key] = value
    
    providers[provider_id] = provider_data
    config['providers'] = providers
    _save_config(config)
    
    # Reset cached config to pick up changes
    from ..core.llm_config import get_llm_config
    llm_config = get_llm_config()
    llm_config._config = None
    llm_config._active_provider = None
    llm_config._client = None
    
    return {
        "success": True,
        "message": f"Provider '{provider_id}' updated",
        "provider": {"id": provider_id, **provider_data}
    }


@router.delete("/providers/{provider_id}")
async def delete_provider(provider_id: str):
    """Delete an LLM provider configuration."""
    config = _load_config()
    providers = config.get('providers', {})
    
    if provider_id not in providers:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found")
    
    # Don't allow deleting the active provider
    if config.get('active_provider') == provider_id:
        raise HTTPException(
            status_code=400, 
            detail="Cannot delete the active provider. Switch to another provider first."
        )
    
    del providers[provider_id]
    config['providers'] = providers
    _save_config(config)
    
    return {
        "success": True,
        "message": f"Provider '{provider_id}' deleted"
    }


@router.get("/config")
async def get_full_config():
    """Get the full LLM configuration (for the editor)."""
    config = _load_config()
    
    # Mask actual API keys for security (show only env var references)
    providers = config.get('providers', {})
    masked_providers = {}
    
    for pid, pdata in providers.items():
        masked_data = pdata.copy()
        api_key = masked_data.get('api_key', '')
        # If it's an actual key (not an env var reference), mask it
        if api_key and not api_key.startswith('${') and api_key not in ['not-needed', 'ollama']:
            masked_data['api_key'] = '***HIDDEN***'
            masked_data['api_key_set'] = True
        else:
            masked_data['api_key_set'] = api_key.startswith('${')
        masked_providers[pid] = masked_data
    
    return {
        "active_provider": config.get('active_provider'),
        "providers": masked_providers
    }


@router.post("/config/set-active")
async def set_active_provider(request: SwitchProviderRequest):
    """Set the active provider in the config file (persists across restarts)."""
    config = _load_config()
    providers = config.get('providers', {})
    
    if request.provider_id not in providers:
        raise HTTPException(status_code=404, detail=f"Provider '{request.provider_id}' not found")
    
    config['active_provider'] = request.provider_id
    _save_config(config)
    
    # Also switch the in-memory provider
    from ..core.llm_config import get_llm_config
    llm_config = get_llm_config()
    llm_config._config = None
    llm_config._active_provider = None
    llm_config._client = None
    
    # Reset generator
    from ..services.generator import reset_generator
    reset_generator()
    
    return {
        "success": True,
        "message": f"Active provider set to '{request.provider_id}' and saved to config"
    }
