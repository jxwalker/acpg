"""LLM Management API routes."""
from typing import List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/llm", tags=["LLM Management"])


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


class SwitchProviderRequest(BaseModel):
    """Request to switch LLM provider."""
    provider_id: str


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
        from ..services.generator import _generator
        global _generator
        _generator = None
        
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
        response = client.chat.completions.create(
            model=provider.model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a Python code generator. Generate only code, no explanations."
                },
                {
                    "role": "user",
                    "content": "Write a Python function called 'add_numbers' that takes two integers and returns their sum. Include a docstring."
                }
            ],
            max_tokens=200,
            temperature=0.3
        )
        
        generated_code = response.choices[0].message.content.strip()
        
        return {
            "success": True,
            "provider": provider.name,
            "model": provider.model,
            "generated_code": generated_code,
            "tokens_used": response.usage.total_tokens if response.usage else None
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

