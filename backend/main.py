"""ACPG - Agentic Compliance and Policy Governor

Main FastAPI application entry point.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import settings
from app.core.llm_config import get_llm_config
from app.core.service_config import get_cors_origins
from app.services import get_policy_compiler


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler - runs on startup and shutdown."""
    # Startup: Initialize database and load policies
    print("🚀 Starting ACPG - Agentic Compliance and Policy Governor")
    
    # Initialize database
    try:
        from app.core.database import init_db
        init_db()
        print("✅ Database initialized")
    except Exception as e:
        print(f"⚠️  Warning: Could not initialize database: {e}")
    
    # Initialize persistent key manager
    try:
        from app.core.key_manager import get_key_manager
        km = get_key_manager()
        key_info = km.get_key_info()
        print(f"🔑 Signing key loaded: {key_info['fingerprint']}")
    except Exception as e:
        print(f"⚠️  Warning: Could not load signing key: {e}")
    
    # Load policies
    try:
        compiler = get_policy_compiler()
        policies = compiler.get_all_policies()
        print(f"✅ Loaded {len(policies)} policies")
        
        # Group by source
        default_count = len([p for p in policies if not p.id.startswith(('OWASP', 'NIST'))])
        owasp_count = len([p for p in policies if p.id.startswith('OWASP')])
        nist_count = len([p for p in policies if p.id.startswith('NIST')])
        
        print(f"   - Default: {default_count}")
        print(f"   - OWASP: {owasp_count}")
        print(f"   - NIST: {nist_count}")
    except Exception as e:
        print(f"⚠️  Warning: Could not load policies: {e}")
    
    print(f"📋 Max fix iterations: {settings.MAX_FIX_ITERATIONS}")
    
    # Show active LLM provider
    try:
        llm_config = get_llm_config()
        provider = llm_config.get_active_provider()
        print(f"🤖 AI Model: {provider.name}")
        print(f"   Provider: {provider.model}")
    except Exception as e:
        print(f"🤖 AI Model: {settings.OPENAI_MODEL} (default)")
    
    print("=" * 60)
    
    yield
    
    # Shutdown
    print("👋 Shutting down ACPG")


# Create FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""
    ## Agentic Compliance and Policy Governor
    
    ACPG is an automated compliance system that:
    - Generates policy-aware code using AI
    - Analyzes code for policy violations
    - Makes compliance decisions using formal argumentation
    - Produces cryptographically-signed proof bundles
    
    ### Key Features
    - **Generator Agent**: AI-powered code generation and fixing
    - **Prosecutor Agent**: Static analysis with Bandit + regex patterns
    - **Adjudicator**: Formal argumentation with grounded semantics
    - **Proof Bundles**: Cryptographically-signed compliance certificates
    """,
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS for frontend
cors_origins = get_cors_origins()
# Add common dev ports
cors_origins.extend([
    "http://localhost:3000",
    "http://localhost:5173"
])
# Remove duplicates while preserving order
seen = set()
cors_origins = [x for x in cors_origins if not (x in seen or seen.add(x))]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix=settings.API_V1_STR)

# Include LangGraph routes
try:
    from app.api.langgraph_routes import router as langgraph_router
    app.include_router(langgraph_router, prefix=settings.API_V1_STR)
    print("✅ LangGraph orchestration enabled")
except ImportError as e:
    print(f"⚠️  LangGraph not available: {e}")

# Include LLM management routes
try:
    from app.api.llm_routes import router as llm_router
    app.include_router(llm_router, prefix=settings.API_V1_STR)
except ImportError as e:
    print(f"⚠️  LLM routes not available: {e}")

# Include Policy CRUD routes
try:
    from app.api.policy_routes import router as policy_router, groups_router as policy_groups_router
    app.include_router(policy_router, prefix=settings.API_V1_STR)
    app.include_router(policy_groups_router, prefix=settings.API_V1_STR)
    print("✅ Policy management enabled")
except ImportError as e:
    print(f"⚠️  Policy routes not available: {e}")

# Include auth/tenant routes
try:
    from app.api.auth_routes import router as auth_router
    app.include_router(auth_router, prefix=settings.API_V1_STR)
except ImportError as e:
    print(f"⚠️  Auth routes not available: {e}")


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": settings.PROJECT_NAME,
        "version": "1.0.0",
        "docs": "/docs",
        "api": settings.API_V1_STR,
        "endpoints": {
            "health": f"{settings.API_V1_STR}/health",
            "policies": f"{settings.API_V1_STR}/policies",
            "analyze": f"{settings.API_V1_STR}/analyze",
            "generate": f"{settings.API_V1_STR}/generate",
            "enforce": f"{settings.API_V1_STR}/enforce",
            "proof": f"{settings.API_V1_STR}/proof/generate"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
