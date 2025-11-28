"""ACPG - Agentic Compliance and Policy Governor

Main FastAPI application entry point.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import settings
from app.services import get_policy_compiler


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler - runs on startup and shutdown."""
    # Startup: Load policies
    print("🚀 Starting ACPG - Agentic Compliance and Policy Governor")
    
    try:
        compiler = get_policy_compiler()
        policies = compiler.get_all_policies()
        print(f"✅ Loaded {len(policies)} policies")
        for p in policies:
            print(f"   - {p.id}: {p.description[:50]}...")
    except Exception as e:
        print(f"⚠️  Warning: Could not load policies: {e}")
    
    print(f"📋 Max fix iterations: {settings.MAX_FIX_ITERATIONS}")
    print(f"🤖 AI Model: {settings.OPENAI_MODEL}")
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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],  # React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix=settings.API_V1_STR)


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

