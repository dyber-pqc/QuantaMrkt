"""QuantaMrkt API — FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from quantmrkt_api.routes import agents, hndl, migrate, models, transparency

app = FastAPI(
    title="QuantaMrkt API",
    version="0.1.0",
    description="Quantum-safe AI marketplace — model registry, agent identity, PQC migration tools.",
)

# ---------------------------------------------------------------------------
# CORS — allow all origins during development
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers (all under /v1)
# ---------------------------------------------------------------------------
app.include_router(models.router, prefix="/v1")
app.include_router(agents.router, prefix="/v1")
app.include_router(migrate.router, prefix="/v1")
app.include_router(hndl.router, prefix="/v1")
app.include_router(transparency.router, prefix="/v1")


# ---------------------------------------------------------------------------
# Top-level endpoints
# ---------------------------------------------------------------------------
@app.get("/health", tags=["Health"])
async def health_check():
    """Liveness / readiness probe."""
    return {"status": "healthy", "version": "0.1.0"}


@app.get("/", include_in_schema=False)
async def root():
    """Redirect the bare root to the interactive docs."""
    return RedirectResponse(url="/docs")
