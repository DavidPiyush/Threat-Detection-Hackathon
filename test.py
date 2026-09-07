from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.auth import router as auth_router
from routes.gmail import router as gmail_router
from routes.analysis import router as analysis_router
from routes.investigations import router as investigations_router
from routes.health import router as health_router
from routes.reports import router as reports_router


# ============================================================
# APPLICATION LIFECYCLE
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup/shutdown lifecycle.

    Keep startup lightweight.
    Database connections are created per operation through
    database.connect.get_db_connection().
    """

    print("=" * 60)
    print("Threat Detection & Email Forensics Platform")
    print("Backend starting...")
    print("=" * 60)

    yield

    print("=" * 60)
    print("Backend shutting down...")
    print("=" * 60)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="AI-Powered Email Threat Detection Platform",
    description=(
        "AI-assisted email threat detection, email forensics, "
        "threat intelligence, geolocation and investigation platform."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():
    return {
        "success": True,
        "name": "AI-Powered Email Threat Detection Platform",
        "version": "1.0.0",
        "status": "running",
        "documentation": "/docs",
    }


# ============================================================
# API INFO
# ============================================================

@app.get("/api")
async def api_info():
    return {
        "success": True,
        "service": "Threat Detection API",
        "version": "1.0.0",
        "modules": {
            "authentication": "/auth",
            "gmail": "/gmail",
            "analysis": "/analysis",
            "investigations": "/investigations",
            "reports": "/reports",
            "health": "/health",
        },
    }


# ============================================================
# ROUTERS
# ============================================================

app.include_router(
    auth_router
)

app.include_router(
    gmail_router
)

app.include_router(
    analysis_router
)

app.include_router(
    investigations_router
)

app.include_router(
    health_router
)

app.include_router(
    reports_router
)


# ============================================================
# STARTUP MESSAGE
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )