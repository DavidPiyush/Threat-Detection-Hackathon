from fastapi import FastAPI

from routes.auth import router as auth_router
from routes.gmail import router as gmail_router
from routes.analysis import router as analysis_router
from routes.investigations import router as investigations_router
from routes.health import router as health_router
from routes.reports import router as reports_router

app = FastAPI(
    title="ThreatDetect",
    description="AI-Powered Email Threat Detection and Forensic Intelligence Platform",
    version="1.0.0"
)


app.include_router(auth_router)
app.include_router(gmail_router)
app.include_router(analysis_router)
app.include_router(investigations_router)
app.include_router(health_router)
app.include_router(reports_router)


@app.get("/")
async def root():

    return {
        "name": "ThreatDetect",
        "status": "online",
        "version": "1.0.0"
    }