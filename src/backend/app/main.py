from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.models  # noqa: F401
from app.api.artifacts import router as artifacts_router
from app.api.emails import router as emails_router
from app.api.health import router as health_router
from app.api.incidents import router as incidents_router
from app.api.telemetry import router as telemetry_router
from app.api.threat_intel import router as threat_intel_router
from app.core.config import settings
from app.core.security import require_api_key

app = FastAPI(
    title=settings.app_name,
    version="0.3.0",
    dependencies=[Depends(require_api_key)],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in settings.allowed_origins.split(",")
        if origin.strip()
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)
app.include_router(health_router, prefix=settings.api_v1_prefix)
app.include_router(incidents_router, prefix=settings.api_v1_prefix)
app.include_router(emails_router, prefix=settings.api_v1_prefix)
app.include_router(artifacts_router, prefix=settings.api_v1_prefix)
app.include_router(threat_intel_router, prefix=settings.api_v1_prefix)
app.include_router(telemetry_router, prefix=settings.api_v1_prefix)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "MALCIE backend is running"}
