from fastapi import FastAPI

import app.models  # noqa: F401
from app.api.artifacts import router as artifacts_router
from app.api.emails import router as emails_router
from app.api.health import router as health_router
from app.api.incidents import router as incidents_router
from app.core.config import settings

app = FastAPI(title=settings.app_name, version="0.3.0")
app.include_router(health_router, prefix=settings.api_v1_prefix)
app.include_router(incidents_router, prefix=settings.api_v1_prefix)
app.include_router(emails_router, prefix=settings.api_v1_prefix)
app.include_router(artifacts_router, prefix=settings.api_v1_prefix)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "MALCIE backend is running"}
