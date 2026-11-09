from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, Request, status

from app.core.config import settings


def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> None:
    if settings.app_env.lower() not in {"production", "prod"}:
        return
    if request.url.path.endswith("/emails/graph/webhook"):
        return
    configured_key = settings.api_key
    supplied_key = x_api_key
    if supplied_key is None and authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer":
            supplied_key = value
    if not configured_key or not supplied_key or not secrets.compare_digest(
        supplied_key, configured_key
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
