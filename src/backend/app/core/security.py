from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import get_db
from app.models import User


@dataclass(frozen=True)
class AuthenticatedUser:
    id: int | None
    email: str
    role: str
    is_api_key: bool = False


def ensure_incident_access(incident: object, user: AuthenticatedUser | None) -> None:
    owner_id = getattr(incident, "owner_id", None)
    if user and user.id is not None and user.role != "admin" and owner_id != user.id:
        raise HTTPException(status_code=403, detail="Incident access denied")


def _secret() -> bytes:
    secret = (
        settings.auth_secret
        or settings.jwt_secret
        or settings.api_key
        or "development-only-auth-secret"
    )
    return secret.encode()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    salt_text = base64.urlsafe_b64encode(salt).decode()
    digest_text = base64.urlsafe_b64encode(digest).decode()
    return f"pbkdf2_sha256$240000${salt_text}${digest_text}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, digest = encoded.split("$")
        calculated = hashlib.pbkdf2_hmac(
            algorithm.removeprefix("pbkdf2_"),
            password.encode(),
            base64.urlsafe_b64decode(salt),
            int(rounds),
        )
        return hmac.compare_digest(calculated, base64.urlsafe_b64decode(digest))
    except (ValueError, TypeError):
        return False


def create_access_token(user: User) -> str:
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "exp": int(time.time()) + 3600,
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(
        b"="
    )
    signature = hmac.new(_secret(), encoded, hashlib.sha256).digest()
    return f"{encoded.decode()}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def decode_access_token(token: str) -> dict[str, object]:
    try:
        encoded_text, signature_text = token.split(".", 1)
        encoded = encoded_text.encode()
        signature = base64.urlsafe_b64decode(signature_text + "===")
        payload = json.loads(base64.urlsafe_b64decode(encoded + b"==="))
    except (ValueError, TypeError, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Invalid access token") from None
    if not hmac.compare_digest(signature, hmac.new(_secret(), encoded, hashlib.sha256).digest()):
        raise HTTPException(status_code=401, detail="Invalid access token")
    if int(payload.get("exp", 0)) <= int(time.time()):
        raise HTTPException(status_code=401, detail="Access token expired")
    return payload


def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> None:
    if settings.app_env.lower() not in {"production", "prod"}:
        return
    if request.url.path.endswith("/emails/graph/webhook") or "/auth/" in request.url.path:
        return
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    get_current_user(request=request, authorization=authorization, db=db)


def get_current_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> AuthenticatedUser | None:
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer" and value:
            if settings.app_env.lower() not in {"production", "prod"} and value == settings.api_key:
                return AuthenticatedUser(None, "api-key", "admin", True)
            payload = decode_access_token(value)
            user = db.get(User, int(payload["sub"]))
            if user is None or not user.is_active:
                raise HTTPException(status_code=401, detail="User is inactive or not found")
            return AuthenticatedUser(user.id, user.email, user.role)
    if (
        request.headers.get("X-API-Key")
        and settings.api_key
        and secrets.compare_digest(request.headers["X-API-Key"], settings.api_key)
    ):
        return AuthenticatedUser(None, "api-key", "admin", True)
    if settings.app_env.lower() in {"production", "prod"}:
        raise HTTPException(status_code=401, detail="Authentication required")
    return None


def require_role(*roles: str):
    def dependency(
        user: AuthenticatedUser | None = Depends(get_current_user),
    ) -> AuthenticatedUser | None:
        if user is not None and user.role not in roles and user.role != "admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return dependency
