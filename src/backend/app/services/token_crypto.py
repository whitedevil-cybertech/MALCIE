import base64
import hashlib
import secrets

from app.core.config import settings


def _key() -> bytes:
    value = (
        settings.oauth_encryption_key
        or settings.graph_client_secret
        or settings.auth_secret
        or settings.jwt_secret
    )
    if not value and settings.app_env.lower() in {"production", "prod"}:
        raise RuntimeError("OAUTH_ENCRYPTION_KEY must be configured in production")
    value = value or "development-only-oauth-key"
    return hashlib.sha256(value.encode()).digest()


def encrypt_token(value: str) -> str:
    # AES-GCM is imported lazily so deployments without OAuth enabled can still boot.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(_key()).encrypt(nonce, value.encode(), None)
    return base64.urlsafe_b64encode(nonce + encrypted).decode()


def decrypt_token(value: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = base64.urlsafe_b64decode(value.encode())
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], None).decode()
