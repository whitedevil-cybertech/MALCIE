from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status

from app.core.config import settings


@dataclass
class GraphMessagePayload:
    message_id: str
    eml_content: bytes


class GraphClient:
    def __init__(self, http_client: httpx.Client | None = None) -> None:
        self._client = http_client or httpx.Client(timeout=20)

    def build_auth_url(self, redirect_uri: str) -> tuple[str, str]:
        state = secrets.token_urlsafe(32)
        params = {
            "client_id": settings.graph_client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": settings.graph_scope,
            "state": state,
        }
        url = f"https://login.microsoftonline.com/{settings.graph_tenant_id}/oauth2/v2.0/authorize"
        return f"{url}?{urlencode(params)}", state

    def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, str | int]:
        token_url = (
            f"https://login.microsoftonline.com/{settings.graph_tenant_id}/oauth2/v2.0/token"
        )
        payload = {
            "client_id": settings.graph_client_id,
            "client_secret": settings.graph_client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "scope": settings.graph_scope,
        }
        response = self._client.post(token_url, data=payload)
        if response.status_code >= 400:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to exchange OAuth code with Microsoft Graph",
            )
        token_data = response.json()
        return {
            "access_token": token_data["access_token"],
            "token_type": token_data.get("token_type", "Bearer"),
            "expires_in": int(token_data.get("expires_in", 0)),
            "refresh_token": token_data.get("refresh_token"),
        }

    def get_message_eml(self, access_token: str, message_id: str) -> GraphMessagePayload:
        endpoint = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/$value"
        response = self._client.get(
            endpoint,
            headers={"Authorization": "Bearer " + access_token},
        )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to retrieve email content from Microsoft Graph",
            )
        return GraphMessagePayload(message_id=message_id, eml_content=response.content)


def get_graph_client() -> GraphClient:
    return GraphClient()
