from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class GraphMessagePayload:
    message_id: str
    eml_content: bytes


class GraphClient:
    def __init__(
        self,
        http_client: httpx.Client | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
    ) -> None:
        self._timeout = timeout if timeout is not None else settings.graph_timeout_seconds
        self._max_retries = (
            max_retries if max_retries is not None else settings.graph_max_retries
        )
        self._client = http_client or httpx.Client(timeout=self._timeout)

    def _request_with_retry(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        attempts = 0
        last_exception: Exception | None = None

        while attempts <= self._max_retries:
            try:
                response = self._client.request(method, url, **kwargs)
                if response.status_code == 429 or response.status_code in {500, 502, 503, 504}:
                    if attempts < self._max_retries:
                        retry_after = response.headers.get("Retry-After")
                        if retry_after:
                            try:
                                delay = min(float(retry_after), 10.0)
                            except ValueError:
                                delay = 0.2 * (2**attempts)
                        else:
                            delay = 0.2 * (2**attempts)
                        logger.warning(
                            "Graph transient %s on %s %s. Retry in %ss (%s/%s)",
                            response.status_code,
                            method,
                            url,
                            delay,
                            attempts + 1,
                            self._max_retries,
                        )
                        time.sleep(delay)
                        attempts += 1
                        continue
                return response
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_exception = exc
                if attempts < self._max_retries:
                    delay = 0.2 * (2**attempts)
                    logger.warning(
                        "Graph connection error on %s %s: %s. Retry in %ss (%s/%s)",
                        method,
                        url,
                        exc,
                        delay,
                        attempts + 1,
                        self._max_retries,
                    )
                    time.sleep(delay)
                    attempts += 1
                    continue
                break

        if last_exception:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Microsoft Graph API connection failed: {last_exception}",
            )

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Microsoft Graph API request exceeded maximum retry attempts",
        )

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
        response = self._request_with_retry("POST", token_url, data=payload)
        if response.status_code >= 400:
            logger.error(
                "OAuth token exchange failed with status %s: %s",
                response.status_code,
                response.text,
            )
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
        response = self._request_with_retry(
            "GET",
            endpoint,
            headers={"Authorization": "Bearer " + access_token},
        )
        if response.status_code >= 400:
            logger.error(
                "Failed to fetch message MIME %s with status %s",
                message_id,
                response.status_code,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to retrieve email content from Microsoft Graph",
            )
        return GraphMessagePayload(message_id=message_id, eml_content=response.content)

    def list_messages(
        self,
        access_token: str,
        folder_id: str = "inbox",
        top: int = 10,
        search: str | None = None,
        filter_query: str | None = None,
    ) -> list[dict[str, Any]]:
        top = max(1, min(top, 50))
        if folder_id in {"inbox", "junkemail", "drafts", "sentitems", "deleteditems"}:
            endpoint = f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder_id}/messages"
        elif folder_id and folder_id not in {"all", "messages"}:
            endpoint = f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder_id}/messages"
        else:
            endpoint = "https://graph.microsoft.com/v1.0/me/messages"

        params: dict[str, str] = {
            "$top": str(top),
            "$select": "id,subject,from,receivedDateTime,hasAttachments,isRead",
            "$orderby": "receivedDateTime desc",
        }
        if search:
            params["$search"] = f'"{search}"'
        if filter_query:
            params["$filter"] = filter_query

        response = self._request_with_retry(
            "GET",
            endpoint,
            headers={"Authorization": "Bearer " + access_token},
            params=params,
        )
        if response.status_code >= 400:
            logger.error("Failed to list messages: %s", response.text)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to list messages from Microsoft Graph",
            )

        data = response.json()
        raw_items = data.get("value", [])
        messages: list[dict[str, Any]] = []
        for item in raw_items:
            sender_info = item.get("from", {}).get("emailAddress", {})
            sender_addr = sender_info.get("address")
            messages.append(
                {
                    "id": item["id"],
                    "subject": item.get("subject"),
                    "sender": sender_addr,
                    "received_at": item.get("receivedDateTime"),
                    "has_attachments": bool(item.get("hasAttachments", False)),
                    "is_read": bool(item.get("isRead", False)),
                }
            )
        return messages

    def create_subscription(
        self,
        access_token: str,
        notification_url: str,
        resource: str = "/me/messages",
        change_type: str = "created",
        client_state: str | None = None,
        expiration_minutes: int = 4230,
    ) -> dict[str, Any]:
        endpoint = "https://graph.microsoft.com/v1.0/subscriptions"
        expiration = (
            datetime.now(timezone.utc) + timedelta(minutes=expiration_minutes)
        ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        resolved_client_state = (
            client_state
            or settings.graph_webhook_client_state
            or secrets.token_urlsafe(16)
        )

        payload = {
            "changeType": change_type,
            "notificationUrl": notification_url,
            "resource": resource,
            "expirationDateTime": expiration,
            "clientState": resolved_client_state,
        }

        response = self._request_with_retry(
            "POST",
            endpoint,
            headers={
                "Authorization": "Bearer " + access_token,
                "Content-Type": "application/json",
            },
            json=payload,
        )
        if response.status_code >= 400:
            logger.error("Failed to create webhook subscription: %s", response.text)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to create Microsoft Graph webhook subscription",
            )
        return response.json()

    def delete_subscription(self, access_token: str, subscription_id: str) -> bool:
        endpoint = f"https://graph.microsoft.com/v1.0/subscriptions/{subscription_id}"
        response = self._request_with_retry(
            "DELETE",
            endpoint,
            headers={"Authorization": "Bearer " + access_token},
        )
        return response.status_code in {200, 204}


def get_graph_client() -> GraphClient:
    return GraphClient()
