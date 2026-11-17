from __future__ import annotations

from app.models import EmailEvidence, WebhookDelivery


def test_identity_login_current_user_and_incident_pagination(client) -> None:
    registered = client.post(
        "/api/v1/auth/register",
        json={"email": "analyst@example.test", "password": "correct horse battery"},
    )
    assert registered.status_code == 201
    token = registered.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    current = client.get("/api/v1/auth/me", headers=headers)
    assert current.status_code == 200
    assert current.json()["email"] == "analyst@example.test"

    created = client.post(
        "/api/v1/incidents", headers=headers, json={"title": "Owned incident"}
    )
    assert created.status_code == 200
    listing = client.get("/api/v1/incidents?page=1&page_size=10", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["owner_id"] == current.json()["id"]


def test_graph_and_webhook_deduplication_are_database_entities(client) -> None:
    # The unique constraints are the final concurrency-safe idempotency boundary.
    assert EmailEvidence.__table__.constraints
    assert WebhookDelivery.__table__.constraints
    assert any(
        constraint.name == "uq_emails_graph_message_id"
        for constraint in EmailEvidence.__table__.constraints
    )
    assert any(
        constraint.name == "uq_webhook_deliveries_notification_id"
        for constraint in WebhookDelivery.__table__.constraints
    )
