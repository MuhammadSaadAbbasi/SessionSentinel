import re

import routers.auth as auth_router
from database import SessionLocal
from models import EmailVerificationRequest, SessionCancellationRequest, User
from services.email_service import EmailDeliveryError


def test_signup_rolls_back_when_verification_email_fails(client, monkeypatch):
    def fail(*args, **kwargs):
        raise EmailDeliveryError("delivery failed")

    monkeypatch.setattr(auth_router, "send_email", fail)
    response = client.post(
        "/signup",
        json={"email": "rollback@example.com", "password": "StrongPass123"},
    )
    assert response.status_code == 503
    db = SessionLocal()
    assert db.query(User).filter(User.email == "rollback@example.com").first() is None
    assert db.query(EmailVerificationRequest).count() == 0
    db.close()


def test_signup_verification_is_single_use_and_enables_login(client, monkeypatch):
    sent = []
    monkeypatch.setattr(
        auth_router,
        "send_email",
        lambda recipient, subject, body: sent.append(body),
    )
    response = client.post(
        "/signup",
        json={"email": "verified@example.com", "password": "StrongPass123"},
    )
    assert response.status_code == 201
    assert len(sent) == 1
    token = re.search(r"verify-email\?token=([^\s]+)", sent[0]).group(1)

    assert client.post("/verify-email", json={"token": token}).status_code == 200
    assert client.post("/verify-email", json={"token": token}).status_code == 400
    assert client.post(
        "/login",
        json={
            "email": "verified@example.com",
            "password": "StrongPass123",
            "device_id": "signup-device",
        },
    ).status_code == 200


def test_session_cancellation_link_revokes_only_its_session(client, login, monkeypatch):
    sent = []
    monkeypatch.setattr(auth_router, "send_email", lambda recipient, subject, body: sent.append(body))
    response = login(email="ali@test.com", device="cancel-device")
    assert response.status_code == 200
    token = re.search(r"cancel-session\?token=([^\s]+)", sent[-1]).group(1)

    assert client.post("/cancel-session", json={"token": token}).json() == {
        "status": "cancelled"
    }
    assert client.post("/cancel-session", json={"token": token}).status_code == 400
    db = SessionLocal()
    assert db.query(SessionCancellationRequest).count() == 1
    db.close()
