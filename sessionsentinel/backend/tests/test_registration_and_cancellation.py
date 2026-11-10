import re

import routers.auth as auth_router
from database import SessionLocal
from models import (
    EmailVerificationRequest,
    Incident,
    SessionCancellationRequest,
    User,
    UserSession,
)
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


def test_session_cancellation_link_triggers_r5_account_protection(client, login, monkeypatch):
    sent = []
    monkeypatch.setattr(auth_router, "send_email", lambda recipient, subject, body: sent.append(body))
    response = login(email="ali@test.com", device="cancel-device")
    assert response.status_code == 200
    session_token = response.json()["token"]
    token = re.search(r"cancel-session\?token=([^\s]+)", sent[-1]).group(1)

    second = login(email="ali@test.com", device="second-device")
    assert second.status_code == 200
    second_token = second.json()["token"]
    assert client.post("/cancel-session", json={"token": token}).json()["status"] == "protected"
    assert client.get(
        "/me",
        headers={"Authorization": f"Bearer {session_token}"},
    ).status_code == 401
    assert client.get(
        "/me",
        headers={"Authorization": f"Bearer {second_token}"},
    ).status_code == 401
    assert client.post("/cancel-session", json={"token": token}).status_code == 400
    db = SessionLocal()
    assert db.query(SessionCancellationRequest).count() == 2
    assert db.query(SessionCancellationRequest).filter(
        SessionCancellationRequest.used_at.is_not(None),
    ).count() == 1
    user = db.query(User).filter(User.email == "ali@test.com").one()
    assert user.password_reset_required is True
    assert db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.revoked.is_(False),
    ).count() == 0
    assert db.query(Incident).filter(
        Incident.user_id == user.id,
        Incident.severity == "high",
        Incident.explanation.like("R5:%"),
    ).count() == 1
    db.close()
