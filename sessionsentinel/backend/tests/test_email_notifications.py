from datetime import timedelta
from types import SimpleNamespace

import pytest

import services.email_service as email_service
REAL_SEND_EMAIL = email_service.send_email
from config import R1_CRITICAL_FAILS, R1_HIGH_FAILS
from database import SessionLocal
from models import Event, TrustedDevice, User, VerificationRequest, utcnow
from services.detection import record_r1_incident
from services.detection import ip_retry_after
from services.email_service import (
    EmailConfigurationError,
    EmailDeliveryError,
    create_notification,
    create_verification_request,
)
from security import hash_password


def _configure_mailjet(monkeypatch):
    monkeypatch.setattr(email_service, "MAILJET_API_KEY", "public-key")
    monkeypatch.setattr(email_service, "MAILJET_API_SECRET", "private-secret")
    monkeypatch.setattr(email_service, "MAILJET_FROM_EMAIL", "alerts@example.com")
    monkeypatch.setattr(email_service, "MAILJET_FROM_NAME", "SessionSentinel")


def test_send_email_posts_mailjet_v31_message(monkeypatch):
    _configure_mailjet(monkeypatch)
    response = SimpleNamespace(
        status_code=200,
        json=lambda: {"Messages": [{"Status": "success"}]},
    )
    captured = {}

    def post(url, **kwargs):
        captured.update(url=url, kwargs=kwargs)
        return response

    monkeypatch.setattr(email_service.requests, "post", post)

    REAL_SEND_EMAIL("user@example.com", "Subject", "Hello <user>\nThanks")

    assert captured["url"] == email_service.MAILJET_SEND_URL
    assert captured["kwargs"]["auth"] == ("public-key", "private-secret")
    assert captured["kwargs"]["timeout"] == email_service.MAILJET_TIMEOUT_SECONDS
    message = captured["kwargs"]["json"]["Messages"][0]
    assert message["From"] == {"Email": "alerts@example.com", "Name": "SessionSentinel"}
    assert message["To"] == [{"Email": "user@example.com"}]
    assert message["TextPart"] == "Hello <user>\nThanks"
    assert message["HTMLPart"] == "Hello &lt;user&gt;<br>Thanks"


def test_send_email_requires_mailjet_configuration(monkeypatch):
    monkeypatch.setattr(email_service, "MAILJET_API_KEY", "")

    with pytest.raises(EmailConfigurationError, match="MAILJET_API_KEY"):
        REAL_SEND_EMAIL("user@example.com", "Subject", "Body")


def test_send_email_reports_mailjet_rejection(monkeypatch):
    _configure_mailjet(monkeypatch)
    monkeypatch.setattr(
        email_service.requests,
        "post",
        lambda *args, **kwargs: SimpleNamespace(
            status_code=200,
            json=lambda: {"Messages": [{"Status": "error"}]},
        ),
    )

    with pytest.raises(EmailDeliveryError, match="did not accept"):
        REAL_SEND_EMAIL("user@example.com", "Subject", "Body")


def test_send_email_reports_malformed_mailjet_response(monkeypatch):
    _configure_mailjet(monkeypatch)
    monkeypatch.setattr(
        email_service.requests,
        "post",
        lambda *args, **kwargs: SimpleNamespace(status_code=200, json=lambda: {}),
    )

    with pytest.raises(EmailDeliveryError, match="invalid message result"):
        REAL_SEND_EMAIL("user@example.com", "Subject", "Body")


def test_send_email_reports_mailjet_timeout(monkeypatch):
    _configure_mailjet(monkeypatch)

    def timeout(*args, **kwargs):
        raise email_service.requests.Timeout()

    monkeypatch.setattr(email_service.requests, "post", timeout)

    with pytest.raises(EmailDeliveryError, match="timed out"):
        REAL_SEND_EMAIL("user@example.com", "Subject", "Body")


def _user(db, suffix):
    user = User(
        email=f"notification-{suffix}@test.com",
        password_hash=hash_password("Test@12345"),
    )
    db.add(user)
    db.flush()
    return user


def test_threshold_notifications_are_targeted_and_idempotent(monkeypatch):
    sent = []
    monkeypatch.setattr(email_service, "send_email", lambda recipient, subject, body: sent.append(recipient))
    db = SessionLocal()
    user = _user(db, "threshold")
    for _ in range(R1_HIGH_FAILS):
        db.add(Event(user_id=user.id, email_tried=user.email, device_id="x", type="login_fail"))
    db.flush()
    incident, changed = record_r1_incident(db, user)
    assert changed and incident.severity == "high"
    create_notification(
        db,
        recipient=user.email,
        user_id=user.id,
        incident_id=incident.id,
        kind="r1_high",
        subject="high",
        body="high",
        idempotency_key=f"test-high:{user.id}",
    )
    create_notification(
        db,
        recipient=user.email,
        user_id=user.id,
        incident_id=incident.id,
        kind="r1_high",
        subject="high",
        body="high",
        idempotency_key=f"test-high:{user.id}",
    )
    for _ in range(R1_CRITICAL_FAILS - R1_HIGH_FAILS):
        db.add(Event(user_id=user.id, email_tried=user.email, device_id="x", type="login_fail"))
    db.flush()
    incident, changed = record_r1_incident(db, user)
    assert changed and incident.severity == "critical"
    create_notification(
        db,
        recipient=user.email,
        user_id=user.id,
        incident_id=incident.id,
        kind="r1_critical",
        subject="critical",
        body="critical",
        idempotency_key=f"test-critical:{user.id}",
    )
    db.commit()
    assert sent == [user.email, user.email]
    db.close()


def test_verification_request_is_single_use_and_trusts_only_after_success(monkeypatch, client):
    monkeypatch.setattr(email_service, "send_email", lambda recipient, subject, body: None)
    db = SessionLocal()
    user = _user(db, "verification")
    request, raw_token, body = create_verification_request(
        db, user, "new-device", "203.0.113.10"
    )
    user_id = user.id
    create_notification(
        db,
        recipient=user.email,
        user_id=user.id,
        kind="new_device_verification",
        subject="verify",
        body=body,
        idempotency_key=f"test-verification:{request.id}",
    )
    db.commit()
    db.close()

    response = client.get("/verify-device", params={"token": raw_token})
    assert response.status_code == 200
    assert response.json()["status"] == "verified"
    assert client.get("/verify-device", params={"token": raw_token}).status_code == 400

    db = SessionLocal()
    assert db.query(TrustedDevice).filter(
        TrustedDevice.user_id == user_id,
        TrustedDevice.device_id == "new-device",
    ).count() == 1
    assert db.query(VerificationRequest).filter(
        VerificationRequest.user_id == user_id,
        VerificationRequest.used_at.is_not(None),
    ).count() == 1
    db.close()


def test_expired_verification_is_rejected(client):
    db = SessionLocal()
    user = _user(db, "expired")
    request, raw_token, _ = create_verification_request(
        db, user, "expired-device", "203.0.113.11"
    )
    request.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    db.close()
    assert client.get("/verify-device", params={"token": raw_token}).status_code == 400


def test_mailjet_configuration_failure_is_recorded_without_raising(monkeypatch):
    def fail(*args, **kwargs):
        raise EmailConfigurationError("Mailjet is not configured")

    monkeypatch.setattr(email_service, "send_email", fail)
    db = SessionLocal()
    user = _user(db, "failure")
    notification = create_notification(
        db,
        recipient=user.email,
        user_id=user.id,
        kind="test",
        subject="test",
        body="test",
        idempotency_key=f"test-failure:{user.id}",
    )
    db.commit()
    assert notification.status == "failed"
    assert "Mailjet is not configured" in notification.last_error
    db.close()


def test_shared_ip_rate_limit_does_not_revoke_existing_session(client, login):
    token = login(email="ali@test.com", device="existing-session").json()["token"]
    db = SessionLocal()
    users = db.query(User).filter(User.role == "user").limit(4).all()
    for user in users:
        db.add(Event(
            user_id=user.id,
            email_tried=user.email,
            device_id="shared-ip",
            ip="testclient",
            type="login_fail",
        ))
    db.commit()
    assert ip_retry_after(db, "testclient") > 0
    db.close()
    assert client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
