from datetime import timedelta

import services.email_service as email_service
from config import R1_CRITICAL_FAILS, R1_HIGH_FAILS
from database import SessionLocal
from models import Event, TrustedDevice, User, VerificationRequest, utcnow
from services.detection import record_r1_incident
from services.detection import ip_retry_after
from services.email_service import (
    EmailConfigurationError,
    create_notification,
    create_verification_request,
)
from security import hash_password


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


def test_smtp_configuration_failure_is_recorded_without_raising(monkeypatch):
    def fail(*args, **kwargs):
        raise EmailConfigurationError("SMTP is not configured")

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
    assert "SMTP is not configured" in notification.last_error
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
