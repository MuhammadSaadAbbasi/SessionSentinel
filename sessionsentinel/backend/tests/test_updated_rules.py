from database import SessionLocal
from models import Event, Incident, User, utcnow
from services.detection import (
    account_retry_after,
    record_r1_incident,
    record_shared_ip_incident,
)


def test_r1_escalates_one_incident_at_five_and_ten_failures():
    db = SessionLocal()
    user = db.query(User).filter(User.email == "ali@test.com").one()
    for _ in range(5):
        db.add(Event(
            user_id=user.id,
            email_tried=user.email,
            device_id="r1-test",
            ip="198.51.100.10",
            type="login_fail",
        ))
    db.flush()
    incident, changed = record_r1_incident(db, user)
    assert changed and incident.severity == "high"

    for _ in range(5):
        db.add(Event(
            user_id=user.id,
            email_tried=user.email,
            device_id="r1-test",
            ip="198.51.100.10",
            type="login_fail",
        ))
    db.flush()
    escalated, changed = record_r1_incident(db, user)
    assert changed and escalated.id == incident.id
    assert escalated.severity == "critical"
    assert account_retry_after(db, user.id, user.email) > 0
    assert db.query(Incident).filter(Incident.user_id == user.id).count() == 1
    db.rollback()
    db.close()


def test_r6_records_accounts_and_timestamps_for_shared_ip():
    db = SessionLocal()
    users = db.query(User).filter(User.role == "user").limit(4).all()
    ip = "198.51.100.77"
    for user in users:
        db.add(Event(
            user_id=user.id,
            email_tried=user.email,
            device_id="r6-test",
            ip=ip,
            type="login_fail",
            created_at=utcnow(),
        ))
    db.flush()
    incident, changed = record_shared_ip_incident(db, ip)
    assert changed and incident.severity == "high"
    assert "affected accounts:" in incident.explanation
    assert "timestamps:" in incident.explanation
    db.rollback()
    db.close()
