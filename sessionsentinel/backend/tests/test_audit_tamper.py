from database import SessionLocal
from models import AuditLog
from services.audit_log import append, verify


def test_audit_chain_detects_tampering():
    db = SessionLocal()
    append(db, "test_action", "test", "details")
    db.commit()
    assert verify(db) == "valid"
    entry = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    entry.details = "tampered"
    db.commit()
    assert verify(db) == entry.id
    entry.details = "details"
    db.commit()
    assert verify(db) == "valid"
    db.close()
