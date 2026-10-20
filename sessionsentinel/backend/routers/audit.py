# Audit log viewer and integrity verification.
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from deps import require_admin
from models import AuditLog, User
from services.audit_log import verify

router = APIRouter()


@router.get("/audit")
def audit_entries(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    entries = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all()
    return [
        {
            "id": entry.id,
            "action": entry.action,
            "actor": entry.actor,
            "details": entry.details,
            "created_at": entry.created_at.isoformat() + "Z",
            "prev_hash": entry.prev_hash,
            "hash": entry.hash,
        }
        for entry in entries
    ]


@router.get("/audit/verify")
def verify_audit(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    result = verify(db)
    return {"status": "valid"} if result == "valid" else {"status": "broken", "entry_id": result}
