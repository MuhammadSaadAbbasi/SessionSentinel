# Admin incident investigation endpoints.
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from deps import require_admin
from models import Incident, User
from services.agent import investigate

router = APIRouter()


def _summary(db: Session, incident: Incident) -> dict:
    user = db.get(User, incident.user_id) if incident.user_id else None
    return {
        "id": incident.id,
        "user_id": incident.user_id,
        "email": user.email if user else None,
        "severity": incident.severity,
        "status": incident.status,
        "explanation": incident.explanation,
        "created_at": incident.created_at.isoformat() + "Z",
    }


@router.get("/admin/incidents")
def list_incidents(
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)
    incidents = query.order_by(Incident.created_at.desc(), Incident.id.desc()).all()
    return [_summary(db, incident) for incident in incidents]


@router.get("/admin/incidents/{incident_id}")
def incident_detail(
    incident_id: int,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = _summary(db, incident)
    result.update(investigate(db, incident))
    return result
