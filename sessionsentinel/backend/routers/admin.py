# Admin incident investigation endpoints.
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from deps import require_admin
from models import Incident, User, UserSession
from schemas import IncidentStatusRequest
from services.agent import investigate
from services.response import revoke_session, update_incident_status

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


@router.post("/admin/sessions/{session_id}/revoke")
def revoke(
    session_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    session = db.get(UserSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.revoked:
        revoke_session(db, session, admin.email)
        db.commit()
    return {"status": "ok"}


@router.post("/admin/incidents/{incident_id}/status")
def set_status(
    incident_id: int,
    body: IncidentStatusRequest,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    allowed = {"open", "investigating", "contained", "resolved", "false_positive"}
    if body.status not in allowed:
        raise HTTPException(status_code=422, detail="Invalid incident status")
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    update_incident_status(db, incident, body.status, admin.email, body.note)
    db.commit()
    return {"status": "ok"}
