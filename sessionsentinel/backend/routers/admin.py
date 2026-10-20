# Admin incident investigation endpoints.
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from deps import require_admin
from models import Incident, Notification, User, UserSession
from schemas import IncidentStatusRequest
from services.agent import investigate
from services.response import revoke_session, update_incident_status
from services.email_service import retry_notification

router = APIRouter()


def _summary(db: Session, incident: Incident) -> dict:
    user = db.get(User, incident.user_id) if incident.user_id else None
    notifications = db.query(Notification).filter(
        Notification.incident_id == incident.id
    ).all()
    return {
        "id": incident.id,
        "user_id": incident.user_id,
        "email": user.email if user else None,
        "severity": incident.severity,
        "status": incident.status,
        "explanation": incident.explanation,
        "created_at": incident.created_at.isoformat() + "Z",
        "notification_status": [
            {
                "id": item.id,
                "kind": item.kind,
                "status": item.status,
                "attempts": item.attempts,
                "last_error": item.last_error,
                "created_at": item.created_at.isoformat() + "Z",
            }
            for item in notifications
        ],
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


@router.get("/admin/notifications")
def list_notifications(
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    notifications = db.query(Notification).order_by(Notification.created_at.desc()).limit(200).all()
    return [
        {
            "id": item.id,
            "incident_id": item.incident_id,
            "recipient": item.recipient,
            "kind": item.kind,
            "status": item.status,
            "attempts": item.attempts,
            "last_error": item.last_error,
            "created_at": item.created_at.isoformat() + "Z",
            "sent_at": item.sent_at.isoformat() + "Z" if item.sent_at else None,
        }
        for item in notifications
    ]


@router.post("/admin/notifications/{notification_id}/retry")
def retry_email(
    notification_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    notification = db.get(Notification, notification_id)
    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    retry_notification(db, notification)
    append_details = f"notification_id={notification.id};status={notification.status}"
    from services.audit_log import append

    append(db, "notification_retry", admin.email, append_details)
    db.commit()
    return {"status": notification.status, "attempts": notification.attempts}
