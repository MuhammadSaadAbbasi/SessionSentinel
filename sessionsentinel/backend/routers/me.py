# routers/me.py
# Logged-in user ki apni information. Har query user_id se filter hoti hai (doosre ka data nahi dikhta).
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_session, get_current_user
from models import Event, Incident, TrustedDevice, User, UserSession
from schemas import UserReportRequest
from services.response import revoke_all_sessions
from services.audit_log import append
from services.email_service import create_notification

router = APIRouter()


def _iso(dt):
    return dt.isoformat() + "Z"        # DB mein UTC save hai, "Z" laga ke frontend ko batate hain


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "role": user.role}


@router.get("/me/activity")
def activity(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    events = (db.query(Event).filter(Event.user_id == user.id)
              .order_by(Event.created_at.desc(), Event.id.desc()).limit(50).all())
    return [{"id": e.id, "type": e.type, "device_id": e.device_id, "ip": e.ip,
             "created_at": _iso(e.created_at)} for e in events]


@router.get("/me/sessions")
def sessions(user: User = Depends(get_current_user), cur: UserSession = Depends(get_current_session),
             db: Session = Depends(get_db)):
    rows = (db.query(UserSession).filter(UserSession.user_id == user.id, UserSession.revoked == False)  # noqa: E712
            .order_by(UserSession.created_at.desc()).all())
    return [{"id": s.id, "device_id": s.device_id, "created_at": _iso(s.created_at),
             "current": s.id == cur.id} for s in rows]


@router.post("/me/report")
def report(
    body: UserReportRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    event = db.query(Event).filter(Event.id == body.event_id, Event.user_id == user.id).first()
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    if not body.is_me:
        user.password_reset_required = True
        revoke_all_sessions(db, user.id, user.email)
        incident = Incident(
            user_id=user.id,
            severity="high",
            status="open",
            explanation=f"R5: user reported event {event.id} as unauthorized",
        )
        db.add(incident)
        append(db, "unauthorized_activity_reported", user.email, f"event_id={event.id}")
        create_notification(
            db,
            recipient=user.email,
            user_id=user.id,
            incident_id=incident.id,
            kind="unauthorized_activity",
            subject="SessionSentinel: Account Protection Activated",
            body=(
                "SessionSentinel Account Protection\n\n"
                "Event: Unauthorized activity reported\n"
                f"Account: {user.email}\n"
                f"Detected: {_iso(event.created_at)}\n\n"
                "All active sessions were revoked and a password reset is required. "
                "If you need help, contact your administrator."
            ),
            idempotency_key=f"unauthorized:{user.id}:{event.id}",
        )
    else:
        device = db.query(TrustedDevice).filter(
            TrustedDevice.user_id == user.id,
            TrustedDevice.device_id == event.device_id,
        ).first()
        if device is None:
            db.add(TrustedDevice(user_id=user.id, device_id=event.device_id))
        incident = db.query(Incident).filter(
            Incident.user_id == user.id,
            Incident.status == "open",
            Incident.explanation.like("%new device%"),
        ).order_by(Incident.id.desc()).first()
        if incident:
            incident.status = "resolved"
        append(db, "activity_confirmed", user.email, f"event_id={event.id};device_id={event.device_id}")
    db.commit()
    return {"status": "ok"}
