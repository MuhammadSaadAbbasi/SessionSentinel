"""Security response actions used by admin and user report routes."""

from sqlalchemy.orm import Session

from models import Incident, UserSession
from services.audit_log import append


def revoke_session(db: Session, session: UserSession, actor: str) -> None:
    session.revoked = True
    append(db, "session_revoked", actor, f"session_id={session.id}")


def update_incident_status(
    db: Session, incident: Incident, status: str, actor: str, note: str
) -> None:
    incident.status = status
    incident.explanation = f"{incident.explanation}\nStatus note: {note}".strip()
    append(db, "incident_status_changed", actor, f"incident_id={incident.id};status={status}")


def revoke_all_sessions(db: Session, user_id: int, actor: str) -> int:
    sessions = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.revoked.is_(False),
    ).all()
    for session in sessions:
        session.revoked = True
    if sessions:
        append(db, "all_sessions_revoked", actor, f"user_id={user_id};count={len(sessions)}")
    return len(sessions)
