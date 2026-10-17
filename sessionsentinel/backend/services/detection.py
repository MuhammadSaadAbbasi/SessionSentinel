"""Account-scoped detection rules used by the login route."""

from datetime import timedelta

from sqlalchemy.orm import Session

from config import R1_MAX_FAILS, R1_THROTTLE_SECONDS, R1_WINDOW_SECONDS
from models import Event, Incident, TrustedDevice, User


def _window_start():
    from models import utcnow

    return utcnow() - timedelta(seconds=R1_WINDOW_SECONDS)


def failed_logins(db: Session, user_id: int | None, email: str) -> list[Event]:
    query = db.query(Event).filter(
        Event.type == "login_fail",
        Event.created_at >= _window_start(),
    )
    if user_id is None:
        query = query.filter(Event.user_id.is_(None), Event.email_tried == email)
    else:
        query = query.filter(Event.user_id == user_id)
    return query.order_by(Event.created_at.asc()).all()


def r1_triggered(db: Session, user_id: int | None, email: str) -> bool:
    return len(failed_logins(db, user_id, email)) >= R1_MAX_FAILS


def retry_after(db: Session, user_id: int, email: str) -> int:
    failures = failed_logins(db, user_id, email)
    if len(failures) < R1_MAX_FAILS:
        return 0
    from models import utcnow

    elapsed = int((utcnow() - failures[-R1_MAX_FAILS].created_at).total_seconds())
    return max(1, R1_THROTTLE_SECONDS - elapsed)


def _incident_exists(db: Session, user_id: int, explanation: str) -> bool:
    return db.query(Incident).filter(
        Incident.user_id == user_id,
        Incident.explanation == explanation,
        Incident.created_at >= _window_start(),
    ).first() is not None


def record_r1_incident(db: Session, user: User) -> Incident | None:
    explanation = f"R1: {R1_MAX_FAILS} failed logins within {R1_WINDOW_SECONDS} seconds"
    if _incident_exists(db, user.id, explanation):
        return None
    incident = Incident(
        user_id=user.id,
        severity="medium",
        status="open",
        explanation=explanation,
    )
    db.add(incident)
    return incident


def inspect_success(
    db: Session, user: User, device_id: str
) -> tuple[bool, bool]:
    """Return (R1 was active, device was unfamiliar) before trust is updated."""
    r1 = r1_triggered(db, user.id, user.email)
    if db.query(TrustedDevice).filter(TrustedDevice.user_id == user.id).count() == 0:
        return r1, False
    known = db.query(TrustedDevice).filter(
        TrustedDevice.user_id == user.id,
        TrustedDevice.device_id == device_id,
    ).first() is not None
    unfamiliar = not known
    if unfamiliar:
        db.add(Event(
            user_id=user.id,
            email_tried=user.email,
            device_id=device_id,
            type="new_device",
        ))
        explanation = "R3: successful login from a new device"
        if not _incident_exists(db, user.id, explanation):
            db.add(Incident(
                user_id=user.id,
                severity="medium",
                status="open",
                explanation=explanation,
            ))
    return r1, unfamiliar
