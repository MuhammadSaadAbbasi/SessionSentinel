"""Detection rules and response state used by the login and report routes."""

from datetime import timedelta

from sqlalchemy.orm import Session

from config import (
    R1_CORRELATION_SECONDS,
    R1_CRITICAL_FAILS,
    R1_HIGH_FAILS,
    R1_LOCK_SECONDS,
    R1_WINDOW_SECONDS,
    R6_ACCOUNT_THRESHOLD,
    R6_IP_THROTTLE_SECONDS,
)
from models import Event, Incident, TrustedDevice, User


def _window_start(seconds: int = R1_WINDOW_SECONDS):
    from models import utcnow

    return utcnow() - timedelta(seconds=seconds)


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
    return len(failed_logins(db, user_id, email)) >= R1_HIGH_FAILS


def account_retry_after(db: Session, user_id: int, email: str) -> int:
    failures = failed_logins(db, user_id, email)
    if len(failures) < R1_CRITICAL_FAILS:
        return 0
    from models import utcnow

    elapsed = int((utcnow() - failures[-R1_CRITICAL_FAILS].created_at).total_seconds())
    return max(1, R1_LOCK_SECONDS - elapsed)


def ip_retry_after(db: Session, ip: str | None) -> int:
    if not ip:
        return 0
    accounts = suspicious_accounts(db, ip)
    if len(accounts) <= R6_ACCOUNT_THRESHOLD:
        return 0
    from models import utcnow

    latest = (
        db.query(Event)
        .filter(Event.ip == ip, Event.type.in_(("login_fail", "new_device")))
        .order_by(Event.created_at.desc())
        .first()
    )
    if latest is None:
        return 0
    elapsed = int((utcnow() - latest.created_at).total_seconds())
    return max(1, R6_IP_THROTTLE_SECONDS - elapsed)


def _incident_exists(db: Session, user_id: int | None, explanation: str) -> Incident | None:
    return db.query(Incident).filter(
        Incident.user_id == user_id,
        Incident.explanation == explanation,
        Incident.created_at >= _window_start(),
    ).first()


def r1_severity(failure_count: int) -> str | None:
    if failure_count >= R1_CRITICAL_FAILS:
        return "critical"
    if failure_count >= R1_HIGH_FAILS:
        return "high"
    return None


def record_r1_incident(db: Session, user: User) -> tuple[Incident | None, bool]:
    failure_count = len(failed_logins(db, user.id, user.email))
    severity = r1_severity(failure_count)
    if severity is None:
        return None, False
    explanation = (
        f"R1: {failure_count} failed logins within {R1_WINDOW_SECONDS} seconds"
    )
    incident = (
        db.query(Incident)
        .filter(
            Incident.user_id == user.id,
            Incident.explanation.like("R1:%"),
            Incident.created_at >= _window_start(),
        )
        .order_by(Incident.id.desc())
        .first()
    )
    changed = False
    if incident is None:
        incident = Incident(
            user_id=user.id,
            severity=severity,
            status="open",
            explanation=explanation,
        )
        db.add(incident)
        changed = True
    elif incident.severity != severity and (
        severity == "critical" or incident.severity != "critical"
    ):
        incident.severity = severity
        incident.explanation = explanation
        changed = True
    return incident, changed


def suspicious_accounts(db: Session, ip: str) -> set[int]:
    events = (
        db.query(Event)
        .filter(
            Event.ip == ip,
            Event.user_id.is_not(None),
            Event.type.in_(("login_fail", "new_device")),
            Event.created_at >= _window_start(),
        )
        .all()
    )
    return {event.user_id for event in events if event.user_id is not None}


def record_shared_ip_incident(db: Session, ip: str | None) -> tuple[Incident | None, bool]:
    if not ip:
        return None, False
    accounts = suspicious_accounts(db, ip)
    if len(accounts) <= R6_ACCOUNT_THRESHOLD:
        return None, False
    account_list = ", ".join(str(account_id) for account_id in sorted(accounts))
    explanation_prefix = f"R6: shared IP {ip}"
    incident = (
        db.query(Incident)
        .filter(
            Incident.user_id.is_(None),
            Incident.explanation.like(f"{explanation_prefix}%"),
            Incident.created_at >= _window_start(),
        )
        .order_by(Incident.id.desc())
        .first()
    )
    timestamps = (
        db.query(Event)
        .filter(
            Event.ip == ip,
            Event.user_id.is_not(None),
            Event.type.in_(("login_fail", "new_device")),
            Event.created_at >= _window_start(),
        )
        .order_by(Event.created_at.asc())
        .all()
    )
    details = ", ".join(
        f"user={event.user_id}@{event.created_at.isoformat()}Z" for event in timestamps
    )
    explanation = (
        f"{explanation_prefix}; affected accounts: {account_list}; "
        f"timestamps: {details}"
    )
    if incident is None:
        incident = Incident(
            user_id=None,
            severity="high",
            status="open",
            explanation=explanation,
        )
        db.add(incident)
        return incident, True
    if incident.explanation != explanation:
        incident.explanation = explanation
        return incident, True
    return incident, False


def inspect_success(
    db: Session, user: User, device_id: str, ip: str | None
) -> tuple[bool, bool, bool]:
    """Return (R1 active, unfamiliar device, unusual location) before trust updates."""
    r1 = r1_triggered(db, user.id, user.email)
    has_trusted_device = db.query(TrustedDevice).filter(
        TrustedDevice.user_id == user.id
    ).count() > 0
    if not has_trusted_device:
        return r1, False, False
    known = db.query(TrustedDevice).filter(
        TrustedDevice.user_id == user.id,
        TrustedDevice.device_id == device_id,
    ).first() is not None
    unfamiliar = not known
    known_ips = {
        event.ip
        for event in db.query(Event).filter(
            Event.user_id == user.id,
            Event.type == "login_ok",
            Event.ip.is_not(None),
        ).all()
    }
    unusual_location = bool(ip and known_ips and ip not in known_ips)
    if unfamiliar:
        db.add(Event(
            user_id=user.id,
            email_tried=user.email,
            device_id=device_id,
            type="new_device",
            ip=ip,
        ))
        explanation = "R3: successful login from a new device"
        if _incident_exists(db, user.id, explanation) is None:
            db.add(Incident(
                user_id=user.id,
                severity="medium",
                status="open",
                explanation=explanation,
            ))
    elif unusual_location:
        db.add(Event(
            user_id=user.id,
            email_tried=user.email,
            device_id=device_id,
            type="unusual_location",
            ip=ip,
        ))
        explanation = "R3: successful login from an unusual location"
        if _incident_exists(db, user.id, explanation) is None:
            db.add(Incident(
                user_id=user.id,
                severity="medium",
                status="open",
                explanation=explanation,
            ))
    return r1, unfamiliar, unusual_location


def r2_triggered(db: Session, user_id: int) -> bool:
    failures = (
        db.query(Event)
        .filter(
            Event.user_id == user_id,
            Event.type == "login_fail",
            Event.created_at >= _window_start(R1_CORRELATION_SECONDS),
        )
        .order_by(Event.created_at.asc())
        .all()
    )
    if len(failures) < R1_HIGH_FAILS:
        return False
    return (
        db.query(Event)
        .filter(
            Event.user_id == user_id,
            Event.type == "login_ok",
            Event.created_at >= failures[-R1_HIGH_FAILS].created_at,
        )
        .first()
        is not None
    )
