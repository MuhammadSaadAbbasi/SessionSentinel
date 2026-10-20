"""Rule-based investigation for an incident."""

import re

from sqlalchemy.orm import Session

from config import R1_CORRELATION_SECONDS, R1_HIGH_FAILS, R1_WINDOW_SECONDS
from models import Event, Incident, User, utcnow


def _iso(value):
    return value.isoformat() + "Z"


def investigate(db: Session, incident: Incident) -> dict:
    shared_ip = None
    if incident.user_id is None:
        match = re.search(r"R6: shared IP ([^;]+)", incident.explanation)
        shared_ip = match.group(1) if match else None
    event_query = db.query(Event)
    if incident.user_id is None:
        event_query = event_query.filter(Event.ip == shared_ip)
    else:
        event_query = event_query.filter(Event.user_id == incident.user_id)
    events = event_query.order_by(Event.created_at.asc(), Event.id.asc()).limit(200).all()
    user = db.get(User, incident.user_id) if incident.user_id else None
    failures = [event for event in events if event.type == "login_fail"]
    successful = [event for event in events if event.type == "login_ok"]
    new_devices = [event for event in events if event.type == "new_device"]
    recent_failures = [
        event for event in failures
        if (utcnow() - event.created_at).total_seconds() <= R1_WINDOW_SECONDS
    ]
    r1 = len(recent_failures) >= R1_HIGH_FAILS
    r2 = r1 and any(
        success.created_at >= recent_failures[0].created_at
        for success in successful
    )
    r3 = bool(new_devices)
    r6 = incident.explanation.startswith("R6:")

    indicators = []
    if r1:
        indicators.append(
            f"{R1_HIGH_FAILS} failed logins within {R1_WINDOW_SECONDS // 60} minutes"
        )
    if r2:
        indicators.append("successful login followed the failed-login sequence")
    if r3:
        indicators.append("login from an unfamiliar device")
    if r6:
        indicators.append("suspicious login activity shared an IP across accounts")
    if not indicators:
        indicators.append(incident.explanation or "incident was raised for review")

    if r6:
        risk = "high"
        recommendation = "apply IP-level rate limiting and investigate the affected accounts"
    elif r1 and r2 and r3:
        risk = "high"
        recommendation = "revoke the session, require re-authentication, and notify the owner"
    elif r1 or r3:
        risk = "medium"
        recommendation = "verify the activity with the account owner"
    else:
        risk = incident.severity
        recommendation = "continue monitoring the account"

    return {
        "incident_id": incident.id,
        "user": user.email if user else None,
        "risk_level": risk,
        "evidence": indicators,
        "explanation": (
            f"Incident: Possible account compromise\n"
            f"Evidence: {'; '.join(indicators)}\n"
            f"Assessment: {risk.capitalize()} priority\n"
            f"Recommended: {recommendation}"
        ),
        "recommended_action": recommendation,
        "timeline": [
            {
                "id": event.id,
                "type": event.type,
                "device_id": event.device_id,
                "ip": event.ip,
                "created_at": _iso(event.created_at),
            }
            for event in events
        ],
    }
