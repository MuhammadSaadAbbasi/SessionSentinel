"""Append-only, hash-chained audit log helpers."""

import hashlib

from sqlalchemy.orm import Session

from models import AuditLog, utcnow

GENESIS_HASH = "0" * 64


def _digest(prev_hash: str, action: str, actor: str, details: str, created_at) -> str:
    payload = f"{prev_hash}{action}{actor}{details}{created_at.isoformat()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append(db: Session, action: str, actor: str, details: str) -> AuditLog:
    previous = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = previous.hash if previous else GENESIS_HASH
    created_at = utcnow()
    entry = AuditLog(
        action=action,
        actor=actor,
        details=details,
        created_at=created_at,
        prev_hash=prev_hash,
        hash=_digest(prev_hash, action, actor, details, created_at),
    )
    db.add(entry)
    return entry


def verify(db: Session) -> str | int:
    previous_hash = GENESIS_HASH
    entries = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    for entry in entries:
        expected = _digest(
            previous_hash,
            entry.action,
            entry.actor,
            entry.details,
            entry.created_at,
        )
        if entry.prev_hash != previous_hash or entry.hash != expected:
            return entry.id
        previous_hash = entry.hash
    return "valid"
