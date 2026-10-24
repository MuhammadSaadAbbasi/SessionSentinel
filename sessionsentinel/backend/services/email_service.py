"""Resend delivery and security-email templates."""

import hashlib
import html
import secrets
from datetime import timedelta
from urllib.parse import quote

import logging
import html
import resend
from resend.exceptions import ResendError

from config import (
    ADMIN_EMAIL,
    APP_BASE_URL,
    RESEND_API_KEY,
    RESEND_FROM_EMAIL,
    VERIFICATION_TTL_SECONDS,
    EMAIL_VERIFICATION_TTL_SECONDS,
    SESSION_CANCELLATION_TTL_SECONDS,
)
from models import (
    EmailVerificationRequest,
    Notification,
    SessionCancellationRequest,
    User,
    UserSession,
    VerificationRequest,
    utcnow,
)


class EmailConfigurationError(RuntimeError):
    pass


class EmailDeliveryError(RuntimeError):
    pass


def _resend_configured() -> bool:
    return bool(RESEND_API_KEY and RESEND_FROM_EMAIL)



logger = logging.getLogger(__name__)

def send_email(recipient: str, subject: str, body: str) -> None:
    if not _resend_configured():
        raise EmailConfigurationError(
            "Resend is not configured; set RESEND_API_KEY and RESEND_FROM_EMAIL"
        )

    if "@" not in recipient or recipient.count("@") != 1:
        raise EmailDeliveryError("Invalid notification recipient")

    resend.api_key = RESEND_API_KEY

    try:
        resend.Emails.send(
            {
                "from": RESEND_FROM_EMAIL,
                "to": recipient,
                "subject": subject,
                "html": html.escape(body).replace("\n", "<br>"),
            }
        )
    except Exception as exc:
        logger.exception("Email sending failed; exception type: %s", type(exc).__name__)
        raise EmailDeliveryError(
            f"Email delivery failed ({type(exc).__name__})"
        ) from exc


def create_notification(
    db,
    *,
    recipient: str,
    kind: str,
    subject: str,
    body: str,
    idempotency_key: str,
    user_id: int | None = None,
    incident_id: int | None = None,
) -> Notification:
    existing = db.query(Notification).filter(
        Notification.idempotency_key == idempotency_key
    ).first()
    if existing is not None:
        return existing
    notification = Notification(
        user_id=user_id,
        incident_id=incident_id,
        recipient=recipient,
        kind=kind,
        subject=subject,
        body=body,
        idempotency_key=idempotency_key,
        status="pending",
    )
    db.add(notification)
    db.flush()
    try:
        send_email(recipient, subject, body)
    except (EmailConfigurationError, EmailDeliveryError) as exc:
        notification.status = "failed"
        notification.last_error = str(exc)
    else:
        notification.status = "sent"
        notification.sent_at = utcnow()
    notification.attempts += 1
    return notification


def retry_notification(db, notification: Notification) -> Notification:
    if notification.status == "sent":
        return notification
    try:
        send_email(notification.recipient, notification.subject, notification.body)
    except (EmailConfigurationError, EmailDeliveryError) as exc:
        notification.status = "failed"
        notification.last_error = str(exc)
    else:
        notification.status = "sent"
        notification.last_error = None
        notification.sent_at = utcnow()
    notification.attempts += 1
    return notification
def failed_login_body(user: User, count: int, severity: str) -> str:
    return (
        "SessionSentinel Security Alert\n\n"
        "Event: Repeated failed login attempts\n"
        f"Account: {user.email}\n"
        f"Detected: {utcnow().isoformat()}Z\n"
        f"Attempts in the configured window: {count}\n"
        f"Severity: {severity}\n\n"
        "If this activity was not yours, reset your password and review active sessions."
    )


def critical_login_body(user: User, count: int) -> str:
    return (
        "SessionSentinel Critical Security Alert\n\n"
        "Event: Critical repeated login activity\n"
        f"Account: {user.email}\n"
        f"Detected: {utcnow().isoformat()}Z\n"
        f"Attempts in the configured window: {count}\n\n"
        "A temporary account restriction is active. If this was not you, secure your "
        "account and contact an administrator."
    )


def unusual_location_body(user: User, ip: str | None) -> str:
    return (
        "SessionSentinel Security Alert\n\n"
        "Event: Login from an unusual location\n"
        f"Account: {user.email}\n"
        f"Detected: {utcnow().isoformat()}Z\n"
        f"Network address: {ip or ' unavailable'}\n\n"
        "Review this activity. A network address alone does not prove compromise; "
        "secure your account if you do not recognize the sign-in."
    )


def create_verification_request(db, user: User, device_id: str, ip: str | None):
    raw_token = secrets.token_urlsafe(32)
    request = VerificationRequest(
        user_id=user.id,
        device_id=device_id,
        ip=ip,
        token_hash=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
        expires_at=utcnow() + timedelta(seconds=VERIFICATION_TTL_SECONDS),
    )
    db.add(request)
    db.flush()
    link = f"{APP_BASE_URL.rstrip('/')}/verify-device?token={quote(raw_token)}"
    body = (
        "SessionSentinel Security Verification\n\n"
        "Event: New device sign-in verification\n"
        f"Account: {user.email}\n"
        f"Detected: {utcnow().isoformat()}Z\n"
        f"Device: {device_id}\n\n"
        f"Verify this device using the following link (valid for {VERIFICATION_TTL_SECONDS // 60} minutes):\n"
        f"{link}\n\n"
        "If you did not initiate this sign-in, do not use the link and secure your account."
    )
    return request, raw_token, body


def create_email_verification_request(db, user: User):
    raw_token = secrets.token_urlsafe(32)
    request = EmailVerificationRequest(
        user_id=user.id,
        token_hash=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
        expires_at=utcnow() + timedelta(seconds=EMAIL_VERIFICATION_TTL_SECONDS),
    )
    db.add(request)
    db.flush()
    link = f"{APP_BASE_URL.rstrip('/')}/verify-email?token={quote(raw_token)}"
    body = (
        "SessionSentinel Email Verification\n\n"
        f"Verify your account using this link (valid for "
        f"{EMAIL_VERIFICATION_TTL_SECONDS // 3600} hours):\n{link}\n\n"
        "If you did not create this account, ignore this message."
    )
    return request, body


def create_session_cancellation_request(db, user: User, session: UserSession):
    raw_token = secrets.token_urlsafe(32)
    request = SessionCancellationRequest(
        user_id=user.id,
        session_id=session.id,
        token_hash=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
        expires_at=utcnow() + timedelta(seconds=SESSION_CANCELLATION_TTL_SECONDS),
    )
    db.add(request)
    db.flush()
    link = f"{APP_BASE_URL.rstrip('/')}/cancel-session?token={quote(raw_token)}"
    body = (
        "SessionSentinel Session Security\n\n"
        f"A new sign-in session was created for {user.email}.\n\n"
        f"If this was not you, cancel it here (link valid for "
        f"{SESSION_CANCELLATION_TTL_SECONDS // 60} minutes):\n{link}\n\n"
        "This link cancels only this sign-in session."
    )
    return request, body


def admin_recipient() -> str | None:
    return ADMIN_EMAIL or None
