# routers/auth.py
# /login aur /logout.
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_session
from models import Event, Incident, TrustedDevice, User, UserSession, VerificationRequest, utcnow
from schemas import LoginRequest, PasswordResetRequest
from security import hash_password, new_token, verify_password
from services.audit_log import append
from services.email_service import (
    admin_recipient,
    create_notification,
    create_verification_request,
    critical_login_body,
    failed_login_body,
    unusual_location_body,
)
from services.detection import (
    failed_logins,
    account_retry_after,
    ip_retry_after,
    inspect_success,
    r2_triggered,
    record_shared_ip_incident,
    record_r1_incident,
)

router = APIRouter()


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None
    email = body.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    account_wait = account_retry_after(db, user.id, email) if user else 0
    ip_wait = ip_retry_after(db, ip)
    if account_wait or ip_wait:
        wait = max(account_wait, ip_wait)
        append(db, "login_throttled", "system", f"email={email};retry_after={wait}")
        db.commit()
        raise HTTPException(
            status_code=429,
            detail={"message": "Too many login attempts", "retry_after": wait},
            headers={"Retry-After": str(wait)},
        )
    if user is not None and user.password_reset_required:
        raise HTTPException(
            status_code=403,
            detail="Password reset required before signing in",
        )
    ok = user is not None and verify_password(body.password, user.password_hash)

    if not ok:
        # Fail ka event hamesha save hota hai (user na ho tab bhi, user_id None). Day 3 ke rules isi se chalte hain.
        db.add(Event(user_id=user.id if user else None, email_tried=email,
                     device_id=body.device_id, ip=ip, type="login_fail"))
        db.commit()
        if user is not None:
            incident, changed = record_r1_incident(db, user)
            if changed and incident is not None:
                append(db, "r1_escalated", "system", f"user_id={user.id};severity={incident.severity}")
                count = len(failed_logins(db, user.id, email))
                if incident.severity == "high":
                    create_notification(
                        db,
                        recipient=user.email,
                        user_id=user.id,
                        incident_id=incident.id,
                        kind="r1_high",
                        subject="SessionSentinel Security Alert: Repeated Failed Login Attempts",
                        body=failed_login_body(user, count, incident.severity),
                        idempotency_key=f"r1-high:{user.id}:{incident.id}",
                    )
                elif incident.severity == "critical":
                    create_notification(
                        db,
                        recipient=user.email,
                        user_id=user.id,
                        incident_id=incident.id,
                        kind="r1_critical",
                        subject="SessionSentinel Critical Alert: Temporary Account Restriction",
                        body=critical_login_body(user, count),
                        idempotency_key=f"r1-critical:{user.id}:{incident.id}",
                    )
                    recipient = admin_recipient()
                    if recipient:
                        create_notification(
                            db,
                            recipient=recipient,
                            incident_id=incident.id,
                            kind="r1_critical_admin",
                            subject="SessionSentinel Admin Alert: Critical Login Activity",
                            body=(
                                "SessionSentinel Admin Alert\n\n"
                                f"Account: {user.email}\n"
                                f"Detected: {utcnow().isoformat()}Z\n"
                                "A critical failed-login threshold was crossed and temporary "
                                "account protection is active."
                            ),
                            idempotency_key=f"r1-critical-admin:{user.id}:{incident.id}",
                        )
            shared_incident, shared_changed = record_shared_ip_incident(db, ip)
            if shared_changed and shared_incident is not None:
                append(db, "r6_shared_ip_detected", "system", shared_incident.explanation)
                recipient = admin_recipient()
                if recipient:
                    create_notification(
                        db,
                        recipient=recipient,
                        incident_id=shared_incident.id,
                        kind="r6_admin",
                        subject="SessionSentinel Admin Alert: Shared-IP Activity",
                        body=(
                            "SessionSentinel Admin Alert\n\n"
                            "Event: Shared-IP suspicious activity\n"
                            f"Detected: {utcnow().isoformat()}Z\n"
                            "Review the admin dashboard for affected account IDs and timestamps.\n\n"
                            f"{shared_incident.explanation}"
                        ),
                        idempotency_key=f"r6-admin:{shared_incident.id}",
                    )
            wait = account_retry_after(db, user.id, email)
            if wait:
                append(db, "login_throttled", "system", f"user_id={user.id};retry_after={wait}")
                db.commit()
                raise HTTPException(
                    status_code=429,
                    detail={"message": "Account temporarily locked", "retry_after": wait},
                    headers={"Retry-After": str(wait)},
                )
            ip_wait = ip_retry_after(db, ip)
            if ip_wait:
                db.commit()
                raise HTTPException(
                    status_code=429,
                    detail={"message": "IP temporarily rate limited", "retry_after": ip_wait},
                    headers={"Retry-After": str(ip_wait)},
                )
            db.commit()
        # Message same: attacker ko pata na chale ke email maujood hai ya nahi.
        raise HTTPException(status_code=401, detail="Invalid email or password")

    r1_active, unfamiliar_device, unusual_location = inspect_success(
        db, user, body.device_id, ip
    )
    if unfamiliar_device:
        verification, _, verification_body = create_verification_request(
            db, user, body.device_id, ip
        )
        create_notification(
            db,
            recipient=user.email,
            user_id=user.id,
            kind="new_device_verification",
            subject="SessionSentinel: Verify New Device Sign-In",
            body=verification_body,
            idempotency_key=f"new-device:{user.id}:{body.device_id}:{verification.id}",
        )
    elif unusual_location:
        incident = db.query(Incident).filter(
            Incident.user_id == user.id,
            Incident.explanation == "R3: successful login from an unusual location",
            Incident.status == "open",
        ).order_by(Incident.id.desc()).first()
        if incident is not None:
            create_notification(
                db,
                recipient=user.email,
                user_id=user.id,
                incident_id=incident.id,
                kind="unusual_location",
                subject="SessionSentinel: Review Unusual Login Location",
                body=unusual_location_body(user, ip),
                idempotency_key=f"unusual-location:{user.id}:{incident.id}",
            )
    db.add(Event(user_id=user.id, email_tried=email, device_id=body.device_id, ip=ip, type="login_ok"))
    if db.query(TrustedDevice).filter(
        TrustedDevice.user_id == user.id
    ).count() == 0:
        db.add(TrustedDevice(user_id=user.id, device_id=body.device_id))
    if r1_active and (unfamiliar_device or unusual_location):
        incident = db.query(Incident).filter(
            Incident.user_id == user.id,
            Incident.explanation.like("R1:%"),
            Incident.status == "open",
        ).order_by(Incident.id.desc()).first()
        if incident:
            incident.severity = "critical" if incident.severity == "critical" else "high"
            incident.explanation += (
                "\nR4: R1 sequence followed by a successful login from an "
                "unfamiliar device or location"
            )
    elif r1_active and r2_triggered(db, user.id):
        incident, _ = record_r1_incident(db, user)
        if incident is not None and "\nR2:" not in incident.explanation:
            incident.explanation += (
                "\nR2: successful login followed the repeated-failure sequence"
            )
            append(db, "r2_correlated", "system", f"user_id={user.id};incident_id={incident.id}")
    token = new_token()
    session = UserSession(user_id=user.id, token=token, device_id=body.device_id)
    db.add(session)
    if r1_active and (unfamiliar_device or unusual_location):
        session.revoked = True
        append(db, "high_risk_session_held", "system", f"user_id={user.id};device_id={body.device_id}")
    db.commit()
    return {
        "token": token,
        "role": user.role,
        "email": user.email,
        "requires_reauthentication": bool(
            r1_active and (unfamiliar_device or unusual_location)
        ),
    }


@router.get("/verify-device")
def verify_device(token: str = Query(min_length=20), db: Session = Depends(get_db)):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    request = db.query(VerificationRequest).filter(
        VerificationRequest.token_hash == token_hash
    ).first()
    if request is None or request.used_at is not None or request.expires_at <= utcnow():
        raise HTTPException(status_code=400, detail="Verification link is invalid or expired")
    user = db.get(User, request.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="Verification account not found")
    trusted = db.query(TrustedDevice).filter(
        TrustedDevice.user_id == user.id,
        TrustedDevice.device_id == request.device_id,
    ).first()
    if trusted is None:
        db.add(TrustedDevice(user_id=user.id, device_id=request.device_id))
    request.used_at = utcnow()
    append(db, "device_verified", user.email, f"device_id={request.device_id}")
    create_notification(
        db,
        recipient=user.email,
        user_id=user.id,
        kind="device_verified",
        subject="SessionSentinel: Device Verification Successful",
        body=(
            "SessionSentinel Security Update\n\n"
            "Event: New device verified successfully\n"
            f"Account: {user.email}\n"
            f"Verified: {utcnow().isoformat()}Z\n"
            f"Device: {request.device_id}\n\n"
            "If you did not approve this activity, reset your password and revoke active sessions."
        ),
        idempotency_key=f"device-verified:{request.id}",
    )
    db.commit()
    return {"status": "verified", "device_id": request.device_id}


@router.post("/logout")
def logout(s: UserSession = Depends(get_current_session), db: Session = Depends(get_db)):
    s.revoked = True          # token ab bekaar: agli request par 401
    db.add(Event(user_id=s.user_id, email_tried="", device_id=s.device_id, type="logout"))
    db.commit()
    return {"status": "ok"}


@router.post("/reset-password")
def reset_password(body: PasswordResetRequest, db: Session = Depends(get_db)):
    if len(body.new_password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
    user = db.query(User).filter(User.email == body.email.strip().lower()).first()
    if user is None:
        raise HTTPException(status_code=404, detail="Account not found")
    user.password_hash = hash_password(body.new_password)
    user.password_reset_required = False
    for session in db.query(UserSession).filter(UserSession.user_id == user.id).all():
        session.revoked = True
    append(db, "password_changed", "user", f"user_id={user.id}")
    db.commit()
    return {"status": "ok"}
