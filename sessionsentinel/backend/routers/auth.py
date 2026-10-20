# routers/auth.py
# /login aur /logout.
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from config import R1_MAX_FAILS
from database import get_db
from deps import get_current_session
from models import Event, Incident, TrustedDevice, User, UserSession
from schemas import LoginRequest, PasswordResetRequest
from security import hash_password, new_token, verify_password
from services.audit_log import append
from services.detection import (
    failed_logins,
    inspect_success,
    record_r1_incident,
    retry_after,
)

router = APIRouter()


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None
    email = body.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if user is not None and user.password_reset_required:
        raise HTTPException(
            status_code=403,
            detail="Password reset required before signing in",
        )
    ok = user is not None and verify_password(body.password, user.password_hash)

    if not ok:
        if user is not None:
            wait = retry_after(db, user.id, email)
            if wait:
                append(db, "login_throttled", "system", f"user_id={user.id};retry_after={wait}")
                db.commit()
                raise HTTPException(
                    status_code=429,
                    detail={"message": "Too many failed login attempts", "retry_after": wait},
                    headers={"Retry-After": str(wait)},
                )
        # Fail ka event hamesha save hota hai (user na ho tab bhi, user_id None). Day 3 ke rules isi se chalte hain.
        db.add(Event(user_id=user.id if user else None, email_tried=email,
                     device_id=body.device_id, ip=ip, type="login_fail"))
        db.commit()
        if user is not None and len(failed_logins(db, user.id, email)) >= R1_MAX_FAILS:
            record_r1_incident(db, user)
            append(db, "login_throttled", "system", f"user_id={user.id};retry_after_pending")
            db.commit()
            wait = retry_after(db, user.id, email)
            raise HTTPException(
                status_code=429,
                detail={"message": "Too many failed login attempts", "retry_after": wait},
                headers={"Retry-After": str(wait)},
            )
        # Message same: attacker ko pata na chale ke email maujood hai ya nahi.
        raise HTTPException(status_code=401, detail="Invalid email or password")

    r1_active, unfamiliar_device = inspect_success(db, user, body.device_id)
    db.add(Event(user_id=user.id, email_tried=email, device_id=body.device_id, ip=ip, type="login_ok"))
    if unfamiliar_device or db.query(TrustedDevice).filter(
        TrustedDevice.user_id == user.id
    ).count() == 0:
        db.add(TrustedDevice(user_id=user.id, device_id=body.device_id))
    if r1_active and unfamiliar_device:
        incident = db.query(Incident).filter(
            Incident.user_id == user.id,
            Incident.explanation == "R3: successful login from a new device",
            Incident.status == "open",
        ).order_by(Incident.id.desc()).first()
        if incident:
            incident.severity = "high"
            incident.explanation = (
                "R4: R1 failed-login sequence followed by a successful login "
                "from a new device"
            )
    elif r1_active:
        record_r1_incident(db, user)
    token = new_token()
    session = UserSession(user_id=user.id, token=token, device_id=body.device_id)
    db.add(session)
    if r1_active and unfamiliar_device:
        session.revoked = True
        append(db, "high_risk_session_held", "system", f"user_id={user.id};device_id={body.device_id}")
    db.commit()
    return {
        "token": token,
        "role": user.role,
        "email": user.email,
        "requires_reauthentication": bool(r1_active and unfamiliar_device),
    }


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
