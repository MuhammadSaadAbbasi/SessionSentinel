# routers/auth.py
# /login aur /logout.
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from config import R1_MAX_FAILS
from database import get_db
from deps import get_current_session
from models import Event, TrustedDevice, User, UserSession
from schemas import LoginRequest
from security import new_token, verify_password
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
    ok = user is not None and verify_password(body.password, user.password_hash)

    if not ok:
        if user is not None:
            wait = retry_after(db, user.id, email)
            if wait:
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
    if r1_active:
        record_r1_incident(db, user)
    token = new_token()
    db.add(UserSession(user_id=user.id, token=token, device_id=body.device_id))
    db.commit()
    return {"token": token, "role": user.role, "email": user.email}


@router.post("/logout")
def logout(s: UserSession = Depends(get_current_session), db: Session = Depends(get_db)):
    s.revoked = True          # token ab bekaar: agli request par 401
    db.add(Event(user_id=s.user_id, email_tried="", device_id=s.device_id, type="logout"))
    db.commit()
    return {"status": "ok"}
