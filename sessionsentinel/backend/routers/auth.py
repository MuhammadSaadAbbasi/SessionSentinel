# routers/auth.py
# /login aur /logout.
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_session
from models import Event, TrustedDevice, User, UserSession
from schemas import LoginRequest
from security import new_token, verify_password

router = APIRouter()


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None
    email = body.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    ok = user is not None and verify_password(body.password, user.password_hash)

    if not ok:
        # Fail ka event hamesha save hota hai (user na ho tab bhi, user_id None). Day 3 ke rules isi se chalte hain.
        db.add(Event(user_id=user.id if user else None, email_tried=email,
                     device_id=body.device_id, ip=ip, type="login_fail"))
        db.commit()
        # Message same: attacker ko pata na chale ke email maujood hai ya nahi.
        raise HTTPException(status_code=401, detail="Invalid email or password")

    db.add(Event(user_id=user.id, email_tried=email, device_id=body.device_id, ip=ip, type="login_ok"))
    # Pehle device ko trusted bana do. Naye devices ka faisla R3 (Day 3) karega.
    if db.query(TrustedDevice).filter(TrustedDevice.user_id == user.id).count() == 0:
        db.add(TrustedDevice(user_id=user.id, device_id=body.device_id))
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
