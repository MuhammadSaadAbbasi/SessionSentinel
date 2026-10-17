# routers/me.py
# Logged-in user ki apni information. Har query user_id se filter hoti hai (doosre ka data nahi dikhta).
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_session, get_current_user
from models import Event, User, UserSession

router = APIRouter()


def _iso(dt):
    return dt.isoformat() + "Z"        # DB mein UTC save hai, "Z" laga ke frontend ko batate hain


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "role": user.role}


@router.get("/me/activity")
def activity(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    events = (db.query(Event).filter(Event.user_id == user.id)
              .order_by(Event.created_at.desc(), Event.id.desc()).limit(50).all())
    return [{"id": e.id, "type": e.type, "device_id": e.device_id, "ip": e.ip,
             "created_at": _iso(e.created_at)} for e in events]


@router.get("/me/sessions")
def sessions(user: User = Depends(get_current_user), cur: UserSession = Depends(get_current_session),
             db: Session = Depends(get_db)):
    rows = (db.query(UserSession).filter(UserSession.user_id == user.id, UserSession.revoked == False)  # noqa: E712
            .order_by(UserSession.created_at.desc()).all())
    return [{"id": s.id, "device_id": s.device_id, "created_at": _iso(s.created_at),
             "current": s.id == cur.id} for s in rows]
