# deps.py
# "Ye request kis ki hai?" aur "kya ye admin hai?" check karne ke helpers.
# Endpoints mein aise use hote hain: def f(user = Depends(get_current_user))
from datetime import timedelta
from typing import Optional

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from config import SESSION_HOURS
from database import get_db
from models import User, UserSession, utcnow


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=401, detail="Invalid or expired session",
                         headers={"WWW-Authenticate": "Bearer"})


def get_current_session(authorization: Optional[str] = Header(default=None),
                        db: Session = Depends(get_db)) -> UserSession:
    # Header aisa hona chahiye: Authorization: Bearer <token>
    if not authorization or not authorization.startswith("Bearer "):
        raise _unauthorized()
    token = authorization[len("Bearer "):]
    s = db.query(UserSession).filter(UserSession.token == token).first()
    # Token na mile, revoke ho chuka ho, ya purana ho gaya ho: sab par 401.
    # Revoke ka asal check yehi hai (server-side), frontend par bharosa nahi.
    if s is None or s.revoked or utcnow() - s.created_at > timedelta(hours=SESSION_HOURS):
        raise _unauthorized()
    return s


def get_current_user(s: UserSession = Depends(get_current_session),
                     db: Session = Depends(get_db)) -> User:
    user = db.get(User, s.user_id)
    if user is None:
        raise _unauthorized()
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")   # login hai lekin admin nahi
    return user
