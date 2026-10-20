# models.py
# Har class = database ka ek table. Har attribute = us table ka ek column.
# 6 tables: users, events, sessions, trusted_devices, incidents, audit_log

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


def utcnow() -> datetime:
    # Hum saare waqt UTC mein save karte hain (timezone ke jhamele se bachne ke liye).
    # SQLite timezone yaad nahi rakhta, is liye tzinfo hata kar "naive UTC" save karte hain.
    # Poore project mein isi function se waqt lo, taake comparisons mein ghalti na ho.
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------- users
class User(Base):
    __tablename__ = "users"                                   # table ka naam

    id: Mapped[int] = mapped_column(primary_key=True)         # har user ka unique number (1, 2, 3...)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)  # unique: do users ki same email nahi
    password_hash: Mapped[str] = mapped_column(String(255))   # password KABHI plain save nahi hota, sirf Argon2 hash
    role: Mapped[str] = mapped_column(String(20), default="user")  # "user" ya "admin" (RBAC isi se chalega)
    password_reset_required: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ---------------------------------------------------------------- events
# Har login ki koshish ka record: kaun, kis device se, kab, kya hua.
# Detection rules (R1, R2, R3) isi table ko parh kar kaam karenge.
class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    # ForeignKey("users.id") = ye column users table ke id se juda hai.
    # nullable=True: agar kisi ne aisi email try ki jo exist hi nahi karti, to user_id khali (None) rahega.
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    email_tried: Mapped[str] = mapped_column(String(255))     # jo email likhi gayi (user_id na ho tab bhi record rahe)
    device_id: Mapped[str] = mapped_column(String(100), index=True)   # device ki pehchan (browser ka random ID)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    type: Mapped[str] = mapped_column(String(40))             # "login_ok", "login_fail", "session_revoked"...
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


# ---------------------------------------------------------------- sessions
# Login ke baad server ye "pass" (token) deta hai. Revoke karna = revoked ko True kar dena.
# Class ka naam UserSession hai (SQLAlchemy ke Session se confusion na ho), table ka naam "sessions".
class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token: Mapped[str] = mapped_column(String(128), unique=True, index=True)  # lamba random code
    device_id: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)  # True = token ab bekaar (401 milega)


# ---------------------------------------------------------------- trusted_devices
# Har user ke "jaane pehchane" devices. R3 (unfamiliar device) isi se pata chalta hai.
class TrustedDevice(Base):
    __tablename__ = "trusted_devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(String(100))
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ---------------------------------------------------------------- incidents
# Detection ke baad bani hui "case file".
class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(10))                 # "low", "medium", "high"
    status: Mapped[str] = mapped_column(String(20), default="open")   # open, investigating, contained, resolved, false_positive
    explanation: Mapped[str] = mapped_column(Text, default="")        # agent ki likhi wajah (Day 4)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


# ---------------------------------------------------------------- audit_log
# Tamper-evident record. Har entry apna hash aur pichli entry ka hash (prev_hash) rakhti hai.
# Sirf append hoga, kabhi update ya delete nahi (Day 5 mein audit_log.py banega).
class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    action: Mapped[str] = mapped_column(String(60))           # kya hua, jaise "session_revoked"
    actor: Mapped[str] = mapped_column(String(100))           # kis ne kiya ("system" ya admin ki email)
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    prev_hash: Mapped[str] = mapped_column(String(64))        # pichli entry ka hash
    hash: Mapped[str] = mapped_column(String(64))             # is entry ka apna hash (SHA-256 = 64 hex characters)
