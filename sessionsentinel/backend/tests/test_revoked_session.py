# tests/test_revoked_session.py: Confidentiality test: revoke ke baad token reject hona chahiye.
from datetime import timedelta

from database import SessionLocal
from models import UserSession, utcnow
from tests.conftest import auth


def test_logout_revokes_token(client, login):
    t = login().json()["token"]
    assert client.get("/me/activity", headers=auth(t)).status_code == 200
    assert client.post("/logout", headers=auth(t)).status_code == 200
    assert client.get("/me/activity", headers=auth(t)).status_code == 401      # agli hi request par 401


def test_db_revoked_token_rejected(client, login):
    t = login(email="ahmed@test.com").json()["token"]
    db = SessionLocal()
    db.query(UserSession).filter(UserSession.token == t).update({"revoked": True})   # admin revoke jaisa
    db.commit(); db.close()
    assert client.get("/me", headers=auth(t)).status_code == 401


def test_expired_token_rejected(client, login):
    t = login(email="bilal@test.com").json()["token"]
    db = SessionLocal()
    db.query(UserSession).filter(UserSession.token == t).update({"created_at": utcnow() - timedelta(hours=24)})
    db.commit(); db.close()
    assert client.get("/me", headers=auth(t)).status_code == 401
