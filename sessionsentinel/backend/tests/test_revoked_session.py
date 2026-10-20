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


def test_user_reports_unauthorized_event_and_revokes_sessions(client, login):
    first = login(email="sara@test.com", device="sara-device")
    token = first.json()["token"]
    event_id = client.get("/me/activity", headers=auth(token)).json()[0]["id"]
    assert client.post(
        "/me/report",
        headers=auth(token),
        json={"event_id": event_id, "is_me": False},
    ).status_code == 200
    assert client.get("/me/activity", headers=auth(token)).status_code == 401
    assert client.post(
        "/reset-password",
        json={"email": "sara@test.com", "new_password": "NewTest@12345"},
    ).status_code == 200
    assert login(email="sara@test.com", password="NewTest@12345").status_code == 200
    assert client.post(
        "/reset-password",
        json={"email": "sara@test.com", "new_password": "Test@12345"},
    ).status_code == 200
