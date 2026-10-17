# tests/test_login.py: login ke kamyab aur nakam dono nateeje.
from database import SessionLocal
from models import Event
from tests.conftest import auth


def test_login_ok(login):
    r = login()
    assert r.status_code == 200
    assert r.json()["role"] == "user" and r.json()["token"]


def test_wrong_password_401_and_event_saved(login):
    r = login(password="galat")
    assert r.status_code == 401
    db = SessionLocal()
    assert db.query(Event).filter(Event.email_tried == "ali@test.com", Event.type == "login_fail").count() >= 1
    db.close()


def test_unknown_email_same_message_and_no_user_id(login):
    wrong_pw = login(password="galat").json()
    unknown = login(email="nobody@test.com").json()
    assert wrong_pw == unknown                       # attacker farq nahi dekh sakta
    db = SessionLocal()
    e = db.query(Event).filter(Event.email_tried == "nobody@test.com").first()
    assert e is not None and e.user_id is None
    db.close()


def test_protected_route_needs_token(client):
    assert client.get("/me/activity").status_code == 401
    assert client.get("/me/activity", headers=auth("fake-token")).status_code == 401


def test_activity_only_own_events(client, login):
    login(email="sara@test.com")
    t = login(email="ali@test.com").json()["token"]
    events = client.get("/me/activity", headers=auth(t)).json()
    assert events and all(e["type"] in ("login_ok", "login_fail", "logout") for e in events)
    db = SessionLocal()
    sara_ids = {e.id for e in db.query(Event).filter(Event.email_tried == "sara@test.com")}
    db.close()
    assert not sara_ids & {e["id"] for e in events}   # sara ke events ali ko nahi dikhte
