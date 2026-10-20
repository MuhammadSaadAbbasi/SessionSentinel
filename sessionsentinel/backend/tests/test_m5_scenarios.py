from database import SessionLocal
from models import Event, Incident
from tests.conftest import auth


def test_new_device_creates_event_and_incident(client, login):
    assert login(email="ahmed@test.com", device="ahmed-known").status_code == 200
    response = login(email="ahmed@test.com", device="ahmed-new")
    assert response.status_code == 200

    db = SessionLocal()
    assert db.query(Event).filter(
        Event.user_id.is_not(None),
        Event.email_tried == "ahmed@test.com",
        Event.device_id == "ahmed-new",
        Event.type == "new_device",
    ).count() >= 1
    assert db.query(Incident).filter(
        Incident.explanation == "R3: successful login from a new device"
    ).count() >= 1
    db.close()


def test_user_confirms_new_device_and_trusts_it(client, login):
    assert login(email="zara@test.com", device="zara-original").status_code == 200
    login_response = login(email="zara@test.com", device="zara-confirmed")
    token = login_response.json()["token"]
    db = SessionLocal()
    event = db.query(Event).filter(
        Event.email_tried == "zara@test.com",
        Event.device_id == "zara-confirmed",
        Event.type == "new_device",
    ).order_by(Event.id.desc()).first()
    db.close()
    assert event is not None
    assert client.post(
        "/me/report",
        headers=auth(token),
        json={"event_id": event.id, "is_me": True},
    ).status_code == 200
    db = SessionLocal()
    assert db.query(Incident).filter(
        Incident.user_id == event.user_id,
        Incident.status == "resolved",
        Incident.explanation.like("%new device%"),
    ).count() >= 1
    db.close()


def test_success_after_r1_is_recorded(client, login):
    assert login(email="bilal@test.com", device="bilal-known").status_code == 200
    for _ in range(8):
        assert login(
            email="bilal@test.com",
            password="wrong-password",
            device="bilal-known",
        ).status_code in (401, 429)

    response = login(email="bilal@test.com", device="bilal-known")
    assert response.status_code == 200
    db = SessionLocal()
    assert db.query(Incident).filter(
        Incident.user_id.is_not(None),
        Incident.explanation.like("R1:%"),
    ).count() >= 1
    db.close()


def test_admin_response_and_audit_endpoints(client, login):
    user_token = login(email="zara@test.com", device="zara-response").json()["token"]
    session_id = client.get(
        "/me/sessions", headers=auth(user_token)
    ).json()[0]["id"]
    admin = client.post(
        "/login",
        json={
            "email": "admin@test.com",
            "password": "Admin@12345",
            "device_id": "admin-response",
        },
    ).json()["token"]

    assert client.post(
        f"/admin/sessions/{session_id}/revoke",
        headers=auth(admin),
    ).status_code == 200
    assert client.get("/me", headers=auth(user_token)).status_code == 401

    incident = client.get("/admin/incidents", headers=auth(admin)).json()[0]
    assert client.post(
        f"/admin/incidents/{incident['id']}/status",
        headers=auth(admin),
        json={"status": "investigating", "note": "M5 scenario"},
    ).status_code == 200
    assert client.get("/audit", headers=auth(admin)).status_code == 200
    assert client.get("/audit/verify", headers=auth(admin)).json()["status"] == "valid"
