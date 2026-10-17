# Rate-limit behavior tests
from database import SessionLocal
from models import Incident, User
from tests.conftest import auth


def test_r1_throttles_only_target_account(client, login):
    responses = [
        login(email="zara@test.com", password="wrong-password", device="attack-device")
        for _ in range(8)
    ]

    assert [response.status_code for response in responses] == [401] * 7 + [429]
    body = responses[-1].json()
    assert body["detail"]["retry_after"] > 0
    assert responses[-1].headers["Retry-After"] == str(body["detail"]["retry_after"])

    db = SessionLocal()
    zara = db.query(User).filter(User.email == "zara@test.com").one()
    incident = db.query(Incident).filter(Incident.user_id == zara.id).first()
    db.close()
    assert incident is not None
    assert login(email="sara@test.com").status_code == 200


def test_admin_incidents_require_admin_and_include_investigation(client, login):
    assert client.get("/admin/incidents").status_code == 401
    user_token = login(email="ali@test.com").json()["token"]
    assert client.get("/admin/incidents", headers=auth(user_token)).status_code == 403

    admin_response = client.post(
        "/login",
        json={
            "email": "admin@test.com",
            "password": "Admin@12345",
            "device_id": "admin-test-device",
        },
    )
    admin_token = admin_response.json()["token"]
    response = client.get("/admin/incidents", headers=auth(admin_token))
    assert response.status_code == 200
    assert response.json()

    incident_id = response.json()[0]["id"]
    detail = client.get(
        f"/admin/incidents/{incident_id}", headers=auth(admin_token)
    )
    assert detail.status_code == 200
    body = detail.json()
    assert body["timeline"]
    assert body["evidence"]
    assert "Assessment:" in body["explanation"]
