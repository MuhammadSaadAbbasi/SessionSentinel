# tests/conftest.py
# Tests ke liye alag database use hota hai, asli sessionsentinel.db ko haath nahi lagta.
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_sessionsentinel.db"   # config import hone se PEHLE set hona zaroori

import pytest
from fastapi.testclient import TestClient

import seed
from database import Base, engine
from main import app
import services.email_service as email_service
import routers.auth as auth_router


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    monkeypatch.setattr(email_service, "send_email", lambda recipient, subject, body: None)
    monkeypatch.setattr(auth_router, "send_email", lambda recipient, subject, body: None)
    seed.main()                       # 6 test users
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def login(client):
    # login(email) -> response. Password default test password hai.
    def _login(email="ali@test.com", password="Test@12345", device="dev-1"):
        return client.post("/login", json={"email": email, "password": password, "device_id": device})
    return _login


def auth(token):
    return {"Authorization": f"Bearer {token}"}
