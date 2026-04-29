import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app as app_module


@pytest.fixture(autouse=True)
def isolate_auth_state(monkeypatch):
    monkeypatch.setattr(app_module, "MONGO_ENABLED", False)
    monkeypatch.setattr(app_module, "ASYNC_MONGO_ENABLED", False)
    monkeypatch.setattr(app_module, "users_col", None)
    monkeypatch.setattr(app_module, "async_users_col", None)
    monkeypatch.setattr(app_module, "redis_client", None)
    app_module.USERS.clear()
    app_module.LOCAL_USER_CACHE.clear()
    app_module.LOCAL_TOKEN_CACHE.clear()
    app_module.RATE_LIMIT_LOCAL.clear()


@pytest.fixture
def client():
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as test_client:
        yield test_client


def register_user(client, email="testuser@example.com", password="Password123!"):
    return client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
            "firstName": "Test",
            "lastName": "User",
            "role": "client",
        },
    )


def login_user(client, email="testuser@example.com", password="Password123!"):
    return client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )


def test_register_success(client):
    response = register_user(client)
    payload = response.get_json()

    assert response.status_code == 201
    assert payload["status"] == "ok"
    assert payload["message"] == "Account created successfully"
    assert payload.get("token")


def test_register_duplicate_email(client):
    register_user(client)
    response = register_user(client)

    assert response.status_code == 409
    assert response.get_json()["message"] == "Email already registered"


def test_login_success(client):
    register_user(client)
    response = login_user(client)
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "ok"
    assert payload["message"] == "Login successful"
    assert payload.get("token")


def test_login_invalid_password(client):
    register_user(client)
    response = login_user(client, password="WrongPassword123!")

    assert response.status_code == 401
    assert response.get_json()["message"] == "Invalid email or password"


def test_profile_requires_token(client):
    response = client.get("/api/auth/profile")

    assert response.status_code == 401
    assert response.get_json()["message"] == "Missing token"


def test_profile_success_with_token(client):
    reg_response = register_user(client)
    token = reg_response.get_json()["token"]

    response = client.get(
        "/api/auth/profile",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["user"]["email"] == "testuser@example.com"


def test_refresh_token_success(client):
    reg_response = register_user(client)
    token = reg_response.get_json()["token"]

    response = client.post(
        "/api/auth/refresh",
        json={},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload.get("token")


def test_logout_success(client):
    reg_response = register_user(client)
    token = reg_response.get_json()["token"]

    response = client.post(
        "/api/auth/logout",
        json={},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.get_json()["message"] == "Logout successful"
