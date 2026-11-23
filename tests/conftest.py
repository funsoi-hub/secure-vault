import re

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

CSRF_RE = re.compile(r'name="csrf_token" value="([0-9a-f]{64})"')
PASSWORD = "correct horse battery staple"


@pytest.fixture
def app(tmp_path):
    return create_app(Settings(env="test", database_url=f"sqlite:///{tmp_path / 'test.db'}"))


def make_client(app):
    # https base URL so Secure cookies are sent, like in production
    return TestClient(app, base_url="https://testserver", follow_redirects=False)


@pytest.fixture
def client(app):
    return make_client(app)


def csrf(client, path="/login"):
    match = CSRF_RE.search(client.get(path).text)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


def register(client, email="alice@example.com", password=PASSWORD):
    return client.post("/register", data={
        "email": email, "password": password, "confirm": password, "csrf_token": csrf(client, "/register"),
    })


def login(client, email="alice@example.com", password=PASSWORD):
    return client.post("/login", data={"email": email, "password": password, "csrf_token": csrf(client)})


def signed_in(app, email="alice@example.com"):
    c = make_client(app)
    assert register(c, email).status_code == 303
    assert login(c, email).headers["location"] == "/notes"
    return c


def create_note(client, title="Bank PIN", body="1234 is not my PIN"):
    r = client.post("/notes/new", data={"title": title, "body": body, "csrf_token": csrf(client, "/notes")})
    assert r.status_code == 303
    return r.headers["location"].rsplit("/", 1)[1]
