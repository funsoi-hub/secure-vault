import time

import pyotp
from sqlalchemy import select

from app.models import Session, User
from app.security import verify_totp

from .conftest import PASSWORD, csrf, login, make_client, register, signed_in


def test_register_and_login(client):
    assert register(client).status_code == 303
    r = login(client)
    assert r.status_code == 303 and r.headers["location"] == "/notes"
    assert client.get("/notes").status_code == 200


def test_protected_pages_redirect_when_signed_out(client):
    for path in ("/notes", "/files", "/account", "/notes/new"):
        r = client.get(path)
        assert r.status_code == 303 and r.headers["location"] == "/login"


def test_weak_and_mismatched_passwords_rejected(client):
    token = csrf(client, "/register")
    r = client.post("/register", data={"email": "bob@example.com", "password": "short",
                                       "confirm": "different", "csrf_token": token})
    assert r.status_code == 400
    assert "at least 12" in r.text and "don&#39;t match" in r.text


def test_password_stored_as_argon2_hash(app, client):
    register(client)
    with app.state.SessionLocal() as db:
        user = db.scalar(select(User))
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD not in user.password_hash


def test_login_error_does_not_reveal_whether_account_exists(client):
    register(client)
    wrong_password = login(client, password="not the right password")
    no_such_user = login(client, email="nobody@example.com")
    assert wrong_password.status_code == no_such_user.status_code == 401
    assert "Incorrect email or password" in wrong_password.text
    assert "Incorrect email or password" in no_such_user.text


def test_account_locks_after_repeated_failures(app, client):
    register(client)
    for _ in range(app.state.settings.max_failed_logins):
        login(client, password="wrong password guess")
    assert login(client).status_code == 401  # right password, but locked
    with app.state.SessionLocal() as db:
        assert db.scalar(select(User)).locked_until is not None


def test_login_rate_limited_per_ip(client):
    for _ in range(10):
        login(client, email="spray@example.com", password="guess guess guess")
    assert login(client, email="spray@example.com").status_code == 429


def test_session_cookie_flags(client):
    register(client)
    cookie = login(client).headers.get_list("set-cookie")
    session_cookie = next(c for c in cookie if c.startswith("vault_session="))
    lowered = session_cookie.lower()
    assert "httponly" in lowered and "secure" in lowered and "samesite=strict" in lowered


def test_session_token_stored_hashed(app, client):
    register(client)
    login(client)
    raw = client.cookies.get("vault_session")
    with app.state.SessionLocal() as db:
        stored = db.scalar(select(Session)).token_hash
    assert raw and stored != raw and len(stored) == 64


def test_logout_invalidates_session_server_side(app):
    c = signed_in(app)
    stolen = c.cookies.get("vault_session")
    c.post("/logout", data={"csrf_token": csrf(c, "/notes")})
    attacker = make_client(app)
    attacker.cookies.set("vault_session", stolen)
    assert attacker.get("/notes").status_code == 303


def test_sign_out_everywhere(app):
    phone, laptop = signed_in(app), make_client(app)
    login(laptop)
    assert laptop.get("/notes").status_code == 200
    phone.post("/account/sessions/revoke", data={"csrf_token": csrf(phone, "/account")})
    assert laptop.get("/notes").status_code == 303


def _enable_mfa(app, client):
    page = client.get("/account/mfa").text
    secret = page.split('class="mono">')[1].split("<")[0]
    code = pyotp.TOTP(secret).now()
    r = client.post("/account/mfa", data={"code": code, "csrf_token": csrf(client, "/account")})
    assert r.status_code == 303
    return secret


def test_mfa_required_after_enabling(app):
    c = signed_in(app)
    secret = _enable_mfa(app, c)

    fresh = make_client(app)
    r = login(fresh)
    assert r.headers["location"] == "/login/mfa"
    assert fresh.get("/notes").status_code == 303  # password alone isn't enough

    # Same code that was just used to enable MFA is rejected (replay protection)
    r = fresh.post("/login/mfa", data={"code": pyotp.TOTP(secret).now(), "csrf_token": csrf(fresh, "/login/mfa")})
    if r.status_code == 401:  # still in the same 30s window: wait for the next code
        time.sleep(31 - time.time() % 30)
        r = fresh.post("/login/mfa", data={"code": pyotp.TOTP(secret).now(),
                                           "csrf_token": csrf(fresh, "/login/mfa")})
    assert r.status_code == 303 and r.headers["location"] == "/notes"
    assert fresh.get("/notes").status_code == 200


def test_totp_codes_cannot_be_replayed():
    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret).now()
    step = verify_totp(secret, code, last_step=0)
    assert step is not None
    assert verify_totp(secret, code, last_step=step) is None
    assert verify_totp(secret, "000000" if code != "000000" else "111111", last_step=0) is None
    assert verify_totp(secret, "abcdef", last_step=0) is None


def test_mfa_secret_encrypted_at_rest(app):
    c = signed_in(app)
    secret = _enable_mfa(app, c)
    with app.state.SessionLocal() as db:
        blob = db.scalar(select(User)).totp_secret_enc
    assert secret.encode() not in blob
