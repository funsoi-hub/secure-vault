from .conftest import create_note, csrf, register, signed_in


def test_post_without_csrf_token_rejected(client):
    r = client.post("/login", data={"email": "a@example.com", "password": "x"})
    assert r.status_code == 403


def test_csrf_token_from_another_browser_rejected(app, client):
    from .conftest import make_client
    attacker = make_client(app)
    stolen_token = csrf(attacker)
    register(client)
    r = client.post("/login", data={"email": "alice@example.com", "password": "x", "csrf_token": stolen_token})
    assert r.status_code == 403


def test_cross_origin_post_rejected(client):
    token = csrf(client)
    r = client.post("/login", data={"email": "a@example.com", "password": "x", "csrf_token": token},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_security_headers_present(client):
    h = client.get("/login").headers
    assert "script-src 'none'" in h["content-security-policy"]
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-frame-options"] == "DENY"
    assert h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer"
    assert h["strict-transport-security"].startswith("max-age=")
    assert h["cache-control"] == "no-store"


def test_api_docs_disabled(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_stored_xss_is_escaped(app):
    c = signed_in(app)
    note_id = create_note(c, title="<script>alert(1)</script>", body='<img src=x onerror="alert(2)">')
    page = c.get(f"/notes/{note_id}").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert '<img src=x onerror="alert(2)">' not in page


def test_post_without_content_length_rejected(client):
    def body():
        yield b"email=a"
    r = client.post("/login", content=body(), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 411


def test_oversized_request_rejected(app, client):
    limit = app.state.settings.max_upload_bytes
    r = client.post("/login", content=b"a" * (limit + 128 * 1024),
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413
