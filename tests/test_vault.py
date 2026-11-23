from datetime import timedelta

import pytest
from sqlalchemy import select, update

from app.crypto import DecryptionError, Vault
from app.models import Note, ShareLink, StoredFile, User

from .conftest import create_note, csrf, make_client, signed_in

SECRET_BODY = "my recovery phrase is apple banana cherry"


def test_notes_encrypted_at_rest(app):
    c = signed_in(app)
    create_note(c, title="Recovery phrase", body=SECRET_BODY)
    with app.state.SessionLocal() as db:
        note = db.scalar(select(Note))
    assert SECRET_BODY.encode() not in note.body_enc
    assert b"Recovery phrase" not in note.title_enc
    assert SECRET_BODY in c.get(f"/notes/{note.id}").text


def test_users_cannot_read_or_change_each_others_notes(app):
    alice, mallory = signed_in(app, "alice@example.com"), signed_in(app, "mallory@example.com")
    note_id = create_note(alice, body=SECRET_BODY)
    token = csrf(mallory, "/notes")
    assert mallory.get(f"/notes/{note_id}").status_code == 404
    assert mallory.get(f"/notes/{note_id}/edit").status_code == 404
    edit = {"title": "pwned", "body": "", "csrf_token": token}
    assert mallory.post(f"/notes/{note_id}/edit", data=edit).status_code == 404
    assert mallory.post(f"/notes/{note_id}/delete", data={"csrf_token": token}).status_code == 404
    share = {"hours": "24", "max_views": "5", "csrf_token": token}
    assert mallory.post(f"/notes/{note_id}/share", data=share).status_code == 404
    assert SECRET_BODY in alice.get(f"/notes/{note_id}").text


def test_ciphertext_moved_between_users_fails_to_decrypt(app):
    """AAD binds ciphertext to its owner: a DB attacker can't swap rows to read data."""
    alice, mallory = signed_in(app, "alice@example.com"), signed_in(app, "mallory@example.com")
    create_note(alice, body=SECRET_BODY)
    mallory_note = create_note(mallory, body="nothing")
    with app.state.SessionLocal() as db:
        alice_note = db.scalar(select(Note).where(Note.id != mallory_note))
        db.execute(update(Note).where(Note.id == mallory_note).values(body_enc=alice_note.body_enc))
        db.commit()
    r = mallory.get(f"/notes/{mallory_note}")
    assert r.status_code == 500 and SECRET_BODY not in r.text


def test_tampered_ciphertext_detected():
    vault = Vault(b"k" * 32)
    dek = vault.new_data_key()
    blob = bytearray(vault.encrypt(dek, b"hello", "ctx"))
    blob[-1] ^= 1
    with pytest.raises(DecryptionError):
        vault.decrypt(dek, bytes(blob), "ctx")
    with pytest.raises(DecryptionError):
        vault.decrypt(dek, vault.encrypt(dek, b"hello", "ctx"), "other-ctx")


def test_wrong_master_key_cannot_unwrap_data_key():
    dek = Vault.new_data_key()
    wrapped = Vault(b"a" * 32).wrap_key(dek, "user1")
    with pytest.raises(DecryptionError):
        Vault(b"b" * 32).unwrap_key(wrapped, "user1")


# -------------------------------------------------------------------- sharing

def _share(client, note_id, hours="24", views="2"):
    r = client.post(f"/notes/{note_id}/share", data={"hours": hours, "max_views": views,
                                                     "csrf_token": csrf(client, f"/notes/{note_id}")})
    assert r.status_code == 200
    return "/s/" + r.text.split("https://testserver/s/")[1].split('"')[0]


def _reveal(client, path):
    return client.post(path, data={"csrf_token": csrf(client, path)})


def test_share_link_respects_view_limit(app):
    alice = signed_in(app)
    link = _share(alice, create_note(alice, body=SECRET_BODY), views="2")
    guest = make_client(app)
    assert guest.get(link).status_code == 200  # preview doesn't spend a view
    assert guest.get(link).status_code == 200
    assert SECRET_BODY in _reveal(guest, link).text
    assert SECRET_BODY in _reveal(guest, link).text
    assert guest.get(link).status_code == 404  # used up


def test_share_token_stored_hashed(app):
    alice = signed_in(app)
    link = _share(alice, create_note(alice))
    with app.state.SessionLocal() as db:
        stored = db.scalar(select(ShareLink)).token_hash
    assert link.split("/s/")[1] != stored


def test_expired_and_revoked_links_stop_working(app):
    alice = signed_in(app)
    note_id = create_note(alice)
    expired, revoked = _share(alice, note_id), _share(alice, note_id)
    with app.state.SessionLocal() as db:
        first, second = db.scalars(select(ShareLink).order_by(ShareLink.created_at)).all()
        first.expires_at = first.created_at - timedelta(minutes=1)
        db.commit()
        second_id = second.id
    alice.post(f"/shares/{second_id}/revoke", data={"csrf_token": csrf(alice, f"/notes/{note_id}")})
    guest = make_client(app)
    assert guest.get(expired).status_code == 404
    assert guest.get(revoked).status_code == 404


def test_guessed_share_token_rejected(client):
    assert client.get("/s/not-a-real-token").status_code == 404


def test_share_options_validated(app):
    alice = signed_in(app)
    note_id = create_note(alice)
    token = csrf(alice, f"/notes/{note_id}")
    for hours, views in (("9999", "1"), ("24", "0"), ("24", "1000"), ("abc", "1")):
        r = alice.post(f"/notes/{note_id}/share", data={"hours": hours, "max_views": views, "csrf_token": token})
        assert r.status_code == 400


# -------------------------------------------------------------------- files

def _upload(client, name, content):
    return client.post("/files", data={"csrf_token": csrf(client, "/files")}, files={"upload": (name, content)})


def test_file_upload_encrypted_and_downloaded_as_attachment(app):
    c = signed_in(app)
    assert _upload(c, "passport.html", b"<script>alert(1)</script> secret").status_code == 303
    with app.state.SessionLocal() as db:
        stored = db.scalar(select(StoredFile))
    assert b"secret" not in stored.content_enc and b"passport" not in stored.name_enc
    r = c.get(f"/files/{stored.id}")
    assert r.content == b"<script>alert(1)</script> secret"
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["content-disposition"].startswith("attachment;")


def test_upload_filename_sanitised(app):
    c = signed_in(app)
    _upload(c, "../../etc/passwd\r\n.txt", b"x")
    assert "../" not in c.get("/files").text
    assert "passwd" in c.get("/files").text


def test_oversized_and_empty_uploads_rejected(app):
    c = signed_in(app)
    assert _upload(c, "empty.txt", b"").status_code == 400
    too_big = b"x" * (app.state.settings.max_upload_bytes + 1)
    assert _upload(c, "big.bin", too_big).status_code == 413


def test_users_cannot_download_each_others_files(app):
    alice, mallory = signed_in(app, "alice@example.com"), signed_in(app, "mallory@example.com")
    _upload(alice, "secret.txt", b"top secret")
    with app.state.SessionLocal() as db:
        file_id = db.scalar(select(StoredFile)).id
    assert mallory.get(f"/files/{file_id}").status_code == 404
    assert mallory.post(f"/files/{file_id}/delete", data={"csrf_token": csrf(mallory, "/files")}).status_code == 404


def test_each_user_gets_a_unique_data_key(app):
    signed_in(app, "alice@example.com")
    signed_in(app, "bob@example.com")
    with app.state.SessionLocal() as db:
        a, b = db.scalars(select(User)).all()
    vault = app.state.vault
    assert vault.unwrap_key(a.wrapped_dek, a.id) != vault.unwrap_key(b.wrapped_dek, b.id)
