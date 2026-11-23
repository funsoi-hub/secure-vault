"""Secure Vault: an encrypted notes and file vault.

Run locally:  uvicorn app.main:create_app --factory --reload
"""

from __future__ import annotations

import re
import secrets
import unicodedata
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote, urlsplit

import segno
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select, update
from sqlalchemy.orm import Session as DBSession
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import Settings, load_settings
from .crypto import DecryptionError, Vault
from .models import AuditEvent, Note, ShareLink, StoredFile, User, make_session_factory, new_id, utcnow
from .security import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    RateLimiter,
    audit,
    client_ip,
    create_session,
    csrf_token_for,
    csrf_valid,
    destroy_all_sessions,
    destroy_session,
    hash_password,
    hash_share_token,
    load_session,
    needs_rehash,
    new_csrf_cookie,
    new_totp_secret,
    password_problems,
    verify_password,
    verify_totp,
)

BASE_DIR = Path(__file__).resolve().parent
EMAIL_RE = re.compile(r"[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}")
MAX_TITLE, MAX_BODY = 200, 50_000
SHARE_HOURS = {1, 24, 168}

CSP = (
    "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
)


class LoginRequired(Exception):
    """Raised by the auth dependency; turned into a redirect to /login."""


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(title="Secure Vault", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.vault = vault = Vault(settings.master_key)
    app.state.SessionLocal = make_session_factory(settings.database_url)
    app.state.limiters = limiters = {
        "login": RateLimiter(10, 60),       # per IP
        "register": RateLimiter(10, 3600),  # per IP
        "mfa": RateLimiter(5, 300),         # per pending session's user
        "share": RateLimiter(30, 60),       # per IP
    }

    templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))

    # ------------------------------------------------------------------ middleware

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            length = request.headers.get("content-length")
            if length is None:
                return PlainTextResponse("Length required", status_code=411)
            if not length.isdigit():
                return PlainTextResponse("Bad request", status_code=400)
            if int(length) > settings.max_upload_bytes + 64 * 1024:
                return PlainTextResponse("Request too large", status_code=413)

        issued = None
        request.state.csrf_cookie = request.cookies.get(CSRF_COOKIE)
        if not request.state.csrf_cookie:
            issued = request.state.csrf_cookie = new_csrf_cookie()

        response = await call_next(request)

        if issued:
            set_cookie(response, CSRF_COOKIE, issued)
        h = response.headers
        h["Content-Security-Policy"] = CSP
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"  # share tokens live in URLs: never leak them
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        if settings.cookie_secure:
            h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        if not request.url.path.startswith("/static/"):
            h["Cache-Control"] = "no-store"
        return response

    # ------------------------------------------------------------------ helpers

    def set_cookie(response: Response, name: str, value: str, max_age: int | None = None) -> None:
        response.set_cookie(
            name, value, max_age=max_age, path="/", httponly=True,
            secure=settings.cookie_secure, samesite="strict",
        )

    def render(request: Request, name: str, status_code: int = 200, **context) -> Response:
        context["csrf_token"] = csrf_token_for(request.state.csrf_cookie, settings)
        context.setdefault("user", getattr(request.state, "user", None))
        return templates.TemplateResponse(request, name, context, status_code=status_code)

    def redirect(url: str) -> RedirectResponse:
        return RedirectResponse(url, status_code=303)

    def get_db(request: Request):
        db = request.app.state.SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def current_user(request: Request, db: DBSession = Depends(get_db)) -> User:
        sess = load_session(db, request, settings)
        if sess is None or not sess.mfa_verified:
            raise LoginRequired()
        user = db.get(User, sess.user_id)
        if user is None:
            raise LoginRequired()
        request.state.user = user
        return user

    async def checked_form(request: Request):
        """Parse a form and enforce CSRF protection. Every POST handler calls this first."""
        origin = request.headers.get("origin")
        if origin and origin != "null" and urlsplit(origin).netloc != request.headers.get("host"):
            raise HTTPException(403, "Cross-origin request blocked.")
        form = await request.form(max_files=1, max_fields=20)
        token = form.get("csrf_token")
        if not csrf_valid(request.cookies.get(CSRF_COOKIE), token if isinstance(token, str) else None, settings):
            raise HTTPException(403, "Your form expired or was not sent from this site. Reload and try again.")
        return form

    def text(form, key: str) -> str:
        value = form.get(key, "")
        return value if isinstance(value, str) else ""

    def dek_for(user: User) -> bytes:
        return vault.unwrap_key(user.wrapped_dek, user.id)

    def owned_note(db: DBSession, user: User, note_id: str) -> Note:
        # Always scope lookups to the owner. A wrong owner gets 404, not 403, so IDs reveal nothing.
        note = db.scalar(select(Note).where(Note.id == note_id, Note.owner_id == user.id))
        if note is None:
            raise HTTPException(404, "Note not found.")
        return note

    def decrypt_note(dek: bytes, note: Note) -> dict:
        ctx = f"note:{note.owner_id}:{note.id}"
        return {
            "id": note.id,
            "title": vault.decrypt(dek, note.title_enc, ctx + ":title").decode(),
            "body": vault.decrypt(dek, note.body_enc, ctx + ":body").decode(),
            "updated_at": note.updated_at,
        }

    def encrypt_note(dek: bytes, note: Note, title: str, body: str) -> None:
        ctx = f"note:{note.owner_id}:{note.id}"
        note.title_enc = vault.encrypt(dek, title.encode(), ctx + ":title")
        note.body_enc = vault.encrypt(dek, body.encode(), ctx + ":body")
        note.updated_at = utcnow()

    def validate_note(title: str, body: str) -> list[str]:
        errors = []
        if not title.strip() or len(title) > MAX_TITLE:
            errors.append(f"Title must be 1 to {MAX_TITLE} characters.")
        if len(body) > MAX_BODY:
            errors.append(f"Note must be at most {MAX_BODY:,} characters.")
        return errors

    def note_shares(db: DBSession, note: Note) -> list[ShareLink]:
        return list(db.scalars(
            select(ShareLink).where(ShareLink.note_id == note.id).order_by(desc(ShareLink.created_at))
        ))

    def safe_filename(name: str) -> str:
        name = Path(name.replace("\\", "/")).name
        name = "".join(c for c in name if unicodedata.category(c)[0] != "C").strip(" .")
        return name[:200] or "file"

    # ------------------------------------------------------------------ error handling

    @app.exception_handler(LoginRequired)
    async def login_required(request: Request, exc: LoginRequired):
        return redirect("/login")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        if not hasattr(request.state, "csrf_cookie"):
            return PlainTextResponse(str(exc.detail), status_code=exc.status_code)
        message = exc.detail if exc.status_code != 404 or exc.detail != "Not Found" else "Page not found."
        return render(request, "error.html", exc.status_code, message=message)

    @app.exception_handler(DecryptionError)
    async def decryption_error(request: Request, exc: DecryptionError):
        # Tampered or mis-keyed data: fail closed and don't reveal details.
        return render(request, "error.html", 500, message="This item could not be decrypted.")

    # ------------------------------------------------------------------ routes: misc

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return JSONResponse({"status": "ok"})

    @app.get("/")
    def home(request: Request, db: DBSession = Depends(get_db)):
        sess = load_session(db, request, settings)
        return redirect("/notes" if sess and sess.mfa_verified else "/login")

    # ------------------------------------------------------------------ routes: auth

    @app.get("/register")
    def register_page(request: Request):
        return render(request, "register.html")

    @app.post("/register")
    async def register(request: Request, db: DBSession = Depends(get_db)):
        form = await checked_form(request)
        if not limiters["register"].allow(client_ip(request)):
            return render(request, "register.html", 429, errors=["Too many sign-ups from your network. Try later."])
        email = text(form, "email").strip().lower()
        password, confirm = text(form, "password"), text(form, "confirm")

        errors = []
        if len(email) > 254 or not EMAIL_RE.fullmatch(email):
            errors.append("Enter a valid email address.")
        errors += password_problems(password, email)
        if password != confirm:
            errors.append("The passwords don't match.")
        if not errors and db.scalar(select(User.id).where(User.email == email)):
            errors.append("An account with that email already exists.")
        if errors:
            return render(request, "register.html", 400, errors=errors, email=email)

        user = User(id=new_id(), email=email, password_hash=hash_password(password), wrapped_dek=b"")
        user.wrapped_dek = vault.wrap_key(Vault.new_data_key(), user.id)
        db.add(user)
        db.commit()
        audit(db, request, "register", user.id)
        return redirect("/login?registered=1")

    @app.get("/login")
    def login_page(request: Request, registered: int = 0):
        return render(request, "login.html", registered=bool(registered))

    @app.post("/login")
    async def login(request: Request, db: DBSession = Depends(get_db)):
        form = await checked_form(request)
        email, password = text(form, "email").strip().lower(), text(form, "password")
        generic = "Incorrect email or password, or the account is temporarily locked."

        if not limiters["login"].allow(client_ip(request)):
            audit(db, request, "login_rate_limited", detail=email[:100])
            return render(request, "login.html", 429, error="Too many sign-in attempts. Wait a minute.")

        user = db.scalar(select(User).where(User.email == email))
        now = utcnow()
        if user and user.locked_until and user.locked_until > now:
            verify_password(None, password)  # keep timing consistent with a normal attempt
            audit(db, request, "login_while_locked", user.id)
            return render(request, "login.html", 401, error=generic, email=email)

        if not verify_password(user.password_hash if user else None, password):
            if user:
                user.failed_logins += 1
                if user.failed_logins >= settings.max_failed_logins:
                    user.failed_logins = 0
                    user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                    audit(db, request, "account_locked", user.id)
                db.commit()
            audit(db, request, "login_failed", user.id if user else None, detail=email[:100])
            return render(request, "login.html", 401, error=generic, email=email)

        user.failed_logins, user.locked_until = 0, None
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
        db.commit()

        destroy_session(db, request)  # never reuse a pre-login session (session fixation)
        token = create_session(db, user, mfa_verified=not user.totp_enabled)
        response = redirect("/login/mfa" if user.totp_enabled else "/notes")
        set_cookie(response, SESSION_COOKIE, token, max_age=settings.session_absolute_hours * 3600)
        set_cookie(response, CSRF_COOKIE, new_csrf_cookie())  # rotate CSRF secret on privilege change
        audit(db, request, "login_password_ok" if user.totp_enabled else "login_success", user.id)
        return response

    @app.get("/login/mfa")
    def mfa_page(request: Request, db: DBSession = Depends(get_db)):
        sess = load_session(db, request, settings)
        if sess is None or sess.mfa_verified:
            return redirect("/login")
        return render(request, "mfa_verify.html")

    @app.post("/login/mfa")
    async def mfa_verify(request: Request, db: DBSession = Depends(get_db)):
        form = await checked_form(request)
        sess = load_session(db, request, settings)
        if sess is None or sess.mfa_verified:
            return redirect("/login")
        user = db.get(User, sess.user_id)
        if not limiters["mfa"].allow(user.id):
            audit(db, request, "mfa_rate_limited", user.id)
            return render(request, "mfa_verify.html", 429, error="Too many codes tried. Wait 5 minutes.")
        secret = vault.decrypt_secret(user.totp_secret_enc, f"totp:{user.id}").decode()
        step = verify_totp(secret, text(form, "code"), user.totp_last_step)
        if step is None:
            audit(db, request, "mfa_failed", user.id)
            return render(request, "mfa_verify.html", 401, error="That code is wrong or was already used.")

        user.totp_last_step = step
        db.delete(sess)
        db.commit()
        token = create_session(db, user, mfa_verified=True)  # new session ID after the second factor
        response = redirect("/notes")
        set_cookie(response, SESSION_COOKIE, token, max_age=settings.session_absolute_hours * 3600)
        set_cookie(response, CSRF_COOKIE, new_csrf_cookie())
        audit(db, request, "login_success", user.id, detail="mfa")
        return response

    @app.post("/logout")
    async def logout(request: Request, db: DBSession = Depends(get_db)):
        await checked_form(request)
        sess = load_session(db, request, settings)
        if sess:
            audit(db, request, "logout", sess.user_id)
        destroy_session(db, request)
        response = redirect("/login")
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # ------------------------------------------------------------------ routes: notes

    @app.get("/notes")
    def list_notes(request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
        dek = dek_for(user)
        rows = db.scalars(select(Note).where(Note.owner_id == user.id).order_by(desc(Note.updated_at)))
        return render(request, "notes.html", notes=[decrypt_note(dek, n) for n in rows])

    @app.get("/notes/new")
    def new_note_page(request: Request, user: User = Depends(current_user)):
        return render(request, "note_form.html", note=None)

    @app.post("/notes/new")
    async def create_note(request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
        form = await checked_form(request)
        title, body = text(form, "title"), text(form, "body")
        errors = validate_note(title, body)
        if errors:
            return render(request, "note_form.html", 400, note={"title": title, "body": body}, errors=errors)
        note = Note(id=new_id(), owner_id=user.id)
        encrypt_note(dek_for(user), note, title.strip(), body)
        db.add(note)
        db.commit()
        audit(db, request, "note_created", user.id)
        return redirect(f"/notes/{note.id}")

    @app.get("/notes/{note_id}")
    def view_note(note_id: str, request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
        note = owned_note(db, user, note_id)
        return render(request, "note_view.html", note=decrypt_note(dek_for(user), note),
                      shares=note_shares(db, note), now=utcnow())

    @app.get("/notes/{note_id}/edit")
    def edit_note_page(note_id: str, request: Request, user: User = Depends(current_user),
                       db: DBSession = Depends(get_db)):
        note = owned_note(db, user, note_id)
        return render(request, "note_form.html", note=decrypt_note(dek_for(user), note))

    @app.post("/notes/{note_id}/edit")
    async def edit_note(note_id: str, request: Request, user: User = Depends(current_user),
                        db: DBSession = Depends(get_db)):
        form = await checked_form(request)
        note = owned_note(db, user, note_id)
        title, body = text(form, "title"), text(form, "body")
        errors = validate_note(title, body)
        if errors:
            return render(request, "note_form.html", 400,
                          note={"id": note.id, "title": title, "body": body}, errors=errors)
        encrypt_note(dek_for(user), note, title.strip(), body)
        db.commit()
        audit(db, request, "note_updated", user.id)
        return redirect(f"/notes/{note.id}")

    @app.post("/notes/{note_id}/delete")
    async def delete_note(note_id: str, request: Request, user: User = Depends(current_user),
                          db: DBSession = Depends(get_db)):
        await checked_form(request)
        note = owned_note(db, user, note_id)
        for link in note_shares(db, note):
            db.delete(link)
        db.delete(note)
        db.commit()
        audit(db, request, "note_deleted", user.id)
        return redirect("/notes")

    # ------------------------------------------------------------------ routes: sharing

    @app.post("/notes/{note_id}/share")
    async def create_share(note_id: str, request: Request, user: User = Depends(current_user),
                           db: DBSession = Depends(get_db)):
        form = await checked_form(request)
        note = owned_note(db, user, note_id)
        try:
            hours, max_views = int(text(form, "hours")), int(text(form, "max_views"))
        except ValueError:
            raise HTTPException(400, "Choose an expiry and a view limit.") from None
        if hours not in SHARE_HOURS or not 1 <= max_views <= 100:
            raise HTTPException(400, "Choose an expiry and a view limit.")

        token = secrets.token_urlsafe(32)  # 256 bits; only its hash is stored
        db.add(ShareLink(token_hash=hash_share_token(token), note_id=note.id, owner_id=user.id,
                         expires_at=utcnow() + timedelta(hours=hours), max_views=max_views))
        db.commit()
        audit(db, request, "share_created", user.id, detail=f"{hours}h/{max_views} views")
        share_url = str(request.base_url) + f"s/{token}"
        return render(request, "note_view.html", note=decrypt_note(dek_for(user), note),
                      shares=note_shares(db, note), now=utcnow(), new_share_url=share_url)

    @app.post("/shares/{share_id}/revoke")
    async def revoke_share(share_id: str, request: Request, user: User = Depends(current_user),
                           db: DBSession = Depends(get_db)):
        await checked_form(request)
        link = db.scalar(select(ShareLink).where(ShareLink.id == share_id, ShareLink.owner_id == user.id))
        if link is None:
            raise HTTPException(404, "Share link not found.")
        link.revoked = True
        db.commit()
        audit(db, request, "share_revoked", user.id)
        return redirect(f"/notes/{link.note_id}")

    def usable_link(db: DBSession, token: str) -> ShareLink | None:
        link = db.scalar(select(ShareLink).where(ShareLink.token_hash == hash_share_token(token)))
        if link is None or link.revoked or link.expires_at <= utcnow() or link.views >= link.max_views:
            return None
        return link

    @app.get("/s/{token}")
    def shared_landing(token: str, request: Request, db: DBSession = Depends(get_db)):
        # GET never spends a view: chat apps and email scanners "preview" links automatically.
        if not limiters["share"].allow(client_ip(request)):
            raise HTTPException(429, "Too many requests. Wait a minute.")
        if usable_link(db, token) is None:
            raise HTTPException(404, "This link is invalid, expired, or has been used up.")
        response = render(request, "shared_note.html", token=token, note=None)
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response

    @app.post("/s/{token}")
    async def shared_reveal(token: str, request: Request, db: DBSession = Depends(get_db)):
        await checked_form(request)
        if not limiters["share"].allow(client_ip(request)):
            raise HTTPException(429, "Too many requests. Wait a minute.")
        link = usable_link(db, token)
        if link is None:
            raise HTTPException(404, "This link is invalid, expired, or has been used up.")
        # Atomic: two people racing for the last view can't both get it.
        spent = db.execute(
            update(ShareLink)
            .where(ShareLink.id == link.id, ShareLink.views < ShareLink.max_views, ShareLink.revoked.is_(False))
            .values(views=ShareLink.views + 1)
        )
        db.commit()
        if spent.rowcount != 1:
            raise HTTPException(404, "This link is invalid, expired, or has been used up.")
        note = db.get(Note, link.note_id)
        owner = db.get(User, link.owner_id)
        audit(db, request, "share_viewed", owner.id)
        response = render(request, "shared_note.html", token=token, note=decrypt_note(dek_for(owner), note),
                          remaining=link.max_views - link.views - 1)
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response

    # ------------------------------------------------------------------ routes: files

    @app.get("/files")
    def list_files(request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
        dek = dek_for(user)
        rows = db.scalars(select(StoredFile).where(StoredFile.owner_id == user.id)
                          .order_by(desc(StoredFile.created_at)))
        files = [{"id": f.id, "size": f.size, "created_at": f.created_at,
                  "name": vault.decrypt(dek, f.name_enc, f"file:{user.id}:{f.id}:name").decode()} for f in rows]
        return render(request, "files.html", files=files, max_mb=settings.max_upload_bytes // (1024 * 1024))

    @app.post("/files")
    async def upload_file(request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
        form = await checked_form(request)
        upload = form.get("upload")
        if not isinstance(upload, UploadFile) or not upload.filename:
            raise HTTPException(400, "Choose a file to upload.")
        content = await upload.read(settings.max_upload_bytes + 1)
        if len(content) > settings.max_upload_bytes:
            raise HTTPException(413, "That file is too large.")
        if not content:
            raise HTTPException(400, "That file is empty.")
        stored = StoredFile(id=new_id(), owner_id=user.id, size=len(content))
        dek, ctx = dek_for(user), f"file:{user.id}:{stored.id}"
        stored.name_enc = vault.encrypt(dek, safe_filename(upload.filename).encode(), ctx + ":name")
        stored.content_enc = vault.encrypt(dek, content, ctx + ":content")
        db.add(stored)
        db.commit()
        audit(db, request, "file_uploaded", user.id, detail=f"{len(content)} bytes")
        return redirect("/files")

    def owned_file(db: DBSession, user: User, file_id: str) -> StoredFile:
        stored = db.scalar(select(StoredFile).where(StoredFile.id == file_id, StoredFile.owner_id == user.id))
        if stored is None:
            raise HTTPException(404, "File not found.")
        return stored

    @app.get("/files/{file_id}")
    def download_file(file_id: str, request: Request, user: User = Depends(current_user),
                      db: DBSession = Depends(get_db)):
        stored = owned_file(db, user, file_id)
        dek, ctx = dek_for(user), f"file:{user.id}:{stored.id}"
        name = vault.decrypt(dek, stored.name_enc, ctx + ":name").decode()
        content = vault.decrypt(dek, stored.content_enc, ctx + ":content")
        audit(db, request, "file_downloaded", user.id)
        # Always a download, never rendered inline: an uploaded .html or .svg can't run script on our origin.
        return Response(content, media_type="application/octet-stream", headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
        })

    @app.post("/files/{file_id}/delete")
    async def delete_file(file_id: str, request: Request, user: User = Depends(current_user),
                          db: DBSession = Depends(get_db)):
        await checked_form(request)
        db.delete(owned_file(db, user, file_id))
        db.commit()
        audit(db, request, "file_deleted", user.id)
        return redirect("/files")

    # ------------------------------------------------------------------ routes: account & MFA

    @app.get("/account")
    def account(request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
        events = db.scalars(select(AuditEvent).where(AuditEvent.user_id == user.id)
                            .order_by(desc(AuditEvent.created_at)).limit(25))
        return render(request, "account.html", events=list(events))

    @app.get("/account/mfa")
    def mfa_setup_page(request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
        if user.totp_enabled:
            return redirect("/account")
        if user.totp_secret_enc is None:
            user.totp_secret_enc = vault.encrypt_secret(new_totp_secret().encode(), f"totp:{user.id}")
            db.commit()
        secret = vault.decrypt_secret(user.totp_secret_enc, f"totp:{user.id}").decode()
        uri = f"otpauth://totp/Secure%20Vault:{quote(user.email)}?secret={secret}&issuer=Secure%20Vault"
        qr = segno.make(uri, error="m").svg_data_uri(scale=5, dark="#0b1220", light="#ffffff")
        return render(request, "mfa_setup.html", secret=secret, qr=qr)

    @app.post("/account/mfa")
    async def mfa_enable(request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
        form = await checked_form(request)
        if user.totp_enabled or user.totp_secret_enc is None:
            return redirect("/account")
        secret = vault.decrypt_secret(user.totp_secret_enc, f"totp:{user.id}").decode()
        step = verify_totp(secret, text(form, "code"), user.totp_last_step)
        if step is None:
            uri = f"otpauth://totp/Secure%20Vault:{quote(user.email)}?secret={secret}&issuer=Secure%20Vault"
            qr = segno.make(uri, error="m").svg_data_uri(scale=5, dark="#0b1220", light="#ffffff")
            return render(request, "mfa_setup.html", 400, secret=secret, qr=qr,
                          error="That code didn't match. Check your phone's clock and try again.")
        user.totp_enabled, user.totp_last_step = True, step
        db.commit()
        audit(db, request, "mfa_enabled", user.id)
        return redirect("/account")

    @app.post("/account/mfa/disable")
    async def mfa_disable(request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
        form = await checked_form(request)
        if not user.totp_enabled:
            return redirect("/account")
        secret = vault.decrypt_secret(user.totp_secret_enc, f"totp:{user.id}").decode()
        step = verify_totp(secret, text(form, "code"), user.totp_last_step)
        if not verify_password(user.password_hash, text(form, "password")) or step is None:
            audit(db, request, "mfa_disable_failed", user.id)
            raise HTTPException(401, "Your password or code was wrong, so MFA is still on.")
        user.totp_enabled, user.totp_secret_enc, user.totp_last_step = False, None, step
        db.commit()
        audit(db, request, "mfa_disabled", user.id)
        return redirect("/account")

    @app.post("/account/sessions/revoke")
    async def sign_out_everywhere(request: Request, user: User = Depends(current_user),
                                  db: DBSession = Depends(get_db)):
        await checked_form(request)
        destroy_all_sessions(db, user.id)
        audit(db, request, "all_sessions_revoked", user.id)
        response = redirect("/login")
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    return app
