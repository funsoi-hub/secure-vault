"""Authentication, session, CSRF, MFA and rate-limiting primitives."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from .config import Settings
from .models import AuditEvent, Session, User, utcnow

SESSION_COOKIE = "vault_session"
CSRF_COOKIE = "vault_csrf"

# --------------------------------------------------------------------------- passwords

_hasher = PasswordHasher()  # Argon2id with the library's OWASP-aligned defaults
# Verified against when the email doesn't exist, so a login takes the same time either way
# (this stops attackers telling real accounts apart by response time).
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

COMMON_PASSWORDS = {
    "password1234", "123456789012", "qwertyuiop12", "iloveyou1234", "passwordpassword",
    "letmein12345", "welcome12345", "administrator", "changeme1234", "abc123456789",
}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


def password_problems(password: str, email: str) -> list[str]:
    """NIST SP 800-63B style: long passphrases, block obvious ones, no composition rules."""
    problems = []
    if len(password) < 12:
        problems.append("Use at least 12 characters.")
    if len(password) > 128:
        problems.append("Use at most 128 characters.")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS or lowered == email.lower() or lowered == email.split("@")[0].lower():
        problems.append("That password is too easy to guess.")
    return problems


# --------------------------------------------------------------------------- sessions


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: DBSession, user: User, mfa_verified: bool) -> str:
    token = secrets.token_urlsafe(32)
    db.add(Session(token_hash=_hash_token(token), user_id=user.id, mfa_verified=mfa_verified))
    db.commit()
    return token


def load_session(db: DBSession, request: Request, settings: Settings) -> Session | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    sess = db.scalar(select(Session).where(Session.token_hash == _hash_token(token)))
    if sess is None:
        return None
    now = utcnow()
    idle_expired = now - sess.last_seen > timedelta(minutes=settings.session_idle_minutes)
    absolute_expired = now - sess.created_at > timedelta(hours=settings.session_absolute_hours)
    if idle_expired or absolute_expired:
        db.delete(sess)
        db.commit()
        return None
    sess.last_seen = now
    db.commit()
    return sess


def destroy_session(db: DBSession, request: Request) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        sess = db.scalar(select(Session).where(Session.token_hash == _hash_token(token)))
        if sess:
            db.delete(sess)
            db.commit()


def destroy_all_sessions(db: DBSession, user_id: str) -> None:
    for sess in db.scalars(select(Session).where(Session.user_id == user_id)):
        db.delete(sess)
    db.commit()


def hash_share_token(token: str) -> str:
    return _hash_token(token)


# --------------------------------------------------------------------------- CSRF
# Signed double-submit cookie (OWASP CSRF cheat sheet): a random cookie, and a form token
# that is an HMAC of it. An attacker's site can't read the cookie, so it can't forge the token.


def new_csrf_cookie() -> str:
    return secrets.token_urlsafe(32)


def csrf_token_for(cookie_value: str, settings: Settings) -> str:
    return hmac.new(settings.secret_key, cookie_value.encode(), hashlib.sha256).hexdigest()


def csrf_valid(cookie_value: str | None, submitted: str | None, settings: Settings) -> bool:
    if not cookie_value or not submitted:
        return False
    return hmac.compare_digest(csrf_token_for(cookie_value, settings), submitted)


# --------------------------------------------------------------------------- MFA (TOTP)


def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str, last_step: int) -> int | None:
    """Return the accepted time-step, or None. Rejects reuse of a code already accepted."""
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(secret)
    now = time.time()
    for drift in (-1, 0, 1):  # allow 30s of clock skew either way
        at = now + drift * 30
        step = int(at // 30)
        if hmac.compare_digest(totp.at(at), code):
            return step if step > last_step else None
    return None


# --------------------------------------------------------------------------- rate limiting


class RateLimiter:
    """Sliding-window limiter. In-memory, so per process: use Redis if you run many workers."""

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit, self.window = limit, window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


# --------------------------------------------------------------------------- audit log


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def audit(db: DBSession, request: Request, event: str, user_id: str | None = None, detail: str = "") -> None:
    db.add(AuditEvent(user_id=user_id, event=event, ip=client_ip(request), detail=detail[:255]))
    db.commit()
