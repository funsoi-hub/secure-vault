"""Runtime configuration, loaded from environment variables.

Secrets are never hard-coded. In production the app refuses to start if a
required secret is missing, instead of silently falling back to a weak default.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import secrets
from dataclasses import dataclass, field

log = logging.getLogger("vault.config")


@dataclass(frozen=True)
class Settings:
    env: str = "development"
    database_url: str = "sqlite:///./vault.db"
    # Key-encryption key (KEK): wraps every user's data-encryption key.
    master_key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)
    # Used to sign CSRF tokens. Separate from the KEK so the two can rotate independently.
    secret_key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)
    cookie_secure: bool = True
    allowed_hosts: tuple[str, ...] = ("*",)
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    max_upload_bytes: int = 5 * 1024 * 1024
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    @property
    def is_production(self) -> bool:
        return self.env == "production"


def _decode_key(name: str, env: str) -> bytes:
    raw = os.getenv(name, "").strip()
    if not raw:
        if env == "production":
            raise RuntimeError(f"{name} must be set when VAULT_ENV=production")
        log.warning("%s not set: using a random key. Data will be unreadable after a restart.", name)
        return secrets.token_bytes(32)
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError(f"{name} is not valid base64") from exc
    if len(key) != 32:
        raise RuntimeError(f"{name} must decode to exactly 32 bytes (got {len(key)})")
    return key


def load_settings() -> Settings:
    env = os.getenv("VAULT_ENV", "development").lower()
    hosts = tuple(h.strip() for h in os.getenv("ALLOWED_HOSTS", "*").split(",") if h.strip())
    return Settings(
        env=env,
        database_url=os.getenv("DATABASE_URL", "sqlite:///./vault.db"),
        master_key=_decode_key("VAULT_MASTER_KEY", env),
        secret_key=_decode_key("VAULT_SECRET_KEY", env),
        cookie_secure=os.getenv("COOKIE_SECURE", "true").lower() != "false",
        allowed_hosts=hosts or ("*",),
    )
