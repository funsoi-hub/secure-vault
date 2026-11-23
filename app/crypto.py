"""Envelope encryption for everything a user stores.

    master key (KEK, from env) --wraps--> per-user data key (DEK) --encrypts--> notes, files, TOTP secret

* AES-256-GCM everywhere: confidentiality and integrity in one primitive.
* A fresh 96-bit random nonce per encryption.
* Associated data (AAD) binds each ciphertext to its owner and record, so a
  ciphertext copied into another user's row, or another field, fails to decrypt.
* A version byte prefixes every blob so the format or key can be rotated later.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = b"\x01"
NONCE_LEN = 12


class DecryptionError(Exception):
    """Raised when a ciphertext is tampered with, or used in the wrong context."""


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return VERSION + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def _open(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < 1 + NONCE_LEN + 16 or blob[:1] != VERSION:
        raise DecryptionError("unsupported or truncated ciphertext")
    nonce, ct = blob[1 : 1 + NONCE_LEN], blob[1 + NONCE_LEN :]
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise DecryptionError("ciphertext failed authentication") from exc


class Vault:
    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes")
        self._kek = master_key

    # Data keys -----------------------------------------------------------
    @staticmethod
    def new_data_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    def wrap_key(self, dek: bytes, user_id: str) -> bytes:
        return _seal(self._kek, dek, f"dek:{user_id}".encode())

    def unwrap_key(self, wrapped: bytes, user_id: str) -> bytes:
        return _open(self._kek, wrapped, f"dek:{user_id}".encode())

    # Records -------------------------------------------------------------
    @staticmethod
    def encrypt(dek: bytes, plaintext: bytes, context: str) -> bytes:
        return _seal(dek, plaintext, context.encode())

    @staticmethod
    def decrypt(dek: bytes, blob: bytes, context: str) -> bytes:
        return _open(dek, blob, context.encode())

    # Server-held secrets (e.g. TOTP seeds) are wrapped directly with the KEK.
    def encrypt_secret(self, plaintext: bytes, context: str) -> bytes:
        return _seal(self._kek, plaintext, context.encode())

    def decrypt_secret(self, blob: bytes, context: str) -> bytes:
        return _open(self._kek, blob, context.encode())
