"""TOTP (RFC 6238) and at-rest encryption of TOTP secrets.

MFA primitives. Design:

- TOTP is implemented using only the stdlib `hmac` (SHA-1), matching `auth.py`
  in avoiding extra dependencies. Defaults: 6 digits, 30-second period,
  verification window +/-1 (clock-skew tolerant).
- Secrets (base32 strings) are never stored in plaintext; they are encrypted
  with `cryptography` Fernet before storage. The key is read from the
  environment variable `MFA_SECRET_KEY` (a Fernet key).
- If `MFA_SECRET_KEY` is unset, MFA is treated as "not configured"
  (`mfa_configured()` returns False). In that case registration is refused and
  encrypt/decrypt return None (fail-safe).

User persistence and columns are handled by `agent.users` / `agent.models.user`;
this module is limited to crypto/OTP primitives.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import struct
import time
import urllib.parse

logger = logging.getLogger(__name__)

# TOTP parameters (RFC 6238 standard)
_DIGITS = 6
_PERIOD = 30  # seconds
_ALGO = "SHA1"  # match the default of authenticator apps
_SECRET_BYTES = 20  # 32 characters in base32
_DEFAULT_WINDOW = 1  # allow +/-1 step (+/-30 seconds)


def generate_secret() -> str:
    """Generate a new TOTP secret (base32, no padding)."""
    raw = secrets.token_bytes(_SECRET_BYTES)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def otpauth_uri(secret_b32: str, account: str, issuer: str = "Red Agent") -> str:
    """Build an otpauth:// URI for authenticator app enrollment (manual key entry or QR)."""
    label = urllib.parse.quote(f"{issuer}:{account}")
    params = urllib.parse.urlencode(
        {
            "secret": secret_b32,
            "issuer": issuer,
            "algorithm": _ALGO,
            "digits": _DIGITS,
            "period": _PERIOD,
        }
    )
    return f"otpauth://totp/{label}?{params}"


def _b32_decode(secret_b32: str) -> bytes | None:
    """Decode a base32 secret (restores padding, case-insensitive). None if invalid."""
    s = (secret_b32 or "").strip().replace(" ", "").upper()
    if not s:
        return None
    pad = "=" * (-len(s) % 8)
    try:
        return base64.b32decode(s + pad, casefold=True)
    except (ValueError, TypeError):
        return None


def _hotp(key: bytes, counter: int) -> str:
    """HOTP (RFC 4226): compute a 6-digit code from a counter."""
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**_DIGITS)).zfill(_DIGITS)


def generate_code(secret_b32: str, at: int | None = None) -> str | None:
    """Return the TOTP code for the given time (default: now). None if secret is invalid."""
    key = _b32_decode(secret_b32)
    if key is None:
        return None
    counter = int((_now() if at is None else at) // _PERIOD)
    return _hotp(key, counter)


def verify_code(
    code: str, secret_b32: str, window: int = _DEFAULT_WINDOW, at: int | None = None
) -> bool:
    """Verify a TOTP code, allowing +/-window steps, using constant-time comparison.

    code is 6 digits (surrounding whitespace and hyphens are ignored). Invalid
    input or an invalid secret returns False.
    """
    if not code:
        return False
    normalized = code.strip().replace("-", "").replace(" ", "")
    if len(normalized) != _DIGITS or not normalized.isdigit():
        return False
    key = _b32_decode(secret_b32)
    if key is None:
        return False
    base = int((_now() if at is None else at) // _PERIOD)
    for offset in range(-window, window + 1):
        candidate = _hotp(key, base + offset)
        if hmac.compare_digest(candidate, normalized):
            return True
    return False


def _mfa_key() -> str:
    return os.getenv("MFA_SECRET_KEY", "").strip()


def mfa_configured() -> bool:
    """Whether MFA is usable (`MFA_SECRET_KEY` is set and valid as a Fernet key)."""
    return _fernet() is not None


def _fernet():
    """Build a Fernet instance from the env key. None if unset/invalid."""
    key = _mfa_key()
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet

        return Fernet(key.encode("ascii"))
    except Exception:
        logger.warning("MFA_SECRET_KEY is set but invalid as a Fernet key; MFA disabled")
        return None


def encrypt_secret(secret_b32: str) -> str | None:
    """Encrypt a base32 secret into a storable string. None if the key is unset."""
    f = _fernet()
    if f is None or not secret_b32:
        return None
    return f.encrypt(secret_b32.encode("ascii")).decode("ascii")


def decrypt_secret(enc: str | None) -> str | None:
    """Decrypt a stored ciphertext back to a base32 secret. None if key unset or decryption fails."""
    f = _fernet()
    if f is None or not enc:
        return None
    try:
        return f.decrypt(enc.encode("ascii")).decode("ascii")
    except Exception:
        logger.warning("failed to decrypt stored MFA secret (key rotated or corrupted?)")
        return None


def _now() -> int:
    """Current UNIX time in seconds; isolated in a function for easy test patching."""
    return int(time.time())
