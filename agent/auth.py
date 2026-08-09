"""Authentication utilities (multi-operator: password/session primitives).

Login session primitives: scrypt password hashing/verification and issuance/
verification of a signed session token containing the username (for httpOnly
cookies). User persistence and CRUD live in `agent.users` (DB); this module
provides only the crypto primitives.

No external dependencies: password hashing uses stdlib `hashlib.scrypt`, session
signing uses stdlib `hmac` (SHA-256). (PyJWT is avoided to dodge the `jwt` package
name collision.)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time

logger = logging.getLogger(__name__)

_SCRYPT_N = 2**14  # CPU/memory cost
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_SALT_BYTES = 16
# scrypt maxmem needs ~128*N*r*p bytes; N=16384,r=8,p=1 is ~16MB.
_SCRYPT_MAXMEM = 128 * _SCRYPT_N * _SCRYPT_R * _SCRYPT_P * 2


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _session_secret() -> str:
    return _env("SESSION_SIGNING_SECRET")


def session_ttl_seconds() -> int:
    raw = _env("SESSION_TTL_SECONDS", "28800")  # default 8 hours
    try:
        return max(60, int(raw))
    except ValueError:
        return 28800


def session_cookie_name() -> str:
    return _env("SESSION_COOKIE_NAME", "ra_session")


def app_env() -> str:
    """Runtime mode (default "prod"); only toggles the SESSION_COOKIE_SECURE default."""
    return _env("APP_ENV", "prod").lower()


def session_cookie_secure() -> bool:
    """Cookie Secure attribute; explicit SESSION_COOKIE_SECURE wins, else dev=False."""
    raw = _env("SESSION_COOKIE_SECURE")
    if raw:
        return raw.lower() not in ("false", "0", "off", "no")
    return app_env() != "dev"


def auth_enabled() -> bool:
    """Whether login auth is on (true when SESSION_SIGNING_SECRET is set).

    When off, all endpoints are open for dev use; always set it on a shared host.
    With zero users, login is impossible (fail-closed).
    """
    return bool(_session_secret())


def hash_password(plain: str) -> str:
    """Hash a plaintext password into `scrypt$N$r$p$salt_b64$dk_b64` form."""
    salt = secrets.token_bytes(_SCRYPT_SALT_BYTES)
    dk = hashlib.scrypt(
        plain.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=_SCRYPT_MAXMEM,
    )

    def b64(b: bytes) -> str:
        return base64.b64encode(b).decode("ascii")

    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${b64(salt)}${b64(dk)}"


def verify_password(plain: str, stored: str) -> bool:
    """Verify a plaintext password against a stored scrypt hash (constant time)."""
    if not stored or not plain:
        return False
    try:
        scheme, n_s, r_s, p_s, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
    except (ValueError, TypeError):
        return False

    try:
        actual = hashlib.scrypt(
            plain.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
            maxmem=128 * n * r * p * 2,
        )
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(actual, expected)


# Session token format:
#   base64url(payload_json) + "." + base64url(hmac_sha256(payload_b64, secret))
# Not JWT-compatible, but sufficient for a signed single-user session; no external deps.

def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sign(payload_b64: str, secret: str) -> str:
    sig = hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64u_encode(sig)


def create_session_token(username: str) -> str:
    """Issue a signed session token (containing the username) on successful login."""
    secret = _session_secret()
    if not secret:
        raise RuntimeError("SESSION_SIGNING_SECRET is not set")
    if not username:
        raise ValueError("username must not be empty")
    now = _now()
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + session_ttl_seconds(),
    }
    payload_b64 = _b64u_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{payload_b64}.{_sign(payload_b64, secret)}"


def mfa_challenge_ttl_seconds() -> int:
    """TTL of an MFA challenge token in seconds (default 300 = 5 minutes)."""
    raw = _env("MFA_CHALLENGE_TTL_SECONDS", "300")
    try:
        return max(30, int(raw))
    except ValueError:
        return 300


def create_mfa_challenge_token(username: str) -> str:
    """Issue a short-lived signed token for a password-verified but TOTP-unverified state.

    Carries `pur:"mfa"` to distinguish it from a session token (read_session_username
    rejects it). The frontend posts this token plus a one-time code to /login/mfa.
    """
    secret = _session_secret()
    if not secret:
        raise RuntimeError("SESSION_SIGNING_SECRET is not set")
    if not username:
        raise ValueError("username must not be empty")
    now = _now()
    payload = {
        "sub": username,
        "pur": "mfa",
        "iat": now,
        "exp": now + mfa_challenge_ttl_seconds(),
    }
    payload_b64 = _b64u_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{payload_b64}.{_sign(payload_b64, secret)}"


def read_mfa_challenge(token: str | None) -> str | None:
    """Verify an MFA challenge token (signature, expiry, pur=mfa) and return sub."""
    payload = _read_signed_payload(token)
    if payload is None or payload.get("pur") != "mfa":
        return None
    sub = payload.get("sub")
    return sub if isinstance(sub, str) and sub else None


def _read_signed_payload(token: str | None) -> dict | None:
    """Verify a signed token's signature and expiry (exp); return the payload dict."""
    secret = _session_secret()
    if not secret or not token or "." not in token:
        return None
    payload_b64, _, sig = token.partition(".")
    if not payload_b64 or not sig:
        return None
    if not hmac.compare_digest(sig, _sign(payload_b64, secret)):
        return None
    try:
        payload = json.loads(_b64u_decode(payload_b64))
        exp = int(payload.get("exp", 0))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    if _now() >= exp:
        return None
    return payload if isinstance(payload, dict) else None


def read_session_username(token: str | None) -> str | None:
    """Verify a session token (signature, expiry) and return the username (sub).

    Rejects MFA challenge tokens (pur=mfa), which are not full sessions. DB-side
    user validity is checked separately by the caller.
    """
    payload = _read_signed_payload(token)
    if payload is None or payload.get("pur") == "mfa":
        return None
    sub = payload.get("sub")
    return sub if isinstance(sub, str) and sub else None


def _now() -> int:
    """Current UNIX seconds, isolated in a function for easy test patching."""
    return int(time.time())
