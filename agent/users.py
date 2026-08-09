"""DB store for login users (multi-user, all equal privileges).

Auth primitives (scrypt hashing/verification) are delegated to agent.auth.
Usernames are stripped of surrounding whitespace and remain case-sensitive.
"""
from __future__ import annotations

import datetime as _dt
import logging
import uuid

from sqlalchemy import func, select, update

from agent import auth
from agent.db import session_factory
from agent.models.user import User

logger = logging.getLogger(__name__)

# Dummy hash used to run one verification even when the user does not exist,
# reducing the timing difference that would reveal account existence.
# Lazily generated to avoid running scrypt at import time.
_DUMMY_HASH: str | None = None


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = auth.hash_password("timing-mitigation-dummy")
    return _DUMMY_HASH


def _norm(username: str) -> str:
    return (username or "").strip()


async def get_user(username: str) -> User | None:
    username = _norm(username)
    if not username:
        return None
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(select(User).where(User.username == username))
        return result.scalar_one_or_none()


async def count_users() -> int:
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(select(func.count()).select_from(User))
        return int(result.scalar_one())


async def is_active(username: str) -> bool:
    """True if the user exists and is not disabled."""
    user = await get_user(username)
    return bool(user and not user.disabled)


async def verify_user(username: str, password: str) -> User | None:
    """Verify username/password; return the User if valid, else None (failed or disabled)."""
    user = await get_user(username)
    if user is None or user.disabled:
        # Spend a constant verification cost even when absent/disabled to reduce timing leaks.
        auth.verify_password(password, _dummy_hash())
        return None
    if not auth.verify_password(password, user.password_hash):
        return None
    return user


async def create_user(username: str, password: str) -> User:
    username = _norm(username)
    if not username:
        raise ValueError("username must not be empty")
    if not password:
        raise ValueError("password must not be empty")
    if await get_user(username) is not None:
        raise ValueError(f"user already exists: {username}")
    user = User(
        id=str(uuid.uuid4()),
        username=username,
        password_hash=auth.hash_password(password),
        disabled=False,
        created_at=_dt.datetime.now(_dt.timezone.utc),
    )
    factory = session_factory()
    async with factory() as session:
        session.add(user)
        await session.commit()
    logger.info("user created: %s", username)
    return user


async def set_user_password(username: str, new_password: str) -> bool:
    """Update the given user's password; False if no such user."""
    if not new_password:
        raise ValueError("password must not be empty")
    new_hash = auth.hash_password(new_password)
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(
            update(User).where(User.username == _norm(username)).values(password_hash=new_hash)
        )
        await session.commit()
    return (result.rowcount or 0) > 0


async def set_disabled(username: str, disabled: bool) -> bool:
    """Toggle the given user's enabled/disabled state; False if no such user."""
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(
            update(User).where(User.username == _norm(username)).values(disabled=disabled)
        )
        await session.commit()
    return (result.rowcount or 0) > 0


async def list_users() -> list[User]:
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(select(User).order_by(User.username))
        return list(result.scalars().all())


# ----------------------------
# MFA (TOTP) store
# ----------------------------
# Encryption/decryption and code verification live in agent.totp; this module only
# persists the ciphertext (mfa_secret_enc) and the enabled flag (mfa_enabled).


async def get_mfa(username: str) -> tuple[bool, str | None]:
    """Return (mfa_enabled, mfa_secret_enc); (False, None) if the user does not exist."""
    user = await get_user(username)
    if user is None:
        return (False, None)
    return (bool(user.mfa_enabled), user.mfa_secret_enc)


async def set_pending_mfa_secret(username: str, secret_enc: str) -> bool:
    """Begin enrollment: store the encrypted secret and keep enabled False.

    Reset enabled to False so an existing active MFA can be re-enrolled: the old
    setting stays disabled until the new secret's code is verified, avoiding a
    half-configured dual state. False if no such user.
    """
    if not secret_enc:
        raise ValueError("secret_enc must not be empty")
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(
            update(User)
            .where(User.username == _norm(username))
            .values(mfa_secret_enc=secret_enc, mfa_enabled=False)
        )
        await session.commit()
    return (result.rowcount or 0) > 0


async def activate_mfa(username: str) -> bool:
    """Complete enrollment: set mfa_enabled=True after code verification succeeds; False if no such user."""
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(
            update(User).where(User.username == _norm(username)).values(mfa_enabled=True)
        )
        await session.commit()
    return (result.rowcount or 0) > 0


async def disable_mfa(username: str) -> bool:
    """Disable/reset MFA: set enabled=False and secret_enc=NULL; False if no such user.

    Shared by user self-service removal and CLI lockout recovery (mfa-reset).
    """
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(
            update(User)
            .where(User.username == _norm(username))
            .values(mfa_secret_enc=None, mfa_enabled=False)
        )
        await session.commit()
    return (result.rowcount or 0) > 0
