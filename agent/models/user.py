"""Persistence model for login users (multi-user, all equal privileges).

Passwords are stored as scrypt hashes; no plaintext is kept. There is no role
column. disabled=True users cannot log in and their existing sessions are
invalidated (re-checked by middleware on every request).
"""
from __future__ import annotations

import datetime as _dt

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from agent.db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # MFA (TOTP), opt-in. secret is stored as Fernet ciphertext, never plaintext.
    # mid-enrollment (secret issued but not yet verified) leaves secret_enc set with enabled False.
    mfa_secret_enc: Mapped[str | None] = mapped_column(String(512), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: _dt.datetime.now(_dt.timezone.utc),
    )
