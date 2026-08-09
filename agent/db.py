"""SQLAlchemy 2.0 async-based DB layer.

Persists retest results (markdown / final_output) in SQLite, provides the async
engine and AsyncSession factory, and creates the DB directory and tables at startup.
Only `retest_records` is persisted; DC cache / thread state / thread secret stay in
process memory. SQLite + aiosqlite is the default; set `DATABASE_URL` to switch to
PostgreSQL etc.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DB_PATH = _PROJECT_ROOT / "data" / "retest_history.db"
_DEFAULT_DATABASE_URL = f"sqlite+aiosqlite:///{_DEFAULT_DB_PATH.as_posix()}"

DATABASE_URL = os.getenv("DATABASE_URL", _DEFAULT_DATABASE_URL)


class Base(DeclarativeBase):
    """Declarative base for ORM models."""


_engine = create_async_engine(DATABASE_URL, echo=False, future=True)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)


def _ensure_sqlite_dir() -> None:
    """Create the directory for the SQLite DB file; no-op for other backends."""
    if not DATABASE_URL.startswith("sqlite"):
        return
    after_scheme = DATABASE_URL.split("///", 1)[-1]
    if not after_scheme:
        return
    db_path = Path(after_scheme).expanduser()
    if not db_path.is_absolute():
        db_path = (_PROJECT_ROOT / db_path).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)


async def init_db() -> None:
    """Create tables at startup, leaving existing tables untouched."""
    _ensure_sqlite_dir()
    # Importing the model modules registers each model on Base.metadata.
    from agent.models import (  # noqa: F401
        audit_log,
        rto_record,
        retest_record,
        user,
    )

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # create_all does not add columns to existing tables, so patch them manually.
        await conn.run_sync(_ensure_retest_verdict_column)
        await conn.run_sync(_ensure_retest_commands_column)
        await conn.run_sync(_ensure_users_mfa_columns)
    logger.info("DB initialized: %s", DATABASE_URL)


def _ensure_retest_verdict_column(conn) -> None:
    """Add retest_records.verdict if missing (lightweight migration)."""
    from sqlalchemy import inspect, text

    inspector = inspect(conn)
    if "retest_records" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("retest_records")}
    if "verdict" in columns:
        return
    conn.execute(text("ALTER TABLE retest_records ADD COLUMN verdict VARCHAR(32)"))
    logger.info("DB migration: added retest_records.verdict column")


def _ensure_retest_commands_column(conn) -> None:
    """Add retest_records.commands_gz if missing (lightweight migration)."""
    from sqlalchemy import inspect, text

    inspector = inspect(conn)
    if "retest_records" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("retest_records")}
    if "commands_gz" in columns:
        return
    conn.execute(text("ALTER TABLE retest_records ADD COLUMN commands_gz BLOB"))
    logger.info("DB migration: added retest_records.commands_gz column")


def _ensure_users_mfa_columns(conn) -> None:
    """Add users.mfa_secret_enc / mfa_enabled if missing (lightweight migration)."""
    from sqlalchemy import inspect, text

    inspector = inspect(conn)
    if "users" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("users")}
    if "mfa_secret_enc" not in columns:
        conn.execute(text("ALTER TABLE users ADD COLUMN mfa_secret_enc VARCHAR(512)"))
        logger.info("DB migration: added users.mfa_secret_enc column")
    if "mfa_enabled" not in columns:
        # SQLite requires a default when adding a NOT NULL column to existing rows.
        conn.execute(
            text("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT 0")
        )
        logger.info("DB migration: added users.mfa_enabled column")


async def dispose_db() -> None:
    """Dispose the engine at shutdown."""
    await _engine.dispose()


def session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the factory that issues new AsyncSession instances."""
    return _session_factory
