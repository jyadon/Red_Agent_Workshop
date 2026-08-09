"""Audit logging for accountability in multi-operator deployments.

Records who did what and when for key auth events and sensitive actions. Recording is
best-effort and never blocks the app; sensitive data (passwords, etc.) must not go in detail.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import os
import uuid

from sqlalchemy import delete, select

from agent.db import session_factory
from agent.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


def retention_days() -> int:
    """Audit log retention in days (default 180); older rows are pruned periodically."""
    raw = os.getenv("AUDIT_LOG_RETENTION_DAYS", "180").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 180


def prune_interval_hours() -> float:
    """Interval between periodic prunes, in hours (default 24)."""
    raw = os.getenv("AUDIT_LOG_PRUNE_INTERVAL_HOURS", "24").strip()
    try:
        return max(0.1, float(raw))
    except ValueError:
        return 24.0


async def record(
    username: str | None,
    action: str,
    detail: str | None = None,
    source_ip: str | None = None,
) -> None:
    """Record a single audit log entry; never raises on failure."""
    try:
        entry = AuditLog(
            id=str(uuid.uuid4()),
            created_at=_dt.datetime.now(_dt.timezone.utc),
            username=(username or "anonymous")[:128],
            action=(action or "")[:64],
            detail=detail,
            source_ip=source_ip,
        )
        factory = session_factory()
        async with factory() as session:
            session.add(entry)
            await session.commit()
    except Exception:
        logger.exception("audit record failed (action=%s user=%s)", action, username)


async def list_recent(limit: int = 200) -> list[AuditLog]:
    """Return audit logs in most-recent-first order."""
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(
            select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())


async def prune_older_than(days: int | None = None) -> int:
    """Delete audit logs older than the retention window and return the deleted count.

    On SQLite, DELETE does not shrink the file, but freed pages are reused by later
    inserts so size plateaus (run VACUUM separately to reclaim actual disk space).
    """
    days = days if days is not None else retention_days()
    cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=days)
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(delete(AuditLog).where(AuditLog.created_at < cutoff))
        await session.commit()
    deleted = result.rowcount or 0
    if deleted:
        logger.info("audit_log pruned: %d rows older than %d days", deleted, days)
    return deleted


async def run_periodic_prune() -> None:
    """In-app periodic task: prune once at startup, then once per interval.

    Started via asyncio.create_task from lifespan and cancelled on shutdown.
    Prune failures are logged and swallowed so the loop keeps running.
    """
    while True:
        try:
            await prune_older_than()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("periodic audit prune failed")
        try:
            await asyncio.sleep(prune_interval_hours() * 3600)
        except asyncio.CancelledError:
            raise
