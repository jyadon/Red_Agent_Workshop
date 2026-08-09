"""Temporary throttling of failed logins (auto-releasing).

Instead of permanent lockouts or manual admin unlocks, this rejects only while
recent failures are too numerous and releases automatically over time.

It reuses the existing `audit_log` (login / login_failed already recorded with IP):

- State lives in the DB, so it is shared across workers and restarts (no extra table).
- Per user, it counts failures since the last successful login and within the window.
  A successful login resets the count.
- If failures reach the threshold, the user is locked. As the oldest counted failure
  falls out of the window the count drops, so with no further failures the lock
  releases automatically over time.

Threshold and window seconds are tuned via environment variables. This is an
application-side backstop, not a substitute for rate limiting at the network edge.
"""
from __future__ import annotations

import datetime as _dt
import os
from dataclasses import dataclass

from sqlalchemy import func, select

from agent.db import session_factory
from agent.models.audit_log import AuditLog


def threshold() -> int:
    """Failure count that triggers a lock (default 5)."""
    raw = os.getenv("LOGIN_LOCKOUT_THRESHOLD", "5").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 5


def window_seconds() -> int:
    """Window for counting failures, also the lock duration (seconds; default 900 = 15 min).

    The lock releases automatically once this many seconds pass after the last counted failure.
    """
    raw = os.getenv("LOGIN_LOCKOUT_WINDOW_SECONDS", "900").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 900


@dataclass(frozen=True)
class LockStatus:
    """Throttling decision result.

    - locked: True while locked.
    - retry_after: estimated seconds until release (0 when locked=False). For the Retry-After header.
    - failures: failure count within the window (for audit/debugging).
    """

    locked: bool
    retry_after: int
    failures: int


def _as_utc(value: _dt.datetime) -> _dt.datetime:
    """Treat a naive datetime (from SQLite) as UTC-aware."""
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value


async def check(username: str, *, now: _dt.datetime | None = None) -> LockStatus:
    """Count recent login_failed events and return the user's lock status.

    `now` is for test injection; normally the current UTC time is used.
    """
    uname = (username or "").strip() or "anonymous"
    th = threshold()
    window = window_seconds()
    now = now or _dt.datetime.now(_dt.timezone.utc)
    cutoff = now - _dt.timedelta(seconds=window)

    factory = session_factory()
    async with factory() as session:
        # Raise the window's lower bound to the last successful login so that a
        # success resets the counter.
        last_ok = await session.execute(
            select(func.max(AuditLog.created_at)).where(
                AuditLog.username == uname,
                AuditLog.action == "login",
            )
        )
        last_ok_at = last_ok.scalar_one_or_none()
        lower = cutoff
        if last_ok_at is not None and _as_utc(last_ok_at) > lower:
            lower = _as_utc(last_ok_at)

        rows = await session.execute(
            select(AuditLog.created_at)
            .where(
                AuditLog.username == uname,
                AuditLog.action == "login_failed",
                AuditLog.created_at > lower,
            )
            .order_by(AuditLog.created_at.asc())
        )
        times = [_as_utc(r[0]) for r in rows.all()]

    count = len(times)
    if count < th:
        return LockStatus(locked=False, retry_after=0, failures=count)

    # Threshold reached. Once the first (count - th + 1) failures fall out of the window,
    # count < th. Release time is when the last of those, times[count - th], expires.
    releasing = times[count - th]
    release_at = releasing + _dt.timedelta(seconds=window)
    retry_after = int((release_at - now).total_seconds())
    if retry_after <= 0:
        return LockStatus(locked=False, retry_after=0, failures=count)
    return LockStatus(locked=True, retry_after=retry_after, failures=count)
