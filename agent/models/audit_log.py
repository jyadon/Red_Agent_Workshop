"""Persistence model for audit logs (who did what and when).

Records authentication events (login/logout/change_password) and sensitive
operations (retest runs, command approval/execution, Entra collection, etc.)
for accountability in multi-user deployments.
"""
from __future__ import annotations

import datetime as _dt

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agent.db import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: _dt.datetime.now(_dt.timezone.utc),
    )
    # Unauthenticated attempts are recorded as "anonymous" etc.
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    # Optional context (target finding_no, command summary, etc.); never store sensitive data.
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_audit_log_created_at", "created_at"),
        Index("ix_audit_log_username_created_at", "username", "created_at"),
    )
