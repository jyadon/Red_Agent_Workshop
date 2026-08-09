"""Persistence model for retest results."""
from __future__ import annotations

import datetime as _dt

from sqlalchemy import Boolean, DateTime, Index, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from agent.db import Base


class RetestRecord(Base):
    __tablename__ = "retest_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_no: Mapped[str] = mapped_column(String(64), nullable=False)
    thread_id: Mapped[str] = mapped_column(String(64), nullable=False)
    markdown_gz: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # NULL for legacy rows or when extraction failed; computed lazily on read.
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    final_output_gz: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    final_output_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    # gzip'd JSON array of placeholder-ized commands captured during the run (for RTO export).
    # NULL for legacy rows or runs that executed no commands.
    commands_gz: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: _dt.datetime.now(_dt.timezone.utc),
    )

    __table_args__ = (
        Index("ix_retest_records_finding_no_created_at", "finding_no", "created_at"),
    )
