"""Persistence model for RTO execution results.

markdown and final_output are stored as gzip-compressed BLOBs. Records are
shared across all authenticated users (no user column), same as retest_records.
"""
from __future__ import annotations

import datetime as _dt

from sqlalchemy import Boolean, DateTime, Index, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from agent.db import Base


class RTORecord(Base):
    __tablename__ = "rto_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    thread_id: Mapped[str] = mapped_column(String(64), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    markdown_gz: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    final_output_gz: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    final_output_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: _dt.datetime.now(_dt.timezone.utc),
    )

    __table_args__ = (
        Index("ix_rto_records_created_at", "created_at"),
    )
