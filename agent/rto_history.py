"""Repository for RTO execution results (RTORecord).

final_output_json is capped by `RTO_FINAL_OUTPUT_MAX_BYTES`; on overflow it is
head/tail-preserving truncated. Both markdown and final_output_json are stored
gzip-compressed.
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select

from agent.credential_mask import mask_report_text
from agent.db import session_factory
from agent.models.rto_record import RTORecord

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RTOHistoryItem:
    """DTO for API responses, with BLOBs already decoded/decompressed."""

    id: str
    thread_id: str
    domain: str
    markdown: str
    final_output: Any | None
    final_output_truncated: bool
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "threadId": self.thread_id,
            "domain": self.domain,
            "markdown": self.markdown,
            "finalOutput": self.final_output,
            "finalOutputTruncated": self.final_output_truncated,
            "createdAt": self.created_at.isoformat(),
        }


def _max_final_output_bytes() -> int:
    """0 or negative means unlimited."""
    raw = os.getenv("RTO_FINAL_OUTPUT_MAX_BYTES", "1048576")
    try:
        return max(0, int(raw))
    except ValueError:
        return 1_048_576


def _truncate_head_tail(text: str, limit: int) -> tuple[str, bool]:
    """If text's byte length exceeds limit, keep head/tail and place a marker in the middle."""
    if limit <= 0:
        return text, False
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    marker_template = "\n... truncated {n} bytes ...\n"
    reserve = len(marker_template.format(n=len(encoded)).encode("utf-8"))
    remaining = max(0, limit - reserve)
    head_bytes = remaining // 2
    tail_bytes = remaining - head_bytes
    head = encoded[:head_bytes].decode("utf-8", errors="ignore")
    tail = encoded[-tail_bytes:].decode("utf-8", errors="ignore") if tail_bytes > 0 else ""
    dropped = len(encoded) - len(head.encode("utf-8")) - len(tail.encode("utf-8"))
    return f"{head}{marker_template.format(n=dropped)}{tail}", True


def _gzip_bytes(text: str | None) -> bytes | None:
    return gzip.compress(text.encode("utf-8")) if text is not None else None


def _gunzip_str(blob: bytes | None) -> str | None:
    return gzip.decompress(blob).decode("utf-8") if blob is not None else None


def _dump_final_output_json(final_output: Any) -> str | None:
    if final_output is None:
        return None
    try:
        return json.dumps(final_output, ensure_ascii=False)
    except (TypeError, ValueError):
        logger.warning("RTO final_output JSON serialization failed; storing repr fallback")
        return json.dumps({"__repr__": repr(final_output)}, ensure_ascii=False)


def _load_final_output_json(text: str | None) -> Any | None:
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"__raw__": text}


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _to_dto(record: RTORecord) -> RTOHistoryItem:
    md = _gunzip_str(record.markdown_gz) or ""
    fo_json = _gunzip_str(record.final_output_gz)
    return RTOHistoryItem(
        id=record.id,
        thread_id=record.thread_id,
        domain=record.domain or "",
        markdown=md,
        final_output=_load_final_output_json(fo_json),
        final_output_truncated=bool(record.final_output_truncated),
        created_at=_aware(record.created_at),
    )


async def save_record(
    *,
    thread_id: str,
    domain: str,
    markdown: str | None,
    final_output: Any,
) -> "RTOHistoryItem | None":
    """Persist history on RTO completion. Skips when markdown is empty."""
    if not thread_id:
        logger.warning("rto_history.save_record skipped: empty thread_id")
        return None
    md = markdown if isinstance(markdown, str) and markdown.strip() else None
    if md is None:
        logger.info("rto_history.save_record skipped: empty markdown (thread=%s)", thread_id)
        return None

    # At-rest protection: redact credentials discovered during the attack
    # (plaintext passwords / hashes) before storage. Does not affect live display.
    md = mask_report_text(md) or md

    raw_final = _dump_final_output_json(final_output)
    truncated = False
    if raw_final is not None:
        raw_final = mask_report_text(raw_final)
        raw_final, truncated = _truncate_head_tail(raw_final, _max_final_output_bytes())

    record = RTORecord(
        id=str(uuid.uuid4()),
        thread_id=thread_id,
        domain=domain or "",
        markdown_gz=_gzip_bytes(md) or b"",
        final_output_gz=_gzip_bytes(raw_final),
        final_output_truncated=truncated,
        created_at=datetime.now(timezone.utc),
    )
    factory = session_factory()
    async with factory() as session:
        session.add(record)
        await session.commit()
    logger.info(
        "rto_history saved (id=%s thread=%s domain=%s truncated=%s)",
        record.id,
        thread_id,
        domain,
        truncated,
    )
    return _to_dto(record)


async def list_all() -> list[RTOHistoryItem]:
    """Return all RTO execution history, newest first."""
    factory = session_factory()
    async with factory() as session:
        stmt = select(RTORecord).order_by(RTORecord.created_at.desc())
        result = await session.execute(stmt)
        records = result.scalars().all()
    return [_to_dto(r) for r in records]


async def get_by_id(record_id: str) -> RTOHistoryItem | None:
    factory = session_factory()
    async with factory() as session:
        record = await session.get(RTORecord, record_id)
        return _to_dto(record) if record is not None else None


async def delete_by_id(record_id: str) -> bool:
    """Delete one record. Returns False if no match."""
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(
            delete(RTORecord).where(RTORecord.id == record_id)
        )
        await session.commit()
    return result.rowcount > 0


async def delete_by_ids(ids: list[str]) -> int:
    if not ids:
        return 0
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(
            delete(RTORecord).where(RTORecord.id.in_(ids))
        )
        await session.commit()
    return result.rowcount or 0


async def delete_all() -> int:
    factory = session_factory()
    async with factory() as session:
        result = await session.execute(delete(RTORecord))
        await session.commit()
    return result.rowcount or 0
