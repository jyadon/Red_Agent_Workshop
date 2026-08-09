"""Repository for retest results (RetestRecord).

final_output_json is capped by RETEST_FINAL_OUTPUT_MAX_BYTES; when exceeded it
is head/tail truncated with a central "... truncated N bytes ..." marker. Both
markdown and final_output_json are gzip-compressed and stored as BLOBs.
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
from agent.markdown_extract import extract_markdown_from_final_output
from agent.models.retest_record import RetestRecord
from agent.verdict import extract_verdict

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RetestHistoryItem:
    """API response DTO with BLOBs already decoded/decompressed."""

    id: str
    finding_no: str
    thread_id: str
    markdown: str
    final_output: Any | None
    final_output_truncated: bool
    created_at: datetime
    # Normalized verdict code (resolved/partial/unresolved/inconclusive); None if not extractable.
    verdict: str | None
    # Placeholder-ized commands captured during the run (for RTO export). Empty for legacy rows.
    commands: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "findingNo": self.finding_no,
            "threadId": self.thread_id,
            "markdown": self.markdown,
            "finalOutput": self.final_output,
            "finalOutputTruncated": self.final_output_truncated,
            "createdAt": self.created_at.isoformat(),
            "verdict": self.verdict,
            "commands": self.commands,
        }


@dataclass(frozen=True)
class FindingStatus:
    """Latest status per finding (lightweight DTO for list badges); excludes markdown body."""

    finding_no: str
    verdict: str | None
    created_at: datetime
    thread_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "findingNo": self.finding_no,
            "verdict": self.verdict,
            "createdAt": self.created_at.isoformat(),
            "threadId": self.thread_id,
        }


def _max_final_output_bytes() -> int:
    """Byte cap for final_output; 0 or negative means unlimited."""
    raw = os.getenv("RETEST_FINAL_OUTPUT_MAX_BYTES", "1048576")
    try:
        value = int(raw)
    except ValueError:
        return 1_048_576
    return max(0, value)


def _truncate_head_tail(text: str, limit: int) -> tuple[str, bool]:
    """Keep head/tail and insert a central marker when the byte length exceeds limit; returns (text, truncated). limit<=0 is unlimited."""
    if limit <= 0:
        return text, False
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    marker_template = "\n... truncated {n} bytes ...\n"
    sample_marker = marker_template.format(n=len(encoded))
    sample_marker_bytes = len(sample_marker.encode("utf-8"))
    remaining = max(0, limit - sample_marker_bytes)
    head_bytes = remaining // 2
    tail_bytes = remaining - head_bytes

    # errors="ignore" absorbs cuts that land mid UTF-8 multibyte sequence
    head_slice = encoded[:head_bytes].decode("utf-8", errors="ignore")
    tail_slice = encoded[-tail_bytes:].decode("utf-8", errors="ignore") if tail_bytes > 0 else ""
    truncated_bytes = (
        len(encoded) - len(head_slice.encode("utf-8")) - len(tail_slice.encode("utf-8"))
    )
    marker = marker_template.format(n=truncated_bytes)
    return f"{head_slice}{marker}{tail_slice}", True


def _gzip_bytes(text: str | None) -> bytes | None:
    if text is None:
        return None
    return gzip.compress(text.encode("utf-8"))


def _gunzip_str(blob: bytes | None) -> str | None:
    if blob is None:
        return None
    return gzip.decompress(blob).decode("utf-8")


def _dump_final_output_json(final_output: Any) -> str | None:
    """Serialize final_output to a JSON string, falling back to repr if not serializable."""
    if final_output is None:
        return None
    try:
        return json.dumps(final_output, ensure_ascii=False)
    except (TypeError, ValueError):
        logger.warning("final_output JSON serialization failed; storing repr fallback")
        return json.dumps({"__repr__": repr(final_output)}, ensure_ascii=False)


def _load_final_output_json(text: str | None) -> Any | None:
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"__raw__": text}


async def save_record(
    *,
    finding_no: str,
    thread_id: str,
    markdown: str | None,
    final_output: Any,
    commands: list[dict[str, Any]] | None = None,
) -> "RetestHistoryItem | None":
    """Save a history record on retest completion; skips if markdown cannot be extracted. final_output_json is truncated per RETEST_FINAL_OUTPUT_MAX_BYTES."""
    if not finding_no or not thread_id:
        logger.warning(
            "retest_history.save_record skipped: finding_no=%r thread_id=%r",
            finding_no,
            thread_id,
        )
        return None

    md = markdown if isinstance(markdown, str) and markdown.strip() else None
    if md is None:
        md = extract_markdown_from_final_output(final_output)
    if md is None or not md.strip():
        logger.info(
            "retest_history.save_record skipped: empty markdown (finding=%s thread=%s)",
            finding_no,
            thread_id,
        )
        return None

    # At-rest protection: mask credentials (plaintext passwords/hashes) discovered
    # during the attack before persisting. Does not affect live display.
    md = mask_report_text(md) or md

    raw_final = _dump_final_output_json(final_output)
    truncated = False
    if raw_final is not None:
        raw_final = mask_report_text(raw_final)
        raw_final, truncated = _truncate_head_tail(raw_final, _max_final_output_bytes())

    # Placeholder-ized commands captured during the run. Already stripped of secrets at capture;
    # mask_report_text is a defense-in-depth pass in case a credential slipped into a command.
    commands_json: str | None = None
    if commands:
        commands_json = json.dumps(commands, ensure_ascii=False)
        commands_json = mask_report_text(commands_json) or commands_json

    record = RetestRecord(
        id=str(uuid.uuid4()),
        finding_no=finding_no,
        thread_id=thread_id,
        markdown_gz=_gzip_bytes(md) or b"",
        final_output_gz=_gzip_bytes(raw_final),
        final_output_truncated=truncated,
        commands_gz=_gzip_bytes(commands_json),
        # Store the structured verdict at save time for the list's latest-status display.
        verdict=extract_verdict(md),
        created_at=datetime.now(timezone.utc),
    )

    factory = session_factory()
    async with factory() as session:
        session.add(record)
        await session.commit()

    logger.info(
        "retest_history saved (id=%s finding=%s thread=%s truncated=%s)",
        record.id,
        finding_no,
        thread_id,
        truncated,
    )
    return _to_dto(record)


def _to_dto(record: RetestRecord) -> RetestHistoryItem:
    md = _gunzip_str(record.markdown_gz) or ""
    fo_json = _gunzip_str(record.final_output_gz)
    # Lazily derive from markdown when the verdict column is NULL (legacy rows saved before the column existed).
    verdict = record.verdict or extract_verdict(md)
    commands: list[dict[str, Any]] = []
    commands_json = _gunzip_str(getattr(record, "commands_gz", None))
    if commands_json:
        try:
            loaded = json.loads(commands_json)
            if isinstance(loaded, list):
                commands = [c for c in loaded if isinstance(c, dict)]
        except json.JSONDecodeError:
            commands = []
    return RetestHistoryItem(
        id=record.id,
        finding_no=record.finding_no,
        thread_id=record.thread_id,
        markdown=md,
        final_output=_load_final_output_json(fo_json),
        final_output_truncated=bool(record.final_output_truncated),
        created_at=_ensure_aware(record.created_at),
        verdict=verdict,
        commands=commands,
    )


def _ensure_aware(value: datetime) -> datetime:
    """Attach UTC since DateTime values returned from SQLite may be naive."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


async def list_by_finding(finding_no: str) -> list[RetestHistoryItem]:
    """Return the history for a finding, newest first."""
    factory = session_factory()
    async with factory() as session:
        stmt = (
            select(RetestRecord)
            .where(RetestRecord.finding_no == finding_no)
            .order_by(RetestRecord.created_at.desc())
        )
        result = await session.execute(stmt)
        records = result.scalars().all()
    return [_to_dto(r) for r in records]


async def latest_status_summary() -> list[FindingStatus]:
    """Return the latest-record verdict summary per finding (for list status badges).

    Does not read the final_output BLOB. Only legacy rows with a NULL verdict
    have their markdown decompressed to derive the verdict lazily."""
    factory = session_factory()
    async with factory() as session:
        # Ordered by created_at desc per finding so each finding's first row is the latest.
        stmt = select(
            RetestRecord.finding_no,
            RetestRecord.verdict,
            RetestRecord.created_at,
            RetestRecord.thread_id,
            RetestRecord.markdown_gz,
        ).order_by(RetestRecord.finding_no, RetestRecord.created_at.desc())
        result = await session.execute(stmt)
        rows = result.all()

    seen: set[str] = set()
    summary: list[FindingStatus] = []
    for finding_no, verdict, created_at, thread_id, markdown_gz in rows:
        if finding_no in seen:
            continue
        seen.add(finding_no)
        resolved_verdict = verdict
        if resolved_verdict is None:
            resolved_verdict = extract_verdict(_gunzip_str(markdown_gz))
        summary.append(
            FindingStatus(
                finding_no=finding_no,
                verdict=resolved_verdict,
                created_at=_ensure_aware(created_at),
                thread_id=thread_id,
            )
        )
    return summary


async def get_by_id(record_id: str) -> RetestHistoryItem | None:
    factory = session_factory()
    async with factory() as session:
        stmt = select(RetestRecord).where(RetestRecord.id == record_id)
        result = await session.execute(stmt)
        record = result.scalar_one_or_none()
    return _to_dto(record) if record else None


async def delete_by_id(record_id: str) -> bool:
    """Delete one record; False if no matching record exists."""
    factory = session_factory()
    async with factory() as session:
        stmt = delete(RetestRecord).where(RetestRecord.id == record_id)
        result = await session.execute(stmt)
        await session.commit()
    return result.rowcount > 0


async def delete_by_finding(finding_no: str) -> int:
    """Delete all records for a finding; returns the number deleted."""
    factory = session_factory()
    async with factory() as session:
        stmt = delete(RetestRecord).where(RetestRecord.finding_no == finding_no)
        result = await session.execute(stmt)
        await session.commit()
    return result.rowcount or 0
