"""Load and serve the server-side findings JSON file."""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")


def _resolve_findings_file() -> str:
    """Resolve FINDINGS_FILE, confined to within _PROJECT_ROOT."""
    raw = os.getenv("FINDINGS_FILE", "").strip()
    default = (_PROJECT_ROOT / "data" / "findings.json").resolve()
    if not raw:
        return str(default)

    candidate = (
        Path(raw).resolve()
        if os.path.isabs(raw)
        else (_PROJECT_ROOT / raw).resolve()
    )
    try:
        candidate.relative_to(_PROJECT_ROOT)
    except ValueError:
        logger.warning(
            "FINDINGS_FILE=%s is outside project root %s; falling back to %s",
            raw,
            _PROJECT_ROOT,
            default,
        )
        return str(default)
    return str(candidate)


FINDINGS_FILE = _resolve_findings_file()

# Cache and the lock protecting it. Invalidation and reload happen in a single
# critical section so another thread never observes None between the two.
_cache_lock = threading.Lock()
_findings_cache: list[dict[str, Any]] | None = None
_report_metadata: dict[str, Any] | None = None
# mtime (ns) of the last loaded file, used to detect changes and auto-reload.
# None means nothing has been loaded yet.
_findings_mtime_ns: int | None = None


def _current_file_mtime_ns() -> int | None:
    """Return the mtime (ns) of FINDINGS_FILE, or None if missing/unreadable."""
    try:
        return os.stat(FINDINGS_FILE).st_mtime_ns
    except OSError:
        return None


def _normalize_finding(raw: dict[str, Any], index: int) -> dict[str, Any]:
    """Normalize a raw finding: derive `no` from `section`, strip trailing whitespace."""
    finding = dict(raw)

    if "no" not in finding and "section" in finding:
        finding["no"] = f"No.{str(finding['section'])}"
    elif "no" not in finding:
        finding["no"] = f"No.{str(index + 1)}"

    for key in ("risk_level", "summary", "description", "recommendation"):
        if key in finding and isinstance(finding[key], str):
            finding[key] = finding[key].strip()

    # Normalize platform to a list (single string -> [string]; missing/empty -> ["other"]).
    # Multiple values (e.g. ["ad", "entra"]) pass through so the API/frontend see a consistent array.
    plat = finding.get("platform")
    if plat is None or plat == "" or plat == []:
        finding["platform"] = ["other"]
    elif isinstance(plat, str):
        finding["platform"] = [plat]

    return finding


def _load_findings_locked() -> list[dict[str, Any]]:
    """Load findings; must be called while holding _cache_lock."""
    global _findings_cache, _report_metadata, _findings_mtime_ns

    path = Path(FINDINGS_FILE)
    if not path.exists():
        _findings_cache = []
        _report_metadata = None
        _findings_mtime_ns = None
        return _findings_cache

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    _report_metadata = data.get("report_metadata")
    raw_findings = data.get("findings", [])
    _findings_cache = [_normalize_finding(f, i) for i, f in enumerate(raw_findings)]
    _findings_mtime_ns = _current_file_mtime_ns()
    logger.info("findings loaded: %d entries, mtime_ns=%s", len(_findings_cache), _findings_mtime_ns)
    return _findings_cache


def load_findings() -> list[dict[str, Any]]:
    with _cache_lock:
        # Auto-reload when the file has changed on disk.
        current_mtime = _current_file_mtime_ns()
        if (
            _findings_cache is None
            or current_mtime is None
            or _findings_mtime_ns is None
            or current_mtime != _findings_mtime_ns
        ):
            return _load_findings_locked()
        return _findings_cache


def get_finding(finding_id: str) -> dict[str, Any] | None:
    for f in load_findings():
        if f.get("no") == finding_id:
            return f
    return None


def get_report_metadata() -> dict[str, Any] | None:
    load_findings()
    with _cache_lock:
        return _report_metadata


def reload_findings() -> list[dict[str, Any]]:
    """Invalidate the cache and reload, all within the lock."""
    global _findings_cache, _report_metadata, _findings_mtime_ns
    with _cache_lock:
        _findings_cache = None
        _report_metadata = None
        _findings_mtime_ns = None
        return _load_findings_locked()
