"""Extract a structured verdict (remediation status) from retest Markdown.

Verdict vocabulary matches the fallbacks in prompts.py / agent.py:
- Resolved            -> "resolved"
- Partially Resolved  -> "partial"
- Unresolved          -> "unresolved"
- Inconclusive / Unverified -> "inconclusive"

Extraction priority (kept in sync with the frontend front/src/lib/verdict.ts):
1. The authoritative canonical marker line the report is required to emit, e.g.
   `Verdict: Unresolved`. The LAST such line wins (it is the report's final line).
2. Otherwise the conclusion section under a verdict/judgement/conclusion heading
   (the LAST such section, since the conclusion comes last).
3. Otherwise the whole document, taking the LAST verdict keyword (the conclusion
   tends to sit at the end). Taking the last -- not the first -- keyword avoids
   picking up an incidental "Resolved" from an earlier "expected post-remediation
   state" description, which is what produced Verdict/body mismatches.
"""
from __future__ import annotations

import re

# Normalized status codes (must match the frontend color-coding keys).
VERDICT_RESOLVED = "resolved"
VERDICT_PARTIAL = "partial"
VERDICT_UNRESOLVED = "unresolved"
VERDICT_INCONCLUSIVE = "inconclusive"

VALID_VERDICTS = frozenset(
    {VERDICT_RESOLVED, VERDICT_PARTIAL, VERDICT_UNRESOLVED, VERDICT_INCONCLUSIVE}
)

# (keyword, status code). "Partially Resolved" precedes "Resolved" so the substring
# "Resolved" inside it is not mistaken for a standalone Resolved.
_VERDICT_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("Partially Resolved", VERDICT_PARTIAL),
    ("Resolved", VERDICT_RESOLVED),
    ("Unresolved", VERDICT_UNRESOLVED),
    ("Inconclusive", VERDICT_INCONCLUSIVE),
    ("Unverified", VERDICT_INCONCLUSIVE),
)

_PARTIALLY_PREFIX = "Partially "

# A line carrying the canonical marker: contains the word "Verdict" followed by a colon
# (ASCII or full-width). Matches both `Verdict: X` and a `## Verdict: X` heading.
_CANONICAL_LINE_RE = re.compile(r"(?im)^[^\n]*\bverdict\b[^\n]*[:：].*$")
# Markdown heading (# through ######) naming the conclusion.
_JUDGMENT_HEADING_RE = re.compile(
    r"(?im)^#{1,6}\s*.*(?:verdict|judgement|judgment|conclusion).*$"
)
# Start of the next heading (used to detect the section end).
_NEXT_HEADING_RE = re.compile(r"\n#{1,6}\s")


def _match_verdict_first(text: str) -> str | None:
    """Return the status code for the earliest-occurring verdict keyword in text."""
    best_index: int | None = None
    best_code: str | None = None
    for keyword, code in _VERDICT_KEYWORDS:
        idx = text.find(keyword)
        if idx == -1:
            continue
        if best_index is None or idx < best_index:
            best_index = idx
            best_code = code
    return best_code


def _match_verdict_last(text: str) -> str | None:
    """Return the status code for the latest-occurring verdict keyword in text.

    Preferred for whole-document / section scans: the concluding verdict sits at the
    end, so an earlier incidental "Resolved" (e.g. an expected-state description) must
    not win.
    """
    best_index: int | None = None
    best_code: str | None = None
    for keyword, code in _VERDICT_KEYWORDS:
        idx = text.rfind(keyword)
        if idx == -1:
            continue
        if best_index is None or idx > best_index:
            best_index = idx
            best_code = code
    # A bare "Resolved" that is actually the tail of "Partially Resolved" is partial.
    if (
        best_code == VERDICT_RESOLVED
        and best_index is not None
        and best_index >= len(_PARTIALLY_PREFIX)
        and text[best_index - len(_PARTIALLY_PREFIX) : best_index] == _PARTIALLY_PREFIX
    ):
        return VERDICT_PARTIAL
    return best_code


def _canonical_verdict(markdown: str) -> str | None:
    """Return the code from the LAST canonical `Verdict:` line, or None."""
    code: str | None = None
    for m in _CANONICAL_LINE_RE.finditer(markdown):
        found = _match_verdict_first(m.group(0))
        if found is not None:
            code = found
    return code


def _judgment_section(markdown: str) -> str | None:
    """Return the text of the LAST conclusion heading section, else None."""
    last: re.Match[str] | None = None
    for m in _JUDGMENT_HEADING_RE.finditer(markdown):
        last = m
    if last is None:
        return None
    rest = markdown[last.end():]
    nxt = _NEXT_HEADING_RE.search(rest)
    return rest[: nxt.start()] if nxt else rest


def extract_verdict(markdown: str | None) -> str | None:
    """Extract a normalized verdict code from retest Markdown, or None.

    Prefers the required canonical marker line, then the conclusion section, then the
    last keyword in the whole document.
    """
    if not markdown or not markdown.strip():
        return None
    code = _canonical_verdict(markdown)
    if code is not None:
        return code
    section = _judgment_section(markdown)
    if section is not None:
        code = _match_verdict_last(section)
        if code is not None:
            return code
    return _match_verdict_last(markdown)
