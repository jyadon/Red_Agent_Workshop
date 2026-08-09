from __future__ import annotations

from fastmcp import FastMCP

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

mcp = FastMCP("red-team-report-tools")

# Sandbox base to prevent path traversal; defaults to CWD when unset.
_REPORT_PDF_BASE_DIR = Path(
    os.getenv("REPORT_PDF_BASE_DIR", os.getcwd())
).expanduser().resolve()


def _ensure_within_base(p: Path) -> tuple[bool, str | None]:
    """Verify that an already-resolved path is under BASE_DIR."""
    try:
        p.relative_to(_REPORT_PDF_BASE_DIR)
        return True, None
    except ValueError:
        return False, (
            f"Path is outside the allowed base directory "
            f"({_REPORT_PDF_BASE_DIR}): {p}"
        )

# ----------------------------
# Helpers
# ----------------------------

REPORT_KEYWORDS = [
    "red team",
    "red_team",
    "pentest",
    "penetration",
    "security assessment",
    "vulnerability assessment",
    "report",
    "finding",
]

FINDING_HEADERS = [
    "finding",
    "findings",
    "observation",
    "issue",
    "weakness",
    "vulnerability",
]

REMEDIATION_HEADERS = [
    "recommendation",
    "recommendations",
    "remediation",
    "recommended remediation",
    "proposed remediation",
    "mitigation",
    "countermeasure",
]

SEVERITY_PATTERNS = [
    r"\bcritical\b",
    r"\bhigh\b",
    r"\bmedium\b",
    r"\blow\b",
    r"\binformational\b",
]


@dataclass
class PdfCandidate:
    path: str
    score: int
    reason: str
    size_bytes: int
    mtime: float


def score_pdf(path: Path) -> PdfCandidate:
    score = 0
    reasons: list[str] = []

    lower_path = str(path).lower()
    name = path.name.lower()

    for kw in REPORT_KEYWORDS:
        if kw in name:
            score += 20
            reasons.append(f"filename contains '{kw}'")
        elif kw in lower_path:
            score += 8
            reasons.append(f"path contains '{kw}'")

    try:
        stat = path.stat()
        size_bytes = stat.st_size
        mtime = stat.st_mtime
    except OSError:
        size_bytes = 0
        mtime = 0.0

    if size_bytes > 200_000:
        score += 5
        reasons.append("reasonable size for report")
    if size_bytes > 2_000_000:
        score += 5
        reasons.append("large PDF, likely full report")

    return PdfCandidate(
        path=str(path),
        score=score,
        reason="; ".join(reasons) if reasons else "matched by extension only",
        size_bytes=size_bytes,
        mtime=mtime,
    )


def clean_text(text: str) -> str:
    text = text.replace("\x00", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def split_into_pages_blob(pages: list[dict[str, Any]]) -> str:
    chunks = []
    for p in pages:
        chunks.append(f"\n--- PAGE {p['page']} ---\n{p['text']}\n")
    return "\n".join(chunks)


def guess_is_scanned_or_bad_extract(pages: list[dict[str, Any]]) -> bool:
    joined = "\n".join(p["text"] for p in pages).strip()
    if len(joined) < 500:
        return True
    weird_ratio = sum(1 for c in joined if ord(c) > 65533) / max(len(joined), 1)
    return weird_ratio > 0.05


def extract_sections_from_text(text: str) -> list[dict[str, Any]]:
    """Lightweight rule-based extraction of findings from report text."""
    lines = [line.strip() for line in text.splitlines()]
    lines = [line for line in lines if line]

    findings: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    mode: str | None = None

    def flush_current():
        nonlocal current
        if current and (
            current.get("title") or current.get("finding_text") or current.get("remediation_text")
        ):
            findings.append(current)
        current = None

    for line in lines:
        lower = line.lower()

        if any(h == lower or lower.startswith(h + ":") for h in FINDING_HEADERS):
            flush_current()
            current = {
                "title": "",
                "severity": None,
                "finding_text": "",
                "remediation_text": "",
                "pages": [],
            }
            mode = "finding"
            continue

        if any(h == lower or lower.startswith(h + ":") for h in REMEDIATION_HEADERS):
            if current is None:
                current = {
                    "title": "",
                    "severity": None,
                    "finding_text": "",
                    "remediation_text": "",
                    "pages": [],
                }
            mode = "remediation"
            continue

        if current is None:
            # Treat a line like "High - Weak password policy" as a finding start.
            sev = None
            for pat in SEVERITY_PATTERNS:
                if re.search(pat, lower):
                    sev = re.search(pat, lower).group(0).capitalize()
                    break
            if sev:
                current = {
                    "title": line,
                    "severity": sev,
                    "finding_text": "",
                    "remediation_text": "",
                    "pages": [],
                }
                mode = "finding"
                continue

        if current is not None:
            if current.get("severity") is None:
                for pat in SEVERITY_PATTERNS:
                    m = re.search(pat, lower)
                    if m:
                        current["severity"] = m.group(0).capitalize()
                        break

            if not current.get("title") and len(line) <= 120:
                current["title"] = line
                continue

            if mode == "remediation":
                current["remediation_text"] += (line + "\n")
            else:
                current["finding_text"] += (line + "\n")

    flush_current()

    normalized = []
    for item in findings:
        normalized.append(
            {
                "title": clean_text(item.get("title", "")),
                "severity": item.get("severity"),
                "finding_text": clean_text(item.get("finding_text", "")),
                "remediation_text": clean_text(item.get("remediation_text", "")),
                "pages": item.get("pages", []),
            }
        )

    # Fallback: if nothing was captured, grab text around remediation headers only.
    if not normalized:
        rem_blocks = []
        pattern = re.compile(
            r"(?is)("
            + "|".join(re.escape(h) for h in REMEDIATION_HEADERS)
            + r")\s*:?\s*(.{0,3000})"
        )
        for m in pattern.finditer(text):
            rem_blocks.append(
                {
                    "title": "",
                    "severity": None,
                    "finding_text": "",
                    "remediation_text": clean_text(m.group(2)),
                    "pages": [],
                }
            )
        normalized = rem_blocks

    return normalized


# ----------------------------
# MCP Tools
# ----------------------------

@mcp.tool()
def find_report_pdf(
    root_dir: str = "/home",
    max_results: int = 10,
) -> dict[str, Any]:
    """
    Search recursively for PDF files likely to be Red Team / pentest reports.
    Returns ranked candidates with score and reason.
    """
    root = Path(root_dir).expanduser().resolve()
    ok, err = _ensure_within_base(root)
    if not ok:
        return {"ok": False, "error": err}
    if not root.exists():
        return {"ok": False, "error": f"root_dir does not exist: {root}"}

    candidates: list[PdfCandidate] = []

    for path in root.rglob("*.pdf"):
        try:
            candidates.append(score_pdf(path))
        except Exception:
            continue

    ranked = sorted(
        candidates,
        key=lambda x: (x.score, x.size_bytes, x.mtime),
        reverse=True,
    )[:max_results]

    return {
        "ok": True,
        "root_dir": str(root),
        "count": len(ranked),
        "candidates": [asdict(x) for x in ranked],
    }


@mcp.tool()
def read_pdf(
    pdf_path: str,
    use_ocr_fallback: bool = True,
    max_pages: int | None = None,
) -> dict[str, Any]:
    """
    Read a PDF file and return page-wise text.
    First tries normal text extraction. If extraction looks poor and OCR fallback
    is enabled, tries OCR.
    """
    path = Path(pdf_path).expanduser().resolve()
    ok, err = _ensure_within_base(path)
    if not ok:
        return {"ok": False, "error": err}
    if not path.exists():
        return {"ok": False, "error": f"PDF not found: {path}"}
    if path.suffix.lower() != ".pdf":
        return {"ok": False, "error": f"Not a PDF: {path}"}

    pages: list[dict[str, Any]] = []

    # 1) Normal extraction
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        total_pages = len(reader.pages)
        limit = min(total_pages, max_pages) if max_pages else total_pages

        for i in range(limit):
            txt = reader.pages[i].extract_text() or ""
            pages.append(
                {
                    "page": i + 1,
                    "text": clean_text(txt),
                    "extraction_method": "text",
                }
            )
    except Exception as e:
        pages = []
        text_error = str(e)
    else:
        text_error = None

    # 2) OCR fallback
    if use_ocr_fallback and (not pages or guess_is_scanned_or_bad_extract(pages)):
        try:
            from pdf2image import convert_from_path
            import pytesseract

            ocr_pages: list[dict[str, Any]] = []
            images = convert_from_path(str(path), dpi=200)

            if max_pages:
                images = images[:max_pages]

            for idx, img in enumerate(images, start=1):
                txt = pytesseract.image_to_string(img)
                ocr_pages.append(
                    {
                        "page": idx,
                        "text": clean_text(txt),
                        "extraction_method": "ocr",
                    }
                )

            if ocr_pages:
                pages = ocr_pages
        except Exception as e:
            ocr_error = str(e)
        else:
            ocr_error = None
    else:
        ocr_error = None

    if not pages:
        return {
            "ok": False,
            "error": "Could not extract text from PDF",
            "text_error": text_error,
            "ocr_error": ocr_error,
        }

    return {
        "ok": True,
        "pdf_path": str(path),
        "page_count": len(pages),
        "pages": pages,
        "text_error": text_error,
        "ocr_error": ocr_error,
    }


@mcp.tool()
def extract_report_sections(
    pdf_json: str,
) -> dict[str, Any]:
    """
    Extract likely findings and recommended remediations from the JSON returned
    by read_pdf(). Input must be a JSON string.
    """
    try:
        payload = json.loads(pdf_json)
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"Invalid JSON: {e}"}

    if not payload.get("ok"):
        return {"ok": False, "error": "Input payload is not ok=true"}

    pages = payload.get("pages", [])
    if not pages:
        return {"ok": False, "error": "No pages found in payload"}

    text = split_into_pages_blob(pages)
    findings = extract_sections_from_text(text)

    return {
        "ok": True,
        "pdf_path": payload.get("pdf_path"),
        "finding_count": len(findings),
        "findings": findings,
    }

if __name__ == "__main__":
    mcp.run()