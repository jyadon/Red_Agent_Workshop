"""Helpers to extract the markdown body from an LLM final_output.

Python port of `extractFinalOutputText` + `sanitizeAssistantText` in
`front/src/lib/final-output.ts`. Kept identical to the frontend implementation
so the rendered form stays consistent across clients.
"""
from __future__ import annotations

import re
from typing import Any


def _is_record(value: Any) -> bool:
    return isinstance(value, dict)


def _content_to_text(content: Any) -> str | None:
    """Stringify a content field; handles list / dict / str."""
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if not _is_record(item):
                continue
            for key in ("text", "content", "value"):
                v = item.get(key)
                if isinstance(v, str):
                    parts.append(v)
                    break
        return "\n".join(parts) if parts else None

    if _is_record(content):
        for key in ("text", "content", "value"):
            v = content.get(key)
            if isinstance(v, str):
                return v

    return None


def _message_to_text(message: Any) -> str | None:
    if isinstance(message, str):
        return message
    if not _is_record(message):
        return None
    return _content_to_text(message.get("content")) or _content_to_text(message.get("text"))


def extract_final_output_text(output: Any) -> str | None:
    """Extract assistant text from the data of an SSE `final` event."""
    if output is None:
        return None
    if isinstance(output, str):
        return output
    if not _is_record(output):
        return None

    messages = output.get("messages")
    if isinstance(messages, list) and messages:
        last_message = messages[-1]
        text = _message_to_text(last_message)
        if text:
            return text

    return _content_to_text(output.get("content")) or _content_to_text(output.get("message"))


_FINAL_CHANNEL_RE = re.compile(
    r"<\|channel\|>\s*final\s*(?:<\|message\|>|<\|content\|>)?",
    re.IGNORECASE,
)
_NEXT_CHANNEL_RE = re.compile(r"<\|channel\|>", re.IGNORECASE)


def _extract_final_channel_text(text: str) -> str:
    """Return the text after `<|channel|>final ...` (uses the last one if multiple)."""
    last_match: re.Match[str] | None = None
    for m in _FINAL_CHANNEL_RE.finditer(text):
        last_match = m
    if not last_match:
        return text
    start = last_match.end()
    tail = text[start:]
    next_match = _NEXT_CHANNEL_RE.search(tail)
    if not next_match:
        return tail
    return tail[: next_match.start()]


_SANITIZE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"<think>[\s\S]*?</think>", re.IGNORECASE), ""),
    (
        re.compile(
            r"<\|channel\|>\s*thought\s*(?:<\|message\|>|<\|content\|>)?[\s\S]*?(?=<\|channel\|>|$)",
            re.IGNORECASE,
        ),
        "",
    ),
    (
        re.compile(
            r"<\|channel\|>\s*(?:analysis|thought)\b[\s\S]*?(?=<\|channel\|>|$)",
            re.IGNORECASE,
        ),
        "",
    ),
    (
        re.compile(
            r"<\|channel\|>\s*\w+\s*(?:<\|message\|>|<\|content\|>)?",
            re.IGNORECASE,
        ),
        "",
    ),
    (re.compile(r"<\|(?:message|content|end)\|>", re.IGNORECASE), ""),
    (re.compile(r"<\|?channel>thought", re.IGNORECASE), ""),
    (re.compile(r"<channel\|?>\s*thought", re.IGNORECASE), ""),
    (re.compile(r"<\|?channel\|?>", re.IGNORECASE), ""),
    (re.compile(r"<channel\|?>", re.IGNORECASE), ""),
    (re.compile(r"^```markdown\s*", re.IGNORECASE), ""),
    (re.compile(r"^```md\s*", re.IGNORECASE), ""),
    (re.compile(r"```$", re.IGNORECASE), ""),
]


def sanitize_assistant_text(text: str) -> str:
    """Strip system-origin tokens such as `<think>` and `<|channel|>thought`."""
    out = _extract_final_channel_text(text)
    for pattern, repl in _SANITIZE_PATTERNS:
        out = pattern.sub(repl, out)
    return out.strip()


def extract_markdown_from_final_output(final_output: Any) -> str | None:
    """Return the extracted and sanitized markdown from final_output, or None."""
    text = extract_final_output_text(final_output)
    if not text:
        return None
    cleaned = sanitize_assistant_text(text)
    return cleaned or None
