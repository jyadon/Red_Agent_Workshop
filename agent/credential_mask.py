"""Mask discovered credentials that leak into report text before history is saved.

Targets credentials revealed during attack execution:
- Cleartext passwords (netexec/CME `domain\\user:pass (Pwn3d!)`, spray failure lines, etc.)
- Hashes (NTDS LM/NT, Kerberos krb5tgs/krb5asrep, DCC2, labeled hash lines)

At-rest only: this is NOT applied to live output / SSE, so the operator can still
verify real values during execution. The target AD password entered by the user is
separately redacted to `<PASS>` by `agent.agent._redact_thread_secrets`; this module
does not know thread secrets and detects purely by pattern.

`mask_report_text` is the public entry point and works on both markdown and
final_output (JSON string).
"""
from __future__ import annotations

import re

_MASK = "█"
_MAX_MID = 12  # cap on masked middle chars so long hashes don't produce huge █ runs


def _mask_token(value: str) -> str:
    """Mask a value keeping only its first and last char (middle capped at 12)."""
    n = len(value)
    if n <= 2:
        # 2 chars or fewer: mask fully, since keeping both ends would expose everything
        return _MASK * n
    mid = min(n - 2, _MAX_MID)
    return value[0] + _MASK * mid + value[-1]


# netexec/CME `domain\user:password`. The `\` separator allows one or more chars so
# markdown (single `\`) and final_output JSON (escaped `\\`) both match. Both success
# (`[+]`) and failure (`[-]`) lines leak the attempted password, so both are targeted.
_CRED_PAIR = re.compile(
    r"(?P<head>[^\s\\/:()]+\\+[^\s\\/:()]+:)(?P<secret>[^\s()\"]+)"
)

# secretsdump NTDS dump line `user:rid:lmhash:nthash:::`.
_NTDS = re.compile(
    r"(?P<pre>[^\s:]+:\d+:)(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32})"
)

# Kerberos hashes (GetUserSPNs=krb5tgs / GetNPUsers=krb5asrep, etc.).
_KRB = re.compile(r"\$krb5\w*\$\S+")

# DCC2 / MSCache hashes.
_DCC2 = re.compile(r"\$(?:DCC2|MSCACHE\w*)\$\S+", re.IGNORECASE)

# Labeled cleartext/hash lines (e.g. gpp_password `password: ...`), label at line start.
_LABELED = re.compile(
    r"(?im)^(?P<label>[ \t]*(?:password|cleartext(?: password)?|pwd|nt ?hash|hash)"
    r"[ \t]*[:=][ \t]*)(?P<secret>\S+)"
)

# Do not re-mask existing placeholders like `<PASS>`.
_PLACEHOLDER = re.compile(r"^<[^>]+>$")


def _sub_cred_pair(text: str) -> str:
    return _CRED_PAIR.sub(lambda m: m.group("head") + _mask_token(m.group("secret")), text)


def _sub_ntds(text: str) -> str:
    return _NTDS.sub(
        lambda m: m.group("pre") + _mask_token(m.group("lm")) + ":" + _mask_token(m.group("nt")),
        text,
    )


def _sub_krb(text: str) -> str:
    return _KRB.sub(lambda m: _mask_token(m.group(0)), text)


def _sub_dcc2(text: str) -> str:
    return _DCC2.sub(lambda m: _mask_token(m.group(0)), text)


def _sub_labeled(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        secret = m.group("secret")
        if _PLACEHOLDER.match(secret):
            return m.group(0)
        return m.group("label") + _mask_token(secret)

    return _LABELED.sub(repl, text)


def mask_report_text(text: str | None) -> str | None:
    """Mask discovered credentials in report text (markdown / final_output JSON string).

    Hashes are processed before credential pairs and labeled lines to avoid mutual
    interference. Idempotent: applying it multiple times yields the same result.
    """
    if not text:
        return text
    text = _sub_ntds(text)
    text = _sub_krb(text)
    text = _sub_dcc2(text)
    text = _sub_cred_pair(text)
    text = _sub_labeled(text)
    return text
