from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import re
import shlex
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

# thread_id propagation channel so MCP tools can read it during the verify/approval
# flow. contextvars propagate automatically down the asyncio task tree, so a value
# set in _stream_agent is visible to downstream langgraph / MCP tool ainvoke calls.
_current_thread_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_thread_id", default=None
)

# Placeholder that keeps plaintext passwords out of prompts/events. The LLM uses this
# token in commands and the server substitutes the real value just before execution.
PASSWORD_PLACEHOLDER = "<PASS>"

# Plaintext passwords are kept here per thread_id, NOT in ThreadState: process memory
# only, volatile across restart, never emitted to SSE events/prompts. Value is a
# (password, stored_at_unix_seconds) tuple; discarded on access once TTL is exceeded.
_THREAD_SECRETS: dict[str, tuple[str, float]] = {}
_THREAD_SECRET_TTL_SECONDS = float(os.getenv("THREAD_SECRET_TTL_SECONDS", "3600"))


def _store_thread_password(thread_id: str, password: str | None) -> None:
    if password:
        _THREAD_SECRETS[thread_id] = (password, time.time())


def _get_thread_password(thread_id: str) -> str | None:
    entry = _THREAD_SECRETS.get(thread_id)
    if entry is None:
        return None
    password, stored_at = entry
    if time.time() - stored_at > _THREAD_SECRET_TTL_SECONDS:
        # Prevent leakage from abandoned threads (e.g. user never approves).
        _THREAD_SECRETS.pop(thread_id, None)
        return None
    return password


def _clear_thread_password(thread_id: str) -> None:
    _THREAD_SECRETS.pop(thread_id, None)


# secret=true verification_inputs (passwords, etc.). Kept separate from runtime user
# vars: escaped with _shell_sq_escape (safe inside '...') on injection and masked to
# <PASS> in display/logs/command output. Same TTL as the AD-password _THREAD_SECRETS.
# thread_id -> ({key: raw_value}, stored_at)
_THREAD_INPUT_SECRETS: dict[str, tuple[dict[str, str], float]] = {}


def _store_thread_input_secrets(
    thread_id: str, secrets: dict[str, str] | None
) -> None:
    if secrets:
        _THREAD_INPUT_SECRETS[thread_id] = (
            {str(k): str(v) for k, v in secrets.items()},
            time.time(),
        )


def _get_thread_input_secrets(thread_id: str | None) -> dict[str, str]:
    if not thread_id:
        return {}
    entry = _THREAD_INPUT_SECRETS.get(thread_id)
    if entry is None:
        return {}
    secrets, stored_at = entry
    if time.time() - stored_at > _THREAD_SECRET_TTL_SECONDS:
        _THREAD_INPUT_SECRETS.pop(thread_id, None)
        return {}
    return dict(secrets)


def _clear_thread_input_secrets(thread_id: str) -> None:
    _THREAD_INPUT_SECRETS.pop(thread_id, None)


def sweep_expired_thread_secrets() -> int:
    """Bulk-delete passwords/secret inputs past their TTL. Helper for background sweeps."""
    now = time.time()
    expired = [
        tid
        for tid, (_, at) in _THREAD_SECRETS.items()
        if now - at > _THREAD_SECRET_TTL_SECONDS
    ]
    for tid in expired:
        _THREAD_SECRETS.pop(tid, None)
    expired_inputs = [
        tid
        for tid, (_, at) in _THREAD_INPUT_SECRETS.items()
        if now - at > _THREAD_SECRET_TTL_SECONDS
    ]
    for tid in expired_inputs:
        _THREAD_INPUT_SECRETS.pop(tid, None)
    return len(expired) + len(expired_inputs)


from deepagents import create_deep_agent
from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from agent.dc_discovery import (
    absorb_command_output,
    format_dcs_for_prompt,
    get_dcs,
    register_dc,
)
from agent.prompts import (
    COMMAND_EXECUTOR_PROMPT,
    DEEP_AGENT_PROMPT,
    RTO_JUDGE_PROMPT,
    VERIFICATION_PLANNER_PROMPT,
)
from agent.rto_playbook import (
    evaluate_when,
    extract_tokens,
    load_playbook,
    placeholderize_command,
    render_command,
)
from agent.schemas import FindingItem
from agent.store import append_event, get_or_create_thread

# thread_id -> AD domain under test (used as the default domain in execute_approved_command)
_THREAD_DOMAINS: dict[str, str] = {}

# thread_id -> finding number under test (linkage key when persisting retest history to DB)
_THREAD_FINDING_NOS: dict[str, str] = {}


def _store_thread_domain(thread_id: str, domain: str | None) -> None:
    if domain:
        _THREAD_DOMAINS[thread_id] = domain


def _get_thread_domain(thread_id: str) -> str | None:
    return _THREAD_DOMAINS.get(thread_id)


def _clear_thread_domain(thread_id: str) -> None:
    _THREAD_DOMAINS.pop(thread_id, None)



def _store_thread_finding_no(thread_id: str, finding_no: str | None) -> None:
    if finding_no:
        _THREAD_FINDING_NOS[thread_id] = finding_no


def _get_thread_finding_no(thread_id: str) -> str | None:
    return _THREAD_FINDING_NOS.get(thread_id)


def _clear_thread_finding_no(thread_id: str) -> None:
    _THREAD_FINDING_NOS.pop(thread_id, None)


# --- RTO export capture -----------------------------------------------------------------
# During a verification (retest) run, each executed command is captured with its engagement
# specifics (domain/user/password/dns/inputs) replaced by {{placeholders}}, so the operator can
# later Export selected ones into the RTO playbook (rto.json) without leaking secrets.
#
# _THREAD_PLACEHOLDER_CTX holds only NON-secret values (domain/user/dns + non-secret inputs);
# the password and secret inputs are pulled from _THREAD_SECRETS / _THREAD_INPUT_SECRETS at
# capture time so no second copy of a secret is kept here.
_THREAD_PLACEHOLDER_CTX: dict[str, dict[str, str]] = {}
_THREAD_CAPTURED_COMMANDS: dict[str, list[dict[str, str]]] = {}


def _store_thread_placeholder_ctx(
    thread_id: str,
    execution_context: dict[str, Any] | None,
    runtime_variables: dict[str, str] | None,
) -> None:
    ctx: dict[str, str] = {}
    if execution_context:
        # execution_context uses "pass"; the password itself is not stored here (see above).
        for src_key, placeholder in (("domain", "domain"), ("user", "user"), ("dns", "dns")):
            value = execution_context.get(src_key)
            if value:
                ctx[placeholder] = str(value)
    for key, value in (runtime_variables or {}).items():
        if value:
            ctx[str(key)] = str(value)
    # Mark the thread as a capture target even if ctx is empty (e.g. Entra-only, local commands),
    # so its commands are still collected; secrets are folded in at capture time.
    _THREAD_PLACEHOLDER_CTX[thread_id] = ctx


def _capture_retest_command(thread_id: str | None, command: str) -> None:
    """Placeholder-ize a just-executed retest command and record it for later RTO export.

    No-op unless the thread is a capture target (set by _store_thread_placeholder_ctx). The
    password (from _THREAD_SECRETS) and any secret inputs (_THREAD_INPUT_SECRETS) are folded into
    the placeholder context here so they never persist in a captured command.
    """
    if not thread_id or not command:
        return
    ctx = _THREAD_PLACEHOLDER_CTX.get(thread_id)
    if ctx is None:
        return
    full_ctx = dict(ctx)
    password = _get_thread_password(thread_id)
    if password:
        full_ctx["password"] = password
    for key, value in _get_thread_input_secrets(thread_id).items():
        if value:
            full_ctx[str(key)] = value
    safe = placeholderize_command(command, full_ctx)
    bucket = _THREAD_CAPTURED_COMMANDS.setdefault(thread_id, [])
    if any(entry.get("command") == safe for entry in bucket):
        return
    bucket.append({"command": safe})


def get_thread_captured_commands(thread_id: str | None) -> list[dict[str, str]]:
    """Return the placeholder-ized commands captured during a retest (for export/persistence)."""
    if not thread_id:
        return []
    return [dict(entry) for entry in _THREAD_CAPTURED_COMMANDS.get(thread_id, [])]


def _clear_thread_capture(thread_id: str) -> None:
    _THREAD_PLACEHOLDER_CTX.pop(thread_id, None)
    _THREAD_CAPTURED_COMMANDS.pop(thread_id, None)


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")


# Runs tools/AD_Recon/ad_dns_recon.py as a subprocess to mechanically obtain DC info and
# register it into _DC_CACHE. execution_context (domain/user/pass/dns) is passed straight
# through as CLI args. Execution is expected to go via SOCKS_HOST:SOCKS_PORT.
_AD_DNS_RECON_SCRIPT = _PROJECT_ROOT / "tools" / "AD_Recon" / "ad_dns_recon.py"
_AD_DNS_RECON_TIMEOUT = float(os.getenv("AD_DNS_RECON_TIMEOUT", "60"))


async def _attempt_ad_dns_recon(
    cmd: list[str],
    thread_id: str,
    domain: str,
    attempt: int,
    max_attempts: int,
    env: dict[str, str] | None = None,
) -> int:
    """Launch ad_dns_recon once and return the number of DCs registered.

    Exceptions are swallowed (logged only) and 0 is returned so the caller decides on
    retries. env: environment for the child process (carries the password via
    AD_RECON_PASSWORD so it never appears on the command line).
    """
    # Record what was invoked; the password is passed via env, not on the command line.
    logger.info(
        "ad_dns_recon launching (attempt=%d/%d, thread=%s, domain=%s): %s",
        attempt,
        max_attempts,
        thread_id,
        domain,
        " ".join(cmd),
    )
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_AD_DNS_RECON_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning(
                "ad_dns_recon timed out after %.0fs (attempt=%d/%d, thread=%s, domain=%s)",
                _AD_DNS_RECON_TIMEOUT,
                attempt,
                max_attempts,
                thread_id,
                domain,
            )
            return 0

        stdout_text = (stdout or b"").decode("utf-8", errors="replace").strip()
        stderr_text = (stderr or b"").decode("utf-8", errors="replace").strip()

        # Always emit the head of stderr (success or failure) to ease triage.
        if stderr_text:
            logger.info(
                "ad_dns_recon stderr (attempt=%d/%d, thread=%s, head=2000):\n%s",
                attempt,
                max_attempts,
                thread_id,
                stderr_text[:2000],
            )

        if proc.returncode != 0:
            logger.warning(
                "ad_dns_recon exited non-zero (code=%s, attempt=%d/%d, thread=%s)",
                proc.returncode,
                attempt,
                max_attempts,
                thread_id,
            )
            return 0

        if not stdout_text:
            logger.info(
                "ad_dns_recon produced empty stdout (attempt=%d/%d, thread=%s)",
                attempt,
                max_attempts,
                thread_id,
            )
            return 0

        try:
            data = json.loads(stdout_text)
        except json.JSONDecodeError:
            logger.warning(
                "ad_dns_recon stdout was not valid JSON (attempt=%d/%d, thread=%s): %s",
                attempt,
                max_attempts,
                thread_id,
                stdout_text[:500],
            )
            return 0

        # v2 shape: { "success": bool, "result": { "domain": str, "domain_controllers": [...] }, "error": str? }
        if not isinstance(data, dict) or not data.get("success"):
            logger.info(
                "ad_dns_recon returned success=false (attempt=%d/%d, thread=%s, error=%s)",
                attempt,
                max_attempts,
                thread_id,
                data.get("error") if isinstance(data, dict) else None,
            )
            return 0

        result_block = data.get("result") or {}
        resolved_domain = result_block.get("domain") or domain
        dc_list = result_block.get("domain_controllers", []) or []
        logger.info(
            "ad_dns_recon parsed JSON (attempt=%d/%d, thread=%s): resolved_domain=%s, dc_count=%d, dns_servers=%s",
            attempt,
            max_attempts,
            thread_id,
            resolved_domain,
            len(dc_list),
            result_block.get("dns_servers"),
        )
        registered = 0
        for dc in dc_list:
            fqdn = dc.get("fqdn")
            ip = dc.get("ip")
            if not fqdn:
                logger.warning(
                    "ad_dns_recon DC entry missing fqdn (thread=%s, entry=%r)",
                    thread_id,
                    dc,
                )
                continue
            registered_entry = register_dc(
                resolved_domain, fqdn, ip, source="ad_dns_recon"
            )
            if registered_entry is None:
                logger.warning(
                    "register_dc rejected entry (thread=%s, domain=%s, fqdn=%s, ip=%s)",
                    thread_id,
                    resolved_domain,
                    fqdn,
                    ip,
                )
            else:
                registered += 1

        logger.info(
            "ad_dns_recon registered %d DC(s) for domain=%s (attempt=%d/%d, thread=%s)",
            registered,
            resolved_domain,
            attempt,
            max_attempts,
            thread_id,
        )
        return registered
    except Exception:
        logger.exception(
            "ad_dns_recon subprocess execution failed (attempt=%d/%d, thread=%s)",
            attempt,
            max_attempts,
            thread_id,
        )
        return 0


async def _run_ad_dns_recon(
    thread_id: str,
    *,
    domain: str,
    user: str,
    password: str,
    dns: str | None = None,
) -> int:
    """Run ad_dns_recon.py as a subprocess and register DC info into _DC_CACHE.

    Auto-retries up to AD_DNS_RECON_MAX_ATTEMPTS times when 0 DCs are registered, and
    returns the final count. Exhausting all attempts with 0 does not halt verification.
    dns is currently unused by the command build (the --pivot line is commented out); the
    argument is kept for forward compatibility if --pivot is enabled later.
    """
    if not all([domain, user, password]):
        return 0
    if not _AD_DNS_RECON_SCRIPT.exists():
        logger.warning("ad_dns_recon script not found at %s", _AD_DNS_RECON_SCRIPT)
        return 0

    socks_host = os.getenv("SOCKS_HOST", "127.0.0.1")
    socks_port = os.getenv("SOCKS_PORT", "1080")
    max_attempts = max(1, int(os.getenv("AD_DNS_RECON_MAX_ATTEMPTS", "2")))
    retry_delay = max(0.0, float(os.getenv("AD_DNS_RECON_RETRY_DELAY_SECONDS", "2")))

    # ad_dns_recon v2: first arg is the AD domain name. When dns is given, switch to
    # direct SRV lookup via --dns-server (works even when DNS is not the DC / AD-integrated
    # DNS is absent); otherwise fall back to legacy Mode B (SMB against the domain name).
    # SOCKS goes through the proxy set up by the execution layer (default 1080).
    # SECURITY: passing the password as a CLI arg would expose it via `ps aux`, so it is
    # passed to the child only via env AD_RECON_PASSWORD; the parent os.environ is never
    # polluted (a fresh env dict is built).
    cmd: list[str] = [
        sys.executable,
        str(_AD_DNS_RECON_SCRIPT),
        domain,
    ]
    if dns:
        # Direct DNS lookup mode: no auth needed, so -u/-p are not passed.
        cmd += ["--dns-server", dns]
    else:
        # Legacy Mode B (domain name -> DC discovery via SMB handshake).
        cmd += ["-u", user]
    cmd += [
        "--socks-host",
        socks_host,
        "--socks-port",
        str(socks_port),
        "--json",
        "-q",
    ]
    child_env = {**os.environ, "AD_RECON_PASSWORD": password}

    for attempt in range(1, max_attempts + 1):
        registered = await _attempt_ad_dns_recon(
            cmd, thread_id, domain, attempt, max_attempts, env=child_env
        )
        if registered > 0:
            return registered
        if attempt < max_attempts:
            logger.info(
                "ad_dns_recon attempt %d/%d yielded 0 entries; retrying in %.1fs (thread=%s)",
                attempt,
                max_attempts,
                retry_delay,
                thread_id,
            )
            if retry_delay > 0:
                await asyncio.sleep(retry_delay)

    logger.info(
        "ad_dns_recon gave up after %d attempt(s) with 0 DC(s) registered (thread=%s, domain=%s)",
        max_attempts,
        thread_id,
        domain,
    )
    return 0


# ----------------------------
# Entra ID collection preflight (forward-only operation): collect with roadrecon using a
# token the operator obtained and supplied on a compliant device. Collection (auth+gather)
# is confined to deterministic scripts and never exposed to the LLM.
# ----------------------------
_ENTRA_COLLECT_SCRIPT = _PROJECT_ROOT / "tools" / "Entra_Recon" / "roadrecon_collect.py"
_ENTRA_RECON_TIMEOUT = float(os.getenv("ENTRA_RECON_TIMEOUT", "900"))

# tenant(normalized) -> collected roadrecon.db path. In-process cache (same policy as DC cache).
_ENTRA_DB_CACHE: dict[str, str] = {}


def _norm_tenant(tenant: str | None) -> str:
    return (tenant or "default").strip().lower()


def _entra_base_dir() -> Path:
    return Path(os.getenv("ENTRA_DB_DIR", str(_PROJECT_ROOT / "data" / "entra")))


def _entra_tenant_dir(tenant: str | None) -> Path:
    """Per-tenant output directory; the name is sanitized to reject `..` and similar."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", _norm_tenant(tenant)).strip("._") or "default"
    return _entra_base_dir() / safe


def _entra_db_path(tenant: str | None) -> Path:
    return _entra_tenant_dir(tenant) / "roadrecon.db"


def get_entra_db(tenant: str | None) -> str | None:
    """Return the tenant's collected roadrecon.db path (None if not collected).

    Falls back to a collected file on disk when it is not in the in-memory cache (so it
    can be reused after a process restart without re-supplying a token). Invalidates a
    cache entry whose file has since been deleted.
    """
    key = _norm_tenant(tenant)
    cached = _ENTRA_DB_CACHE.get(key)
    if cached and os.path.exists(cached):
        return cached
    disk = _entra_db_path(tenant)
    if disk.exists():
        _ENTRA_DB_CACHE[key] = str(disk)
        return str(disk)
    if cached:
        _ENTRA_DB_CACHE.pop(key, None)
    return None


def list_entra_dbs() -> list[dict[str, Any]]:
    """List collected Entra data (roadrecon.db under each tenant directory)."""
    base = _entra_base_dir()
    out: list[dict[str, Any]] = []
    if not base.exists():
        return out
    for child in sorted(base.iterdir()):
        db = child / "roadrecon.db"
        if child.is_dir() and db.exists():
            st = db.stat()
            out.append(
                {
                    "tenant": child.name,
                    "path": str(db),
                    "sizeBytes": st.st_size,
                    "modifiedAt": datetime.utcfromtimestamp(st.st_mtime).isoformat()
                    + "Z",
                }
            )
    return out


def delete_entra_db(tenant: str) -> bool:
    """Delete the tenant's entire output directory and invalidate the in-memory cache.
    Constrained to under `base` to prevent path traversal. Returns False if absent."""
    base = _entra_base_dir().resolve()
    target = _entra_tenant_dir(tenant).resolve()
    if target == base or base not in target.parents:
        raise ValueError("invalid tenant directory")
    existed = target.exists()
    if existed:
        shutil.rmtree(target, ignore_errors=True)
    _ENTRA_DB_CACHE.pop(_norm_tenant(tenant), None)
    return existed


def _shred_path(path: Path) -> None:
    """Overwrite then delete a sensitive token file (.roadtools_auth), best-effort."""
    try:
        if not path.exists():
            return
        try:
            size = path.stat().st_size
            with open(path, "r+b") as f:
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            pass
        path.unlink(missing_ok=True)
    except Exception:
        logger.warning("failed to shred %s", path)


async def _exec_roadrecon(
    thread_id: str,
    *,
    mode: str,
    tenant: str | None,
    token: str | None,
    db_path: Path | None,
    authfile: Path,
    token_type: str = "prt-cookie",
) -> dict[str, Any] | None:
    """Run roadrecon_collect.py as a subprocess under proxychains and return stdout JSON.

    SOCKS is carried through to roadrecon by proxychains (LD_PRELOAD). SECURITY: the token
    is passed only via the child's ROADRECON_TOKEN env var, never argv (parent environ is
    untouched and it is never logged). Returns None on process error / bad JSON / timeout.
    """
    if not _ENTRA_COLLECT_SCRIPT.exists():
        logger.warning("entra collect script not found at %s", _ENTRA_COLLECT_SCRIPT)
        return None
    proxy_enabled = os.getenv("ENTRA_RECON_PROXYCHAINS", "true").lower() == "true"
    proxy_prefix = (
        os.getenv("KALI_PROXY_COMMAND", "proxychains -q").split() if proxy_enabled else []
    )
    cmd = [
        *proxy_prefix,
        sys.executable,
        str(_ENTRA_COLLECT_SCRIPT),
        "--mode", mode,
        "--authfile", str(authfile),
        "--token-type", token_type,
        "-q",
    ]
    if db_path is not None:
        cmd += ["--database", str(db_path)]
    if tenant:
        cmd += ["--tenant", tenant]
    child_env = {**os.environ}
    if token:
        child_env["ROADRECON_TOKEN"] = token

    logger.info(
        "entra recon launching (thread=%s, tenant=%s, mode=%s)",
        thread_id, _norm_tenant(tenant), mode,
    )
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=child_env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_ENTRA_RECON_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning(
                "entra recon timed out (thread=%s, mode=%s)", thread_id, mode
            )
            return None
        err = (stderr or b"").decode("utf-8", errors="replace").strip()
        out = (stdout or b"").decode("utf-8", errors="replace").strip()
        if err:
            logger.info("entra recon stderr(head):\n%s", err[:2000])
        if not out:
            logger.warning(
                "entra recon no stdout (rc=%s, thread=%s, mode=%s)",
                proc.returncode, thread_id, mode,
            )
            return None
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            logger.warning(
                "entra recon stdout not JSON (thread=%s): %s", thread_id, out[:500]
            )
            return None
        return data if isinstance(data, dict) else None
    except Exception:
        logger.exception(
            "entra recon subprocess failed (thread=%s, mode=%s)", thread_id, mode
        )
        return None


async def _run_entra_recon(
    thread_id: str, *, tenant: str | None, token: str, token_type: str
) -> str | None:
    """Run auth+gather together (both), producing roadrecon.db, cached per tenant.
    Returns the db path on success, None on failure (verification is not halted). The
    token file is discarded by the script's both mode after it runs."""
    db_path = _entra_db_path(tenant)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    authfile = db_path.parent / ".roadtools_auth"
    data = await _exec_roadrecon(
        thread_id,
        mode="both",
        tenant=tenant,
        token=token,
        db_path=db_path,
        authfile=authfile,
        token_type=token_type,
    )
    if not data or not data.get("success"):
        logger.info(
            "entra recon (both) failed (thread=%s, error=%s)",
            thread_id, (data or {}).get("error"),
        )
        return None
    resolved = data.get("database") or str(db_path)
    _ENTRA_DB_CACHE[_norm_tenant(tenant)] = resolved
    logger.info(
        "entra recon collected db=%s (thread=%s, tenant=%s)",
        resolved, thread_id, _norm_tenant(tenant),
    )
    return resolved


async def collect_entra_now(
    tenant: str, token: str, token_type: str = "prt-cookie"
) -> dict[str, Any]:
    """Entry point of the collection API (auth+gather together). Runs roadrecon
    synchronously and returns the result. Independent of retest; the token is used only
    here and never persisted. Use entra_auth_now / entra_gather_now to split the two."""
    db = await _run_entra_recon(
        "entra-collect", tenant=tenant, token=token, token_type=token_type
    )
    if db:
        return {"ok": True, "tenant": _norm_tenant(tenant), "database": db}
    return {"ok": False, "tenant": _norm_tenant(tenant)}


# ----------------------------
# Entra auth/gather split: hold the token obtained by auth (authfile JSON blob) until gather.
# - Memory only, TTL-volatile, lost on process restart (must re-obtain).
# - Contains a refresh token, so it is written to disk only during auth/gather and _shred'd
#   immediately after.
# - No PII (UPN, display name) or tokens in prompts/SSE/logs (only oid and tenant are logged).
# Benefit: the PRT Cookie is short-lived, but the refresh token auth exchanged is long-lived,
#   so gather can be re-run any number of times without re-fetching the Cookie (recollect/retry).
# session_id -> {"tenant": str, "blob": str, "identity": dict, "stored_at": float}
# ----------------------------
_ENTRA_AUTH_SESSIONS: dict[str, dict[str, Any]] = {}
_ENTRA_AUTH_TTL_SECONDS = float(os.getenv("ENTRA_AUTH_TTL_SECONDS", "3600"))


def _purge_expired_entra_sessions() -> int:
    now = time.time()
    expired = [
        sid
        for sid, v in _ENTRA_AUTH_SESSIONS.items()
        if now - v.get("stored_at", 0) > _ENTRA_AUTH_TTL_SECONDS
    ]
    for sid in expired:
        _ENTRA_AUTH_SESSIONS.pop(sid, None)
    return len(expired)


def clear_entra_session(session_id: str) -> bool:
    """Discard an auth session (the held token). Returns True if it existed."""
    return _ENTRA_AUTH_SESSIONS.pop(session_id, None) is not None


async def entra_auth_now(
    tenant: str, token: str, token_type: str = "prt-cookie"
) -> dict[str, Any]:
    """auth only: exchange a PRT Cookie (etc.) for access/refresh tokens.
    On success returns non-sensitive identity and a session_id. The obtained token (authfile
    blob) is held in an in-memory session and immediately discarded from disk. gather is done
    later via entra_gather_now(session_id) (recollect without re-fetching the short-lived Cookie)."""
    _purge_expired_entra_sessions()
    tenant_dir = _entra_tenant_dir(tenant)
    tenant_dir.mkdir(parents=True, exist_ok=True)
    authfile = tenant_dir / f".roadtools_auth.{uuid4().hex}"
    try:
        data = await _exec_roadrecon(
            "entra-auth",
            mode="auth",
            tenant=tenant,
            token=token,
            db_path=None,
            authfile=authfile,
            token_type=token_type,
        )
        if not data or not data.get("success"):
            # Log the failure reason (roadrecon error summary); previously it was dropped,
            # so the cause (tenant not found / expired / CA, etc.) was invisible server-side.
            logger.info(
                "entra auth failed (tenant=%s, error=%s)",
                _norm_tenant(tenant), (data or {}).get("error"),
            )
            return {
                "ok": False,
                "stage": "auth",
                "tenant": _norm_tenant(tenant),
                "error": _normalize_entra_error((data or {}).get("error")),
            }
        # Read the authfile contents (token), hold in memory, discard from disk.
        try:
            blob = authfile.read_text(encoding="utf-8")
        except Exception:
            logger.warning("entra auth: failed to read authfile blob")
            return {"ok": False, "stage": "auth", "tenant": _norm_tenant(tenant)}
        session_id = uuid4().hex
        identity = data.get("identity") or {}
        _ENTRA_AUTH_SESSIONS[session_id] = {
            "tenant": tenant,
            "blob": blob,
            "identity": identity,
            "stored_at": time.time(),
        }
        # No PII (UPN/display name) in logs; only tenant and oid.
        logger.info(
            "entra auth ok (tenant=%s, oid=%s, session=%s)",
            _norm_tenant(tenant), identity.get("oid"), session_id,
        )
        return {
            "ok": True,
            "tenant": _norm_tenant(tenant),
            "session_id": session_id,
            "identity": identity,
        }
    finally:
        _shred_path(authfile)


async def entra_gather_now(session_id: str) -> dict[str, Any]:
    """gather only: run roadrecon gather using the held session (authfile blob).
    Can recollect any number of times without re-fetching the Cookie. Returns the
    roadrecon.db path on success. The token is on disk only during gather, then discarded."""
    _purge_expired_entra_sessions()
    sess = _ENTRA_AUTH_SESSIONS.get(session_id)
    if not sess:
        return {"ok": False, "error": "session_not_found"}
    tenant = sess["tenant"]
    db_path = _entra_db_path(tenant)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    authfile = db_path.parent / f".roadtools_auth.{uuid4().hex}"
    try:
        authfile.write_text(sess["blob"], encoding="utf-8")
        try:
            os.chmod(authfile, 0o600)
        except Exception:
            pass
        data = await _exec_roadrecon(
            "entra-gather",
            mode="gather",
            tenant=tenant,
            token=None,
            db_path=db_path,
            authfile=authfile,
        )
        if not data or not data.get("success"):
            return {
                "ok": False,
                "tenant": _norm_tenant(tenant),
                "error": (data or {}).get("error") or "gather_failed",
            }
        resolved = data.get("database") or str(db_path)
        _ENTRA_DB_CACHE[_norm_tenant(tenant)] = resolved
        return {"ok": True, "tenant": _norm_tenant(tenant), "database": resolved}
    finally:
        _shred_path(authfile)


# ----------------------------
# Entra gather jobs (async collection): gather on a huge tenant takes minutes, which can exceed
# an upstream proxy's response timeout. So HTTP returns
# immediately (202 + job_id), collection proceeds in a background asyncio task, and the
# frontend polls job status. State is in-memory (lost on restart, but roadrecon.db is on
# disk so there is no real harm; on job loss the client falls back to /databases to check
# whether collection completed).
# job_id -> {"job_id","session_id","tenant","status","database","error",
#            "started_at","finished_at"}
# ----------------------------
_ENTRA_GATHER_JOBS: dict[str, dict[str, Any]] = {}
_ENTRA_GATHER_JOB_TTL_SECONDS = float(os.getenv("ENTRA_GATHER_JOB_TTL_SECONDS", "1800"))
# The event loop holds only weak refs to create_task tasks, so without a strong ref the task
# could be GC'd mid-run (leaving a job stuck "running", never purged even by TTL). Keep a
# strong ref here and drop it via a done callback on completion.
_ENTRA_GATHER_TASKS: set[asyncio.Task] = set()


def _purge_expired_gather_jobs() -> int:
    """Purge jobs past their TTL since completion/failure (running jobs are kept)."""
    now = time.time()
    expired = [
        jid
        for jid, v in _ENTRA_GATHER_JOBS.items()
        if v.get("status") in ("done", "failed")
        and now - (v.get("finished_at") or now) > _ENTRA_GATHER_JOB_TTL_SECONDS
    ]
    for jid in expired:
        _ENTRA_GATHER_JOBS.pop(jid, None)
    return len(expired)


def _normalize_entra_error(raw: str | None) -> str:
    """Normalize roadrecon's raw error string into a summary free of sensitive data (token
    fragments, etc.). Returns only fixed wording for responses/frontend display (never the
    raw string). Details remain in the server logs (e.g. _exec_roadrecon stderr head)."""
    text = (raw or "").lower()
    if not text or text == "gather_failed":
        return "Collection failed (check the network path and token validity)."
    if "timed out" in text or "timeout" in text:
        return (
            "Collection timed out (for large tenants, consider raising "
            "ENTRA_RECON_TIMEOUT / ROADRECON_TIMEOUT)."
        )
    if "command not found" in text:
        return "roadrecon was not found (check its installation / PATH)."
    if "aadsts90002" in text or ("tenant" in text and "not found" in text):
        return "Tenant not found (check the tenant ID/domain)."
    if "403" in text or "insufficient" in text or "authorization_requestdenied" in text:
        return "Insufficient permissions possible (check the directory read permissions collection requires)."
    if "401" in text or "invalid_grant" in text or "audience" in text:
        return "Authentication error (check token expiry / audience)."
    return "Collection failed (check the network path and token validity)."


def _public_gather_job(job: dict[str, Any]) -> dict[str, Any]:
    """Non-sensitive view returned to the client (excludes session_id, etc.)."""
    return {
        "job_id": job["job_id"],
        "tenant": _norm_tenant(job.get("tenant")),
        "status": job.get("status"),
        "database": job.get("database"),
        "error": job.get("error"),
    }


def get_entra_gather_job(job_id: str) -> dict[str, Any] | None:
    """Return the non-sensitive job view (None if unknown). Called from the status GET; no logging."""
    job = _ENTRA_GATHER_JOBS.get(job_id)
    return _public_gather_job(job) if job else None


async def _run_entra_gather_job(job_id: str) -> None:
    """Run gather in the background and update job state, reusing entra_gather_now.
    Exceptions are reliably recorded as failed (not swallowed)."""
    job = _ENTRA_GATHER_JOBS.get(job_id)
    if job is None:
        return
    tenant = job.get("tenant")
    try:
        result = await entra_gather_now(job["session_id"])
        if result.get("ok"):
            job["status"] = "done"
            job["database"] = result.get("database")
            job["error"] = None
            logger.info(
                "entra gather job done (job=%s, tenant=%s)",
                job_id, _norm_tenant(tenant),
            )
        else:
            job["status"] = "failed"
            job["error"] = _normalize_entra_error(result.get("error"))
            logger.info(
                "entra gather job failed (job=%s, tenant=%s, error=%s)",
                job_id, _norm_tenant(tenant), result.get("error"),
            )
    except Exception:
        job["status"] = "failed"
        job["error"] = "An internal error occurred during collection (check the server logs)."
        logger.exception("entra gather job crashed (job=%s)", job_id)
    finally:
        job["finished_at"] = time.time()


def start_entra_gather_job(session_id: str) -> dict[str, Any]:
    """Start gather in the background and immediately return job info (HTTP does not wait).
    Returns session_not_found if the session is missing (caller turns it into a 404). Reuses a
    running job for the same tenant to prevent double-starts."""
    _purge_expired_gather_jobs()
    _purge_expired_entra_sessions()
    sess = _ENTRA_AUTH_SESSIONS.get(session_id)
    if not sess:
        return {"ok": False, "error": "session_not_found"}
    tenant = sess["tenant"]
    # Reuse a running job for the same tenant (prevents double-starts from double-clicks, etc.).
    for existing in _ENTRA_GATHER_JOBS.values():
        if existing.get("status") == "running" and _norm_tenant(
            existing.get("tenant")
        ) == _norm_tenant(tenant):
            return {"ok": True, **_public_gather_job(existing)}
    job_id = uuid4().hex
    job = {
        "job_id": job_id,
        "session_id": session_id,
        "tenant": tenant,
        "status": "running",
        "database": None,
        "error": None,
        "started_at": time.time(),
        "finished_at": None,
    }
    _ENTRA_GATHER_JOBS[job_id] = job
    logger.info(
        "entra gather job started (job=%s, tenant=%s)", job_id, _norm_tenant(tenant)
    )
    task = asyncio.create_task(_run_entra_gather_job(job_id))
    _ENTRA_GATHER_TASKS.add(task)
    task.add_done_callback(_ENTRA_GATHER_TASKS.discard)
    return {"ok": True, **_public_gather_job(job)}


def _resolve_entra_tenant(explicit: str | None) -> str | None:
    """Decide which tenant the retest should reference. Use the explicit one if given;
    otherwise default to the sole collected tenant only when exactly one exists; if several
    exist and none is specified, return None (-> no database path in the prompt -> Unverified)."""
    if explicit:
        return explicit
    dbs = list_entra_dbs()
    if len(dbs) == 1:
        return dbs[0]["tenant"]
    return None


LM_STUDIO_URL = os.getenv("LLM_BASE_URL", "http://localhost:1234/v1")
MODEL_NAME = os.getenv("LLM_MODEL", "local-model")
LLM_API_KEY = os.getenv("LLM_API_KEY", "lm-studio")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.2"))
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "3600"))

_kali_script_raw = os.getenv("KALI_MCP_SCRIPT", "")
KALI_SCRIPT = (
    str((_PROJECT_ROOT / _kali_script_raw).resolve())
    if _kali_script_raw
    else str(_PROJECT_ROOT / "kali-mcp" / "server.py")
)

MCP_SERVERS = {
    "Kali-Direct-Manager": {
        # Default to the Python running this agent (sys.executable) so that, when started from
        # the project venv (`make dev`), kali-mcp/server.py resolves the same venv's dependencies
        # (fastmcp, etc.). Override with KALI_MCP_COMMAND to switch explicitly.
        "command": os.getenv("KALI_MCP_COMMAND", sys.executable),
        "args": [KALI_SCRIPT],
        "transport": "stdio",
    },
}

model = ChatOpenAI(
    base_url=LM_STUDIO_URL,
    api_key=LLM_API_KEY,
    model=MODEL_NAME,
    temperature=LLM_TEMPERATURE,
    timeout=LLM_TIMEOUT,
)

_mcp_client: MultiServerMCPClient | None = None
_mcp_tools: list | None = None
_checkpointer: MemorySaver | None = None
_agent = None


def _build_finding_context(
    finding: FindingItem,
    user_instruction: str | None = None,
    execution_context: dict[str, Any] | None = None,
    runtime_variables: dict[str, str] | None = None,
) -> str:
    """Assemble the shared finding+context block (platform, execution context, provided inputs,
    tool restrictions, finding fields, references). Reused by build_finding_prompt (deep-agent
    path) and the plan/judge steps of the batch retest pipeline so all three see identical facts."""
    refs = (
        "\n".join(f"- {ref.name}: {ref.url}" for ref in finding.references)
        if finding.references
        else "None"
    )

    # Authoritative target environment from findings.json (never inferred by the LLM). Resolved
    # up front because both the execution context and [Target Platform] below depend on it.
    _raw_platform = getattr(finding, "platform", ["other"])
    _target_platforms = (
        _raw_platform if isinstance(_raw_platform, list) else [_raw_platform]
    ) or ["other"]

    extra_instruction = (
        f"""

[Additional Instructions]
{user_instruction}
"""
        if user_instruction
        else ""
    )

    execution_context_text = ""
    if execution_context:
        domain = execution_context.get("domain") or "Unspecified"
        user = execution_context.get("user") or "Unspecified"
        # Policy: embed the real password directly into the prompt (see feedback memory).
        password_value = execution_context.get("pass") or ""
        dns = execution_context.get("dns") or "Unspecified"

        password_line = (
            f"- Password: {password_value}"
            if password_value
            else "- Password: Unspecified"
        )

        # Real value if a password exists, else the literal `<password>` for command examples.
        password_example = password_value if password_value else "<password>"

        # If DCs were discovered in prior verification, add them to the prompt as known facts.
        known_dcs_block = (
            format_dcs_for_prompt(domain) if domain and domain != "Unspecified" else ""
        )
        if known_dcs_block:
            dc_line = "- Domain controllers: refer to the \"Known Domain Controllers\" section below (no re-fetch needed)"
            known_dcs_section = f"\n\n{known_dcs_block}\n  * The above was mechanically extracted from prior verification in the same process and may be trusted. Re-querying DNS SRV / nxc smb for the same DC can be skipped."
        else:
            dc_line = "- Domain controller IP/hostname: Unspecified (if needed, design a check command to obtain it first)"
            known_dcs_section = ""

        # Entra: hand the LLM the real path of the already-collected roadrecon.db so it can write
        # a literal query. Commands are free-form (no {{var}} rendering), so the path must be a
        # concrete value here. Only for findings that actually target Entra -- on an AD-only
        # finding this line would be noise, and worse, _resolve_entra_tenant falls back to the
        # sole collected tenant, which would dangle an unrelated database in front of the LLM.
        entra_line = ""
        if "entra" in _target_platforms:
            _tenant = _resolve_entra_tenant(execution_context.get("tenant"))
            _entra_db = get_entra_db(_tenant) if _tenant else None
            entra_line = (
                f"\n- Collected Entra database (local file, query it directly; do NOT use SOCKS): {_entra_db}"
                if _entra_db
                else "\n- Collected Entra database: none was collected, so report Entra checks as Unverified; do not attempt to collect."
            )

        execution_context_text = f"""

[Execution Context]
- Domain name: {domain}
- Username: {user}
{password_line}
- DNS server IP address: {dns}
{dc_line}{entra_line}{known_dcs_section}

Network:
- The target network (AD domain, etc.) is reached via a SOCKS5 proxy
- SOCKS routing is applied automatically by the execution layer, so do not prefix commands with `proxychains` or similar

Obtaining DC info:
- When a check needs a DC IP/hostname and it is unknown, first discover the DC by querying the DNS SRV record `_ldap._tcp.<domain>` against `{dns}`
  e.g. `dig @{dns} _ldap._tcp.{domain} SRV +short`
  e.g. `nslookup -type=SRV _ldap._tcp.{domain} {dns}`
- If it cannot be obtained from the given DNS server, infer the hostname from the SMB response, e.g. `nxc smb {domain} -u {user} -p '{password_example}'`

Handling credentials:
- For checks that require authentication, embed the domain/user/DNS/password above directly into the command
- Write the given real password verbatim; do not use a placeholder or mask it
- e.g. `nxc ldap dc01.{domain} -u {user} -p '{password_example}' --query '...'`
"""

    # Finding-specific values the operator entered at retest time (target host, etc.). The LLM
    # designs command strings, so surface these directly so it can embed them (credentials/DC
    # still come from the execution context above). Only pattern-validated values reach here.
    provided_inputs_text = ""
    if runtime_variables:
        _input_lines = "\n".join(
            f"- {key}: {value}" for key, value in runtime_variables.items() if value
        )
        if _input_lines:
            provided_inputs_text = f"""

[Provided Inputs]
The operator supplied these finding-specific values; use them in the commands you design.
{_input_lines}
"""

    _platform_labels = {
        "ad": "Windows Active Directory (on-prem)",
        "entra": "Microsoft Entra ID (cloud; query the collected roadrecon database named in the execution context)",
        "other": "Other (includes Linux/Unix; determine the target environment and check method from the finding's content)",
        "retest_not_supported": "Automated retest not supported (cannot run from the frontend; normally unreachable here)",
    }
    platform_lines = "\n".join(
        f"- {_platform_labels.get(p, p)}" for p in _target_platforms
    )
    platform_block = f"\n[Target Platform]\n{platform_lines}\n"

    # Optional advisory tool hints from the report author (findings.json `tool_hints`). Surfaced
    # so the planner prefers the operator's intended tooling; the LLM still authors the commands.
    _tool_hints = getattr(finding, "tool_hints", []) or []
    tool_hints_block = ""
    _hint_lines = "\n".join(f"- {str(h).strip()}" for h in _tool_hints if str(h).strip())
    if _hint_lines:
        tool_hints_block = f"""
[Tools to Use]
The report author RESTRICTS the tools for verifying this finding. Every verification command MUST invoke ONLY these tools:
{_hint_lines}
This restriction is mandatory, not advisory. You MUST forward this exact [Tools to Use] list to verification_planner in the task you give it, and reject/redo any proposed command that invokes a tool outside this list. Do not use any other tool unless the check genuinely cannot be determined with the tools above after a real attempt -- only then may you add a single minimal alternative, and you MUST state explicitly why the listed tools were insufficient. Never substitute a heavier or more intrusive tool (e.g. a remote command-execution framework such as wmiexec/psexec) for a listed read-only one. Keep every command read-only / non-destructive and consistent with [Target Platform].
"""

    return f"""{platform_block}
[Finding Number]
{finding.no}

[Title]
{finding.title}

[Risk Level]
{finding.risk_level}

[Summary]
{finding.summary}

[Details]
{finding.description}

[Recommended Remediation]
{finding.recommendation}
{_judgment_criteria_block(finding)}
[References]
{refs}
{execution_context_text}
{provided_inputs_text}
{tool_hints_block}
{extra_instruction}"""


def build_finding_prompt(
    finding: FindingItem,
    user_instruction: str | None = None,
    execution_context: dict[str, Any] | None = None,
    runtime_variables: dict[str, str] | None = None,
) -> str:
    """Deep-agent (legacy) finding prompt: shared context + the orchestrator's Requirements."""
    context = _build_finding_context(
        finding, user_instruction, execution_context, runtime_variables
    )
    return f"""
The following is a finding from a security assessment.
Based on it, verify whether the recommended remediation has been applied. Follow the target platform below.
{context}

Requirements:
- Design a verification procedure for **every environment listed** in [Target Platform] above (if several, check each individually; e.g. if AD and Entra are both listed, perform both the AD-side and Entra-side checks; if "Other" is included, determine the target environment (Linux, etc.) and check method from the finding's content)
- Lay out what state things should be in if the recommended remediation has been applied
- Design a safe, non-destructive check command to confirm that state
- For AD checks, start the procedure from obtaining the target DC IP/hostname when it is unknown
- Assume the target network is reached via a SOCKS5 proxy, and do not prefix commands with `proxychains` or similar
- If a command needs to be executed, delegate it to the execution-only agent
- Do not assert facts not present in the input
- If information is missing, state explicitly what you assumed
- Focus on this single finding only; do not broaden to other findings
- If domain name, username, password, and DNS server info are given, design the procedure on that basis
- If [Tools to Use] is listed, design the commands using ONLY those tools; use a different tool only when the check cannot be determined with them after a genuine attempt (then state why), and never swap in a heavier / more intrusive tool. Keep commands read-only and platform-appropriate
- If authentication is required, embed the given real password verbatim into the command string (do not use a placeholder or mask it)
- If [Judgment Criteria] is provided, judge Resolved / Partially Resolved / Unresolved strictly according to it (if the criteria's satisfaction cannot be confirmed, Inconclusive). If no [Judgment Criteria] is provided, judge based on whether the recommended remediation has been applied
- Finally, summarize with justification as one of: Resolved / Partially Resolved / Unresolved / Inconclusive
- End the report with a single authoritative marker line, on its own line, in EXACTLY this format and nothing after it:
  `Verdict: <Resolved|Partially Resolved|Unresolved|Inconclusive>`
  This final line is machine-read and MUST match your narrative conclusion. When you describe the state expected once the remediation is applied, phrase it so the words Resolved / Partially Resolved / Unresolved / Inconclusive do NOT appear as a standalone judgment before this final line (e.g. write "signing would be enforced" rather than "would be Resolved"). Use those verdict words only in your conclusion and in this final marker line.
""".strip()



def _shell_sq_escape(value: str) -> str:
    """Escape only single quotes so the value embeds safely inside a template's '...'.

    SECURITY: inside POSIX shell '...' every char except `'` (i.e. $ ; space ` etc.) is
    literal, so replacing `'` with `'\\''` (close quote -> escaped ' -> reopen quote)
    prevents command injection regardless of the value's contents. Values without `'` are
    returned unchanged. Invariant: the value MUST be placed inside the template's '...'
    (passwords are operated under this convention).
    """
    return value.replace("'", "'\\''")

def _redact_thread_secrets(text: str | None, thread_id: str | None) -> str | None:
    """Mask the AD password and secret input values (both raw and '...'-escaped forms) to
    <PASS>. Used for command display and command output (nxc etc. include the password in
    output on successful auth)."""
    if not text:
        return text
    text = _redact_password(
        text, _get_thread_password(thread_id) if thread_id else None
    )
    for _sv in _get_thread_input_secrets(thread_id).values():
        if not _sv:
            continue
        text = text.replace(_sv, PASSWORD_PLACEHOLDER)
        _esc = _shell_sq_escape(_sv)
        if _esc != _sv:
            text = text.replace(_esc, PASSWORD_PLACEHOLDER)
    return text


def build_subagents(tools: list) -> list[dict[str, Any]]:
    """Wire the verification planner + executor subagents.

    The planner designs command strings from the finding; the executor runs them via the raw
    execute_kali_command tool. The tool is gated by interrupt_on so, when require_approval is on,
    each generated command goes through Human-in-the-loop review (approve/edit/reject) before it
    runs. Accuracy is guaranteed by that human review rather than by a fixed command catalog.
    """
    verification_planner = {
        "name": "verification_planner",
        "description": "Verification planner agent that designs safe, non-destructive check command strings from a single finding and its recommended remediation.",
        "system_prompt": VERIFICATION_PLANNER_PROMPT,
        "tools": [],
    }

    # Give the executor the wrapped execute_kali_command tool (password substitution / proxychains
    # normalization / DC absorption are applied in the MCP wrapper). interrupt_on triggers the HITL
    # review for the generated command string.
    kali_tool = next(
        (t for t in tools if getattr(t, "name", "") == "execute_kali_command"), None
    )
    executor_tools = [kali_tool] if kali_tool is not None else []
    command_executor = {
        "name": "command_executor",
        "description": "Execution-only agent that runs the command string designed by the planner via execute_kali_command and returns the observed result.",
        "system_prompt": COMMAND_EXECUTOR_PROMPT,
        "tools": executor_tools,
        "interrupt_on": {"execute_kali_command": True},
    }

    return [verification_planner, command_executor]


def _wrap_kali_tool_for_dc_absorption(tool):
    """Wrap the `execute_kali_command` MCP tool to mechanically extract DC info from command
    output after a successful call and register it into the in-process cache. It reads only
    the command string and stdout/stderr (not LLM output), so mis-extraction risk is low.
    """
    tool_name = getattr(tool, "name", "")
    if tool_name != "execute_kali_command":
        return tool

    original_ainvoke = tool.ainvoke

    async def _wrapped_ainvoke(input_data, *args, **kwargs):
        # SECURITY: substitute password placeholders (<PASS>, {password}, $PASSWORD, etc.)
        # with the real value just before execution. Backstop for when the LLM left a placeholder.
        tid = _current_thread_id.get()
        password = _get_thread_password(tid) if tid else None
        if password:
            try:
                input_data = _substitute_password_placeholder(input_data, password)
            except Exception:
                # On failure, continue with the original input_data (do not halt execution).
                logger.exception(
                    "Password placeholder substitution in MCP wrapper failed"
                )

        result = await original_ainvoke(input_data, *args, **kwargs)
        try:
            command = ""
            if isinstance(input_data, dict):
                command = str(input_data.get("command") or "")
            elif isinstance(input_data, str):
                command = input_data
            output_text = _extract_mcp_text(result)
            default_domain = _get_thread_domain(tid) if tid else None
            if command and output_text:
                absorb_command_output(
                    command, output_text, default_domain=default_domain
                )
            # Capture the executed command (placeholder-ized) for optional RTO export. No-op for
            # non-verification threads; secrets are stripped inside _capture_retest_command.
            _capture_retest_command(tid, command)
        except Exception:
            logger.exception("DC absorption inside MCP tool wrapper failed")
        return result

    # langchain tools are usually pydantic and forbid direct attribute replacement, so wrap
    # by swapping just ainvoke.
    try:
        tool.ainvoke = _wrapped_ainvoke  # type: ignore[assignment]
        return tool
    except Exception:
        # If the swap fails, do not wrap (avoid misbehavior).
        logger.warning("Failed to wrap MCP tool ainvoke for DC absorption")
        return tool


async def init_agent() -> None:
    global _mcp_client, _mcp_tools, _checkpointer, _agent

    if _agent is not None:
        return

    _mcp_client = MultiServerMCPClient(MCP_SERVERS)
    raw_tools = await _mcp_client.get_tools()
    _mcp_tools = [_wrap_kali_tool_for_dc_absorption(t) for t in raw_tools]
    _checkpointer = MemorySaver()

    subagents = build_subagents(_mcp_tools)

    _agent = create_deep_agent(
        model=model,
        tools=[],
        subagents=subagents,
        system_prompt=DEEP_AGENT_PROMPT,
        checkpointer=_checkpointer,
    )


async def get_agent():
    if _agent is None:
        await init_agent()
    return _agent


async def get_mcp_tools():
    if _mcp_tools is None:
        await init_agent()
    return _mcp_tools or []


def _extract_mcp_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, list):
        parts = []
        for item in result:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item["text"])
            elif isinstance(item, str):
                parts.append(item)
        if parts:
            return "".join(parts)
    if hasattr(result, "content"):
        return _extract_mcp_text(result.content)
    return str(result)


def _redact_password(text: str, password: str | None) -> str:
    if not password or not text:
        return text
    # Mask the raw password (the form that appears in command output, etc.).
    text = text.replace(password, PASSWORD_PLACEHOLDER)
    # Rendered commands embed it in the '...'-escaped form, so also replace the escaped form to
    # reliably mask passwords that contain `'`.
    escaped = _shell_sq_escape(password)
    if escaped != password:
        text = text.replace(escaped, PASSWORD_PLACEHOLDER)
    return text


def _redact_value(value: Any, password: str | None) -> Any:
    if isinstance(value, str):
        return _redact_password(value, password)
    if isinstance(value, dict):
        return {key: _redact_value(item, password) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, password) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item, password) for item in value)
    return value


def _redact_interrupt_secrets(value: Any, thread_id: str | None) -> Any:
    """Recursively mask the AD password and secret inputs to <PASS> everywhere in an interrupt
    payload before it is stored on the thread and streamed to the UI.

    The plaintext password must never reach the browser (SSE / GET /threads). Execution still
    works because <PASS> is substituted back to the real value at run time
    (_prepare_resume_decisions for approve/edit + the MCP tool wrapper), so the review dialog and
    resume round-trip only ever see the placeholder."""
    if isinstance(value, str):
        return _redact_thread_secrets(value, thread_id) or value
    if isinstance(value, dict):
        return {key: _redact_interrupt_secrets(item, thread_id) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_interrupt_secrets(item, thread_id) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_interrupt_secrets(item, thread_id) for item in value)
    return value


# Placeholder patterns the LLM tends to write instead of embedding the real password. Even
# when the prompt instructs embedding the real value, models sometimes emit <PASS> or
# {password}, etc. as safe-side behavior, so this is a backstop that substitutes just before
# execution. Order matters: ${...} before {...}, and the longer alternative (PASSWORD) before
# the shorter (PASS).
_PASSWORD_PLACEHOLDER_RE = re.compile(
    r"""
    (?:
        # ${...} form (`$` + braces): ${PASS}, ${PASSWORD}, ${password}
        \$\{\s*
        (?: PASSWORD | password | PASS | pass )
        \s*\}
    )
    |
    (?:
        # <...> form: <PASS>, <password>, <your_password>, <insert_password>, <actual_password>
        <\s*
        (?:
            YOUR_PASSWORD | YOUR[-_ ]PASSWORD
            | INSERT_PASSWORD | INSERT[-_ ]PASSWORD
            | ACTUAL_PASSWORD | ACTUAL[-_ ]PASSWORD
            | PASSWORD | password
            | PASS | pass
        )
        \s*>
    )
    |
    (?:
        # {...} form (braces, no `$`): {PASS}, {password}
        \{\s*
        (?: PASSWORD | password | PASS | pass )
        \s*\}
    )
    |
    (?:
        # $... form (no braces, word boundary required): $PASS, $PASSWORD, $password
        \$ (?: PASSWORD | password | PASS | pass ) \b
    )
    |
    (?:
        # Obvious all-caps giveaways: YOUR_PASSWORD, PASSWORD_HERE, INSERT_PASSWORD_HERE
        \b (?: YOUR_PASSWORD | PASSWORD_HERE | INSERT_PASSWORD_HERE ) \b
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _substitute_password_placeholder(value: Any, password: str | None) -> Any:
    """Mechanically substitute LLM-emitted password placeholders (<PASS>, {password},
    $PASSWORD, etc.) with the real value, recursing into dict/list/tuple. No-op when password
    is None/empty."""
    if not password:
        return value
    if isinstance(value, str):
        # Passing password directly as replacement text would interpret `\1` `\g<..>` `\\` as
        # backreferences/escapes, risking wrong expansion or exceptions. Use a lambda to return
        # it as a literal value, not a replacement string.
        return _PASSWORD_PLACEHOLDER_RE.sub(lambda _m: password, value)
    if isinstance(value, dict):
        return {
            key: _substitute_password_placeholder(item, password)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_substitute_password_placeholder(item, password) for item in value]
    if isinstance(value, tuple):
        return tuple(_substitute_password_placeholder(item, password) for item in value)
    return value


def _prepare_resume_decisions(
    interrupt: dict[str, Any] | None,
    decisions: list[dict[str, Any]],
    password: str | None,
) -> list[dict[str, Any]]:
    """Normalize the internal decisions representation into the form langchain's HITL
    middleware expects.

    Internal form (from resume_endpoint):
      {"type": "approve"}
      {"type": "edit", "args": {...}}           # main.py already repacked edited_args -> args
      {"type": "reject", "comment": "..."}

    langchain HITL expected form (`HumanInTheLoopMiddleware._process_decision`):
      {"type": "approve"}
      {"type": "edit", "edited_action": {"name": <tool_name>, "args": {...}}}
      {"type": "reject"}

    Also performs <PASS> placeholder substitution. An approve whose args still contain a
    placeholder is promoted to edit to fill the real value.
    """
    actions = interrupt.get("actions", []) if interrupt else []
    prepared: list[dict[str, Any]] = []

    for idx, decision in enumerate(decisions):
        d_type = decision.get("type")
        result: dict[str, Any] = {"type": d_type}
        if decision.get("comment"):
            result["comment"] = decision["comment"]

        action = actions[idx] if idx < len(actions) else {}
        action_name = action.get("name")
        original_args = action.get("args", {})

        if d_type == "approve":
            # An approve containing a placeholder is promoted to edit to fill the real value.
            if password and action_name and PASSWORD_PLACEHOLDER in str(original_args):
                result["type"] = "edit"
                result["edited_action"] = {
                    "name": action_name,
                    "args": _substitute_password_placeholder(original_args, password),
                }
        elif d_type == "edit" and action_name:
            # Take the internal args key (resume_endpoint repacked from d.edited_args) and
            # convert it to langchain's edited_action form.
            user_args = decision.get("args")
            if user_args is None:
                user_args = decision.get("edited_args")
            # Structured HITL edit: {bin, args: [...]}. Recombine into a single command
            # string with shlex.join -- each token is shell-quoted, so the exec-time
            # shlex.split yields exactly these tokens (no injection through an edited arg).
            # The binary is LOCKED to the LLM's original choice: resume_endpoint already
            # rejects a changed bin, and here we defensively fall back to the original bin.
            if isinstance(user_args, dict) and isinstance(user_args.get("args"), list):
                orig_command = (
                    original_args.get("command")
                    if isinstance(original_args, dict)
                    else None
                )
                orig_bin, _orig_tokens, _ok = _split_command_for_review(orig_command)
                new_bin = user_args.get("bin") or orig_bin or ""
                tokens = [str(new_bin)] + [str(t) for t in user_args["args"]]
                merged_args: dict[str, Any] = {"command": shlex.join(tokens)}
                # Preserve the tool's other args (e.g. use_proxychains) from the original call.
                if isinstance(original_args, dict) and "use_proxychains" in original_args:
                    merged_args["use_proxychains"] = original_args["use_proxychains"]
                user_args = merged_args
            elif user_args is None:
                user_args = original_args or {}
            substituted = (
                _substitute_password_placeholder(user_args, password)
                if password
                else user_args
            )
            result["edited_action"] = {
                "name": action_name,
                "args": substituted,
            }
        # type == "reject" has no extra fields.

        prepared.append(result)

    return prepared


async def execute_kali_command(
    command: str,
    password: str | None = None,
    use_proxychains: bool = True,
) -> dict[str, Any]:
    """Substitute LLM-emitted password placeholders (<PASS>, {password}, $PASSWORD, etc.) with
    the `password` argument before passing to MCP.

    use_proxychains: whether to prefix proxychains. Default True (preserves legacy behavior of
    RTO and the manual-approval path). On the verification path the catalog's proxychains value
    is auto-normalized by the MCP wrapper, so it need not be specified explicitly here."""
    real_command = (
        _substitute_password_placeholder(command, password) if password else command
    )

    tools = await get_mcp_tools()
    for tool in tools:
        if tool.name == "execute_kali_command":
            start = time.time()
            result = await tool.ainvoke(
                {"command": real_command, "use_proxychains": use_proxychains}
            )
            duration_ms = int((time.time() - start) * 1000)
            output = _extract_mcp_text(result)
            # SECURITY: keep any plaintext password out of events even if it appears in stdout.
            # Also mask secret inputs (nxc etc. include the password in output on successful auth).
            sanitized_output = _redact_password(output, password)
            sanitized_output = _redact_thread_secrets(
                sanitized_output, _current_thread_id.get()
            )
            return {
                "output": sanitized_output,
                "exitCode": 0,
                "durationMs": duration_ms,
            }
    raise RuntimeError("execute_kali_command tool not found in MCP tools")


# Advisory `<bin> --help` cache (binary name -> (text, stored_at)). Help text is stable, so a
# long TTL avoids re-invoking the MCP tool for the same binary during a review session.
_COMMAND_HELP_CACHE: dict[str, tuple[str, float]] = {}
_COMMAND_HELP_TTL_SECONDS = float(os.getenv("COMMAND_HELP_TTL_SECONDS", "3600"))


async def get_command_help(binary: str) -> str:
    """Return `<binary> --help` text (advisory) via the MCP command_help tool, cached per binary.

    Used by the HITL review UI to help a human reviewer spot invalid / nonexistent options while
    editing a command's arguments. Read-only: it never runs a target-affecting action.
    """
    name = (binary or "").strip()
    if not name:
        return "No binary name was provided."
    cached = _COMMAND_HELP_CACHE.get(name)
    if cached and time.time() - cached[1] <= _COMMAND_HELP_TTL_SECONDS:
        return cached[0]
    tools = await get_mcp_tools()
    for tool in tools:
        if tool.name == "command_help":
            result = await tool.ainvoke({"binary": name})
            text = _extract_mcp_text(result)
            _COMMAND_HELP_CACHE[name] = (text, time.time())
            return text
    raise RuntimeError("command_help tool not found in MCP tools")


async def start_command_approval(
    thread_id: str,
    command: str,
    label: str | None = None,
    finding_id: str | None = None,
) -> None:
    thread = get_or_create_thread(thread_id, kind="verification")
    thread.status = "waiting_human"

    # Build the payload, then mask the password / secret inputs to <PASS> before storing/streaming
    # it. The real value is restored at execution (execute_approved_command -> execute_kali_command
    # substitutes), so plaintext never reaches the browser.
    review_bin, arg_tokens, structured = _split_command_for_review(command)
    interrupt_payload = _redact_interrupt_secrets(
        {
            "id": f"intr-{uuid4().hex}",
            "actions": [
                {
                    "index": 0,
                    "name": "execute_kali_command",
                    "args": {"command": command},
                    "description": label or f"Execute: {command}",
                    "allowed_decisions": ["approve", "edit", "reject"],
                    # Structured-edit fields (bin locked, arg_tokens editable); see serialize_interrupt.
                    "bin": review_bin,
                    "arg_tokens": arg_tokens,
                    "structured": structured,
                }
            ],
        },
        thread_id,
    )
    thread.interrupt = interrupt_payload

    append_event(thread_id, {"type": "status", "phase": "command_approval"})
    append_event(thread_id, {"type": "interrupt", "interrupt": interrupt_payload})


async def execute_approved_command(
    thread_id: str,
    command: str,
) -> None:
    thread = get_or_create_thread(thread_id)
    thread.status = "running"
    thread.interrupt = None

    append_event(thread_id, {"type": "status", "phase": "executing"})

    password = _get_thread_password(thread_id)

    try:
        result = await execute_kali_command(command, password=password)
        append_event(
            thread_id,
            {
                "type": "command_result",
                "command": command,
                "output": result["output"],
                "exitCode": result["exitCode"],
                "durationMs": result["durationMs"],
            },
        )

        # Mechanically extract DC info from command output into the in-process cache.
        try:
            registered = absorb_command_output(
                command,
                result.get("output", ""),
                default_domain=_get_thread_domain(thread_id),
            )
            if registered:
                append_event(
                    thread_id,
                    {
                        "type": "status",
                        "phase": "dc_discovery_updated",
                        "registered": registered,
                    },
                )
        except Exception:
            # DC extraction failure must not affect the main verification result.
            logger.exception("DC info extraction failed for thread %s", thread_id)

        thread.status = "completed"
        thread.final_output = result
        append_event(thread_id, {"type": "final", "data": result})
    except Exception as e:
        thread.status = "failed"
        # Keep redacted detail for internal use (logs/monitoring). Mask the AD password plus
        # secret inputs.
        thread.error = _redact_thread_secrets(
            _redact_password(str(e), password), thread_id
        )
        logger.exception("execute_approved_command failed for thread %s", thread_id)
        # Keep the externally emitted SSE message generic.
        append_event(
            thread_id,
            {
                "type": "error",
                "message": "Command execution failed",
            },
        )
    finally:
        _clear_thread_password(thread_id)


def new_thread_id() -> str:
    return str(uuid4())


def _split_command_for_review(command: Any) -> tuple[str | None, list[str], bool]:
    """Split a command string into (bin, arg_tokens, ok) for HITL presentation.

    The retest tool call carries the command as one string; the review UI shows the binary
    LOCKED and each argument individually editable. Splitting is done with shlex
    (deterministic) rather than asking the LLM to structure the args. Returns ok=False on a
    parse error (unbalanced quotes), a non-string, or an empty command; the UI then falls
    back to raw-string review (no per-arg editing). On resume, an edit is recombined with
    shlex.join so the tokens round-trip exactly (see _prepare_resume_decisions).
    """
    if not isinstance(command, str):
        return None, [], False
    try:
        toks = shlex.split(command)
    except ValueError:
        return None, [], False
    if not toks:
        return None, [], False
    return toks[0], toks[1:], True


def serialize_interrupt(interrupt_obj: Any) -> dict[str, Any]:
    interrupt_id = getattr(interrupt_obj, "id", None)
    interrupt_value = getattr(interrupt_obj, "value", {}) or {}

    action_requests = interrupt_value.get("action_requests", [])
    review_configs = interrupt_value.get("review_configs", [])

    normalized_actions = []
    for idx, action in enumerate(action_requests):
        review = review_configs[idx] if idx < len(review_configs) else {}
        args = action.get("args", {})
        review_bin, arg_tokens, structured = _split_command_for_review(
            args.get("command") if isinstance(args, dict) else None
        )
        normalized_actions.append(
            {
                "index": idx,
                "name": action.get("name"),
                "args": args,
                "description": action.get("description"),
                "allowed_decisions": review.get("allowed_decisions", []),
                # Structured-edit fields for HITL: `bin` is locked (the tool the LLM chose),
                # `arg_tokens` are individually editable. `structured` is False when the
                # command could not be tokenized -> UI falls back to raw-string review.
                "bin": review_bin,
                "arg_tokens": arg_tokens,
                "structured": structured,
            }
        )

    return {
        "id": interrupt_id,
        "actions": normalized_actions,
        "raw": interrupt_value,
    }


def extract_interrupts_from_chunk(chunk: Any) -> list[Any] | None:
    if not isinstance(chunk, dict):
        return None

    interrupts = chunk.get("__interrupt__")
    if interrupts:
        return list(interrupts)

    interrupts = chunk.get("interrupts")
    if interrupts:
        return list(interrupts)

    return None


def extract_text_from_chunk(chunk: Any) -> str:
    if not isinstance(chunk, dict):
        return ""

    parts: list[str] = []

    def walk(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            if value.strip():
                parts.append(value)
            return
        if isinstance(value, dict):
            for v in value.values():
                walk(v)
            return
        if isinstance(value, list):
            for item in value:
                walk(item)
            return
        content = getattr(value, "content", None)
        if isinstance(content, str) and content.strip():
            parts.append(content)

    walk(chunk)
    return "\n".join(parts).strip()


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                value = item.get("text") or item.get("content") or item.get("value")
                if isinstance(value, str):
                    parts.append(value)
            else:
                value = getattr(item, "text", None) or getattr(item, "content", None)
                if isinstance(value, str):
                    parts.append(value)
        return "\n".join(part for part in parts if part.strip()).strip()
    if isinstance(content, dict):
        value = content.get("text") or content.get("content") or content.get("value")
        return value.strip() if isinstance(value, str) else ""

    return ""


def _message_to_text(message: Any) -> str:
    if isinstance(message, str):
        return message.strip()
    if isinstance(message, dict):
        return _content_to_text(message.get("content") or message.get("text"))

    return _content_to_text(
        getattr(message, "content", None) or getattr(message, "text", None)
    )


def extract_last_message_text_from_chunk(chunk: Any) -> str:
    if not isinstance(chunk, dict):
        return ""

    latest_text = ""

    def walk(value: Any) -> None:
        nonlocal latest_text
        if isinstance(value, dict):
            messages = value.get("messages")
            if isinstance(messages, list) and messages:
                text = _message_to_text(messages[-1])
                if text:
                    latest_text = text
            for v in value.values():
                walk(v)
            return
        if isinstance(value, list):
            for item in value:
                walk(item)

    walk(chunk)
    return latest_text.strip()


async def _stream_agent(thread_id: str, thread, agent, input_data, config) -> None:
    collected_text: list[str] = []
    latest_message_text = ""

    # Let the downstream MCP tool wrapper read the thread_id currently being processed.
    token = _current_thread_id.set(thread_id)
    try:
        # In auto-approve mode, loop internally on interrupt -> auto approve -> resume. With
        # require_approval=True, return on the first interrupt (legacy) and wait for the user.
        current_input = input_data
        while True:
            interrupt_payload: dict[str, Any] | None = None

            async for chunk in agent.astream(current_input, config=config):
                interrupts = extract_interrupts_from_chunk(chunk)
                if interrupts:
                    # Mask the AD password / secret inputs to <PASS> before this payload is stored
                    # on the thread or streamed to the UI. The real value is restored at execution
                    # (_prepare_resume_decisions + MCP wrapper), so plaintext never reaches the browser.
                    interrupt_payload = _redact_interrupt_secrets(
                        serialize_interrupt(interrupts[0]), thread_id
                    )
                    break  # leave the astream for-loop; branch auto/manual in the outer while

                # Mask any password / secret that appears in a streamed chunk (e.g. the executor's
                # tool-call args) before it leaves the server. String-only redaction keeps the chunk
                # structure intact, so downstream chunk scanning is unaffected.
                append_event(
                    thread_id,
                    {"type": "chunk", "data": _redact_interrupt_secrets(chunk, thread_id)},
                )
                text = extract_last_message_text_from_chunk(chunk)
                if text:
                    latest_message_text = text
                else:
                    text = extract_text_from_chunk(chunk)
                if text:
                    collected_text.append(text)

            if interrupt_payload is None:
                break  # natural end (astream completed with no interrupt)

            if thread.require_approval:
                # Legacy HITL: hand off to UI approval.
                thread.status = "waiting_human"
                thread.interrupt = interrupt_payload
                append_event(
                    thread_id, {"type": "interrupt", "interrupt": interrupt_payload}
                )
                return

            # auto-approve: treat all actions as approved and fire the resume ourselves.
            append_event(
                thread_id,
                {
                    "type": "interrupt",
                    "interrupt": interrupt_payload,
                    "auto_approved": True,
                },
            )
            auto_decisions = [
                {"type": "approve"} for _ in interrupt_payload.get("actions", [])
            ]
            password = _get_thread_password(thread_id)
            resume_decisions = _prepare_resume_decisions(
                interrupt_payload, auto_decisions, password
            )
            append_event(
                thread_id,
                {
                    "type": "resumed",
                    "decisions": auto_decisions,
                    "auto_approved": True,
                },
            )
            # Resume astream with the resume input on the next loop iteration.
            current_input = Command(resume={"decisions": resume_decisions})

        # Breaking out of the while loop means normal completion.
        thread.status = "completed"
        thread.interrupt = None

        final_text = latest_message_text or "\n".join(
            t for t in collected_text if t.strip()
        ).strip()
        # The planner prompt instructs the LLM to embed the real AD password verbatim into
        # verification commands, so the final report restates commands like `-p 'RealPass'`.
        # Mask the password (and secret inputs) to <PASS> before storing, so neither the SSE
        # final event nor the saved history leaks it. Done here (before _clear_thread_password
        # below) while the thread secret is still available.
        final_text = _redact_thread_secrets(final_text, thread_id)
        if final_text:
            thread.final_output = {"content": final_text}
        else:
            thread.final_output = {"message": "completed"}

        # Persist retest history to DB (just before emitting SSE final). Failure does not halt
        # the main flow; log only.
        finding_no = _get_thread_finding_no(thread_id)
        if finding_no:
            try:
                from agent.retest_history import save_record

                await save_record(
                    finding_no=finding_no,
                    thread_id=thread_id,
                    markdown=final_text or None,
                    final_output=thread.final_output,
                    # Placeholder-ized commands captured during the run, for optional RTO export.
                    commands=get_thread_captured_commands(thread_id),
                )
            except Exception:
                logger.exception(
                    "Failed to persist retest history (thread=%s finding=%s)",
                    thread_id,
                    finding_no,
                )

        append_event(thread_id, {"type": "final", "data": thread.final_output})
        _clear_thread_password(thread_id)
        _clear_thread_finding_no(thread_id)
        _clear_thread_capture(thread_id)

    except Exception as e:
        thread.status = "failed"
        # Keep detail for internal use; redact since it may contain the AD password + secret inputs.
        password = _get_thread_password(thread_id)
        thread.error = _redact_thread_secrets(
            _redact_password(str(e), password), thread_id
        )
        logger.exception("_stream_agent failed for thread %s", thread_id)
        append_event(
            thread_id,
            {
                "type": "error",
                "message": "Agent stream failed",
            },
        )
        _clear_thread_password(thread_id)
        _clear_thread_capture(thread_id)
    finally:
        _current_thread_id.reset(token)


# finding-body -> check-query (catalog id) mapping used for deterministic retest of Entra-only
# findings. No LLM file exploration or command generation; queries run mechanically against the
# collected roadrecon.db. Keywords are matched (lowercased) against finding text.
_ENTRA_COMMAND_KEYWORDS: dict[str, tuple[str, ...]] = {
    "entra-ca-policies": (
        "conditional access", "ca policy", "legacy auth", "device", "policy",
    ),
    "entra-user-mfa": (
        "mfa", "multi-factor", "authentication strength", "2fa", "two-factor",
    ),
    "entra-privileged-roles": (
        "privileged", "global admin", "admin role", "role", "privilege",
    ),
    "entra-app-consents": (
        "app", "consent", "oauth", "service principal", "delegat",
    ),
    # For "stale privileged account" findings. Privilege/role keywords overlap with
    # entra-privileged-roles, so restrict this to stale/unused terms to avoid false firing on
    # unrelated privilege findings.
    "entra-stale-privileged-accounts": (
        "dormant", "stale", "inactive", "unused", "abandoned", "provisioning",
    ),
}


def _finding_judgment_criteria(finding: FindingItem) -> str | None:
    """Return the finding's judgment criteria. Treat unspecified or an unsubstituted
    placeholder (<...> such as <replace>) as None so no invalid value is injected into the prompt."""
    raw = getattr(finding, "judgment_criteria", None)
    if not raw:
        return None
    s = str(raw).strip()
    if not s or (s.startswith("<") and s.endswith(">")):
        return None
    return s


def _judgment_criteria_block(finding: FindingItem) -> str:
    """The [Judgment Criteria] block for the interpretation prompt; empty string if unspecified."""
    criteria = _finding_judgment_criteria(finding)
    return f"\n[Judgment Criteria]\n{criteria}\n" if criteria else ""


async def start_verification(
    thread_id: str,
    finding: FindingItem,
    user_instruction: str | None = None,
    execution_context: dict[str, Any] | None = None,
    runtime_variables: dict[str, str] | None = None,
) -> None:
    agent = await get_agent()
    thread = get_or_create_thread(thread_id, kind="verification")
    thread.status = "running"

    # Link finding_no to the thread; needed when saving retest history (DB).
    _store_thread_finding_no(thread_id, finding.no)

    # Register this thread as an RTO-export capture target and record the non-secret placeholder
    # context (domain/user/dns + runtime inputs). Executed commands are captured + placeholder-ized
    # during the run and offered for export on the results view.
    _store_thread_placeholder_ctx(thread_id, execution_context, runtime_variables)

    # Plaintext passwords are assumed already stored in _THREAD_SECRETS by main.py, but for
    # backward compatibility also store when "pass" remains in the dict (tests, etc.).
    if execution_context and execution_context.get("pass"):
        _store_thread_password(thread_id, execution_context.get("pass"))

    # Store the domain under test for linkage into the DC cache.
    if execution_context and execution_context.get("domain"):
        _store_thread_domain(thread_id, execution_context.get("domain"))

    # Entra findings go through the same deep-agent path as AD: the LLM writes the roadrecon
    # queries itself. Collection stays server-side (roadrecon_collect.py), and the resulting
    # path of the collected database is handed to the LLM in the prompt, so it only writes the query.

    # Mechanical DC discovery: if this process has no DC for the domain yet, run
    # tools/AD_Recon/ad_dns_recon.py as a subprocess and put results into _DC_CACHE.
    # build_finding_prompt mixes those into the prompt as "known DCs".
    logger.info(
        "start_verification entered (thread=%s, has_ctx=%s)",
        thread_id,
        execution_context is not None,
    )
    if execution_context:
        domain = execution_context.get("domain")
        user = execution_context.get("user")
        password_val = execution_context.get("pass")
        dns_val = execution_context.get("dns")
        cached = bool(domain and get_dcs(domain))
        # Record why auto DC discovery is skipped (never log the password value). dns is not
        # used by the current ad_dns_recon call, so it is not a preflight requirement.
        logger.info(
            "DC discovery preflight (thread=%s, domain=%s, user_set=%s, password_set=%s, dns=%s, already_cached=%s)",
            thread_id,
            domain,
            bool(user),
            bool(password_val),
            dns_val,
            cached,
        )
        if domain and not cached and user and password_val:
            append_event(thread_id, {"type": "status", "phase": "dc_discovery_started"})
            registered = await _run_ad_dns_recon(
                thread_id,
                domain=domain,
                user=user,
                password=password_val,
                dns=dns_val,
            )
            append_event(
                thread_id,
                {
                    "type": "status",
                    "phase": "dc_discovery_completed",
                    "registered": registered,
                },
            )
        else:
            logger.info(
                "DC discovery skipped (thread=%s) — preflight gate not satisfied",
                thread_id,
            )

    # Entra collection (roadrecon gather) is not attached to retest; it is done beforehand via
    # the dedicated collection API. Retest only reads the collected roadrecon.db, whose path is
    # surfaced in the prompt's [Execution Context]. When nothing was collected the prompt says so,
    # and the finding is reported Unverified rather than querying a database that is not there.

    # Every finding -- AD, Entra or mixed -- goes through the deep agent: the planner designs the
    # command strings and the executor runs them under HITL review.
    prompt = build_finding_prompt(
        finding=finding,
        user_instruction=user_instruction,
        execution_context=execution_context,
        runtime_variables=runtime_variables,
    )
    append_event(thread_id, {"type": "status", "phase": f"Processing {finding.no}"})

    config = {"configurable": {"thread_id": thread_id}}
    await _stream_agent(
        thread_id,
        thread,
        agent,
        {"messages": [{"role": "user", "content": prompt}]},
        config,
    )


async def _judge_rto_step(step, command: str, result: dict[str, Any]) -> str:
    """Pass one step's execution result to the AI to judge success/failure and return the verdict text."""
    user_content = f"""[Step Objective]
{step.description or step.id}

[Judgment Criteria]
{step.judge_criteria or "(Unspecified; judge from a general red-team perspective)"}

[Executed Command]
{command}

[Exit Code]
{result.get("exitCode")}

[Output]
{(result.get("output") or "")[:4000]}
"""
    messages = [
        {"role": "system", "content": RTO_JUDGE_PROMPT},
        {"role": "user", "content": user_content},
    ]
    response = await model.ainvoke(messages)
    raw = response.content if hasattr(response, "content") else str(response)
    return re.sub(r"<think>.*?</think>\s*", "", raw, flags=re.DOTALL).strip()


# Verdict vocabulary (Success/Failure/Inconclusive) and report assembly. RTO attacks all lead
# directly to DA, so no complex path synthesis (LLM final integration); per-step verdicts are
# aggregated deterministically.
_RTO_VERDICT_SUCCESS = "success"
_RTO_VERDICT_FAIL = "fail"
_RTO_VERDICT_INCONCLUSIVE = "inconclusive"

# (keyword, code). The earliest occurrence in the verdict line decides the outcome. Keywords
# must match the (English) RTO judge output.
_RTO_VERDICT_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("Success", _RTO_VERDICT_SUCCESS),
    ("Failure", _RTO_VERDICT_FAIL),
    ("Inconclusive", _RTO_VERDICT_INCONCLUSIVE),
)


def _rto_verdict_match(text: str) -> str | None:
    """Return the code of the earliest-occurring verdict word in text."""
    best_idx: int | None = None
    best_code: str | None = None
    for kw, code in _RTO_VERDICT_KEYWORDS:
        idx = text.find(kw)
        if idx == -1:
            continue
        if best_idx is None or idx < best_idx:
            best_idx = idx
            best_code = code
    return best_code


def _extract_rto_verdict(assessment: str | None) -> str:
    """Deterministically extract the verdict code from judge output. Prefer a line containing
    "Verdict"; otherwise take the earliest verdict word overall. Inconclusive if none found."""
    if not assessment:
        return _RTO_VERDICT_INCONCLUSIVE
    for line in assessment.splitlines():
        if "Verdict" in line:
            code = _rto_verdict_match(line)
            if code is not None:
                return code
    return _rto_verdict_match(assessment) or _RTO_VERDICT_INCONCLUSIVE


def _rto_observation(assessment: str | None) -> str:
    """Take the observation part (body excluding the verdict line) from judge output and flatten to one line."""
    if not assessment:
        return ""
    kept: list[str] = []
    for line in assessment.splitlines():
        s = line.strip()
        if not s:
            continue
        if "Verdict" in s and _rto_verdict_match(s) is not None:
            continue
        kept.append(re.sub(r"^Observation\s*[:：]\s*", "", s))
    return " ".join(kept).strip()


def _rto_template_items(pattern: str, output: str) -> list[str]:
    """Collect success_pattern captures (named val -> group(1)) from matching lines, dedup while
    preserving order. For observation_template's {items}."""
    try:
        rx = re.compile(pattern)
    except re.error:
        return []
    seen: set[str] = set()
    items: list[str] = []
    for m in rx.finditer(output or ""):
        if "val" in (m.groupdict() or {}):
            value = m.group("val")
        elif m.groups():
            value = m.group(1)
        else:
            value = None
        if value and value not in seen:
            seen.add(value)
            items.append(value)
    return items


def _rto_fill_template(template: str, items: list[str]) -> str:
    """Fill observation_template's {items}/{count} (deterministic)."""
    return template.replace("{items}", ", ".join(items)).replace(
        "{count}", str(len(items))
    )


def _assemble_rto_report(judged: list[dict[str, Any]], dcs_present: bool) -> str:
    """Aggregate per-step verdicts deterministically and assemble the final report, listing only
    successes by category. The overall verdict is computed mechanically ("obtainable if at least
    one success"). Since LLM final integration is removed, the conclusion and listed items are
    reproducible every time."""
    successes = [j for j in judged if j.get("verdict") == _RTO_VERDICT_SUCCESS]

    lines: list[str] = ["# Red Team Test Report", "", "## Result"]
    if successes:
        # ==...== is rendered as a highlighter-style mark on display (stripped on download).
        lines.append("==Domain Administrator privileges can be obtained==")
    else:
        lines.append("Obtaining Domain Administrator privileges was not confirmed")
        if not dcs_present:
            lines += [
                "",
                "The attacks may not have run because no DC could be identified. "
                "Check DNS / target domain / credentials / SOCKS connectivity.",
            ]

    if successes:
        lines += ["", "## Successful Attacks", ""]
        order: list[str] = []
        by_cat: dict[str, list[dict[str, Any]]] = {}
        for j in successes:
            cat = j.get("category") or "Other"
            if cat not in by_cat:
                by_cat[cat] = []
                order.append(cat)
            by_cat[cat].append(j)
        # Bullet the categories with attacks nested underneath for readability.
        for cat in order:
            lines.append(f"- **{cat}**")
            for j in by_cat[cat]:
                obs = (j.get("observation") or "").strip()
                item = (
                    f"**{j.get('label')}**: {obs}" if obs else f"**{j.get('label')}**"
                )
                lines.append(f"  - {item}")

        # Recommended remediation (list successful attacks that have a remediation defined).
        remediated = [j for j in successes if (j.get("remediation") or "").strip()]
        if remediated:
            lines += ["", "## Recommended Remediation"]
            seen_labels: set[str] = set()
            for j in remediated:
                key = f"{j.get('label')}|{j.get('remediation')}"
                if key in seen_labels:
                    continue
                seen_labels.add(key)
                lines.append(
                    f"- **{j.get('label')}**: {(j.get('remediation') or '').strip()}"
                )

    return "\n".join(lines) + "\n"


async def start_rto(
    thread_id: str,
    target: str,
    user_instruction: str | None = None,
    execution_context: dict[str, Any] | None = None,
) -> None:
    """Run RTO (Red Team Operations).

    The code loads a JSON playbook, substitutes variables, executes commands in order, and for
    judge=true steps the AI judges success/failure. The final Markdown report is returned as
    final_output.content. The fixed playbook runs deterministically, so commands are executed by
    the code (this function) and the AI acts only as judge.
    """
    thread = get_or_create_thread(thread_id, kind="rto")
    thread.status = "running"
    thread.events.clear()
    thread.event_seq = 0

    password = None
    domain = None
    user = None
    dns = None
    if execution_context:
        password = execution_context.get("pass")
        domain = execution_context.get("domain")
        user = execution_context.get("user")
        dns = execution_context.get("dns")
        if password:
            _store_thread_password(thread_id, password)
        if domain:
            _store_thread_domain(thread_id, domain)

    try:
        playbook = load_playbook()
    except Exception as e:
        thread.status = "failed"
        thread.error = f"Failed to load the RTO playbook: {e}"
        logger.exception("RTO playbook load failed for thread %s", thread_id)
        append_event(
            thread_id, {"type": "error", "message": "RTO playbook load failed"}
        )
        _clear_thread_password(thread_id)
        return

    # For embedding into commands (password escaped assuming '...' injection; extract values are
    # individually shlex.quote'd on the apply_extract side).
    variables = {
        "target": target or "",
        "domain": domain or "",
        "user": user or "",
        "password": _shell_sq_escape(password) if password else "",
        "dns": dns or "",
    }
    # Raw values (pre-quote) for when-evaluation/display. password is excluded (not used in when).
    raw_variables = {
        "target": target or "",
        "domain": domain or "",
        "user": user or "",
        "dns": dns or "",
    }

    total_steps = sum(len(g.steps) for g in playbook.groups)
    append_event(
        thread_id,
        {
            "type": "status",
            "phase": (
                f"RTO started: {playbook.name} "
                f"({len(playbook.groups)} groups / {total_steps} steps)"
            ),
        },
    )

    # Execution state passed to when-evaluation (global across groups).
    state: dict[str, Any] = {
        "raw_variables": raw_variables,
        "outputs": {},  # step_id -> output
        "judge_results": {},  # step_id -> verdict text
        "step_status": {},  # step_id -> "done"|"skipped"|"error"
    }
    # Per-step verdict results (category=group name, label, verdict, observation).
    # Only successes are listed by category in the final report.
    judged: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    step_counter = 0
    # Dedup for append-inherited variables: var -> set of raw tokens taken in so far.
    extract_seen: dict[str, set[str]] = {}

    try:
        for group in playbook.groups:
            # Whole-group gate.
            if not evaluate_when(group.when, state):
                append_event(
                    thread_id,
                    {
                        "type": "status",
                        "phase": f"Skipping group {group.id} (condition not met)",
                    },
                )
                continue

            append_event(
                thread_id,
                {"type": "status", "phase": f"Group: {group.name or group.id}"},
            )
            group_step_results: list[dict[str, Any]] = []

            for step in group.steps:
                step_counter += 1
                base: dict[str, Any] = {
                    "id": step.id,
                    "description": step.description,
                }

                # Branch condition (when). Skip if false.
                if not evaluate_when(step.when, state):
                    record = {
                        **base,
                        "command": None,
                        "status": "skipped",
                        "reason": "Skipped by branch condition (when)",
                    }
                    state["step_status"][step.id] = "skipped"
                    append_event(thread_id, {"type": "chunk", **record})
                    group_step_results.append(record)
                    continue

                rendered, missing = render_command(step.command, variables)
                # Mask the password in the command used for display/judging/report.
                display_command = (
                    _redact_password(rendered, password) if password else rendered
                )
                base["command"] = display_command

                if missing:
                    record = {
                        **base,
                        "status": "skipped",
                        "reason": f"Skipped due to unspecified variables: {', '.join(missing)}",
                    }
                    state["step_status"][step.id] = "skipped"
                    append_event(thread_id, {"type": "chunk", **record})
                    group_step_results.append(record)
                    continue

                append_event(
                    thread_id,
                    {
                        "type": "status",
                        "phase": f"[{step_counter}/{total_steps}] Executing {step.id}",
                    },
                )

                try:
                    result = await execute_kali_command(
                        rendered, password=password, use_proxychains=step.proxychains
                    )
                except Exception as e:
                    record = {
                        **base,
                        "status": "error",
                        "reason": _redact_password(str(e), password),
                    }
                    logger.exception(
                        "RTO step execution failed (thread=%s step=%s)",
                        thread_id,
                        step.id,
                    )
                    state["step_status"][step.id] = "error"
                    append_event(thread_id, {"type": "chunk", **record})
                    group_step_results.append(record)
                    continue

                output = result.get("output") or ""
                state["outputs"][step.id] = output
                state["step_status"][step.id] = "done"

                # Variable inheritance (extract): extracted values feed the later steps' variable
                # pool. An append=True rule concatenates onto an existing same-named variable
                # (aggregating enumeration results from several steps into one variable, e.g.
                # members of multiple privileged groups into joe_users). Dedup is per token to drop
                # duplicate raw values (avoids spray duplicates -> extra lockouts). Already-joined
                # strings are not re-split; they are tracked via extract_seen.
                if step.extract:
                    tokens_by_var = extract_tokens(step.extract, output)
                    rule_by_var = {r.var: r for r in step.extract}
                    for var, toks in tokens_by_var.items():
                        rule = rule_by_var.get(var)
                        sep = rule.join if rule else ","
                        if rule and rule.append and raw_variables.get(var):
                            raw_parts = [raw_variables[var]]
                            rend_parts = [variables[var]]
                            seen = extract_seen.setdefault(var, set())
                        else:
                            raw_parts = []
                            rend_parts = []
                            seen = set()
                            extract_seen[var] = seen
                        for raw_tok, rend_tok in toks:
                            if raw_tok in seen:
                                continue
                            seen.add(raw_tok)
                            raw_parts.append(raw_tok)
                            rend_parts.append(rend_tok)
                        raw_variables[var] = sep.join(raw_parts)
                        variables[var] = sep.join(rend_parts)

                # DC discovery reuses the same mechanism as the retest path: mechanically extract
                # from dig/nslookup SRV and nxc smb output via the strict parser and register into
                # the in-process DC cache.
                try:
                    registered = absorb_command_output(
                        rendered, output, default_domain=domain
                    )
                    if registered:
                        append_event(
                            thread_id,
                            {
                                "type": "status",
                                "phase": "dc_discovery_updated",
                                "registered": registered,
                            },
                        )
                except Exception:
                    logger.exception(
                        "RTO DC extraction failed (thread=%s step=%s)",
                        thread_id,
                        step.id,
                    )

                # Server-inject dc/dcs from the cache (IP preferred, else hostname). As with retest,
                # apply after LLM/extract to make the DC value authoritative. DC values are
                # strict-validated (IPv4/FQDN) with no shell metacharacters, so they embed as-is
                # without quoting.
                if domain:
                    cached_dcs = get_dcs(domain)
                    if cached_dcs:
                        dc_val = cached_dcs[0].ip or cached_dcs[0].hostname
                        dcs_val = " ".join(
                            d.ip or d.hostname for d in cached_dcs
                        )
                        variables["dc"] = dc_val
                        variables["dcs"] = dcs_val
                        raw_variables["dc"] = dc_val
                        raw_variables["dcs"] = dcs_val

                # Register artifacts (render the path best-effort; leave unfilled variables).
                if step.artifact:
                    art_path, _ = render_command(step.artifact.path, variables)
                    artifact_entry = {
                        "path": (
                            _redact_password(art_path, password)
                            if password
                            else art_path
                        ),
                        "label": step.artifact.label or step.id,
                        "step": step.id,
                    }
                    artifacts.append(artifact_entry)
                    append_event(thread_id, {"type": "artifact", **artifact_entry})

                # Verdict and observation for the attack step. If success_pattern exists, the
                # verdict is fixed deterministically by output markers (eliminates LLM variance so
                # successes never disappear); otherwise the LLM judges. The observation (interpretation)
                # is always generated by the LLM (a readable summary of what was confirmed). Since the
                # verdict is fixed, minor variance in the observation text does not change listed items.
                assessment = None
                if step.judge:
                    # observation_template + success_pattern together means fully deterministic (no
                    # LLM). Otherwise call the LLM judge (used for the verdict or the observation).
                    fully_deterministic = bool(
                        step.observation_template and step.success_pattern
                    )
                    if not fully_deterministic:
                        try:
                            assessment = await _judge_rto_step(
                                step, display_command, result
                            )
                            state["judge_results"][step.id] = assessment or ""
                        except Exception:
                            logger.exception(
                                "RTO judge failed (thread=%s step=%s)",
                                thread_id,
                                step.id,
                            )
                    # Verdict: success_pattern first (deterministic), else the LLM verdict.
                    if step.success_pattern:
                        try:
                            matched = (
                                re.search(step.success_pattern, output, re.MULTILINE)
                                is not None
                            )
                        except re.error:
                            matched = False
                        verdict = (
                            _RTO_VERDICT_SUCCESS if matched else _RTO_VERDICT_FAIL
                        )
                    else:
                        verdict = _extract_rto_verdict(assessment)
                    # Observation: fill the template if observation_template exists (deterministic),
                    # else take the LLM observation.
                    if step.observation_template:
                        items = (
                            _rto_template_items(step.success_pattern, output)
                            if step.success_pattern
                            else []
                        )
                        obs = _rto_fill_template(step.observation_template, items)
                        observation = (
                            _redact_password(obs, password) if password else obs
                        )
                    else:
                        observation = _rto_observation(assessment)
                    judged.append(
                        {
                            "step_id": step.id,
                            "category": group.name or group.id,
                            "label": step.label or step.description or step.id,
                            "verdict": verdict,
                            "observation": observation,
                            "remediation": step.remediation,
                        }
                    )

                record = {
                    **base,
                    "status": "done",
                    "exitCode": result.get("exitCode"),
                    "output": output,
                    "assessment": assessment,
                }
                append_event(thread_id, {"type": "chunk", **record})
                group_step_results.append(record)

            # No per-group LLM integration (attacks lead directly to DA, so no path synthesis).
            # Verdicts are already aggregated into judged per attack step.

        # Assemble the final report deterministically from the verdicts (successes only, by category).
        report_md = _assemble_rto_report(judged, bool(raw_variables.get("dcs")))
        thread.status = "completed"
        thread.interrupt = None
        thread.final_output = {"content": report_md, "artifacts": artifacts}

        # Persist run history to DB (saved on completion, like retest). The report has the
        # password masked. Saving before the final notification ensures the saved record is
        # listed when the client re-fetches history on completion detection. Save failure does
        # not affect the main completion.
        try:
            from agent.rto_history import save_record as _save_rto_record

            await _save_rto_record(
                thread_id=thread_id,
                domain=domain or target,
                markdown=report_md,
                final_output=thread.final_output,
            )
        except Exception:
            logger.exception("rto_history save failed for thread %s", thread_id)

        append_event(thread_id, {"type": "final", "data": thread.final_output})
    except Exception as e:
        thread.status = "failed"
        thread.error = _redact_password(str(e), password)
        logger.exception("start_rto failed for thread %s", thread_id)
        append_event(thread_id, {"type": "error", "message": "RTO run failed"})
    finally:
        _clear_thread_password(thread_id)


async def resume_thread(
    thread_id: str,
    decisions: list[dict[str, Any]],
) -> None:
    agent = await get_agent()
    thread = get_or_create_thread(thread_id)
    thread.status = "running"
    password = _get_thread_password(thread_id)
    resume_decisions = _prepare_resume_decisions(thread.interrupt, decisions, password)
    safe_decisions = _redact_value(decisions, password)

    append_event(thread_id, {"type": "resumed", "decisions": safe_decisions})

    config = {"configurable": {"thread_id": thread_id}}
    await _stream_agent(
        thread_id,
        thread,
        agent,
        Command(resume={"decisions": resume_decisions}),
        config,
    )
