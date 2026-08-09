from __future__ import annotations

import asyncio
import importlib
import json
import logging
import os
import re
import shlex
from contextlib import asynccontextmanager
from datetime import datetime
from typing import AsyncIterator

import psutil

# Send application loggers to stderr. uvicorn silences app loggers by default, so
# initialize here to surface logger.info/warning from `agent.agent` / `agent.dc_discovery`.
# Overridable via the LOG_LEVEL env var (default INFO).
_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
# force=True overrides the root logger even if uvicorn grabbed it first.
logging.basicConfig(
    level=_LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    force=True,
)
for _app in ("agent", "agent.agent", "agent.dc_discovery", "agent.main"):
    logging.getLogger(_app).setLevel(_LOG_LEVEL)
for _noisy in ("httpx", "httpcore", "openai", "urllib3"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)


class _HealthAccessLogFilter(logging.Filter):
    """Drop high-frequency health-poll paths from uvicorn's access log.

    The frontend polls `/api/v1/health/socks` every 5s for SOCKS liveness, which
    bloats the access log. Keep the polling interval but suppress only the health
    200 response lines. App-level logs are unaffected.
    """

    # /api/v1/entra/gather/jobs/ is polled every few seconds while gathering, so
    # its 200 access-log lines are suppressed (job lifecycle stays in app logs).
    _QUIET_PATHS = (
        "/api/v1/health/socks",
        "/health",
        "/api/v1/entra/gather/jobs/",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        # Suppress only successful (200) responses; keep 404/5xx for audit/investigation
        # (uvicorn access lines look like `"GET /path HTTP/1.1" 200`).
        message = record.getMessage()
        if '" 200 ' not in message:
            return True
        return not any(path in message for path in self._QUIET_PATHS)


# uvicorn.access has its own handler with propagate=False, so attach the filter to the logger.
logging.getLogger("uvicorn.access").addFilter(_HealthAccessLogFilter())

logger = logging.getLogger(__name__)

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse

from agent.agent import (
    _store_thread_input_secrets,
    _store_thread_password,
    clear_entra_session,
    collect_entra_now,
    delete_entra_db,
    entra_auth_now,
    entra_gather_now,
    execute_approved_command,
    get_command_help,
    get_entra_gather_job,
    list_entra_dbs,
    init_agent,
    start_entra_gather_job,
    new_thread_id,
    resume_thread,
    start_command_approval,
    start_rto,
    start_verification,
)
from agent import audit, auth, login_throttle, totp, users
from agent.findings import (
    get_finding,
    get_report_metadata,
    load_findings,
    reload_findings,
)
from agent.schemas import (
    ChangePasswordRequest,
    EntraAuthRequest,
    EntraCollectRequest,
    EntraGatherRequest,
    ExecuteCommandRequest,
    FindingItem,
    LoginRequest,
    MfaDisableRequest,
    MfaLoginRequest,
    MfaVerifyRequest,
    RTOExecutionContext,
    ResumeRequest,
    RetestRequest,
    RtoExportRequest,
    ThreadCreateRequest,
    ThreadResponse,
    VerificationExecutionContext,
)
from agent.store import THREADS, append_event, get_or_create_thread

# SSE heartbeat interval (seconds), passed to `EventSourceResponse(..., ping=N)`.
# Guards against idle timeouts on any intermediate proxy (default 15s).
# A value <= 0 defers to sse-starlette's default.
_SSE_PING_INTERVAL = int(os.getenv("SSE_PING_INTERVAL_SECONDS", "15"))


def _spawn_task(thread_id: str, coro, label: str) -> asyncio.Task:
    """Wrap create_task; on exception move the thread to failed and emit an error event."""
    task = asyncio.create_task(coro)

    def _on_done(t: asyncio.Task) -> None:
        if t.cancelled():
            return
        exc = t.exception()
        if exc is None:
            return
        logger.exception(
            "Background task %s for thread %s failed",
            label,
            thread_id,
            exc_info=exc,
        )
        thread = THREADS.get(thread_id)
        if thread is None:
            return
        thread.status = "failed"
        # thread.error keeps internal detail for logs/monitoring only.
        thread.error = f"{label}: {exc}"
        # The message streamed over SSE is generic; never leak stack traces or internal paths.
        append_event(
            thread_id,
            {
                "type": "error",
                "message": f"Background task '{label}' failed",
                "label": label,
            },
        )

    task.add_done_callback(_on_done)
    return task


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite (retest_records) at startup.
    # DC cache and thread state stay in process memory (never written to the DB).
    from agent.db import dispose_db, init_db

    try:
        await init_db()
    except Exception:
        logger.exception("Failed to initialize retest history DB")
    await init_agent()
    # Periodic audit-log pruning (in-app task; deletes entries past the retention window).
    prune_task = asyncio.create_task(audit.run_periodic_prune())
    try:
        yield
    finally:
        prune_task.cancel()
        try:
            await prune_task
        except (asyncio.CancelledError, Exception):
            pass
        try:
            await dispose_db()
        except Exception:
            logger.exception("Failed to dispose retest history DB")


# When ENABLE_DOCS=false, disable Swagger UI / ReDoc / OpenAPI schema entirely,
# so production deployments don't expose the API schema, curl examples, or finding structure.
_ENABLE_DOCS = os.getenv("ENABLE_DOCS", "true").lower() != "false"

# Gate for the command-approval (HITL) feature. Default ON for this workspace.
# It enables the "review generated command -> approve/edit/reject -> execute" flow. Edit is
# no longer a command-injection surface: commands run with shell=False, and an edit may change
# only the ARGUMENTS while the tool/binary stays locked (a changed binary is rejected 403).
# When OFF, the server still enforces:
#   - POST /api/v1/commands/execute is rejected with 403
#   - require_approval is forced False at thread creation (retests auto-run without review)
# Truthiness matches the frontend parseFlag (true/1/on); keep it in sync with the frontend's
# VITE_ENABLE_COMMAND_APPROVAL. Default (unset) is ON.
_ENABLE_COMMAND_APPROVAL = (
    os.getenv("ENABLE_COMMAND_APPROVAL", "true").strip().lower()
    in ("true", "1", "on")
)
_docs_url = "/docs" if _ENABLE_DOCS else None
_redoc_url = "/redoc" if _ENABLE_DOCS else None
_openapi_url = "/openapi.json" if _ENABLE_DOCS else None

app = FastAPI(
    title="RedAgent",
    version="0.2.0",
    lifespan=lifespan,
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url=_openapi_url,
    description="""
API for generating verification commands, HITL approval, and command execution for security-assessment findings.

## Overview

Verification tasks are managed under a shared `/threads` resource.
Each thread is one task unit, with SSE streaming and HITL interrupt/resume as the common foundation.

## Basic flow

### Verification (checking a finding's remediation status)

1. POST `kind=verification` and the finding to `/threads`
2. Receive a `thread_id`
3. Subscribe to SSE via `GET /threads/{thread_id}/stream`
4. On an `interrupt` event, approve via `POST /threads/{thread_id}/resume`
5. Complete on the `final` event

## Assumptions

- Verification is one thread = one finding
- Command execution requires HITL approval (interrupt -> approve/edit/reject -> resume)
- The number of `actions` in an `interrupt` must match the number of `decisions`

## SSE event list

Events received via `GET /threads/{thread_id}/stream`:

| event | description |
|---|---|
| `status` | processing started / progress |
| `chunk` | agent intermediate output |
| `interrupt` | awaiting HITL approval; the `actions` array holds command info |
| `resumed` | resume was accepted |
| `final` | processing complete |
| `error` | processing failed |

### interrupt event example

```json
{
  "type": "interrupt",
  "seq": 3,
  "interrupt": {
    "id": "da3d49459f639c6baf0f327706852902",
    "actions": [
      {
        "index": 0,
        "name": "execute_kali_command",
        "args": { "command": "grep -E \\"pam_pwquality\\" /etc/pam.d/common-password" },
        "description": "Tool execution requires approval",
        "allowed_decisions": ["approve", "edit", "reject"]
      }
    ]
  }
}
```

## curl examples

### Create a verification thread

```bash
curl -X POST http://localhost:8000/threads \\
  -H "Content-Type: application/json" \\
  -d '{
    "kind": "verification",
    "context": {
      "primary_finding_id": "No.1",
      "findings": [{
        "no": "No.1",
        "title": "SSH root login enabled",
        "risk_level": "High",
        "summary": "SSH allows root login",
        "description": "PermitRootLogin is set to yes",
        "recommendation": "Set PermitRootLogin to no",
        "references": []
      }]
    }
  }'
```

### Subscribe to SSE

```bash
curl -N http://localhost:8000/threads/<thread_id>/stream
```

### Resume (approve all)

```bash
curl -X POST http://localhost:8000/threads/<thread_id>/resume \\
  -H "Content-Type: application/json" \\
  -d '{ "decisions": [{ "type": "approve" }] }'
```

### Resume (edit command)

```bash
curl -X POST http://localhost:8000/threads/<thread_id>/resume \\
  -H "Content-Type: application/json" \\
  -d '{
    "decisions": [{
      "type": "edit",
      "edited_args": { "command": "cat /etc/ssh/sshd_config" }
    }]
  }'
```

## TypeScript usage example

```typescript
// 1. Start a verification thread
const res = await fetch("http://localhost:8000/threads", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    kind: "verification",
    context: {
      primary_finding_id: "No.1",
      findings: [{ no: "No.1", title: "...", risk_level: "High", summary: "...", description: "...", recommendation: "...", references: [] }]
    }
  })
});
const { thread_id } = await res.json();

// 2. Subscribe to SSE
const es = new EventSource(`http://localhost:8000/threads/${thread_id}/stream`);

es.addEventListener("interrupt", (event) => {
  const data = JSON.parse(event.data);
  console.log("Pending approval:", data.interrupt.actions);
});

es.addEventListener("final", (event) => {
  console.log("Done:", JSON.parse(event.data));
  es.close();
});

// 3. Resume
await fetch(`http://localhost:8000/threads/${thread_id}/resume`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ decisions: [{ type: "approve" }] })
});
```
""",
    openapi_tags=[
        {"name": "Health", "description": "Health check"},
        {
            "name": "Findings",
            "description": "Retrieve and manage findings loaded from the server-side JSON file",
        },
        {"name": "Commands", "description": "Direct command execution via Kali MCP"},
        {
            "name": "Retest",
            "description": "Re-run verification for findings; creates verification threads internally",
        },
        {
            "name": "Threads",
            "description": "Thread management for Verification: create, get status, HITL resume, SSE streaming",
        },
    ],
)

_cors_origins_env = os.getenv(
    "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
)
_cors_origins = [
    origin.strip() for origin in _cors_origins_env.split(",") if origin.strip()
]
_cors_origin_regex = (
    os.getenv(
        "CORS_ORIGIN_REGEX",
        r"^https?://(localhost|127\.0\.0\.1):\d+$",
    ).strip()
    or None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_origin_regex=_cors_origin_regex,
    # Allow credentials for session-cookie auth (so cookies are sent during cross-origin dev).
    # Safe because origins are limited by explicit list + regex, not a wildcard.
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)


# Optional local extension routers: comma-separated importable module paths, each exposing a
# `router` (APIRouter). Empty by default, so a plain checkout loads nothing. Extensions are
# site-local and not part of this repository. They are registered before the auth middleware
# below, which -- because middleware runs outermost-first -- still guards their routes.
for _router_module in filter(None, (m.strip() for m in os.getenv("EXTRA_ROUTERS", "").split(","))):
    try:
        app.include_router(importlib.import_module(_router_module).router)
        logger.info("Loaded extension router: %s", _router_module)
    except Exception:
        logger.exception("Failed to load extension router %s", _router_module)


# --- Authentication (session cookie) ---
# Auth logic is centralized in agent/auth.py. Static API_KEY auth was replaced by session-cookie auth.
# Paths allowed through without auth (health/docs/root/login/auth-status).
# SSE (/threads/{id}/stream) relies on EventSource auto-sending the cookie same-origin,
# so the old ?api_key= query was removed.
_UNAUTHENTICATED_PATHS: set[str] = {
    "/",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/docs/oauth2-redirect",
    "/api/v1/login",
    "/api/v1/login/mfa",
    "/api/v1/auth/status",
}

if not auth.auth_enabled():
    logger.warning(
        "Authentication is disabled (SESSION_SIGNING_SECRET not set). "
        "All endpoints are accessible without login. Set it (and create users via "
        "tools/auth/manage_users.py) for production deployments."
    )
if auth.app_env() == "dev":
    logger.warning(
        "APP_ENV=dev: development defaults active "
        "(session cookie Secure defaults to OFF unless SESSION_COOKIE_SECURE is set). "
        "Do not use in production."
    )


def _client_ip(request: Request) -> str | None:
    """Client IP for auditing; prefers the first XFF entry to account for reverse proxies."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


def _current_username(request: Request) -> str:
    """Return the current username from the session cookie; "anonymous" if unauthenticated/auth disabled."""
    if not auth.auth_enabled():
        return "anonymous"
    token = request.cookies.get(auth.session_cookie_name())
    return auth.read_session_username(token) or "anonymous"


@app.middleware("http")
async def session_auth(request: Request, call_next):
    # When auth is disabled (signing key unset), pass through. Configure it and create users for production.
    if not auth.auth_enabled():
        return await call_next(request)

    path = request.url.path
    if path in _UNAUTHENTICATED_PATHS or request.method == "OPTIONS":
        return await call_next(request)

    token = request.cookies.get(auth.session_cookie_name())
    username = auth.read_session_username(token)
    # Even with a valid signature/expiry, re-check the user exists and is active in the DB (so disabling takes effect immediately).
    if not username or not await users.is_active(username):
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"},
        )
    return await call_next(request)


@app.get("/health", tags=["Health"], summary="Health check")
async def health():
    return {"ok": True}


# --- Auth (multi-user login sessions) ---


def _set_session_cookie(resp: JSONResponse, token: str) -> None:
    resp.set_cookie(
        key=auth.session_cookie_name(),
        value=token,
        max_age=auth.session_ttl_seconds(),
        httponly=True,
        secure=auth.session_cookie_secure(),
        samesite="strict",
        path="/",
    )


@app.post("/api/v1/login", tags=["Auth"], summary="Log in")
async def login(req: LoginRequest, request: Request):
    """Verify username/password and, on success, issue an httpOnly session cookie."""
    if not auth.auth_enabled():
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    ip = _client_ip(request)
    uname = (req.username or "").strip() or "anonymous"

    # Temporary throttling: if there are too many recent failures, reject without verifying credentials.
    # The lock auto-releases over time (no permanent lock, no manual unlock). Attempts made while locked
    # are not counted as login_failed (so they don't extend the window), so even under a continuing attack
    # the lock always releases window seconds after the last valid failure.
    lock = await login_throttle.check(uname)
    if lock.locked:
        await audit.record(uname, "login_locked", source_ip=ip)
        resp = JSONResponse(
            status_code=429,
            content={"detail": "Too many failed attempts. Please try again later."},
        )
        resp.headers["Retry-After"] = str(lock.retry_after)
        return resp

    user = await users.verify_user(req.username, req.password)
    if user is None:
        # Uniform message so as not to leak info to attackers. Failures are audited too.
        await audit.record(uname, "login_failed", source_ip=ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # MFA (opt-in): enrolled users can't get in on password alone; require the TOTP second step.
    if user.mfa_enabled:
        if not totp.mfa_configured():
            # Without a valid server-side key (MFA_SECRET_KEY), stored secrets can't be decrypted,
            # so verification is impossible. Reject fail-closed (recover by clearing via CLI mfa-reset).
            await audit.record(user.username, "login_mfa_unconfigured", source_ip=ip)
            raise HTTPException(
                status_code=503,
                detail="MFA is enabled for this account but not configured on the server.",
            )
        await audit.record(user.username, "login_mfa_challenge", source_ip=ip)
        return JSONResponse(
            content={
                "ok": False,
                "mfa_required": True,
                "mfa_token": auth.create_mfa_challenge_token(user.username),
            }
        )

    resp = JSONResponse(content={"ok": True})
    _set_session_cookie(resp, auth.create_session_token(user.username))
    await audit.record(user.username, "login", source_ip=ip)
    return resp


@app.post("/api/v1/login/mfa", tags=["Auth"], summary="Log in (MFA second step)")
async def login_mfa(req: MfaLoginRequest, request: Request):
    """Verify the short-lived token from step one and the TOTP code, then issue a session cookie."""
    if not auth.auth_enabled():
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    ip = _client_ip(request)
    username = auth.read_mfa_challenge(req.mfa_token)
    if not username:
        # Token expired/tampered/wrong purpose. Make the user restart from step one.
        raise HTTPException(status_code=401, detail="MFA challenge expired or invalid")

    # The second step can also be brute-forced, so apply the same throttling.
    lock = await login_throttle.check(username)
    if lock.locked:
        await audit.record(username, "login_locked", source_ip=ip)
        resp = JSONResponse(
            status_code=429,
            content={"detail": "Too many failed attempts. Please try again later."},
        )
        resp.headers["Retry-After"] = str(lock.retry_after)
        return resp

    if not await users.is_active(username):
        raise HTTPException(status_code=401, detail="Authentication required")
    enabled, secret_enc = await users.get_mfa(username)
    secret = totp.decrypt_secret(secret_enc) if enabled else None
    if not secret or not totp.verify_code(req.code, secret):
        # Record second-step failures as login_failed too, so they feed the existing throttling
        # (which aggregates login_failed) and deter brute force.
        await audit.record(username, "login_failed", source_ip=ip)
        raise HTTPException(status_code=401, detail="Invalid code")

    resp = JSONResponse(content={"ok": True})
    _set_session_cookie(resp, auth.create_session_token(username))
    await audit.record(username, "login", source_ip=ip)
    return resp


@app.post("/api/v1/logout", tags=["Auth"], summary="Log out")
async def logout(request: Request):
    """Discard the session cookie."""
    username = _current_username(request)
    resp = JSONResponse(content={"ok": True})
    resp.delete_cookie(key=auth.session_cookie_name(), path="/")
    await audit.record(username, "logout", source_ip=_client_ip(request))
    return resp


@app.post("/api/v1/change-password", tags=["Auth"], summary="Change login password")
async def change_password(req: ChangePasswordRequest, request: Request):
    """Change the logged-in user's own password (applied to the DB immediately).

    Auth-required endpoint (session already verified by middleware). After matching the current
    password, update to the new one and reissue the session cookie to keep the current login.
    """
    if not auth.auth_enabled():
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    username = _current_username(request)
    if username == "anonymous":
        raise HTTPException(status_code=401, detail="Authentication required")
    if await users.verify_user(username, req.current_password) is None:
        raise HTTPException(status_code=401, detail="Invalid current password")
    if req.new_password == req.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from current")
    await users.set_user_password(username, req.new_password)
    await audit.record(username, "change_password", source_ip=_client_ip(request))
    # Reissue the cookie so the current session survives the password change.
    resp = JSONResponse(content={"ok": True})
    _set_session_cookie(resp, auth.create_session_token(username))
    return resp


# --- MFA (TOTP, optional enrollment). All auth-required (protected by session_auth middleware). ---


def _require_authed_user(request: Request) -> str:
    """Return the authenticated username; 401 if unauthenticated/auth disabled."""
    if not auth.auth_enabled():
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    username = _current_username(request)
    if username == "anonymous":
        raise HTTPException(status_code=401, detail="Authentication required")
    return username


@app.get("/api/v1/mfa/status", tags=["Auth"], summary="MFA status")
async def mfa_status(request: Request):
    """Return the current user's MFA enrollment status and whether MFA is configured on the server."""
    username = _require_authed_user(request)
    enabled, _ = await users.get_mfa(username)
    return {"enabled": enabled, "configured": totp.mfa_configured()}


@app.post("/api/v1/mfa/enroll/start", tags=["Auth"], summary="Start MFA enrollment")
async def mfa_enroll_start(request: Request):
    """Generate a new TOTP secret, encrypt and store it (unverified), and return the base32 and otpauth URI.

    The plaintext secret is returned only in this response. Finalize via /mfa/enroll/verify after registering in an authenticator app."""
    username = _require_authed_user(request)
    if not totp.mfa_configured():
        raise HTTPException(
            status_code=503, detail="MFA is not configured on the server (MFA_SECRET_KEY not set)"
        )
    secret = totp.generate_secret()
    enc = totp.encrypt_secret(secret)
    if enc is None:
        raise HTTPException(status_code=503, detail="Failed to protect MFA secret")
    await users.set_pending_mfa_secret(username, enc)
    await audit.record(username, "mfa_enroll_start", source_ip=_client_ip(request))
    return {"secret": secret, "otpauth_uri": totp.otpauth_uri(secret, username)}


@app.post("/api/v1/mfa/enroll/verify", tags=["Auth"], summary="Complete MFA enrollment")
async def mfa_enroll_verify(req: MfaVerifyRequest, request: Request):
    """Verify the code against the secret issued at enrollment start; on success, enable MFA."""
    username = _require_authed_user(request)
    _, secret_enc = await users.get_mfa(username)
    secret = totp.decrypt_secret(secret_enc)
    if not secret:
        raise HTTPException(status_code=400, detail="No pending MFA enrollment. Start enrollment first.")
    if not totp.verify_code(req.code, secret):
        await audit.record(username, "mfa_enroll_failed", source_ip=_client_ip(request))
        raise HTTPException(status_code=401, detail="Invalid code")
    await users.activate_mfa(username)
    await audit.record(username, "mfa_enabled", source_ip=_client_ip(request))
    return {"ok": True, "enabled": True}


@app.post("/api/v1/mfa/disable", tags=["Auth"], summary="Disable MFA")
async def mfa_disable(req: MfaDisableRequest, request: Request):
    """Disable MFA after confirming identity with the current TOTP code (the secret is also discarded)."""
    username = _require_authed_user(request)
    enabled, secret_enc = await users.get_mfa(username)
    if not enabled:
        return {"ok": True, "enabled": False}
    secret = totp.decrypt_secret(secret_enc)
    if not secret or not totp.verify_code(req.code, secret):
        await audit.record(username, "mfa_disable_failed", source_ip=_client_ip(request))
        raise HTTPException(status_code=401, detail="Invalid code")
    await users.disable_mfa(username)
    await audit.record(username, "mfa_disabled", source_ip=_client_ip(request))
    return {"ok": True, "enabled": False}


@app.get("/api/v1/auth/status", tags=["Auth"], summary="Authentication status")
async def auth_status(request: Request):
    """Unauthenticated-accessible endpoint so the frontend can determine login need/state and the username.

    Also surfaces command_approval_enabled (the server-side ENABLE_COMMAND_APPROVAL gate) so the UI
    can show the per-run review toggle at runtime -- independent of the build-time VITE flag, which
    otherwise goes stale and can hide the toggle while the server still forces approval."""
    if not auth.auth_enabled():
        return {
            "authenticated": True,
            "auth_required": False,
            "username": None,
            "command_approval_enabled": _ENABLE_COMMAND_APPROVAL,
        }
    token = request.cookies.get(auth.session_cookie_name())
    username = auth.read_session_username(token)
    authed = bool(username) and await users.is_active(username)
    return {
        "authenticated": authed,
        "auth_required": True,
        "username": username if authed else None,
        "command_approval_enabled": _ENABLE_COMMAND_APPROVAL,
    }


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root():
    findings = load_findings()
    threads_count = len(THREADS)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Red Agent API</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           background: #0a0a0a; color: #e5e5e5; min-height: 100vh;
           display: flex; align-items: center; justify-content: center; }}
    .container {{ max-width: 640px; width: 100%; padding: 40px 24px; }}
    h1 {{ font-size: 28px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }}
    .sub {{ color: #888; font-size: 14px; margin-top: 4px; }}
    .stats {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 32px; }}
    .stat {{ background: #141414; border: 1px solid #262626; border-radius: 10px; padding: 16px; }}
    .stat-value {{ font-size: 32px; font-weight: 700; color: #fff; }}
    .stat-label {{ font-size: 12px; color: #666; margin-top: 2px; }}
    .links {{ margin-top: 32px; display: flex; flex-direction: column; gap: 8px; }}
    a {{ display: flex; align-items: center; justify-content: space-between;
         padding: 14px 16px; background: #141414; border: 1px solid #262626;
         border-radius: 10px; color: #e5e5e5; text-decoration: none;
         font-size: 14px; transition: border-color 0.15s; }}
    a:hover {{ border-color: #444; }}
    .arrow {{ color: #555; }}
    .badge {{ font-size: 11px; color: #888; background: #1a1a1a;
              padding: 2px 8px; border-radius: 4px; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Red Agent</h1>
    <p class="sub">Verification API</p>

    <div class="stats">
      <div class="stat">
        <div class="stat-value">{len(findings)}</div>
        <div class="stat-label">Findings loaded</div>
      </div>
      <div class="stat">
        <div class="stat-value">{threads_count}</div>
        <div class="stat-label">Active threads</div>
      </div>
    </div>

    <div class="links">
      <a href="/docs">
        <span>Swagger UI</span>
        <span class="badge">OpenAPI</span>
      </a>
      <a href="/redoc">
        <span>ReDoc</span>
        <span class="badge">OpenAPI</span>
      </a>
      <a href="/api/v1/findings">
        <span>GET /api/v1/findings</span>
        <span class="arrow">&rarr;</span>
      </a>
      <a href="/health">
        <span>GET /health</span>
        <span class="arrow">&rarr;</span>
      </a>
    </div>
  </div>
</body>
</html>"""


# --- /findings API ---


@app.get(
    "/api/v1/findings",
    tags=["Findings"],
    summary="Get the list of findings",
    description="Return the findings loaded from the server-side JSON file (set via the `FINDINGS_FILE` env var) along with report metadata.",
)
async def list_findings():
    findings = load_findings()
    metadata = get_report_metadata()
    return {"findings": findings, "metadata": metadata}


@app.get(
    "/api/v1/findings/{finding_id}",
    tags=["Findings"],
    summary="Get a single finding",
    description="Return the finding matching the given finding_id (the `no` field). When only `section` is present, it is normalized to the `No.1` form.",
)
async def get_finding_endpoint(finding_id: str):
    finding = get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@app.post(
    "/api/v1/findings/reload",
    tags=["Findings"],
    summary="Reload findings",
    description="Discard the cache and reload from the JSON file. Call after replacing the file.",
)
async def reload_findings_endpoint():
    findings = reload_findings()
    return {"ok": True, "count": len(findings)}


# --- /commands API ---


@app.post(
    "/api/v1/commands/execute",
    tags=["Commands"],
    summary="Start command execution with HITL approval",
    description="""Present a command as an interrupt and wait for HITL approval.

1. Receive a thread_id
2. Subscribe to SSE via `GET /threads/{thread_id}/stream`
3. Review the command in the `interrupt` event
4. approve/edit/reject via `POST /threads/{thread_id}/resume`
5. After approval, execute via Kali MCP and receive the result over SSE""",
)
async def execute_command_endpoint(req: ExecuteCommandRequest, request: Request):
    # The command-approval (HITL) feature is disabled by default. To close the injection surface
    # of arbitrary command execution, only accept it when ENABLE_COMMAND_APPROVAL=true.
    if not _ENABLE_COMMAND_APPROVAL:
        raise HTTPException(
            status_code=403, detail="command approval feature is disabled"
        )
    thread_id = new_thread_id()
    # Don't keep the sensitive command body in the audit log; record only the target finding and label.
    await audit.record(
        _current_username(request),
        "command_execute",
        detail=f"finding={req.findingId} label={req.label}",
        source_ip=_client_ip(request),
    )
    await start_command_approval(
        thread_id=thread_id,
        command=req.command,
        label=req.label,
        finding_id=req.findingId,
    )

    thread = THREADS.get(thread_id)
    return {
        "ok": True,
        "thread_id": thread_id,
        "status": "waiting_human",
        "interrupt": thread.interrupt if thread else None,
    }


@app.get(
    "/api/v1/commands/help",
    tags=["Commands"],
    summary="Get a tool's --help text (advisory)",
    description="""Return `<bin> --help` for a binary, to help a reviewer spot invalid or
nonexistent options while editing a command's arguments in the HITL dialog. Read-only: it runs
no target-affecting action. Auth-required (session middleware).""",
)
async def command_help_endpoint(bin: str):
    name = (bin or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="bin is required")
    text = await get_command_help(name)
    return {"ok": True, "bin": name, "help": text}


# --- /retest API ---


@app.post(
    "/api/v1/retest",
    tags=["Retest"],
    summary="Start a retest",
    description="""Receive findingIds and create a verification thread for each finding.
Returns a compatibility response in RetestExecution format.""",
)
async def start_retest_endpoint(req: RetestRequest, request: Request):
    finding_ids = req.findingIds
    await audit.record(
        _current_username(request),
        "retest",
        detail=f"findings={','.join(finding_ids)}",
        source_ip=_client_ip(request),
    )

    commands = []
    for fid in finding_ids:
        finding_data = get_finding(fid)
        if not finding_data:
            continue

        thread_id = new_thread_id()
        thread = get_or_create_thread(thread_id, kind="command_approval")
        thread.title = f"Verify {fid}"
        thread.context.primary_finding_id = fid
        thread.context.findings = [finding_data]

        raw = dict(finding_data)
        if "no" not in raw and "section" in raw:
            raw["no"] = f"No.{str(raw['section'])}"
        elif "no" not in raw:
            raw["no"] = fid

        finding = FindingItem(**raw)
        _spawn_task(
            thread_id,
            start_verification(thread_id=thread_id, finding=finding),
            "start_verification",
        )

        commands.append(
            {
                "id": thread_id,
                "findingId": fid,
                "command": f"verification thread for {fid}",
                "label": finding_data.get("title", fid),
                "status": "running",
            }
        )

    exec_id = f"exec-{new_thread_id()}"
    return {
        "id": exec_id,
        "findingIds": finding_ids,
        "status": "running",
        "startedAt": datetime.now().isoformat(),
        "commands": commands,
    }


# --- /threads API ---


@app.post(
    "/threads",
    tags=["Threads"],
    summary="Create a thread",
    description="""Create a new thread.

- `kind=verification`: receive one finding and auto-start the flow of verification-command generation -> HITL approval -> execution (when `auto_start=true`). Include the finding's raw data in `context.findings`.

For verification, the finding is taken from `context.findings[0]` to start processing. When only the `section` field is present, `no` is auto-filled.""",
)
async def create_thread(req: ThreadCreateRequest):
    thread_id = new_thread_id()
    thread = get_or_create_thread(thread_id, kind=req.kind)
    thread.title = req.title
    thread.context.primary_finding_id = req.context.primary_finding_id
    thread.context.findings = req.context.findings
    # Store the frontend checkbox value on the thread (default False = auto-approve).
    # But if command approval is disabled (default), force False server-side even if a direct
    # API call sends True (prevents starting an illegitimate approval flow that bypasses the UI).
    thread.require_approval = req.require_approval and _ENABLE_COMMAND_APPROVAL

    if req.kind == "verification" and req.auto_start:
        if not req.context.findings:
            raise HTTPException(
                status_code=400,
                detail="verification requires at least one finding in context",
            )

        raw = dict(req.context.findings[0])
        if "no" not in raw and "section" in raw:
            raw["no"] = f"No.{str(raw['section'])}"
        elif "no" not in raw:
            raw["no"] = "No.1"

        # Don't trust the client for fields that decide the verification path; treat the
        # server-side findings.json as the source of truth. The frontend Finding type carries
        # only display fields, so a payload-sourced value would leave these empty. If the
        # finding can be looked up on disk by `no`, overwrite them with the disk values.
        disk_finding = get_finding(raw["no"])
        if disk_finding:
            for _key in (
                "verification_inputs",
                "judgment_criteria",
                "platform",
            ):
                if _key in disk_finding:
                    raw[_key] = disk_finding[_key]

        finding = FindingItem(**raw)

        user_instruction = (req.input or {}).get("user_instruction")

        # Validate the data variables the user entered before execution (target server, etc.)
        # against finding.verification_inputs declarations. Accept only declared keys and reject
        # with 400 if required/pattern isn't satisfied (prevents command injection / mis-execution).
        # Only validated values are passed to execution.
        raw_runtime = (req.input or {}).get("runtime_variables") or {}
        if not isinstance(raw_runtime, dict):
            raw_runtime = {}
        runtime_variables: dict[str, str] = {}
        # secret=true inputs (passwords, etc.) are separated from runtime_variables and stored in
        # the server's secret store (subject to escaping + masking; keeps plaintext out of prompts/display/history).
        runtime_secrets: dict[str, str] = {}
        for _spec in finding.verification_inputs:
            _raw_val = raw_runtime.get(_spec.key)
            # Values arrive as an array (multi-line UI) or a string. For multiple, also split
            # whitespace/comma-separated strings. Normalize each value (token) individually.
            if isinstance(_raw_val, (list, tuple)):
                _tokens = [str(x).strip() for x in _raw_val]
            elif _spec.multiple:
                _text = ("" if _raw_val is None else str(_raw_val)).strip()
                _tokens = re.split(r"[\s,]+", _text) if _text else []
            else:
                _tokens = [("" if _raw_val is None else str(_raw_val)).strip()]
            _tokens = [t for t in _tokens if t]
            if not _tokens:
                # If blank, use the declared default. The default value also passes the
                # pattern validation below. Reject with 400 only when there's no default and it's required.
                if _spec.default:
                    _tokens = [_spec.default]
                elif _spec.required:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Required input '{_spec.key}' ({_spec.label}) is not specified",
                    )
                else:
                    continue
            # Validate each token against the pattern individually (400 if any is invalid). This
            # guarantees no whitespace/metacharacters in any value, even for multiple (injection defense).
            for _tok in _tokens:
                try:
                    _ok = re.fullmatch(_spec.pattern, _tok) is not None
                except re.error:
                    # If the declared pattern itself is an invalid regex, reject fail-safe (don't execute).
                    raise HTTPException(
                        status_code=400,
                        detail=f"Validation config (pattern) for input '{_spec.key}' is invalid",
                    )
                if not _ok:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"Input '{_spec.key}' ({_spec.label}) has an invalid format: '{_tok}'"
                        ),
                    )
            # Join validated tokens with a single space into one variable (same as {{dcs}}).
            # Route secret inputs to the secret store, everything else to normal runtime variables.
            if getattr(_spec, "secret", False):
                runtime_secrets[_spec.key] = " ".join(_tokens)
            else:
                runtime_variables[_spec.key] = " ".join(_tokens)

        execution_context = None
        raw_execution_context = (req.input or {}).get("execution_context")
        if raw_execution_context:
            try:
                validated_ctx = VerificationExecutionContext(**raw_execution_context)
            except Exception:
                # Pydantic errors can include input values (incl. the password), so keep the
                # detail in the server log only and return a generic string in the response.
                logger.exception(
                    "Invalid execution_context received for thread %s", thread_id
                )
                raise HTTPException(status_code=400, detail="Invalid execution_context")

            # Keep the plaintext password in _THREAD_SECRETS as a defensive fallback, and also
            # retain it inside the execution_context dict (to embed the real value in the LLM prompt).
            _store_thread_password(thread_id, validated_ctx.pass_)
            execution_context = validated_ctx.model_dump(by_alias=True)

        # Store secret=true inputs (passwords, etc.) in the server's secret store. Don't put them
        # in runtime_variables (keeps plaintext out of prompts/display/history). Their values are
        # redacted to <PASS> in command output/history and placeholder-ized when capturing
        # commands for RTO export; they are never persisted in cleartext.
        if runtime_secrets:
            _store_thread_input_secrets(thread_id, runtime_secrets)

        _spawn_task(
            thread_id,
            start_verification(
                thread_id=thread_id,
                finding=finding,
                user_instruction=user_instruction,
                execution_context=execution_context,
                runtime_variables=runtime_variables,
            ),
            "start_verification",
        )

    if req.kind == "rto" and req.auto_start:
        raw_input = req.input or {}
        user_instruction = raw_input.get("user_instruction")

        # RTO requires credentials. Validate with RTOExecutionContext (domain/user/pass/dns all
        # required), which is separate from the retest VerificationExecutionContext.
        raw_execution_context = raw_input.get("execution_context")
        if not raw_execution_context:
            raise HTTPException(
                status_code=400,
                detail="rto requires execution_context with domain/user/pass/dns",
            )
        try:
            rto_ctx = RTOExecutionContext(**raw_execution_context)
        except Exception:
            # May include the password, so keep detail in the server log only; return a generic string.
            logger.exception(
                "Invalid execution_context received for rto thread %s", thread_id
            )
            raise HTTPException(status_code=400, detail="Invalid execution_context")

        _store_thread_password(thread_id, rto_ctx.pass_)
        execution_context = rto_ctx.model_dump(by_alias=True)
        # The target-domain input doubles as the target.
        target = rto_ctx.domain

        _spawn_task(
            thread_id,
            start_rto(
                thread_id=thread_id,
                target=target,
                user_instruction=user_instruction,
                execution_context=execution_context,
            ),
            "start_rto",
        )

    return ThreadResponse(
        thread_id=thread_id,
        kind=req.kind,
        status=thread.status if not req.auto_start else "running",
        title=thread.title,
    )


@app.get(
    "/threads/{thread_id}",
    tags=["Threads"],
    response_model=ThreadResponse,
    summary="Get thread status",
    description="Get the current thread state (status, pending interrupt, final output, error).",
)
async def get_thread(thread_id: str):
    thread = THREADS.get(thread_id)
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")

    # thread.error holds internal detail (LLM URL, library-internal paths, etc.), so
    # generalize it in the response. The detail remains in the server log.
    public_error = "Thread failed" if thread.status == "failed" else None

    return ThreadResponse(
        thread_id=thread_id,
        kind=thread.kind,
        status=thread.status,
        title=thread.title,
        interrupt=thread.interrupt,
        final_output=thread.final_output,
        error=public_error,
    )


@app.post(
    "/threads/{thread_id}/resume",
    tags=["Threads"],
    summary="Respond to an interrupt and resume the thread",
)
async def resume_endpoint(thread_id: str, req: ResumeRequest):
    thread = THREADS.get(thread_id)
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")

    if thread.status != "waiting_human":
        raise HTTPException(
            status_code=400, detail="Thread is not waiting for human input"
        )

    interrupt = thread.interrupt
    if not interrupt:
        raise HTTPException(
            status_code=400, detail="No active interrupt on this thread"
        )

    current_interrupt_id = interrupt.get("id")
    if current_interrupt_id is None or req.interrupt_id != current_interrupt_id:
        raise HTTPException(
            status_code=409,
            detail="interrupt_id does not match the active interrupt",
        )

    actions = interrupt.get("actions", [])

    # Constrained HITL edit: an edit may change a command's ARGUMENTS but never its binary
    # (the tool the LLM/operator selected). This is what keeps "edit" from being an
    # arbitrary-command execution vector -- the resume path recombines {bin, args} with
    # shlex.join, so an edited arg can only ever become a literal argument to the locked
    # binary (never a second command). Enforced server-side so a direct API call cannot
    # bypass the UI. (Replaces the previous blanket edit-disable gate.)
    for idx, d in enumerate(req.decisions):
        if d.type != "edit":
            continue
        ea = d.edited_args or {}
        new_args = ea.get("args")
        if not isinstance(new_args, list) or not all(isinstance(x, str) for x in new_args):
            raise HTTPException(
                status_code=422,
                detail="edited args must be a list of strings",
            )
        action = actions[idx] if idx < len(actions) else {}
        orig_bin = action.get("bin")
        if orig_bin is not None and ea.get("bin") != orig_bin:
            raise HTTPException(
                status_code=403,
                detail="the tool cannot be changed by editing; only its arguments may be edited",
            )

    decisions_payload = []
    for d in req.decisions:
        item = {"type": d.type}
        if d.type == "edit" and d.edited_args is not None:
            item["args"] = d.edited_args
        if d.comment:
            item["comment"] = d.comment
        decisions_payload.append(item)

    # Execute directly only for a command_approval thread.
    if thread.kind == "command_approval" and interrupt and len(decisions_payload) == 1:
        decision = decisions_payload[0]
        if actions and actions[0].get("name") == "execute_kali_command":
            if decision["type"] == "reject":
                thread.status = "completed"
                thread.interrupt = None
                thread.final_output = {"message": "rejected"}
                append_event(thread_id, {"type": "final", "data": thread.final_output})
                return {"ok": True, "thread_id": thread_id, "status": "completed"}

            if decision["type"] == "edit":
                ea = decision.get("args", {})
                # Structured edit {bin, args:[...]} -> recombine (bin already validated
                # unchanged above); shlex.join keeps each edited arg a single literal token.
                orig_bin = actions[0].get("bin")
                new_bin = ea.get("bin") or orig_bin or ""
                command = shlex.join([str(new_bin)] + [str(x) for x in ea.get("args", [])])
            else:
                command = actions[0]["args"]["command"]
            _spawn_task(
                thread_id,
                execute_approved_command(thread_id, command),
                "execute_approved_command",
            )
            return {"ok": True, "thread_id": thread_id, "status": "running"}

    # "Auto-approve the rest of this run": apply the current decisions, then stop interrupting.
    # Flip the thread's require_approval off so every subsequent command in _stream_agent takes
    # the auto-approve branch. Verification only (RTO/command_approval never set this).
    if req.auto_approve_remaining and thread.kind == "verification":
        thread.require_approval = False

    # verification resume happens on the agent side.
    _spawn_task(
        thread_id,
        resume_thread(
            thread_id=thread_id,
            decisions=decisions_payload,
        ),
        "resume_thread",
    )

    return {"ok": True, "thread_id": thread_id, "status": "running"}


@app.get(
    "/threads/{thread_id}/stream",
    tags=["Threads"],
    summary="Subscribe to a thread's SSE events",
    description="""Receive thread events in real time via Server-Sent Events.

Each event carries a monotonically increasing `seq`. On reconnect, specify the last-seen seq with the `after` parameter to avoid duplicates.

Event types: `status`, `chunk`, `interrupt`, `resumed`, `final`, `error`

- verification thread: SSE ends on `completed` or `failed`""",
)
async def stream_thread(thread_id: str, after: int = 0):
    thread = THREADS.get(thread_id)
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")

    async def event_generator() -> AsyncIterator[dict]:
        # Stream events with seq greater than `after`. Assumes events are appended in seq order.
        sent = sum(1 for evt in thread.events if evt.get("seq", 0) <= after)

        while True:
            t = THREADS.get(thread_id)
            if not t:
                yield {
                    "event": "error",
                    "data": json.dumps({"message": "Thread not found"}),
                }
                return

            while sent < len(t.events):
                evt = t.events[sent]
                sent += 1
                yield {
                    "event": evt.get("type", "message"),
                    "id": str(evt.get("seq", sent)),
                    "data": json.dumps(evt, ensure_ascii=False, default=str),
                }

            if t.status in ("completed", "failed"):
                return

            await asyncio.sleep(0.3)

    # A positive ping value emits a `: ping - <ts>` comment every N seconds.
    # If <= 0, omit it and defer to sse-starlette's default behavior.
    if _SSE_PING_INTERVAL > 0:
        return EventSourceResponse(event_generator(), ping=_SSE_PING_INTERVAL)
    return EventSourceResponse(event_generator())


## DC Cache Debug API

from datetime import timezone

from agent.dc_discovery import get_all_cached_dcs as _dc_get_all
from agent.dc_discovery import get_dcs as _dc_get_dcs


def _dc_entry_to_dict(entry) -> dict:
    """Convert a DCEntry to a JSON-serializable dict, returning both Unix seconds and ISO 8601 (UTC).
    `source` is kept on the dataclass for internal logging but not returned in outward responses."""
    discovered_at = getattr(entry, "discovered_at", None)
    iso = (
        datetime.fromtimestamp(discovered_at, tz=timezone.utc).isoformat()
        if discovered_at is not None
        else None
    )
    return {
        "hostname": getattr(entry, "hostname", None),
        "ip": getattr(entry, "ip", None),
        "discovered_at": discovered_at,
        "discovered_at_iso": iso,
    }


@app.get(
    "/api/v1/dc-cache",
    tags=["Debug"],
    summary="Get the DC cache contents (debug)",
    description=(
        "Return the cache of DC info mechanically extracted from ad_dns_recon and LLM command output. "
        "Filterable via the `domain` query. Volatile in-process only, so it clears on restart."
    ),
)
async def get_dc_cache(domain: str | None = None):
    if domain:
        entries = _dc_get_dcs(domain)
        return {
            "domain": domain.lower().rstrip("."),
            "count": len(entries),
            "entries": [_dc_entry_to_dict(e) for e in entries],
        }

    all_cache = _dc_get_all()
    return {
        "count": sum(len(v) for v in all_cache.values()),
        "domains": {
            dom: [_dc_entry_to_dict(e) for e in entries]
            for dom, entries in all_cache.items()
        },
    }


## Retest History API (SQLite persistence)

from agent import retest_history as _retest_history
from agent import rto_history as _rto_history


@app.get(
    "/api/v1/retest-history",
    tags=["RetestHistory"],
    summary="Get retest history (filtered by finding_no)",
    description=(
        "Return retest history newest-first. The `finding_no` query is required. "
        "History is persisted in server-side SQLite and shared across browsers."
    ),
)
async def list_retest_history(finding_no: str):
    if not finding_no:
        raise HTTPException(status_code=400, detail="finding_no is required")
    items = await _retest_history.list_by_finding(finding_no)
    return {
        "findingNo": finding_no,
        "count": len(items),
        "items": [item.to_dict() for item in items],
    }


@app.get(
    "/api/v1/retest-history/summary",
    tags=["RetestHistory"],
    summary="Get a summary of each finding's latest status",
    description=(
        "Return, in one call, each finding's latest retest verdict (resolved/partial/unresolved/inconclusive) "
        "and execution timestamp. Used for the status badges in the findings list. "
        "Findings with no history are not included in items (the frontend treats them as not run)."
    ),
)
async def retest_history_summary():
    items = await _retest_history.latest_status_summary()
    return {
        "count": len(items),
        "items": [item.to_dict() for item in items],
    }


@app.get(
    "/api/v1/retest-history/{record_id}",
    tags=["RetestHistory"],
    summary="Get a single retest history record",
)
async def get_retest_history(record_id: str):
    item = await _retest_history.get_by_id(record_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Record not found")
    return item.to_dict()


@app.delete(
    "/api/v1/retest-history/{record_id}",
    tags=["RetestHistory"],
    summary="Delete a single retest history record",
)
async def delete_retest_history(record_id: str):
    ok = await _retest_history.delete_by_id(record_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"ok": True, "id": record_id}


@app.delete(
    "/api/v1/retest-history",
    tags=["RetestHistory"],
    summary="Delete all retest history for a finding",
)
async def delete_retest_history_by_finding(finding_no: str):
    if not finding_no:
        raise HTTPException(status_code=400, detail="finding_no is required")
    count = await _retest_history.delete_by_finding(finding_no)
    return {"ok": True, "findingNo": finding_no, "deleted": count}


@app.post(
    "/api/v1/rto-playbook/export",
    tags=["RTO"],
    summary="Export selected retest commands into the RTO playbook",
    description="""Append user-selected, placeholder-ized retest commands to the live RTO
playbook (rto.json), creating it if absent. Commands already present are skipped (dedup by
command string); commands are grouped by finding when findingNo is given.""",
)
async def export_rto_playbook(req: RtoExportRequest, request: Request):
    from agent.rto_playbook import append_commands_to_live

    finding_no = (req.findingNo or "").strip()
    slug = re.sub(r"[^a-z0-9]+", "-", finding_no.lower()).strip("-") if finding_no else ""
    group_id = f"retest-{slug}" if slug else "exported"
    group_name = (
        f"Exported from retest {finding_no}" if finding_no else "Exported from retests"
    )
    items = [c.model_dump() for c in req.commands]
    try:
        result = append_commands_to_live(items, group_id=group_id, group_name=group_name)
    except Exception:
        logger.exception("RTO export failed")
        raise HTTPException(status_code=500, detail="Failed to update the RTO playbook")

    await audit.record(
        _current_username(request),
        "rto_export",
        detail=f"finding={finding_no} added={result.get('added')} skipped={result.get('skipped')}",
        source_ip=_client_ip(request),
    )
    return {"ok": True, **result}


# ----------------------------
# RTO execution history: persisted in server-side SQLite (shared globally). Same approach as retest history.
# ----------------------------


@app.get(
    "/api/v1/rto-history",
    tags=["RTOHistory"],
    summary="List RTO execution history (newest-first)",
    description="Return RTO execution history newest-first. History is persisted in server-side SQLite and shared across browsers.",
)
async def list_rto_history():
    items = await _rto_history.list_all()
    return {"count": len(items), "items": [item.to_dict() for item in items]}


@app.get(
    "/api/v1/rto-history/{record_id}",
    tags=["RTOHistory"],
    summary="Get a single RTO execution history record",
)
async def get_rto_history(record_id: str):
    item = await _rto_history.get_by_id(record_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Record not found")
    return item.to_dict()


@app.delete(
    "/api/v1/rto-history/{record_id}",
    tags=["RTOHistory"],
    summary="Delete a single RTO execution history record",
)
async def delete_rto_history(record_id: str):
    ok = await _rto_history.delete_by_id(record_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"ok": True, "id": record_id}


@app.delete(
    "/api/v1/rto-history",
    tags=["RTOHistory"],
    summary="Bulk-delete RTO execution history (body: {ids:[...]} for selective delete / {all:true} for all)",
)
async def delete_rto_histories(body: dict):
    if body.get("all"):
        deleted = await _rto_history.delete_all()
    else:
        ids = body.get("ids") or []
        deleted = await _rto_history.delete_by_ids(
            ids if isinstance(ids, list) else []
        )
    return {"ok": True, "deleted": deleted}


## Entra Collected Data API


@app.post(
    "/api/v1/entra/collect",
    tags=["Entra"],
    summary="Manually trigger Entra data collection (roadrecon gather) (synchronous)",
    description=(
        "Submit a token (PRT Cookie, etc.) obtained by an operator on a compliant device and "
        "collect the target tenant with roadrecon. A path independent of retests. "
        "The token is not persisted; .roadtools_auth is discarded after collection."
    ),
)
async def collect_entra(req: EntraCollectRequest):
    if not req.tenant.strip():
        raise HTTPException(status_code=400, detail="tenant is required")
    result = await collect_entra_now(
        tenant=req.tenant, token=req.token, token_type=req.token_type
    )
    if not result.get("ok"):
        # Keep failure detail (expired token, etc.) in the server log; generalize the response.
        raise HTTPException(
            status_code=502,
            detail="Entra data collection failed (check for an expired token or the network path)",
        )
    return result


@app.post(
    "/api/v1/entra/auth",
    tags=["Entra"],
    summary="Entra auth only. Exchange a PRT Cookie for tokens and return a session_id",
    description=(
        "Use a short-lived PRT Cookie (etc.) exactly once here to exchange for access/refresh tokens. "
        "The exchanged tokens are held in an in-memory server session (not persisted), and the "
        "identity and session_id are returned. Actual collection happens at /api/v1/entra/gather. "
        "You can re-collect on the same session without re-obtaining the cookie."
    ),
)
async def entra_auth(req: EntraAuthRequest):
    if not req.tenant.strip():
        raise HTTPException(status_code=400, detail="tenant is required")
    result = await entra_auth_now(
        tenant=req.tenant, token=req.token, token_type=req.token_type
    )
    if not result.get("ok"):
        # Keep failure detail (expiry/invalid/CA, etc.) in the server log; generalize the response.
        raise HTTPException(
            status_code=502,
            detail="Entra authentication failed (check for an expired/invalid PRT Cookie or Conditional Access)",
        )
    return result


@app.post(
    "/api/v1/entra/gather",
    tags=["Entra"],
    status_code=202,
    summary="Start Entra collection (gather) in the background and return a job_id",
    description=(
        "Specify the session_id returned by /api/v1/entra/auth and start roadrecon gather "
        "**in the background**. Collecting a huge tenant takes minutes and can exceed an upstream "
        "proxy's response timeout, so HTTP returns 202 + job_id immediately without waiting. "
        "Poll GET /api/v1/entra/gather/jobs/{job_id} for progress. "
        "Callable multiple times for the same session_id / tenant (reuses the existing job while running)."
    ),
)
async def entra_gather(req: EntraGatherRequest):
    result = start_entra_gather_job(session_id=req.session_id)
    if not result.get("ok"):
        if result.get("error") == "session_not_found":
            raise HTTPException(
                status_code=404,
                detail="Session not found (expired/discarded). Please authenticate again.",
            )
        raise HTTPException(
            status_code=502,
            detail="Failed to start Entra data collection.",
        )
    return result


@app.get(
    "/api/v1/entra/gather/jobs/{job_id}",
    tags=["Entra"],
    summary="Get an Entra collection job's status (for polling)",
    description=(
        "Return the status of the job_id returned by POST /api/v1/entra/gather. "
        "status is running / done / failed. Includes database on done, and error (summary) on failed. "
        "Unknown job_ids (e.g. lost on server restart) return 404, so the client should fall back to "
        "GET /api/v1/entra/databases to confirm whether collection completed. "
        "Because high-frequency polling is expected, this endpoint suppresses its access logs."
    ),
)
async def entra_gather_job_status(job_id: str):
    job = get_entra_gather_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job


@app.delete(
    "/api/v1/entra/auth/{session_id}",
    tags=["Entra"],
    summary="Discard the held Entra auth session (tokens)",
)
async def entra_auth_clear(session_id: str):
    cleared = clear_entra_session(session_id)
    return {"ok": True, "cleared": cleared}


@app.get(
    "/api/v1/entra/databases",
    tags=["Entra"],
    summary="List collected Entra data (roadrecon.db)",
)
async def list_entra_databases():
    items = list_entra_dbs()
    return {"count": len(items), "items": items}


@app.delete(
    "/api/v1/entra/databases/{tenant}",
    tags=["Entra"],
    summary="Delete collected Entra data per tenant, including its directory",
)
async def delete_entra_database(tenant: str):
    try:
        existed = delete_entra_db(tenant)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid tenant")
    if not existed:
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True, "tenant": tenant}


## SOCKS Connection Check API

# Liveness is derived from OS-level TCP state / a plain TCP connect, so any upstream SOCKS
# implementation works as-is -- no management API and no forked build required.
#
# SOCKS_CHECK_PORT is the port remote SOCKS clients dial *into* (the reverse-tunnel control
# port). An ESTABLISHED connection there means a client is attached, which is the real
# "traffic can reach the target range" signal. When it is unset we fall back to a TCP connect
# against the SOCKS5 port, which only proves the proxy is listening.
#
# Counting ESTABLISHED on SOCKS_PORT would not work: it is the local proxychains hop, so it
# is empty while idle and would additionally count this health check's own connection.
_SOCKS_HOST = os.getenv("SOCKS_HOST", "127.0.0.1").strip() or "127.0.0.1"
_SOCKS_PORT = int(os.getenv("SOCKS_PORT", "1080"))
_SOCKS_CHECK_PORT = int(os.getenv("SOCKS_CHECK_PORT", "0") or 0)
_SOCKS_CONNECT_TIMEOUT = 2.0


def _established_count_sync(port: int) -> int:
    """Count ESTABLISHED TCP connections whose local port is `port`.

    Reads the OS connection table (on Linux, /proc/net/tcp -- world readable, so no
    elevated privileges are needed; PIDs are never inspected).
    """
    count = 0
    for conn in psutil.net_connections(kind="tcp"):
        laddr = conn.laddr
        if conn.status == psutil.CONN_ESTABLISHED and laddr and laddr.port == port:
            count += 1
    return count


async def _established_count(port: int) -> int:
    """Off-thread wrapper: scanning the connection table blocks."""
    try:
        return await asyncio.to_thread(_established_count_sync, port)
    except Exception:
        logger.exception("Failed to read TCP state for port %s", port)
        return 0


async def _socks_port_open() -> bool:
    """Return True when a TCP connection to the SOCKS5 port succeeds.

    This only proves the listener is up; it cannot tell whether a downstream client is
    attached, because upstream SOCKS servers expose no management API. Treat it as a
    "the proxy process is running" signal, not a guarantee that traffic reaches the target.
    """
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(_SOCKS_HOST, _SOCKS_PORT),
            timeout=_SOCKS_CONNECT_TIMEOUT,
        )
        return True
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


@app.get("/api/v1/health/socks", tags=["Health"], summary="Check SOCKS connection status")
async def check_socks_status():
    """Report SOCKS liveness.

    With SOCKS_CHECK_PORT set, `active` means a client is currently connected
    (mode="established"). Otherwise it only means the SOCKS5 port is listening
    (mode="listen"), which cannot confirm a client is attached.
    """
    if _SOCKS_CHECK_PORT:
        count = await _established_count(_SOCKS_CHECK_PORT)
        return {
            "active": count > 0,
            "mode": "established",
            "host": _SOCKS_HOST,
            "port": _SOCKS_CHECK_PORT,
            "client_count": count,
        }
    return {
        "active": await _socks_port_open(),
        "mode": "listen",
        "host": _SOCKS_HOST,
        "port": _SOCKS_PORT,
        "client_count": None,
    }
