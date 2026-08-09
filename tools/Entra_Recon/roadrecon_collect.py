#!/usr/bin/env python3
"""
roadrecon_collect: deterministic collection wrapper for Entra ID data (forward-only operation).

Takes a token obtained by an operator running BAADTokenBroker or similar on a
compliant device (a PRT Cookie by default), imports it via `roadrecon auth`,
and collects Entra ID data into SQLite (`roadrecon.db`) via `roadrecon gather`.

This script itself is unaware of SOCKS/proxychains. When reaching the target
tenant (cloud) over SOCKS is required, the caller launches it as
`proxychains -q python roadrecon_collect.py ...` (proxychains propagates through
LD_PRELOAD down to the child roadrecon process).

The token is received via the ROADRECON_TOKEN environment variable rather than a
CLI argument to avoid plaintext exposure in `ps aux` and similar; it is removed
from os.environ immediately after being read.

Progress/diagnostics go to stderr; only the final result JSON goes to stdout
(same convention as ad_dns_recon). The backend parses the stdout JSON.
"""

import argparse
import base64
import json
import logging
import os
import subprocess
import sys
from datetime import datetime

# Token is passed via env var because a CLI argument would be exposed in the process list.
_TOKEN_ENV_VAR = "ROADRECON_TOKEN"

logger = logging.getLogger("roadrecon_collect")

# token-type -> roadrecon auth flag; overridable via env var to absorb version differences.
# Default is the PRT Cookie that BAADTokenBroker emits and roadrecon reliably accepts.
_TOKEN_TYPE_FLAGS = {
    "prt-cookie": os.getenv("ROADRECON_AUTH_FLAG_PRT_COOKIE", "--prt-cookie"),
    "refresh-token": os.getenv("ROADRECON_AUTH_FLAG_REFRESH", "--refresh-token"),
    "access-token": os.getenv("ROADRECON_AUTH_FLAG_ACCESS", "--access-token"),
}


def _configure_logging(quiet: bool) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(logging.WARNING if quiet else logging.INFO)


def _emit(payload: dict) -> None:
    """Write the final result JSON to stdout."""
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _run(cmd: list[str], timeout: float) -> tuple[int, str]:
    """Run a child process and return (returncode, stderr_tail); stdout is logged only."""
    logger.info("running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        logger.error("command not found: %s (%s)", cmd[0], e)
        return 127, f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        logger.error("command timed out after %.0fs: %s", timeout, " ".join(cmd))
        return 124, f"timed out after {timeout:.0f}s"
    err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    out = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    if out:
        logger.info("stdout(head):\n%s", out[:1500])
    if err:
        logger.info("stderr(head):\n%s", err[:1500])
    return proc.returncode, err[-1500:]


def _shred(path: str) -> None:
    """Destroy the token file (.roadtools_auth), overwriting its contents once before
    deleting (best effort); failures are swallowed and only logged."""
    try:
        if not path or not os.path.exists(path):
            return
        try:
            size = os.path.getsize(path)
            with open(path, "r+b") as f:
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            pass
        os.remove(path)
        logger.info("auth token file shredded: %s", path)
    except Exception:
        logger.warning("failed to shred auth token file: %s", path)


def _decode_identity(authfile: str) -> dict:
    """Extract only non-sensitive identity info from the authfile (.roadtools_auth JSON).

    Never returns the token material itself (access/refresh/id). Returns only the minimal
    info an operator needs after a successful auth to confirm the correct tenant/user, MFA
    status, and expiry. Never raises; returns a minimal dict even on failure (robustness first).
    """
    info: dict = {}
    try:
        with open(authfile, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return info
    if not isinstance(data, dict):
        return info
    info["tenant"] = data.get("tenantId")
    info["expiresOn"] = data.get("expiresOn")
    info["clientId"] = data.get("_clientId")
    # base64url-decode the accessToken payload (middle segment) to obtain the UPN etc.
    # No signature verification (display-only reference; the successful token exchange is the proof).
    at = data.get("accessToken")
    if isinstance(at, str) and at.count(".") >= 2:
        try:
            payload_b64 = at.split(".")[1]
            pad = "=" * (-len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
            info["upn"] = claims.get("upn") or claims.get("unique_name")
            info["name"] = claims.get("name")
            info["oid"] = claims.get("oid")
            info["aud"] = claims.get("aud")
            amr = claims.get("amr")
            if isinstance(amr, list):
                info["mfa"] = "mfa" in amr
            if not info.get("tenant"):
                info["tenant"] = claims.get("tid")
        except Exception:
            pass
    return {k: v for k, v in info.items() if v is not None}


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _do_auth(args, authfile: str) -> tuple[int, dict]:
    """Run roadrecon auth <flag> <token> [-t tenant] -f <authfile>.
    On success returns (0, {success:True, stage:"auth", identity:{...}}) with non-sensitive identity."""
    # Token is only accepted from the env var and removed immediately after reading.
    token = os.environ.pop(_TOKEN_ENV_VAR, None)
    if not token:
        return 1, {
            "success": False,
            "stage": "auth",
            "error": f"environment variable ${_TOKEN_ENV_VAR} is not set (no token provided)",
            "timestamp": _now(),
        }
    auth_flag = _TOKEN_TYPE_FLAGS[args.token_type]
    auth_cmd = [args.roadrecon_bin, "auth", auth_flag, token, "-f", authfile]
    if args.tenant:
        auth_cmd += ["-t", args.tenant]
    rc, err = _run(auth_cmd, args.timeout)
    if rc != 0 or not os.path.exists(authfile):
        return 1, {
            "success": False,
            "stage": "auth",
            "returncode": rc,
            "error": err or f"roadrecon auth failed (rc={rc})",
            "token_type": args.token_type,
            "timestamp": _now(),
        }
    return 0, {
        "success": True,
        "stage": "auth",
        "tenant": args.tenant,
        "identity": _decode_identity(authfile),
        "timestamp": _now(),
    }


def _do_gather(args, authfile: str) -> tuple[int, dict]:
    """Run roadrecon gather -d <database> -f <authfile>."""
    if not os.path.exists(authfile):
        return 1, {
            "success": False,
            "stage": "gather",
            "error": "authfile does not exist (auth not completed)",
            "timestamp": _now(),
        }
    gather_cmd = [args.roadrecon_bin, "gather", "-d", args.database, "-f", authfile]
    rc, err = _run(gather_cmd, args.timeout)
    success = rc == 0 and os.path.exists(args.database)
    return (0 if success else 1), {
        "success": success,
        "stage": "done" if success else "gather",
        "database": args.database if success else None,
        "tenant": args.tenant,
        "returncode": rc,
        "error": None if success else (err or f"gather failed (rc={rc})"),
        "timestamp": _now(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect Entra ID data via roadrecon (forward-only token input)."
    )
    parser.add_argument(
        "--mode",
        default="both",
        choices=["auth", "gather", "both"],
        help=(
            "auth=import token only (returns identity, does not shred authfile) / "
            "gather=collect using an existing authfile only / both=auth+gather+shred as before (default)"
        ),
    )
    parser.add_argument(
        "--database",
        default=None,
        help="output SQLite DB path (required for gather/both)",
    )
    parser.add_argument(
        "--authfile",
        default=None,
        help="roadrecon auth token file (required for auth/gather; managed by the caller)",
    )
    parser.add_argument(
        "--tenant",
        default=None,
        help="tenant ID or domain (roadrecon auth -t)",
    )
    parser.add_argument(
        "--token-type",
        default=os.getenv("ROADRECON_TOKEN_TYPE", "prt-cookie"),
        choices=sorted(_TOKEN_TYPE_FLAGS.keys()),
        help="type of ROADRECON_TOKEN (default: prt-cookie)",
    )
    parser.add_argument(
        "--roadrecon-bin",
        default=os.getenv("ROADRECON_BIN", "roadrecon"),
        help="roadrecon executable (default: roadrecon / env var ROADRECON_BIN)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.getenv("ROADRECON_TIMEOUT", "600")),
        help="timeout in seconds for each roadrecon subcommand",
    )
    parser.add_argument("--quiet", "-q", action="store_true")
    args = parser.parse_args()

    _configure_logging(args.quiet)

    if args.mode in ("gather", "both") and not args.database:
        _emit({"success": False, "error": "--database is required for gather/both", "timestamp": _now()})
        sys.exit(2)

    # Resolve authfile. auth/gather require it because the caller owns its lifecycle.
    # Only both defaults to placing `.roadtools_auth` alongside the db, as before.
    if args.authfile:
        authfile = args.authfile
    elif args.mode == "both" and args.database:
        db_dir = os.path.dirname(os.path.abspath(args.database)) or "."
        authfile = os.path.join(db_dir, ".roadtools_auth")
    else:
        _emit({"success": False, "error": "--authfile is required for auth/gather", "timestamp": _now()})
        sys.exit(2)

    payload: dict = {"success": False, "timestamp": _now()}
    exit_code = 1
    try:
        if args.mode == "auth":
            # auth only: keep the authfile (the caller reads, retains, then shreds it).
            exit_code, payload = _do_auth(args, authfile)
        elif args.mode == "gather":
            # gather only: use an existing authfile; shredding is left to the caller.
            exit_code, payload = _do_gather(args, authfile)
        else:  # both (legacy): run auth->gather in sequence, always shredding at the end.
            rc, payload = _do_auth(args, authfile)
            if rc == 0:
                exit_code, payload = _do_gather(args, authfile)
            else:
                exit_code = rc
            _shred(authfile)
    except Exception as e:  # noqa: BLE001
        logger.exception("roadrecon_collect failed")
        payload = {"success": False, "error": f"unexpected: {e}", "timestamp": _now()}
        exit_code = 1

    _emit(payload)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
