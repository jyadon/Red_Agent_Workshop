"""Login user management CLI (multi-operator, all equal privilege).

Tool for server administrators to issue, disable, and reset passwords for
accounts. There is no privileged admin surface in the app; only operators with
server access can run this.

Usage:
    python tools/auth/manage_users.py create <username>     # Create (password entered interactively)
    python tools/auth/manage_users.py list                  # List
    python tools/auth/manage_users.py passwd <username>     # Change password
    python tools/auth/manage_users.py disable <username>    # Disable (login blocked, existing sessions invalidated)
    python tools/auth/manage_users.py enable <username>     # Enable

The DB uses `DATABASE_URL` (default ./data/retest_history.db). Tables are created automatically if missing.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# agent.db resolves DATABASE_URL at import time, so load .env first.
try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env")
except Exception:
    pass

from agent import users  # noqa: E402
from agent.db import dispose_db, init_db  # noqa: E402


def _prompt_password() -> str:
    pw1 = getpass.getpass("Password: ")
    if not pw1:
        print("An empty password cannot be set.", file=sys.stderr)
        raise SystemExit(1)
    if len(pw1) < 8:
        print("Password must be at least 8 characters.", file=sys.stderr)
        raise SystemExit(1)
    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        print("Passwords do not match.", file=sys.stderr)
        raise SystemExit(1)
    return pw1


async def _run(args: argparse.Namespace) -> int:
    await init_db()
    try:
        if args.cmd == "create":
            password = _prompt_password()
            try:
                await users.create_user(args.username, password)
            except ValueError as e:
                print(f"Failed to create user: {e}", file=sys.stderr)
                return 1
            print(f"Created user: {args.username}")
            return 0

        if args.cmd == "bootstrap":
            # Non-interactive, idempotent initial user creation (for CI/CD).
            # Password is read from the RA_INITIAL_PASSWORD env var (min 8 chars).
            existing = await users.count_users()
            if existing > 0:
                print(f"{existing} user(s) already exist. Skipping bootstrap.")
                return 0
            password = os.getenv("RA_INITIAL_PASSWORD", "")
            if len(password) < 8:
                print(
                    "RA_INITIAL_PASSWORD is unset or shorter than 8 characters; aborting bootstrap.",
                    file=sys.stderr,
                )
                return 1
            try:
                await users.create_user(args.username, password)
            except ValueError as e:
                print(f"Failed to create user: {e}", file=sys.stderr)
                return 1
            print(f"Created initial user: {args.username}")
            return 0

        if args.cmd == "list":
            rows = await users.list_users()
            if not rows:
                print("No users are registered.")
                return 0
            print(f"{'username':32} {'disabled':9} created_at")
            for u in rows:
                print(f"{u.username:32} {str(u.disabled):9} {u.created_at.isoformat()}")
            return 0

        if args.cmd == "passwd":
            password = _prompt_password()
            ok = await users.set_user_password(args.username, password)
            if not ok:
                print(f"User not found: {args.username}", file=sys.stderr)
                return 1
            print(f"Updated password: {args.username}")
            return 0

        if args.cmd in ("disable", "enable"):
            disabled = args.cmd == "disable"
            ok = await users.set_disabled(args.username, disabled)
            if not ok:
                print(f"User not found: {args.username}", file=sys.stderr)
                return 1
            print(f"{'Disabled' if disabled else 'Enabled'}: {args.username}")
            return 0

        if args.cmd == "mfa-reset":
            # Lockout recovery: clear MFA and discard the secret. The next login
            # works with password only (the user can re-enroll from the UI).
            ok = await users.disable_mfa(args.username)
            if not ok:
                print(f"User not found: {args.username}", file=sys.stderr)
                return 1
            print(f"MFA reset: {args.username} (next login with password only)")
            return 0

        print(f"Unknown command: {args.cmd}", file=sys.stderr)
        return 2
    finally:
        await dispose_db()


def main() -> None:
    parser = argparse.ArgumentParser(description="Login user management CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="List users")
    for name, help_text in (
        ("create", "Create a user"),
        ("bootstrap", "Create initial user (non-interactive, idempotent; password from RA_INITIAL_PASSWORD env var)"),
        ("passwd", "Change password"),
        ("disable", "Disable a user"),
        ("enable", "Enable a user"),
        ("mfa-reset", "Reset MFA (lockout recovery; next login with password only)"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("username")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
