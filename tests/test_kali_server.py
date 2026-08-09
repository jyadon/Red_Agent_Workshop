"""Regression tests for kali-mcp/server.py argv construction (Phase 1: shell=False).

These lock in the security invariant introduced by moving execution from shell=True to
shell=False: a command string is tokenized with shlex and run as an argv list, so shell
metacharacters can never spawn a second process -- only the binary at argv[0] is invoked.

Runs on any machine (no fastmcp needed): fastmcp is stubbed before importing the server,
and only the pure tokenizer (_build_argv) plus the parse-error branch are exercised -- no
subprocess is ever launched.
"""

import importlib
import os
import sys
import types
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_KALI_MCP_DIR = os.path.join(_REPO_ROOT, "kali-mcp")


def _load_server():
    """Import kali-mcp/server.py with a stubbed fastmcp and a known proxy command."""
    fake = types.ModuleType("fastmcp")

    class FastMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            def deco(fn):
                return fn

            return deco

        def run(self, *a, **k):
            pass

    fake.FastMCP = FastMCP
    sys.modules["fastmcp"] = fake
    os.environ["KALI_PROXY_ENABLED"] = "true"
    os.environ["KALI_PROXY_COMMAND"] = "proxychains -q"
    if _KALI_MCP_DIR not in sys.path:
        sys.path.insert(0, _KALI_MCP_DIR)
    sys.modules.pop("server", None)
    return importlib.import_module("server")


class BuildArgvSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = _load_server()

    def test_metacharacters_stay_literal_no_second_command(self):
        # ';' does not chain: the whole string tokenizes to nmap + literal args.
        self.assertEqual(
            self.s._build_argv("nmap -sV 127.0.0.1; whoami", use_proxychains=False),
            ["nmap", "-sV", "127.0.0.1;", "whoami"],
        )
        # '|' is a literal argument to cat, not a pipeline.
        self.assertEqual(
            self.s._build_argv("cat /etc/passwd | grep root", use_proxychains=False),
            ["cat", "/etc/passwd", "|", "grep", "root"],
        )
        # command substitution is not expanded.
        self.assertEqual(
            self.s._build_argv("echo $(id)", use_proxychains=False),
            ["echo", "$(id)"],
        )

    def test_quoted_password_and_multiword_arg_are_single_tokens(self):
        argv = self.s._build_argv(
            "netexec ldap dc01 -u 'alice' -p 'p@ss w0rd!' --groups \"Domain Admins\"",
            use_proxychains=False,
        )
        self.assertIn("p@ss w0rd!", argv)  # space+special password stays one token
        self.assertIn("Domain Admins", argv)  # quoted multiword arg stays one token
        self.assertEqual(argv[0], "netexec")

    def test_multi_value_expands_to_multiple_tokens(self):
        self.assertEqual(
            self.s._build_argv("netexec smb dc1 dc2 dc3 -u user -p pass", use_proxychains=False),
            ["netexec", "smb", "dc1", "dc2", "dc3", "-u", "user", "-p", "pass"],
        )

    def test_proxychains_prefix_added_when_requested(self):
        self.assertEqual(
            self.s._build_argv("dig +short example.com", use_proxychains=True),
            ["proxychains", "-q", "dig", "+short", "example.com"],
        )

    def test_no_double_proxychains_prefix(self):
        self.assertEqual(
            self.s._build_argv("proxychains -q nxc smb dc01", use_proxychains=True),
            ["proxychains", "-q", "nxc", "smb", "dc01"],
        )
        # also via sudo
        self.assertEqual(
            self.s._build_argv("sudo proxychains nxc smb dc01", use_proxychains=True)[:2],
            ["sudo", "proxychains"],
        )

    def test_proxychains_skipped_when_use_false(self):
        self.assertEqual(
            self.s._build_argv("dig +short example.com", use_proxychains=False),
            ["dig", "+short", "example.com"],
        )

    def test_empty_command_yields_empty_argv(self):
        self.assertEqual(self.s._build_argv("   ", use_proxychains=True), [])

    def test_unbalanced_quote_raises_valueerror(self):
        with self.assertRaises(ValueError):
            self.s._build_argv("nxc -p 'unterminated", use_proxychains=False)

    def test_execute_returns_parse_error_string_on_bad_quotes(self):
        # This branch does NOT launch a subprocess.
        out = self.s.execute_kali_command("nxc -p 'unterminated", use_proxychains=False)
        self.assertTrue(out.startswith("Command parse error:"), out)

    def test_execute_returns_message_on_empty_command(self):
        out = self.s.execute_kali_command("   ", use_proxychains=True)
        self.assertEqual(out, "No command was provided.")

    def test_command_help_rejects_empty_and_invalid_names(self):
        # These branches never launch a subprocess.
        self.assertEqual(self.s.command_help("   "), "No binary name was provided.")
        for bad in ["../etc/passwd", "nmap; rm", "a b", "/usr/bin/id", "$(id)", "-p"]:
            self.assertTrue(
                self.s.command_help(bad).startswith("Invalid binary name:"),
                f"expected rejection for {bad!r}",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
