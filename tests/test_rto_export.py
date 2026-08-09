"""Tests for RTO export helpers: command placeholder-ization and playbook append/dedup.

Requires pydantic (agent.schemas). Writes only to a temp file via RTO_PLAYBOOK_PATH; no DB.
"""

import json
import os
import sys
import tempfile
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


class PlaceholderizeTests(unittest.TestCase):
    def test_replaces_engagement_values_with_placeholders(self):
        from agent.rto_playbook import placeholderize_command

        ctx = {
            "domain": "lab.local",
            "user": "svc_adm",
            "password": "P@ss w0rd!",
            "dns": "10.10.10.10",
            "target": "10.10.10.4",
        }
        cmd = "nxc ldap dc01 -u 'svc_adm' -p 'P@ss w0rd!' -d 'lab.local' --dns 10.10.10.10 -t 10.10.10.4"
        out = placeholderize_command(cmd, ctx)
        self.assertNotIn("svc_adm", out)
        self.assertNotIn("P@ss w0rd!", out)
        self.assertNotIn("10.10.10.4", out)
        self.assertIn("{{user}}", out)
        self.assertIn("{{password}}", out)
        self.assertIn("{{target}}", out)

    def test_handles_single_quote_escaped_password(self):
        from agent.rto_playbook import placeholderize_command

        # A password containing ' is embedded as the shell-escaped form '\'' inside '...'.
        pw = "a'b"
        escaped = pw.replace("'", "'\\''")
        cmd = f"nxc smb host -p '{escaped}'"
        out = placeholderize_command(cmd, {"password": pw})
        self.assertNotIn(escaped, out)
        self.assertIn("{{password}}", out)

    def test_empty_context_is_noop(self):
        from agent.rto_playbook import placeholderize_command

        self.assertEqual(placeholderize_command("whoami", {}), "whoami")


class AppendToLiveTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix="_rto.json")
        os.close(fd)
        os.remove(self.path)  # start absent; append should create it
        os.environ["RTO_PLAYBOOK_PATH"] = self.path

    def tearDown(self):
        os.environ.pop("RTO_PLAYBOOK_PATH", None)
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_append_creates_file_and_dedupes(self):
        from agent.rto_playbook import append_commands_to_live, load_playbook

        items = [
            {"command": "nxc ldap {{dc}} -M ldap-checker", "label": "LDAP signing"},
            {"command": "impacket-reg '{{domain}}/{{user}}:{{password}}'@{{dc}} query", "label": "NTLMv1"},
        ]
        r1 = append_commands_to_live(items, group_id="retest-no-3", group_name="Exported from retest No.3")
        self.assertEqual((r1["added"], r1["skipped"]), (2, 0))
        self.assertTrue(os.path.exists(self.path))

        # Re-exporting the same commands adds nothing (dedup by command string).
        r2 = append_commands_to_live(items, group_id="retest-no-3")
        self.assertEqual((r2["added"], r2["skipped"]), (0, 2))

        # The written file is a valid playbook with unique step ids.
        pb = load_playbook()
        step_ids = [s.id for g in pb.groups for s in g.steps]
        self.assertEqual(len(step_ids), len(set(step_ids)))
        self.assertEqual(len(step_ids), 2)

    def test_proxychains_flag_preserved(self):
        from agent.rto_playbook import append_commands_to_live

        append_commands_to_live(
            [{"command": "sqlite3 /tmp/x.db 'SELECT 1'", "proxychains": False}],
            group_id="exported",
        )
        with open(self.path, encoding="utf-8") as f:
            data = json.load(f)
        step = data["groups"][0]["steps"][0]
        self.assertIs(step["proxychains"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
