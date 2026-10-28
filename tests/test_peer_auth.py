# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The root VPN sockets admit only the live Agent PID or local root."""

from __future__ import annotations

from types import SimpleNamespace
import subprocess
import unittest
from unittest.mock import patch

from sovagrid_vpn import peer_auth


class PeerAuthTests(unittest.TestCase):
    def test_main_pid_uses_fixed_systemd_unit_and_exact_response(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout="MainPID=12345\n")

        self.assertEqual(peer_auth.agent_main_pid(runner), 12345)
        self.assertEqual(calls[0][0], ["/usr/bin/systemctl", "--system", "--no-pager",
                                        "--no-ask-password", "--property=MainPID", "show",
                                        "sovagrid-agent.service"])
        self.assertEqual(calls[0][1]["timeout"], 3)

    def test_main_pid_fails_closed_on_missing_malformed_or_failed_result(self):
        for stdout, returncode in (("MainPID=0\n", 0), ("MainPID=123 extra\n", 0),
                                   ("MainPID=2147483648\n", 0), ("MainPID=123\n", 1),
                                   ("MainPID=123\nOther=9\n", 0)):
            with self.subTest(stdout=stdout, returncode=returncode):
                runner = lambda *args, **kwargs: SimpleNamespace(
                    stdout=stdout, returncode=returncode)
                self.assertIsNone(peer_auth.agent_main_pid(runner))
        self.assertIsNone(peer_auth.agent_main_pid(
            lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("systemctl", 3))))

    def test_generic_same_uid_pid_is_denied_but_agent_and_root_are_allowed(self):
        with patch.object(peer_auth, "agent_main_pid", return_value=777) as lookup:
            self.assertFalse(peer_auth.authorized_peer((778, 123), 123))
            self.assertTrue(peer_auth.authorized_peer((777, 123), 123))
            self.assertFalse(peer_auth.authorized_peer((777, 124), 123))
            self.assertTrue(peer_auth.authorized_peer((888, 0), 123))
            self.assertFalse(peer_auth.authorized_peer((0, 0), 123))
            self.assertEqual(lookup.call_count, 2)


if __name__ == "__main__":
    unittest.main()
