# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The Agent-facing VPN protocol cannot request shell, paths or profiles."""

from __future__ import annotations

import json
import socket
import unittest
from unittest.mock import patch

from sovagrid_vpn.control import (ControlError, MAX_REQUEST, dispatch,
                                  parse_action, serve_one)


class FakeManager:
    def __init__(self):
        self.called = None

    def create(self, *args):
        self.called = ("create", args)
        return {"name": args[0], "interface": "sg123", "endpoint": args[3],
                "port": args[1], "subnet": args[2], "clients": 0,
                "active": False, "private_key": "SECRET"}

    def add_client(self, *args):
        self.called = ("add-client", args)
        return {"name": args[1], "address": "10.49.0.2", "profile": "/secret/file",
                "private_key": "SECRET", "active": False, "existing": False}

    def sealed_export(self, *args, **kwargs):
        self.called = ("sealed-export", args, kwargs)
        return {"version": 1, "ephemeral_public_key": "ephemeral",
                "salt": "salt", "nonce": "nonce", "ciphertext": "encrypted",
                "profile": "SECRET", "private_key": "SECRET"}


class ControlTests(unittest.TestCase):
    def test_only_exact_grammars_are_accepted(self):
        self.assertEqual(parse_action(["create", "test-vpn", "--port", "51821",
                                       "--subnet", "10.49.0.0/24", "--endpoint", "8.8.8.8"]),
                         ("create", ("test-vpn", 51821, "10.49.0.0/24", "8.8.8.8")))
        self.assertEqual(parse_action(["remove", "test-vpn", "--confirm-name", "test-vpn"]),
                         ("remove", ("test-vpn", "test-vpn")))
        self.assertEqual(parse_action(["instances"]), ("instances", ()))
        self.assertEqual(parse_action(["sealed-export", "test-vpn", "alice", "A" * 87,
                                       "--route", "full"]),
                         ("sealed-export", ("test-vpn", "alice", "A" * 87, "full")))
        invalid = (
            ["export-client", "test-vpn", "alice", "--output", "/tmp/x"],
            ["recover", "test-vpn"], ["/bin/sh", "-c", "id"],
            ["create", "test-vpn", "--port", "51821", "--subnet", "10.49.0.0/24", "--endpoint", "x", "extra"],
            ["create", "test-vpn", "--subnet", "10.49.0.0/24", "--port", "51821", "--endpoint", "x"],
            ["create", "../etc", "--port", "51821", "--subnet", "10.49.0.0/24", "--endpoint", "x"],
            ["create", "test-vpn", "--port", "1", "--subnet", "10.49.0.0/24", "--endpoint", "x"],
            ["add-client", "test-vpn", "alice\nPostUp=id"],
            ["remove", "test-vpn", "--confirm-name", "other"],
            ["activate", "test-vpn", "--output", "/tmp/file"],
            ["sealed-export", "test-vpn", "alice", "A" * 87, "--route", "unsafe"],
        )
        for argv in invalid:
            with self.subTest(argv=argv), self.assertRaises(ControlError):
                parse_action(argv)

    def test_dispatch_explicitly_filters_manager_result(self):
        manager = FakeManager()
        created = dispatch(["create", "test-vpn", "--port", "51821", "--subnet",
                            "10.49.0.0/24", "--endpoint", "8.8.8.8"], manager)
        self.assertNotIn("SECRET", json.dumps(created))
        self.assertEqual(manager.called[0], "create")
        added = dispatch(["add-client", "test-vpn", "alice"], manager)
        self.assertNotIn("SECRET", json.dumps(added))
        self.assertNotIn("profile", added)
        sealed = dispatch(["sealed-export", "test-vpn", "alice", "A" * 87], manager)
        self.assertEqual(set(sealed), {"version", "ephemeral_public_key", "salt",
                                       "nonce", "ciphertext"})
        self.assertNotIn("SECRET", json.dumps(sealed))
        dispatch(["sealed-export", "test-vpn", "alice", "A" * 87, "--route", "full"], manager)
        self.assertEqual(manager.called[2], {"route": "full"})

    def test_broker_rejects_unknown_fields_and_large_requests(self):
        for payload, expected in (
            (b'{"argv":["instances"],"path":"/etc/shadow"}\n', "Invalid VPN request"),
            (b'x' * (MAX_REQUEST + 1), "VPN message is too large"),
        ):
            with self.subTest(payload=payload[:40]):
                client, server = socket.socketpair()
                with client, server, patch("sovagrid_vpn.control.peer_identity", return_value=(777, 123)), \
                        patch("sovagrid_vpn.peer_auth.agent_main_pid", return_value=777):
                    client.sendall(payload)
                    serve_one(server, 123)
                    result = json.loads(client.recv(1024))
                    self.assertEqual(result, {"ok": False, "error": expected})

    def test_broker_checks_peer_identity_before_dispatch(self):
        client, server = socket.socketpair()
        with client, server, patch("sovagrid_vpn.control.peer_identity", return_value=(321, 123)), \
                patch("sovagrid_vpn.peer_auth.agent_main_pid", return_value=777), \
                patch("sovagrid_vpn.control.dispatch") as operation:
            client.sendall(b'{"argv":["instances"]}\n')
            serve_one(server, 123)
            self.assertEqual(json.loads(client.recv(1024))["error"], "VPN access denied")
            operation.assert_not_called()

    def test_broker_rechecks_agent_pid_before_dispatch(self):
        client, server = socket.socketpair()
        with client, server, patch("sovagrid_vpn.control.peer_identity", return_value=(777, 123)), \
                patch("sovagrid_vpn.peer_auth.agent_main_pid", side_effect=(777, 778)), \
                patch("sovagrid_vpn.control.dispatch") as operation:
            client.sendall(b'{"argv":["instances"]}\n')
            serve_one(server, 123)
            self.assertEqual(json.loads(client.recv(1024))["error"], "VPN access denied")
            operation.assert_not_called()

    def test_broker_returns_only_sanitized_result(self):
        client, server = socket.socketpair()
        with client, server, patch("sovagrid_vpn.control.peer_identity", return_value=(777, 123)), \
                patch("sovagrid_vpn.peer_auth.agent_main_pid", return_value=777), \
                patch("sovagrid_vpn.control.ManagedWireGuard", return_value=FakeManager()):
            client.sendall(b'{"argv":["add-client","test-vpn","alice"]}\n')
            serve_one(server, 123)
            payload = client.recv(1024)
            self.assertNotIn(b"SECRET", payload)
            self.assertNotIn(b"profile", payload)
            result = json.loads(payload)
            self.assertEqual(result["result"], {"name": "alice", "address": "10.49.0.2",
                                                "active": False, "existing": False})


if __name__ == "__main__":
    unittest.main()
