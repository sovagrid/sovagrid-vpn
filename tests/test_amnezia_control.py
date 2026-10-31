# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Broker grammar and secret-free response tests without Docker or root."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

from sovagrid_vpn import amnezia_control as control


def encoded(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


ENVELOPE = {
    "version": 1,
    "ephemeral_public_key": encoded(b"\x04" + b"\x01" * 64),
    "salt": encoded(b"\x02" * 16),
    "nonce": encoded(b"\x03" * 12),
    "ciphertext": encoded(b"\x04" * 32),
}
RECIPIENT = encoded(b"\x04" + b"\x05" * 64)
AWG_PARAMETERS = {"Jc": "4", "Jmin": "10", "Jmax": "50", "S1": "24", "S2": "24",
                  "S3": "24", "S4": "24", "H1": "1", "H2": "2", "H3": "3", "H4": "4"}


class FakeAdmin:
    def __init__(self, target="awg2"):
        self.calls = []
        self.target = target

    def create_profile(self, *args, route):
        self.calls.append(("create_profile", args, route))
        return {"target": self.target, "action": "added", "client": args[0],
                "configured_clients": 3, "cleanup_required": False,
                "profile_format": "awg3-conf" if self.target == "awg2" else "wg-conf",
                "sealed_profile": ENVELOPE,
                "private_key": "MUST_NOT_LEAK"}

    def sealed_export(self, *args):
        self.calls.append(("sealed_export", args))
        return dict(ENVELOPE)

    def revoke(self, *args):
        self.calls.append(("revoke", args))
        return {"target": self.target, "action": "revoked", "client": args[0],
                "configured_clients": 2, "cleanup_required": False,
                "private_key": "MUST_NOT_LEAK"}

    def status(self):
        self.calls.append(("status",))
        return {"target": self.target, "enrolled": True, "recovery_required": False,
                "owned_clients": ["phone"], "private_key": "MUST_NOT_LEAK"}

    def settings_preview(self):
        self.calls.append(("settings_preview",))
        return {"target": self.target, "container_id": "a" * 64,
                "image_id": "sha256:" + "b" * 64, "config_sha256": "c" * 64,
                "table_sha256": "d" * 64, "generation": 0,
                "protocol": "amneziawg" if self.target == "awg2" else "wireguard",
                "interface": "awg0" if self.target == "awg2" else "wg0",
                "listen_port": 49289, "server_address": "10.44.0.1",
                "server_subnet": "10.44.0.0/24", "configured_clients": 1,
                "managed_clients": 0, "external_clients": 1, "awg_parameters": {},
                "awg_parameters_runtime_verified": False,
                "header_protection_key_present": False,
                "awg3_required_parameters_present": False,
                "apply_supported": False,
                "apply_blockers": list(control.PREVIEW_BLOCKERS)}

    def settings_plan(self, digest, generation, patch):
        self.calls.append(("settings_plan", digest, generation, patch))
        proposed = {**AWG_PARAMETERS, **patch}
        return {"target": self.target, "container_id": "a" * 64,
                "image_id": "sha256:" + "b" * 64, "generation": 0,
                "config_sha256": "c" * 64, "table_sha256": "d" * 64,
                "proposed_config_sha256": "e" * 64,
                "current_awg_parameters": AWG_PARAMETERS,
                "proposed_awg_parameters": proposed,
                "changed_fields": sorted(name for name in AWG_PARAMETERS
                                         if AWG_PARAMETERS[name] != proposed[name]),
                "configured_clients": 1, "apply_supported": False,
                "apply_blockers": ["CLIENT_PROFILES_REQUIRE_REISSUE"]}

    def settings_intent(self, digest, generation, proposed, patch):
        self.calls.append(("settings_intent", digest, generation, proposed, patch))
        return {"target": self.target, "action": "settings_intent",
                "confirmation_id": "A" * 43, "expires_at": int(time.time()) + 300,
                "generation": generation, "config_sha256": digest,
                "proposed_config_sha256": proposed, "changed_fields": ["Jc"],
                "configured_clients": 0}

    def settings_apply_confirmed(self, digest, generation, proposed, patch, confirmation):
        self.calls.append(("settings_apply_confirmed", digest, generation,
                           proposed, patch, confirmation))
        return {"target": self.target, "action": "settings_updated",
                "generation": generation + 1, "config_sha256": proposed,
                "cleanup_required": False}


class BrokerTests(unittest.TestCase):
    def test_broker_rejects_generic_same_uid_process_before_mutation(self):
        client, server = socket.socketpair()
        with client, server, patch.object(control, "peer_identity", return_value=(778, 123)), \
                patch("sovagrid_vpn.peer_auth.agent_main_pid", return_value=777), \
                patch.object(control, "dispatch") as mutation:
            client.sendall(b'{"argv":["revoke","awg2","phone"]}\n')
            control.serve_one(server, 123)
            self.assertEqual(json.loads(client.recv(1024))["error"], "Amnezia access denied")
            mutation.assert_not_called()

    def test_broker_rechecks_agent_pid_before_mutation(self):
        client, server = socket.socketpair()
        with client, server, patch.object(control, "peer_identity", return_value=(777, 123)), \
                patch("sovagrid_vpn.peer_auth.agent_main_pid", side_effect=(777, 778)), \
                patch.object(control, "dispatch") as mutation:
            client.sendall(b'{"argv":["revoke","awg2","phone"]}\n')
            control.serve_one(server, 123)
            self.assertEqual(json.loads(client.recv(1024))["error"], "Amnezia access denied")
            mutation.assert_not_called()

    def test_live_agent_pid_can_reach_broker(self):
        client, server = socket.socketpair()
        public = {"target": "awg2", "enrolled": True,
                  "recovery_required": False, "owned_clients": ["phone"]}
        with client, server, patch.object(control, "peer_identity", return_value=(777, 123)), \
                patch("sovagrid_vpn.peer_auth.agent_main_pid", return_value=777), \
                patch.object(control, "_enabled", return_value=True), \
                patch.object(control, "dispatch", return_value=public) as operation:
            client.sendall(b'{"argv":["status","awg2"]}\n')
            control.serve_one(server, 123)
            self.assertEqual(json.loads(client.recv(1024)), {"ok": True, "result": public})
            operation.assert_called_once_with(["status", "awg2"])

    def test_settings_broker_stays_disabled_with_only_peer_marker(self):
        client, server = socket.socketpair()
        argv = ["settings-intent", "awg2", "c" * 64, "0", "e" * 64, '{"Jc":"5"}']
        with client, server, patch.object(control, "peer_identity", return_value=(777, 123)), \
                patch("sovagrid_vpn.peer_auth.agent_main_pid", return_value=777), \
                patch.object(control, "_enabled", return_value=True), \
                patch.object(control, "_settings_enabled", return_value=False), \
                patch.object(control, "dispatch") as mutation:
            client.sendall((json.dumps({"argv": argv}) + "\n").encode())
            control.serve_one(server, 123)
            response = json.loads(client.recv(1024))
            self.assertEqual(response["error"], "Amnezia settings control is disabled")
            mutation.assert_not_called()

    def test_settings_broker_requires_both_markers_and_live_agent(self):
        client, server = socket.socketpair()
        argv = ["settings-intent", "awg2", "c" * 64, "0", "e" * 64, '{"Jc":"5"}']
        public = FakeAdmin().settings_intent("c" * 64, 0, "e" * 64, {"Jc": "5"})
        with client, server, patch.object(control, "peer_identity", return_value=(777, 123)), \
                patch("sovagrid_vpn.peer_auth.agent_main_pid", return_value=777), \
                patch.object(control, "_enabled", return_value=True), \
                patch.object(control, "_settings_enabled", return_value=True), \
                patch.object(control, "dispatch", return_value=public) as operation:
            client.sendall((json.dumps({"argv": argv}) + "\n").encode())
            control.serve_one(server, 123)
            self.assertEqual(json.loads(client.recv(1024)), {"ok": True, "result": public})
            operation.assert_called_once_with(argv)

    def test_exact_grammar_and_no_administrative_actions(self):
        valid = [
            ["add-profile", "awg2", "phone", "10.44.0.3", "vpn.example.com", RECIPIENT],
            ["add-profile", "awg2", "phone", "auto", "vpn.example.com", RECIPIENT],
            ["add-profile", "awg2", "phone", "10.44.0.3", "198.51.100.7", RECIPIENT,
             "--route", "full"],
            ["sealed-export", "awg2", "phone", RECIPIENT],
            ["revoke", "awg2", "phone"], ["status", "awg2"],
            ["settings-preview", "awg2"],
            ["settings-plan", "awg2", "c" * 64, "0", '{"Jc":"5"}'],
            ["settings-intent", "awg2", "c" * 64, "0", "e" * 64, '{"Jc":"5"}'],
            ["settings-apply", "awg2", "c" * 64, "0", "e" * 64,
             '{"Jc":"5"}', "A" * 43],
            ["add-profile", "wireguard", "phone", "10.44.0.3", "vpn.example.com", RECIPIENT],
            ["sealed-export", "wireguard", "phone", RECIPIENT],
            ["revoke", "wireguard", "phone"], ["status", "wireguard"],
            ["settings-preview", "wireguard"],
        ]
        for argv in valid:
            with self.subTest(argv=argv):
                self.assertEqual(control.parse_action(argv)[0], argv[0])
        invalid = [
            ["enroll", "awg2", "--confirm-container-id", "a" * 64],
            ["recover", "awg2"], ["add", "awg2", "phone", "key", "10.44.0.3"],
            ["add-profile", "xray", "phone", "10.44.0.3", "host", RECIPIENT],
            ["revoke", "awg2", "phone", "extra"],
            ["add-profile", "awg2", "phone", "10.44.0.3", "host", RECIPIENT,
             "--route", "bad"],
            ["add-profile", "awg2", "phone", "AUTO", "host", RECIPIENT],
            ["status", "awg2", "--docker", "/var/run/docker.sock"],
            ["settings-preview", "awg2", "--docker"],
            ["settings-plan", "wireguard", "c" * 64, "0", '{"Jc":"5"}'],
            ["settings-plan", "awg2", "c" * 64, "0", '{"PrivateKey":"secret"}'],
            ["settings-plan", "awg2", "c" * 64, "0", '{"Jc":"5","Jc":"6"}'],
            ["settings-intent", "wireguard", "c" * 64, "0", "e" * 64, '{"Jc":"5"}'],
            ["settings-apply", "awg2", "c" * 64, "0", "e" * 64,
             '{"PrivateKey":"secret"}', "A" * 43],
            ["settings-apply", "awg2", "c" * 64, "0", "e" * 64,
             '{"Jc":"5"}', "not-a-confirmation"],
            ["sealed-export", "awg2", "phone", "not-a-key"],
            ["revoke", "awg2", "../other"], ["status", "awg2\nrevoke"],
        ]
        for argv in invalid:
            with self.subTest(argv=argv), self.assertRaises(control.AmneziaControlError):
                control.parse_action(argv)

    def test_dispatch_uses_only_approved_methods_and_strips_secret_fields(self):
        admin = FakeAdmin()
        result = control.dispatch(["add-profile", "awg2", "phone", "10.44.0.3",
                                   "vpn.example.com", RECIPIENT, "--route", "full"], admin)
        self.assertEqual(admin.calls[-1][0], "create_profile")
        self.assertEqual(admin.calls[-1][-1], "full")
        self.assertEqual(set(result["sealed_profile"]), control.ENVELOPE_FIELDS)
        self.assertNotIn("MUST_NOT_LEAK", str(result))
        exported = control.dispatch(["sealed-export", "awg2", "phone", RECIPIENT], admin)
        self.assertEqual(set(exported), control.ENVELOPE_FIELDS)
        self.assertNotIn("MUST_NOT_LEAK", str(exported))
        for argv in (["revoke", "awg2", "phone"], ["status", "awg2"]):
            self.assertNotIn("MUST_NOT_LEAK", str(control.dispatch(argv, admin)))
        preview = control.dispatch(["settings-preview", "awg2"], admin)
        self.assertEqual(set(preview), control.PREVIEW_FIELDS)
        self.assertEqual(admin.calls[-1], ("settings_preview",))

    def test_settings_plan_has_exact_public_schema_and_never_applies(self):
        admin = FakeAdmin()
        argv = ["settings-plan", "awg2", "c" * 64, "0", '{"Jc":"5"}']
        result = control.dispatch(argv, admin)
        self.assertEqual(set(result), control.PLAN_FIELDS)
        self.assertEqual(admin.calls[-1], ("settings_plan", "c" * 64, 0, {"Jc": "5"}))
        self.assertEqual(result["changed_fields"], ["Jc"])
        self.assertFalse(result["apply_supported"])
        for mutation in ({"PrivateKey": "secret"}, {"apply_supported": True},
                         {"proposed_awg_parameters": {"Jc": "5", "HeaderProtectionKey": "secret"}},
                         {"changed_fields": ["H1"]}):
            with self.subTest(mutation=mutation), patch.object(
                    admin, "settings_plan", return_value={**result, **mutation}):
                with self.assertRaises(control.AmneziaControlError):
                    control.dispatch(argv, admin)

    def test_settings_intent_and_apply_have_exact_bounded_public_schema(self):
        admin = FakeAdmin()
        before = ["settings-intent", "awg2", "c" * 64, "0", "e" * 64, '{"Jc":"5"}']
        intent = control.dispatch(before, admin)
        self.assertEqual(set(intent), control.INTENT_FIELDS)
        self.assertEqual(admin.calls[-1], ("settings_intent", "c" * 64, 0,
                                           "e" * 64, {"Jc": "5"}))
        self.assertNotIn("MUST_NOT_LEAK", str(intent))
        apply = ["settings-apply", "awg2", "c" * 64, "0", "e" * 64,
                 '{"Jc":"5"}', "A" * 43]
        result = control.dispatch(apply, admin)
        self.assertEqual(set(result), control.SETTINGS_APPLY_FIELDS)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["config_sha256"], "e" * 64)
        self.assertNotIn("MUST_NOT_LEAK", str(result))
        for mutation in ({"private_key": "MUST_NOT_LEAK"},
                         {"confirmation_id": "short"},
                         {"configured_clients": 1}, {"changed_fields": ["HeaderProtectionKey"]},
                         {"generation": True}, {"target": "wireguard"}):
            with self.subTest(mutation=mutation), patch.object(
                    admin, "settings_intent", return_value={**admin.settings_intent(
                        "c" * 64, 0, "e" * 64, {"Jc": "5"}), **mutation}):
                with self.assertRaises(control.AmneziaControlError):
                    control.dispatch(before, admin)
        with patch.object(admin, "settings_apply_confirmed", return_value={
                "target": "awg2", "action": "settings_updated", "generation": 1,
                "config_sha256": "c" * 64, "cleanup_required": False}):
            with self.assertRaises(control.AmneziaControlError):
                control.dispatch(apply, admin)

    def test_settings_preview_rejects_extra_secret_or_malformed_fields(self):
        admin = FakeAdmin()
        good = admin.settings_preview()
        for changed in ({"private_key": "MUST_NOT_LEAK"},
                        {"target": "wireguard"}, {"listen_port": True},
                        {"server_subnet": "10.44.0.0/33"},
                        {"awg_parameters": {"HeaderProtectionKey": "MUST_NOT_LEAK"}},
                        {"awg_parameters": {"Jc": "65536"}},
                        {"apply_supported": True}):
            with self.subTest(changed=changed), patch.object(
                    admin, "settings_preview", return_value={**good, **changed}):
                with self.assertRaises(control.AmneziaControlError):
                    control.dispatch(["settings-preview", "awg2"], admin)

    def test_wireguard_dispatch_binds_results_to_requested_target(self):
        admin = FakeAdmin("wireguard")
        added = control.dispatch(["add-profile", "wireguard", "phone", "10.44.0.3",
                                  "vpn.example.com", RECIPIENT], admin)
        self.assertEqual(added["profile_format"], "wg-conf")
        self.assertEqual(added["target"], "wireguard")
        self.assertEqual(control.dispatch(["status", "wireguard"], admin)["target"],
                         "wireguard")
        self.assertEqual(control.dispatch(["revoke", "wireguard", "phone"], admin)["target"],
                         "wireguard")
        with self.assertRaises(control.AmneziaControlError):
            control.dispatch(["status", "awg2"], admin)
        with patch.object(admin, "create_profile", return_value={
                "target": "wireguard", "action": "added", "client": "phone",
                "configured_clients": 2, "cleanup_required": False,
                "profile_format": "awg3-conf", "sealed_profile": ENVELOPE}):
            with self.assertRaises(control.AmneziaControlError):
                control.dispatch(["add-profile", "wireguard", "phone", "10.44.0.3",
                                  "vpn.example.com", RECIPIENT], admin)

    def test_rejects_noncanonical_or_oversized_envelope(self):
        for mutation in ({"salt": "!"}, {"nonce": encoded(b"\x01" * 11)},
                         {"ciphertext": encoded(b"\x01" * 4097)},
                         {"version": True}, {"extra": "secret"},
                         {"ephemeral_public_key": encoded(b"\x03" + b"\x01" * 64)}):
            with self.subTest(mutation=tuple(mutation)):
                envelope = {**ENVELOPE, **mutation}
                with self.assertRaises(control.AmneziaControlError):
                    control._envelope(envelope)
        with self.assertRaises(control.AmneziaControlError):
            control._envelope({**ENVELOPE, "private_key": "MUST_NOT_LEAK"})

    def test_rejects_manager_result_with_wrong_client_or_types(self):
        admin = FakeAdmin()
        with patch.object(admin, "revoke", return_value={
                "target": "awg2", "action": "revoked", "client": "other",
                "configured_clients": 1, "cleanup_required": False}):
            with self.assertRaises(control.AmneziaControlError):
                control.dispatch(["revoke", "awg2", "phone"], admin)
        with patch.object(admin, "status", return_value={
                "target": "awg2", "enrolled": True,
                "recovery_required": False, "owned_clients": ["PRIVATE KEY=secret"]}):
            with self.assertRaises(control.AmneziaControlError):
                control.dispatch(["status", "awg2"], admin)

    def test_broker_is_disabled_without_exact_private_root_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "enabled"
            with patch.object(control, "ENABLE_FILE", marker):
                self.assertFalse(control._enabled())
                marker.write_text("enabled\n")
                marker.chmod(0o644)
                self.assertFalse(control._enabled())
                marker.chmod(0o600)
                if marker.stat().st_uid != 0:
                    self.assertFalse(control._enabled())
                marker.write_text("enable\n")
                self.assertFalse(control._enabled())
            settings = Path(temporary) / "settings-enabled"
            with patch.object(control, "SETTINGS_ENABLE_FILE", settings), \
                 patch.object(control, "_enabled", return_value=True):
                self.assertFalse(control._settings_enabled())
                settings.write_text("enabled\n")
                settings.chmod(0o644)
                self.assertFalse(control._settings_enabled())


if __name__ == "__main__":
    unittest.main()
