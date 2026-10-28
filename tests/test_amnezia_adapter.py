# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read-only Amnezia details never expose existing credentials."""

from __future__ import annotations

import base64
from contextlib import redirect_stdout
import io
import json
import subprocess
import unittest
from unittest.mock import patch

from sovagrid_vpn.__main__ import main
from sovagrid_vpn.amnezia_adapter import (ProbeError, collect_amnezia_details,
                                         parse_wg_config)


def key(number: int) -> str:
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


DEFAULT_UUID = "11111111-1111-4111-8111-111111111111"
GUEST_UUID = "22222222-2222-4222-8222-222222222222"


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.awg_config = (f"[Interface]\nPrivateKey = {key(1)}\n"
                           "HeaderProtectionKey = PRIVATE\n"
                           f"[Peer]\nPublicKey = {key(2)}\n"
                           "AllowedIPs = 10.8.1.2/32\n").encode()
        self.wg_config = (f"[Interface]\nPrivateKey = {key(3)}\n"
                          f"[Peer]\nPublicKey = {key(4)}\n"
                          "AllowedIPs = 10.8.2.2/32\n").encode()
        self.xray_config = json.dumps({
            "inbounds": [{"protocol": "vless", "settings": {"clients": [
                {"id": DEFAULT_UUID, "flow": "xtls-rprx-vision"},
                {"id": GUEST_UUID, "flow": "xtls-rprx-vision"}]},
                "streamSettings": {"realitySettings": {"privateKey": "XRAY_PRIVATE"}}}]
        }).encode()
        self.files = {
            ("amnezia-awg2", "/opt/amnezia/awg/awg0.conf"): self.awg_config,
            ("amnezia-awg2", "/opt/amnezia/awg/clientsTable"):
                json.dumps([{"clientId": key(2), "userData": {"clientName": "PERSON"}}]).encode(),
            ("amnezia-wireguard", "/opt/amnezia/wireguard/wg0.conf"): self.wg_config,
            ("amnezia-wireguard", "/opt/amnezia/wireguard/clientsTable"):
                json.dumps([{"clientId": key(4)}]).encode(),
            ("amnezia-xray", "/opt/amnezia/xray/server.json"): self.xray_config,
            ("amnezia-xray", "/opt/amnezia/xray/clientsTable"):
                json.dumps([{"clientId": GUEST_UUID, "userData": {"clientName": "PERSON"}}]).encode(),
            ("amnezia-xray", "/opt/amnezia/xray/xray_uuid.key"):
                (DEFAULT_UUID + "\n").encode(),
        }
        self.awg_dump = ("PRIVATE_INTERFACE\tSERVER_PUBLIC\t42683\toff\n"
                         f"{key(2)}\tPSK_SECRET\t(none)\t10.8.1.2/32\t990\t123\t456\toff\n").encode()

    def __call__(self, command, **kwargs):
        self.calls.append(tuple(command))
        if command[:3] != ("docker", "exec", command[2]):
            raise AssertionError("unexpected Docker command")
        container = command[2]
        if command[3:6] == ("head", "-c", "65537"):
            data = self.files.get((container, command[6]))
            return subprocess.CompletedProcess(command, 0 if data is not None else 1, data or b"", b"SECRET")
        if command[3:] == ("awg", "show", "awg0", "dump"):
            return subprocess.CompletedProcess(command, 0, self.awg_dump, b"SECRET")
        if command[3:] == ("wg", "show", "wg0", "dump"):
            return subprocess.CompletedProcess(command, 1, b"", b"SECRET")
        if command[3:] == ("pgrep", "-x", "xray"):
            return subprocess.CompletedProcess(command, 0, b"123", b"")
        raise AssertionError(f"unexpected fixed Docker operation: {command!r}")


class AmneziaAdapterTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeDocker()
        self.inventory = {"services": [{"name": name, "state": "running"}
                                       for name in ("amnezia-awg2", "amnezia-wireguard",
                                                    "amnezia-xray")]}

    def details(self):
        return collect_amnezia_details(runner=self.fake, timestamp=1000,
                                       inventory=self.inventory)

    def test_ready_down_and_xray_default_are_distinct_and_redacted(self):
        details = self.details()
        self.assertEqual(details["source_status"], "ok")
        by_name = {row["name"]: row for row in details["services"]}
        awg = by_name["amnezia-awg2"]
        self.assertEqual((awg["status"], awg["configured_clients"],
                          awg["runtime_clients"], awg["active_last_3m"]),
                         ("ready", 1, 1, 1))
        self.assertEqual((awg["received_bytes"], awg["sent_bytes"]), (123, 456))
        self.assertTrue(awg["awg3_fields"])
        self.assertEqual(by_name["amnezia-wireguard"]["status"], "interface_down")
        self.assertEqual(by_name["amnezia-xray"]["configured_clients"], 1)
        self.assertEqual(by_name["amnezia-xray"]["status"], "ready")
        encoded = json.dumps(details)
        for secret in (key(1), key(2), key(3), key(4), "PRIVATE_INTERFACE",
                       "PSK_SECRET", "XRAY_PRIVATE", "PERSON", DEFAULT_UUID,
                       GUEST_UUID, "10.8.1.2"):
            self.assertNotIn(secret, encoded)
        self.assertTrue(all(command[:2] == ("docker", "exec") for command in self.fake.calls))
        self.assertTrue(all("sh" not in command and "bash" not in command
                            for command in self.fake.calls))

    def test_drift_and_conflict_are_detected_without_exposing_keys(self):
        self.fake.files[("amnezia-awg2", "/opt/amnezia/awg/clientsTable")] = b"[]"
        details = self.details()
        self.assertEqual(details["services"][0]["status"], "registry_drift")
        self.fake.awg_config += (f"[Peer]\nPublicKey = {key(5)}\n"
                                 "AllowedIPs = 10.8.1.2/32\n").encode()
        self.fake.files[("amnezia-awg2", "/opt/amnezia/awg/awg0.conf")] = self.fake.awg_config
        details = self.details()
        self.assertEqual(details["services"][0]["status"], "error")
        self.assertNotIn(key(5), json.dumps(details))

    def test_parser_rejects_duplicate_peer_addresses(self):
        config = self.fake.awg_config + (f"[Peer]\nPublicKey = {key(5)}\n"
                                         "AllowedIPs = 10.8.1.2/32\n").encode()
        with self.assertRaisesRegex(ProbeError, "address conflict"):
            parse_wg_config(config)

    def test_source_error_yields_no_misleading_container_down_rows(self):
        details = collect_amnezia_details(runner=self.fake, timestamp=1000,
                                          inventory={"source_status": "error", "services": []})
        self.assertEqual(details, {"schema_version": 1, "collected_at": 1000,
                                   "source_status": "error", "services": []})
        self.assertEqual(self.fake.calls, [])

    def test_image_mismatch_does_not_exec_into_reused_container_name(self):
        self.inventory["services"][0]["state"] = "identity_mismatch"
        details = self.details()
        self.assertEqual(details["services"][0]["status"], "identity_mismatch")
        self.assertTrue(all(command[2] != "amnezia-awg2" for command in self.fake.calls))

    def test_publisher_attaches_versioned_details_without_changing_outer_schema(self):
        docker = {"schema_version": 1, "collected_at": 1000, "source": "docker_cli",
                  "source_status": "ok", "services": self.inventory["services"]}
        details = self.details()
        output = io.StringIO()
        with patch("sovagrid_vpn.__main__.collect_snapshot", return_value=docker), \
             patch("sovagrid_vpn.__main__.collect_managed_instances",
                   return_value={"source_status": "ok", "instances": []}), \
             patch("sovagrid_vpn.__main__.collect_amnezia_details", return_value=details) as probe, \
             redirect_stdout(output):
            self.assertEqual(main([]), 0)
        snapshot = json.loads(output.getvalue())
        self.assertEqual(snapshot["schema_version"], 1)
        self.assertEqual(snapshot["amnezia_details"], details)
        probe.assert_called_once_with(inventory=docker, timestamp=1000)
        self.assertNotIn("PRIVATE_INTERFACE", output.getvalue())

    def test_publisher_isolates_probe_exception_without_leaking_message(self):
        docker = {"schema_version": 1, "collected_at": 1000, "source": "docker_cli",
                  "source_status": "ok", "services": []}
        output = io.StringIO()
        with patch("sovagrid_vpn.__main__.collect_snapshot", return_value=docker), \
             patch("sovagrid_vpn.__main__.collect_managed_instances",
                   return_value={"source_status": "ok", "instances": []}), \
             patch("sovagrid_vpn.__main__.collect_amnezia_details",
                   side_effect=RuntimeError("SECRET_PRIVATE_KEY")), \
             redirect_stdout(output):
            self.assertEqual(main([]), 0)
        snapshot = json.loads(output.getvalue())
        self.assertEqual(snapshot["amnezia_details"], {
            "schema_version": 1, "collected_at": 1000,
            "source_status": "error", "services": [],
        })
        self.assertNotIn("SECRET_PRIVATE_KEY", output.getvalue())


if __name__ == "__main__":
    unittest.main()
