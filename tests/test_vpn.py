# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from sovagrid_vpn import InventoryError, collect_snapshot, parse_docker_ps, plan_wireguard
from sovagrid_vpn.__main__ import write_snapshot
from sovagrid_vpn.inventory import DOCKER_COMMAND


def row(**values):
    return json.dumps(values)


class InventoryTests(unittest.TestCase):
    def test_allowlist_redaction_health_and_port_deduplication(self):
        raw = "\n".join([
            row(Names="amnezia-awg2", Image="amnezia-awg2", State="running",
                Status="Up 2 days (healthy)", Ports="0.0.0.0:42683->42683/udp, [::]:42683->42683/udp",
                Env=["PASSWORD=secret"], Command="--token secret"),
            row(Names="sovagrid-hub-1", Image="sovagrid-hub", State="running", Ports="0.0.0.0:8000->80/tcp"),
        ])
        snapshot = parse_docker_ps(raw, timestamp=100)
        service = next(item for item in snapshot["services"] if item["name"] == "amnezia-awg2")
        self.assertEqual(service["state"], "running")
        self.assertEqual(service["health"], "healthy")
        self.assertEqual(service["published_ports"], [{"port": 42683, "protocol": "udp"}])
        self.assertEqual(snapshot["collected_at"], 100)
        self.assertEqual(len(snapshot["services"]), 8)
        self.assertNotIn("secret", json.dumps(snapshot))
        self.assertNotIn("sovagrid-hub", json.dumps(snapshot))

    def test_absent_and_mismatched_images_are_distinct(self):
        snapshot = parse_docker_ps(row(Names="amnezia-xray", Image="unrelated:latest",
                                       State="running", Ports="0.0.0.0:443->443/tcp"), timestamp=1)
        xray = next(item for item in snapshot["services"] if item["name"] == "amnezia-xray")
        self.assertEqual(xray["state"], "identity_mismatch")
        self.assertEqual(xray["published_ports"], [])
        self.assertEqual(snapshot["services"][0]["state"], "absent")

    def test_malformed_duplicate_and_oversized_input(self):
        with self.assertRaises(InventoryError):
            parse_docker_ps("not json")
        entry = row(Names="amnezia-xray", Image="amnezia-xray", State="running")
        with self.assertRaises(InventoryError):
            parse_docker_ps(entry + "\n" + entry)
        with self.assertRaises(InventoryError):
            parse_docker_ps("x" * (256 * 1024 + 1))
        # Unexpected JSON types must not crash the publisher.
        snapshot = parse_docker_ps(row(Names=["amnezia-awg2"], State=[]))
        self.assertTrue(all(item["state"] == "absent" for item in snapshot["services"]))

    def test_runner_uses_only_read_only_docker_command_and_hides_stderr(self):
        calls = []
        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout=row(Names="amnezia-ipsec", Image="amnezia-ipsec", State="running"), stderr="secret")
        snapshot = collect_snapshot(runner, timestamp=5)
        self.assertEqual(calls[0][0], DOCKER_COMMAND)
        self.assertEqual(calls[0][1]["timeout"], 8)
        self.assertEqual(snapshot["source_status"], "ok")
        def failure(command, **kwargs):
            return SimpleNamespace(returncode=1, stdout="", stderr="TOKEN=secret")
        with self.assertRaisesRegex(InventoryError, "unavailable") as context:
            collect_snapshot(failure)
        self.assertNotIn("secret", str(context.exception))

    def test_atomic_private_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "status.json"
            snapshot = parse_docker_ps("", timestamp=7)
            write_snapshot(str(target), snapshot)
            self.assertEqual(json.loads(target.read_text()), snapshot)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(directory).glob(".vpn-status-*")), [])


class ProposalTests(unittest.TestCase):
    def test_plan_reports_known_docker_port_collision_and_cannot_apply(self):
        snapshot = parse_docker_ps(row(Names="amnezia-wireguard", Image="amnezia-wireguard",
                                       State="running", Ports="0.0.0.0:33151->33151/udp"), timestamp=1)
        plan = plan_wireguard("demo-vpn", 33151, "10.49.0.0/24", snapshot)
        self.assertEqual(plan["docker_udp_port_conflicts"], ["amnezia-wireguard"])
        self.assertFalse(plan["can_apply"])

    def test_plan_rejects_invalid_inputs_and_unavailable_inventory(self):
        snapshot = parse_docker_ps("", timestamp=1)
        for args in [("../bad", 51820, "10.49.0.0/24"),
                     ("demo-vpn", True, "10.49.0.0/24"),
                     ("demo-vpn", 51820, "8.8.8.0/24"),
                     ("demo-vpn", 51820, "10.49.0.1/24")]:
            with self.assertRaises(ValueError):
                plan_wireguard(*args, snapshot)
        with self.assertRaises(ValueError):
            plan_wireguard("demo-vpn", 51820, "10.49.0.0/24", {"source_status": "error"})


if __name__ == "__main__":
    unittest.main()
