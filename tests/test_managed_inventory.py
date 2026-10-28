# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Managed status contains no credential material and cannot hide Docker data."""

from __future__ import annotations

import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from sovagrid_vpn.__main__ import main
from sovagrid_vpn.managed import ManagedWireGuard
from sovagrid_vpn.managed_inventory import collect_managed_instances
from test_managed import FakeCommands


class ManagedInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.wg_dir = self.root / "wireguard"
        self.wg_dir.mkdir(mode=0o700)
        self.fake = FakeCommands()
        self.fake.wg_dir = self.wg_dir
        self.manager = ManagedWireGuard(state_root=self.root / "state",
                                        wireguard_dir=self.wg_dir, runner=self.fake,
                                        require_root=False, check_network=False)

    def collect(self):
        return collect_managed_instances(state_root=self.root / "state",
                                         wireguard_dir=self.wg_dir, runner=self.fake,
                                         require_root=False)

    def test_empty_staged_active_and_credentials_are_never_serialized(self):
        self.assertEqual(self.collect(), {"source_status": "ok", "instances": []})
        self.manager.create("phone-vpn", 51821, "10.49.0.0/24", "8.8.8.8")
        self.manager.add_client("phone-vpn", "alice")
        staged = self.collect()
        self.assertEqual(staged["instances"][0]["state"], "stopped")
        self.assertEqual(staged["instances"][0]["client_count"], 1)
        self.assertEqual(set(staged["instances"][0]), {
            "name", "interface", "port", "subnet", "client_count", "state",
        })
        self.manager.activate("phone-vpn")
        active = self.collect()
        self.assertEqual(active["instances"][0]["state"], "active")
        serialized = json.dumps(active)
        state = json.loads((self.root / "state" / "phone-vpn" / "state.json").read_text())
        for secret in (state["server_private_key"], state["server_public_key"],
                       state["clients"]["alice"]["private_key"],
                       state["clients"]["alice"]["public_key"],
                       state["clients"]["alice"]["preshared_key"],
                       state["clients"]["alice"]["address"], state["endpoint"],
                       str(self.root / "state" / "phone-vpn" / "clients" / "alice.conf")):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("profile", serialized)
        self.assertNotIn("peer", serialized)

    def test_pending_or_drifted_instance_is_error_without_private_fields(self):
        self.manager.create("phone-vpn", 51821, "10.49.0.0/24", "8.8.8.8")
        journal = self.root / "state" / "phone-vpn" / "transaction.json"
        journal.write_text("{}")
        item = self.collect()["instances"][0]
        self.assertEqual(item["state"], "error")
        self.assertIsNone(item["port"])
        journal.unlink()
        self.manager.activate("phone-vpn")
        self.fake.live["port"] = "51822"
        self.assertEqual(self.collect()["instances"][0]["state"], "error")

    def test_slow_runtime_probe_does_not_hold_management_lock(self):
        self.manager.create("phone-vpn", 51821, "10.49.0.0/24", "8.8.8.8")
        probing = threading.Event()
        finish_probe = threading.Event()
        result = {}
        original_runtime = ManagedWireGuard._runtime

        def slow_runtime(manager, state, acceptable):
            probing.set()
            if not finish_probe.wait(3):
                raise TimeoutError("runtime probe was not released")
            return original_runtime(manager, state, acceptable)

        def collect_in_thread():
            result["snapshot"] = self.collect()

        with patch.object(ManagedWireGuard, "_runtime", slow_runtime):
            worker = threading.Thread(target=collect_in_thread, daemon=True)
            worker.start()
            try:
                self.assertTrue(probing.wait(2), "inventory did not reach the runtime probe")
                lock_fd = os.open(self.root / "state" / ".lock", os.O_RDWR | os.O_NOFOLLOW)
                acquired = False
                try:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = True
                    except BlockingIOError:
                        pass
                finally:
                    if acquired:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    os.close(lock_fd)
                self.assertTrue(acquired, "slow status probe still holds the management lock")
            finally:
                finish_probe.set()
                worker.join(3)
            self.assertFalse(worker.is_alive(), "inventory thread did not finish")
        self.assertEqual(result["snapshot"]["instances"][0]["state"], "stopped")

    def test_docker_failure_does_not_discard_managed_snapshot(self):
        self.manager.create("phone-vpn", 51821, "10.49.0.0/24", "8.8.8.8")
        out = io.StringIO()
        from sovagrid_vpn.inventory import InventoryError
        with patch("sovagrid_vpn.__main__.collect_snapshot", side_effect=InventoryError("unavailable")), \
             patch("sovagrid_vpn.__main__.collect_managed_instances", side_effect=self.collect), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([]), 2)
        snapshot = json.loads(out.getvalue())
        self.assertEqual(snapshot["source_status"], "error")
        self.assertEqual(snapshot["managed"]["instances"][0]["name"], "phone-vpn")


if __name__ == "__main__":
    unittest.main()
