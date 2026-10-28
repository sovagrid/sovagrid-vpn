# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Isolated nftables routing policy tests; no host network changes."""

from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from sovagrid_vpn.routing import (RoutingError, RoutingPaths, RoutingSetup,
                                  SYSCTL_CONTENT, UNIT_CONTENT, _expected_expr,
                                  _table_name, full_route_ready)


class FakeManager:
    def __init__(self):
        self.state = {"name": "phone-vpn", "interface": "sg615ed6c9020",
                      "subnet": "10.49.0.0/24"}

    def _locked(self):
        return nullcontext()

    def _state(self, name):
        if name != self.state["name"]:
            raise FileNotFoundError(name)
        return dict(self.state)


class FakeTools:
    def __init__(self, manager, paths):
        self.manager = manager
        self.paths = paths
        self.tables = {}
        self.enabled = False
        self.fail_add = False
        self.dropins = ""
        self.calls = []

    def __call__(self, argv, **kwargs):
        argv = tuple(argv)
        self.calls.append(argv)
        output, code = "", 0
        if argv == ("nft", "-j", "list", "tables"):
            output = json.dumps({"nftables": [{"metainfo": {"json_schema_version": 1}}] +
                                 [{"table": {"family": "ip", "name": name}} for name in self.tables]})
        elif argv[:5] == ("nft", "-j", "list", "table", "ip"):
            name = argv[5]
            output = json.dumps({"nftables": [{"metainfo": {"json_schema_version": 1}}] + self.tables[name]})
        elif argv == ("nft", "-f", "-"):
            if self.fail_add:
                code = 1
            else:
                name = _table_name(self.manager.state)
                assert f"add table ip {name}\n" in kwargs["input"]
                self.tables[name] = self._owned_rows()
        elif argv[:4] == ("nft", "delete", "table", "ip"):
            del self.tables[argv[4]]
        elif argv == ("systemctl", "is-enabled", "--quiet", "sovagrid-vpn-routing.service"):
            code = 0 if self.enabled else 1
        elif argv == ("systemctl", "show", "sovagrid-vpn-routing.service",
                      "--property=LoadState,FragmentPath,DropInPaths"):
            loaded = self.paths.unit.exists()
            output = (f"LoadState={'loaded' if loaded else 'not-found'}\n"
                      f"FragmentPath={self.paths.unit if loaded else ''}\nDropInPaths={self.dropins}\n")
        elif argv == ("systemctl", "enable", "sovagrid-vpn-routing.service"):
            self.enabled = True
        elif argv == ("systemctl", "disable", "--now", "sovagrid-vpn-routing.service"):
            self.enabled = False
        elif argv == ("systemctl", "daemon-reload"):
            pass
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, code, output, "secret diagnostic")

    def _owned_rows(self):
        state = self.manager.state
        table = _table_name(state)
        return [
            {"table": {"family": "ip", "name": table, "handle": 7}},
            {"chain": {"family": "ip", "table": table, "name": "postrouting",
                       "type": "nat", "hook": "postrouting", "prio": 100,
                       "policy": "accept", "handle": 8}},
            {"rule": {"family": "ip", "table": table, "chain": "postrouting",
                      "expr": _expected_expr(state), "handle": 9}},
        ]


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.manager = FakeManager()
        self.paths = RoutingPaths(root=root / "policy", unit=root / "sovagrid-vpn-routing.service",
                                  sysctl=root / "70-sovagrid-vpn-routing.conf", forward=root / "ip_forward")
        self.tools = FakeTools(self.manager, self.paths)
        self.paths.forward.write_bytes(b"0\n")
        self.setup = RoutingSetup(manager=self.manager, paths=self.paths, runner=self.tools,
                                  require_root=False)

    def test_preview_arm_reboot_replay_and_disarm(self):
        before = self.setup.preview("phone-vpn")
        self.assertFalse(self.paths.root.exists(), "preview must not create root files")
        self.assertFalse(before["routing_configured"])
        self.assertTrue(before["upstream_firewall_unverified"])
        armed = self.setup.arm("phone-vpn", before["state_revision"])
        self.assertTrue(armed["routing_configured"])
        self.assertTrue(full_route_ready(self.manager.state, setup=self.setup))
        self.assertEqual(self.paths.unit.read_bytes(), UNIT_CONTENT)
        self.assertEqual(self.paths.sysctl.read_bytes(), SYSCTL_CONTENT)
        self.assertTrue(self.tools.enabled)
        self.assertEqual(self.paths.forward.read_bytes(), b"1\n")
        self.tools.tables.clear()
        self.paths.forward.write_bytes(b"0\n")
        self.assertFalse(full_route_ready(self.manager.state, setup=self.setup))
        replay = self.setup.sync()
        self.assertEqual(replay, {"enabled": ["phone-vpn"], "routing_configured": True})
        before = self.setup.preview("phone-vpn")
        disarmed = self.setup.disarm("phone-vpn", before["state_revision"])
        self.assertFalse(disarmed["routing_configured"])
        self.assertFalse(self.tools.tables)
        self.assertFalse(self.tools.enabled)
        self.assertFalse(self.paths.unit.exists())
        self.assertFalse(self.paths.sysctl.exists())
        self.assertEqual(self.paths.forward.read_bytes(), b"1\n",
                         "disarming must not reset global forwarding used by other services")

    def test_stale_preview_and_foreign_rule_fail_closed(self):
        before = self.setup.preview("phone-vpn")
        with self.assertRaisesRegex(RoutingError, "STALE_PREVIEW"):
            self.setup.arm("phone-vpn", "0" * 64)
        name = _table_name(self.manager.state)
        self.tools.tables[name] = self.tools._owned_rows()
        self.tools.tables[name][2]["rule"]["expr"][0]["match"]["right"]["prefix"]["len"] = 16
        with self.assertRaisesRegex(RoutingError, "STALE_PREVIEW"):
            self.setup.arm("phone-vpn", before["state_revision"])
        changed = self.setup.preview("phone-vpn")
        self.assertFalse(changed["nat"])
        with self.assertRaisesRegex(RoutingError, "FOREIGN_NFT_TABLE"):
            self.setup.arm("phone-vpn", changed["state_revision"])
        self.assertFalse(self.paths.policy.exists())

    def test_failed_nft_activation_is_never_reported_ready_and_can_retry(self):
        self.tools.fail_add = True
        before = self.setup.preview("phone-vpn")
        with self.assertRaisesRegex(RoutingError, "ROUTING_COMMAND_FAILED"):
            self.setup.arm("phone-vpn", before["state_revision"])
        recovery = self.setup.preview("phone-vpn")
        self.assertTrue(recovery["armed"])
        self.assertTrue(recovery["recovery_required"])
        self.assertFalse(full_route_ready(self.manager.state, setup=self.setup))
        self.tools.fail_add = False
        self.assertTrue(self.setup.arm("phone-vpn", recovery["state_revision"])["routing_configured"])

    def test_foreign_sysctl_is_preserved(self):
        self.paths.sysctl.write_bytes(b"net.ipv4.ip_forward = 0\n")
        self.paths.sysctl.chmod(0o644)
        before = self.setup.preview("phone-vpn")
        with self.assertRaisesRegex(RoutingError, "FOREIGN_CONFIGURATION"):
            self.setup.arm("phone-vpn", before["state_revision"])
        self.assertEqual(self.paths.sysctl.read_bytes(), b"net.ipv4.ip_forward = 0\n")
        self.assertFalse(self.paths.policy.exists())

    def test_orphaned_owned_table_requires_explicit_disarm_recovery(self):
        name = _table_name(self.manager.state)
        self.tools.tables[name] = self.tools._owned_rows()
        preview = self.setup.preview("phone-vpn")
        self.assertTrue(preview["recovery_required"])
        with self.assertRaisesRegex(RoutingError, "RECOVERY_REQUIRED"):
            self.setup.arm("phone-vpn", preview["state_revision"])
        after = self.setup.disarm("phone-vpn", preview["state_revision"])
        self.assertFalse(after["recovery_required"])
        self.assertNotIn(name, self.tools.tables)

    def test_existing_global_files_without_policy_are_not_adopted(self):
        self.paths.unit.write_bytes(UNIT_CONTENT)
        self.paths.unit.chmod(0o644)
        self.paths.sysctl.write_bytes(SYSCTL_CONTENT)
        self.paths.sysctl.chmod(0o644)
        preview = self.setup.preview("phone-vpn")
        self.assertTrue(preview["recovery_required"])
        with self.assertRaisesRegex(RoutingError, "RECOVERY_REQUIRED"):
            self.setup.arm("phone-vpn", preview["state_revision"])
        recovered = self.setup.disarm("phone-vpn", preview["state_revision"])
        self.assertFalse(recovered["recovery_required"])
        self.assertFalse(self.paths.unit.exists())
        self.assertFalse(self.paths.sysctl.exists())

    def test_nft_json_variants_and_extra_rules(self):
        name = _table_name(self.manager.state)
        rows = self.tools._owned_rows()
        rows[2]["rule"]["expr"][2] = {"masquerade": None}
        self.tools.tables[name] = [rows[2], rows[0], rows[1]]
        self.assertEqual(self.setup._nft_table(self.manager.state), "owned")
        self.tools.tables[name].append({"rule": dict(rows[2]["rule"])})
        self.assertEqual(self.setup._nft_table(self.manager.state), "foreign")

    def test_systemd_dropin_and_symlinked_parent_are_rejected(self):
        before = self.setup.preview("phone-vpn")
        self.tools.dropins = "/etc/systemd/system/sovagrid-vpn-routing.service.d/override.conf"
        before = self.setup.preview("phone-vpn")
        with self.assertRaisesRegex(RoutingError, "FOREIGN_SYSTEMD_UNIT"):
            self.setup.arm("phone-vpn", before["state_revision"])
        self.tools.dropins = ""
        link = Path(self.temp.name) / "linked-systemd"
        link.symlink_to(Path(self.temp.name), target_is_directory=True)
        paths = RoutingPaths(root=self.paths.root, unit=link / "sovagrid-vpn-routing.service",
                             sysctl=self.paths.sysctl, forward=self.paths.forward)
        linked = RoutingSetup(manager=self.manager, paths=paths, runner=self.tools, require_root=False)
        with self.assertRaisesRegex(RoutingError, "UNSAFE_DIRECTORY"):
            linked.preview("phone-vpn")

    def test_disarm_one_instance_keeps_shared_boot_artifacts(self):
        before = self.setup.preview("phone-vpn")
        armed = self.setup.arm("phone-vpn", before["state_revision"])
        policy = self.setup._policy()
        policy["enabled"] = ["other-vpn", "phone-vpn"]
        self.setup._save_policy(policy)
        preview = self.setup.preview("phone-vpn")
        after = self.setup.disarm("phone-vpn", preview["state_revision"])
        self.assertFalse(after["routing_configured"])
        self.assertEqual(self.setup._policy()["enabled"], ["other-vpn"])
        self.assertTrue(self.paths.unit.exists())
        self.assertTrue(self.paths.sysctl.exists())
        self.assertTrue(self.tools.enabled)


if __name__ == "__main__":
    unittest.main()
