# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Security-sensitive managed WireGuard lifecycle tests (no root or network)."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from sovagrid_vpn.managed import ManagedVpnError, ManagedWireGuard, interface_name


def key(number: int) -> str:
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


class FakeCommands:
    def __init__(self):
        self.calls = []
        self.number = 0
        self.last_private = ""
        self.server_public = key(2)
        self.active = False
        self.enabled = False
        self.orphan_iface = False
        self.live = None
        self.wg_dir = None
        self.fail_sync = False
        self.fail_enable = False
        self.routes = []
        self.addresses = []
        self.docker_containers = ""
        self.docker_networks = ""
        self.docker_configs = ""

    def load_config(self, raw):
        config = {"private": "", "port": "", "address": "", "peers": []}
        peer = None
        for line in raw.splitlines():
            line = line.strip()
            if line == "[Peer]":
                peer = {}
                config["peers"].append(peer)
            elif " = " in line:
                field, value = line.split(" = ", 1)
                if peer is None:
                    if field == "PrivateKey":
                        config["private"] = value
                    elif field == "ListenPort":
                        config["port"] = value
                    elif field == "Address":
                        config["address"] = value
                else:
                    peer[field] = value
        self.live = config

    def dump(self):
        if self.live is None:
            raise AssertionError("no live WireGuard config")
        lines = ["\t".join((self.live["private"], self.server_public,
                             self.live["port"], "off"))]
        for peer in self.live["peers"]:
            lines.append("\t".join((peer["PublicKey"], peer["PresharedKey"],
                                    "(none)", peer["AllowedIPs"], "0", "0", "0", "off")))
        return "\n".join(lines) + "\n"

    def __call__(self, args, **kwargs):
        self.calls.append(tuple(args))
        output = ""
        code = 0
        if args[:2] == ("wg", "genkey"):
            self.number += 2
            output = key(self.number - 1) + "\n"
            self.last_private = output.strip()
        elif args[:2] == ("wg", "pubkey"):
            output = key(self.number) + "\n"
            if self.number == 2:
                self.server_public = output.strip()
        elif args[:2] == ("wg", "genpsk"):
            self.number += 1
            output = key(self.number) + "\n"
        elif args[:2] == ("wg", "show"):
            if args[-1] == "dump":
                output = self.dump()
            else:
                output = self.server_public + "\n"
        elif args[:2] == ("wg-quick", "strip"):
            output = Path(args[2]).read_text()
        elif args[:2] == ("wg", "syncconf"):
            code = 1 if self.fail_sync else 0
            if not code:
                self.load_config(Path(args[3]).read_text())
        elif args[:3] == ("systemctl", "is-active", "--quiet"):
            code = 0 if self.active else 3
        elif args[:3] == ("systemctl", "is-enabled", "--quiet"):
            code = 0 if self.enabled else 1
        elif args[:3] == ("systemctl", "enable", "--now"):
            if self.fail_enable:
                code = 1
            else:
                self.active = True
                self.enabled = True
                self.load_config(next(self.wg_dir.glob("sg*.conf")).read_text())
        elif args[:3] == ("systemctl", "disable", "--now"):
            self.active = False
            self.enabled = False
        elif args[:2] == ("systemctl", "stop"):
            self.active = False
        elif args == ("ip", "-j", "route", "show", "table", "all"):
            output = json.dumps(self.routes)
        elif args == ("ip", "-j", "address", "show"):
            output = json.dumps(self.addresses)
        elif len(args) == 6 and args[:5] == ("ip", "-j", "address", "show", "dev"):
            if self.live is None:
                output = "[]"
            else:
                address, prefix = self.live["address"].split("/")
                output = json.dumps([{"addr_info": [{"family": "inet", "local": address,
                                                       "prefixlen": int(prefix)}]}])
        elif args[:4] == ("ip", "link", "show", "dev"):
            code = 0 if self.active or self.orphan_iface else 1
        elif args[:3] == ("docker", "container", "ls"):
            output = self.docker_containers
        elif args[:4] == ("docker", "network", "ls", "-q"):
            output = self.docker_networks
        elif args[:3] == ("docker", "network", "inspect"):
            output = self.docker_configs
        else:
            raise AssertionError(f"Unexpected command: {args}")
        return subprocess.CompletedProcess(args, code, output, "secret diagnostic")


class ManagedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.wg_dir = self.root / "wireguard"
        self.wg_dir.mkdir(mode=0o700)
        self.fake = FakeCommands()
        self.fake.wg_dir = self.wg_dir
        self.manager = ManagedWireGuard(state_root=self.root / "state",
                                        wireguard_dir=self.wg_dir,
                                        runner=self.fake, require_root=False,
                                        check_network=False)

    def create(self, name="demo-vpn", subnet="10.49.0.0/24", port=51820):
        return self.manager.create(name, port, subnet, "8.8.8.8")

    def test_create_is_staged_and_private(self):
        public = self.create()
        self.assertFalse(public["active"])
        self.assertEqual(public["interface"], interface_name("demo-vpn"))
        self.assertFalse(list(self.wg_dir.iterdir()))
        instance = self.root / "state" / "demo-vpn"
        self.assertEqual(stat.S_IMODE(instance.stat().st_mode), 0o700)
        for item in (instance / "state.json", instance / "server.conf"):
            self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o600)
        self.assertNotIn("server_private_key", public)
        self.assertNotIn(key(1), json.dumps(public))

    def test_activate_add_sync_revoke_and_remove_owned_interface(self):
        public = self.create()
        active = self.manager.activate("demo-vpn")
        self.assertTrue(active["active"])
        link = self.wg_dir / f"{public['interface']}.conf"
        self.assertTrue(link.is_symlink())
        added = self.manager.add_client("demo-vpn", "alice")
        self.assertEqual(added["address"], "10.49.0.2")
        profile = Path(added["profile"])
        self.assertEqual(stat.S_IMODE(profile.stat().st_mode), 0o600)
        self.assertIn("AllowedIPs = 10.49.0.0/24", profile.read_text())
        self.assertIn("PresharedKey =", profile.read_text())
        self.assertEqual(self.manager.clients("demo-vpn"),
                         [{"name": "alice", "address": "10.49.0.2"}])
        sync_paths = [Path(call[3]) for call in self.fake.calls
                      if call[:3] == ("wg", "syncconf", public["interface"])]
        self.assertTrue(sync_paths)
        self.assertTrue(all(path.parent == self.wg_dir and path.name.startswith(".sgsync-")
                            and not path.exists() for path in sync_paths))
        self.assertEqual(self.manager.revoke_client("demo-vpn", "alice"),
                         {"name": "alice", "revoked": True, "already_absent": False})
        self.assertFalse(profile.exists())
        self.assertNotIn("# client: alice", link.read_text())
        self.assertEqual(self.manager.remove("demo-vpn", "demo-vpn"),
                         {"name": "demo-vpn", "removed": True})
        self.assertFalse(link.exists())
        self.assertFalse((self.root / "state" / "demo-vpn").exists())

    def test_clients_allocate_unique_addresses_and_reject_exhaustion(self):
        self.create(subnet="10.49.0.0/30")
        self.assertEqual(self.manager.add_client("demo-vpn", "alice")["address"], "10.49.0.2")
        with self.assertRaisesRegex(ManagedVpnError, "no free"):
            self.manager.add_client("demo-vpn", "bob")
        self.assertTrue(self.manager.add_client("demo-vpn", "alice")["existing"])

    def test_conflicts_and_invalid_user_values(self):
        self.create()
        with self.assertRaisesRegex(ManagedVpnError, "conflicts"):
            self.create(name="second", subnet="10.49.0.0/25", port=51821)
        with self.assertRaisesRegex(ManagedVpnError, "conflicts"):
            self.create(name="second", subnet="10.50.0.0/24", port=51820)
        for bad in ("../x", "A", "evil\nPostUp = id", "a" * 40):
            with self.subTest(bad=bad), self.assertRaises(ManagedVpnError):
                self.manager.add_client("demo-vpn", bad)
        for endpoint in ("foo\nPostUp = id", "[::1]", "bad/name"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ManagedVpnError):
                self.manager.create("other", 51822, "10.50.0.0/24", endpoint)

    def test_foreign_symlink_and_profile_are_not_overwritten(self):
        public = self.create()
        foreign = self.root / "foreign"
        foreign.write_text("foreign")
        link = self.wg_dir / f"{public['interface']}.conf"
        link.symlink_to(foreign)
        with self.assertRaisesRegex(ManagedVpnError, "not owned"):
            self.manager.activate("demo-vpn")
        self.assertEqual(foreign.read_text(), "foreign")
        link.unlink()
        client_link = self.root / "state" / "demo-vpn" / "clients" / "alice.conf"
        client_link.symlink_to(foreign)
        with self.assertRaisesRegex(ManagedVpnError, "inventory does not match"):
            self.manager.add_client("demo-vpn", "alice")
        self.assertTrue(client_link.is_symlink())
        self.assertEqual(foreign.read_text(), "foreign")
        client_link.unlink()
        self.manager.add_client("demo-vpn", "alice")
        export_dir = self.root / "export"
        export_dir.mkdir(mode=0o700)
        output = export_dir / "alice.conf"
        output.symlink_to(foreign)
        with self.assertRaisesRegex(ManagedVpnError, "already exists"):
            self.manager.export_client("demo-vpn", "alice", output)
        self.assertEqual(foreign.read_text(), "foreign")

    def test_export_requires_private_directory_and_exclusive_destination(self):
        self.create()
        self.manager.add_client("demo-vpn", "alice")
        directory = self.root / "export"
        directory.mkdir(mode=0o700)
        output = directory / "alice.conf"
        self.manager.export_client("demo-vpn", "alice", output)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaisesRegex(ManagedVpnError, "already exists"):
            self.manager.export_client("demo-vpn", "alice", output)
        directory.chmod(0o755)
        with self.assertRaisesRegex(ManagedVpnError, "unsafe"):
            self.manager.export_client("demo-vpn", "alice", directory / "other.conf")

    def test_sync_failure_leaves_durable_add_for_retry_and_hides_stderr(self):
        self.create()
        self.manager.activate("demo-vpn")
        self.fake.fail_sync = True
        with self.assertRaises(ManagedVpnError) as error:
            self.manager.add_client("demo-vpn", "alice")
        self.assertNotIn("secret diagnostic", str(error.exception))
        journal = self.root / "state" / "demo-vpn" / "transaction.json"
        self.assertTrue(journal.exists())
        with self.assertRaisesRegex(ManagedVpnError, "Pending VPN transaction"):
            self.manager.clients("demo-vpn")
        self.fake.fail_sync = False
        result = self.manager.add_client("demo-vpn", "alice")
        self.assertTrue(result["existing"])
        self.assertFalse(journal.exists())

    def test_revoke_sync_failure_retries_without_claiming_success(self):
        self.create()
        self.manager.activate("demo-vpn")
        profile = Path(self.manager.add_client("demo-vpn", "alice")["profile"])
        self.fake.fail_sync = True
        with self.assertRaises(ManagedVpnError):
            self.manager.revoke_client("demo-vpn", "alice")
        self.assertTrue(profile.exists())
        self.assertTrue((self.root / "state" / "demo-vpn" / "transaction.json").exists())
        self.fake.fail_sync = False
        self.assertTrue(self.manager.revoke_client("demo-vpn", "alice")["already_absent"])
        self.assertFalse(profile.exists())

    def test_activation_can_resume_owned_stopped_unit(self):
        self.create()
        self.manager.activate("demo-vpn")
        self.fake.active = False
        self.assertTrue(self.manager.activate("demo-vpn")["active"])

    def test_orphaned_interface_blocks_activation_sync_revoke_and_remove(self):
        self.create()
        self.manager.add_client("demo-vpn", "alice")
        state = self.manager._state("demo-vpn")
        self.fake.orphan_iface = True
        for operation in (lambda: self.manager.activate("demo-vpn"),
                          lambda: self.manager._sync(state, state),
                          lambda: self.manager.revoke_client("demo-vpn", "alice"),
                          lambda: self.manager.remove("demo-vpn", "demo-vpn")):
            with self.subTest(operation=operation), \
                 self.assertRaisesRegex(ManagedVpnError, "state disagree"):
                operation()
        self.assertTrue((self.root / "state" / "demo-vpn" / "clients" / "alice.conf").exists())
        self.assertFalse((self.root / "state" / "demo-vpn" / "transaction.json").exists())

    def test_active_activate_rejects_peer_port_and_key_drift(self):
        self.create()
        self.manager.activate("demo-vpn")
        self.manager.add_client("demo-vpn", "alice")
        original = json.loads(json.dumps(self.fake.live))
        mutations = (
            lambda item: item.update(port="51899"),
            lambda item: item["peers"].append(dict(item["peers"][0], PublicKey=key(120))),
            lambda item: item["peers"][0].update(PresharedKey=key(121)),
            lambda item: item["peers"][0].update(AllowedIPs="10.49.0.99/32"),
        )
        for mutate in mutations:
            self.fake.live = json.loads(json.dumps(original))
            mutate(self.fake.live)
            with self.subTest(mutate=mutate), \
                 self.assertRaisesRegex(ManagedVpnError, "differs from managed state"):
                self.manager.activate("demo-vpn")
        self.fake.live = original
        self.fake.live["address"] = "10.49.0.99/24"
        with self.assertRaisesRegex(ManagedVpnError, "address differs"):
            self.manager.activate("demo-vpn")
        self.fake.live = original

    def test_failed_activation_preserves_previously_enabled_unit(self):
        self.create()
        state = self.manager._state("demo-vpn")
        link = self.wg_dir / f"{state['interface']}.conf"
        link.symlink_to(self.root / "state" / "demo-vpn" / "server.conf")
        self.fake.enabled = True
        self.fake.fail_enable = True
        with self.assertRaisesRegex(ManagedVpnError, "Command systemctl failed"):
            self.manager.activate("demo-vpn")
        self.assertTrue(self.fake.enabled)
        self.assertTrue(link.is_symlink())
        self.assertIn(("systemctl", "stop", f"wg-quick@{state['interface']}.service"),
                      self.fake.calls)

    def test_remove_refuses_enabled_unit_without_managed_link(self):
        self.create()
        self.fake.enabled = True
        with self.assertRaisesRegex(ManagedVpnError, "Enabled WireGuard unit"):
            self.manager.remove("demo-vpn", "demo-vpn")
        self.assertTrue((self.root / "state" / "demo-vpn").exists())

    def test_failed_activation_removes_only_new_link_and_keeps_staged_keys(self):
        public = self.create()
        self.fake.fail_enable = True
        with self.assertRaisesRegex(ManagedVpnError, "Command systemctl failed"):
            self.manager.activate("demo-vpn")
        self.assertFalse((self.wg_dir / f"{public['interface']}.conf").is_symlink())
        self.assertEqual(len(self.manager.instances()), 1)

    def test_preflight_rejects_host_and_docker_collisions(self):
        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def bind(self, *_):
                return None

        self.manager.check_network = True
        with patch("sovagrid_vpn.managed.socket.socket", return_value=FakeSocket()), \
             patch("sovagrid_vpn.managed.shutil.which", return_value=None):
            self.fake.routes = [{"dst": "10.49.0.0/24"}]
            with self.assertRaisesRegex(ManagedVpnError, "overlaps a host route"):
                self.create()
            self.fake.routes = []
            self.fake.addresses = [{"addr_info": [{"family": "inet", "local": "10.49.0.10", "prefixlen": 24}]}]
            with self.assertRaisesRegex(ManagedVpnError, "overlaps a host route"):
                self.create()
            self.fake.addresses = []
        with patch("sovagrid_vpn.managed.socket.socket", return_value=FakeSocket()), \
             patch("sovagrid_vpn.managed.shutil.which", return_value="/usr/bin/docker"):
            self.fake.docker_containers = json.dumps({"Ports": "0.0.0.0:51820->51820/udp"}) + "\n"
            with self.assertRaisesRegex(ManagedVpnError, "published by Docker"):
                self.create()
            self.fake.docker_containers = json.dumps({"Ports": "0.0.0.0:51819-51821->51819-51821/udp"}) + "\n"
            with self.assertRaisesRegex(ManagedVpnError, "published by Docker"):
                self.create()
            self.fake.docker_containers = ""
            self.fake.docker_networks = "a" * 12 + "\n"
            self.fake.docker_configs = json.dumps([{"Subnet": "fd00::/64"},
                                                   {"Subnet": "10.49.0.0/24"}]) + "\n"
            with self.assertRaisesRegex(ManagedVpnError, "overlaps a Docker network"):
                self.create()

    def test_add_retry_recovers_each_durable_file_boundary(self):
        class SimulatedCrash(BaseException):
            pass

        for marker in ("transaction.json", "alice.conf", "server.conf", "state.json"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                wg_dir = root / "wireguard"
                wg_dir.mkdir(mode=0o700)
                fake = FakeCommands()
                fake.wg_dir = wg_dir
                manager = ManagedWireGuard(state_root=root / "state", wireguard_dir=wg_dir,
                                           runner=fake, require_root=False, check_network=False)
                manager.create("demo-vpn", 51820, "10.49.0.0/24", "8.8.8.8")
                original_write = manager._write

                def crash_after_write(path, data, *, new=False):
                    original_write(path, data, new=new)
                    if path.name == marker:
                        raise SimulatedCrash()

                manager._write = crash_after_write
                with self.assertRaises(SimulatedCrash):
                    manager.add_client("demo-vpn", "alice")
                self.assertTrue((root / "state" / "demo-vpn" / "transaction.json").exists())
                retry = ManagedWireGuard(state_root=root / "state", wireguard_dir=wg_dir,
                                         runner=fake, require_root=False, check_network=False)
                result = retry.add_client("demo-vpn", "alice")
                self.assertTrue(result["existing"])
                self.assertEqual(retry.clients("demo-vpn"),
                                 [{"name": "alice", "address": "10.49.0.2"}])
                self.assertFalse((root / "state" / "demo-vpn" / "transaction.json").exists())

    def test_revoke_retry_recovers_after_live_sync_and_profile_delete(self):
        class SimulatedCrash(BaseException):
            pass

        self.create()
        self.manager.activate("demo-vpn")
        profile = Path(self.manager.add_client("demo-vpn", "alice")["profile"])
        original_sync = self.manager._sync

        def crash_after_sync(before, after):
            original_sync(before, after)
            raise SimulatedCrash()

        self.manager._sync = crash_after_sync
        with self.assertRaises(SimulatedCrash):
            self.manager.revoke_client("demo-vpn", "alice")
        self.assertTrue(profile.exists())
        self.assertTrue((self.root / "state" / "demo-vpn" / "transaction.json").exists())
        retry = ManagedWireGuard(state_root=self.root / "state", wireguard_dir=self.wg_dir,
                                 runner=self.fake, require_root=False, check_network=False)
        self.assertTrue(retry.revoke_client("demo-vpn", "alice")["already_absent"])
        self.assertFalse(profile.exists())
        self.assertEqual(retry.clients("demo-vpn"), [])

        retry.add_client("demo-vpn", "bob")
        original_unlink = retry._unlink

        def crash_after_profile_delete(path):
            original_unlink(path)
            if path.name == "bob.conf":
                raise SimulatedCrash()

        retry._unlink = crash_after_profile_delete
        with self.assertRaises(SimulatedCrash):
            retry.revoke_client("demo-vpn", "bob")
        fresh = ManagedWireGuard(state_root=self.root / "state", wireguard_dir=self.wg_dir,
                                 runner=self.fake, require_root=False, check_network=False)
        self.assertTrue(fresh.revoke_client("demo-vpn", "bob")["already_absent"])
        self.assertFalse((self.root / "state" / "demo-vpn" / "transaction.json").exists())

    def test_recovery_refuses_foreign_live_change_and_preserves_journal(self):
        self.create()
        self.manager.activate("demo-vpn")
        profile = Path(self.manager.add_client("demo-vpn", "alice")["profile"])
        self.fake.fail_sync = True
        with self.assertRaises(ManagedVpnError):
            self.manager.revoke_client("demo-vpn", "alice")
        journal = self.root / "state" / "demo-vpn" / "transaction.json"
        self.assertTrue(journal.exists())
        self.fake.fail_sync = False
        self.fake.live["port"] = "51999"
        with self.assertRaisesRegex(ManagedVpnError, "differs from managed state"):
            self.manager.recover("demo-vpn")
        self.assertTrue(journal.exists())
        self.assertTrue(profile.exists())
        self.fake.live["port"] = "51820"
        self.assertTrue(self.manager.revoke_client("demo-vpn", "alice")["already_absent"])

    def test_repeated_revoke_refuses_lingering_live_peer(self):
        self.create()
        self.manager.activate("demo-vpn")
        self.manager.add_client("demo-vpn", "alice")
        old_peer = dict(self.fake.live["peers"][0])
        self.manager.revoke_client("demo-vpn", "alice")
        self.fake.live["peers"].append(old_peer)
        with self.assertRaisesRegex(ManagedVpnError, "differs from managed state"):
            self.manager.revoke_client("demo-vpn", "alice")

    def test_remove_requires_exact_confirmation_and_rejects_unexpected_file(self):
        self.create()
        with self.assertRaisesRegex(ManagedVpnError, "Confirmation"):
            self.manager.remove("demo-vpn", "other")
        foreign = self.root / "state" / "demo-vpn" / "foreign.txt"
        foreign.write_text("keep")
        with self.assertRaisesRegex(ManagedVpnError, "Unexpected files"):
            self.manager.remove("demo-vpn", "demo-vpn")
        self.assertTrue(foreign.exists())

    def test_tampered_profile_blocks_management(self):
        self.create()
        profile = Path(self.manager.add_client("demo-vpn", "alice")["profile"])
        profile.write_text("[Interface]\nPrivateKey = tampered\n")
        with self.assertRaisesRegex(ManagedVpnError, "profile does not match"):
            self.manager.clients("demo-vpn")

    def test_full_route_export_requires_live_owned_gateway_and_blocks_ipv6_leak(self):
        self.create()
        original = Path(self.manager.add_client("demo-vpn", "alice")["profile"])
        state = self.manager._state("demo-vpn")
        client = state["clients"]["alice"]
        with patch("sovagrid_vpn.routing.full_route_ready", return_value=True):
            with self.assertRaisesRegex(ManagedVpnError, "not configured"):
                self.manager._export_profile(state, "alice", route="full")
        self.manager.activate("demo-vpn")
        with patch("sovagrid_vpn.routing.full_route_ready", return_value=False):
            with self.assertRaisesRegex(ManagedVpnError, "not configured"):
                self.manager._export_profile(state, "alice", route="full")
        with patch("sovagrid_vpn.routing.full_route_ready", return_value=True):
            full = self.manager._export_profile(state, "alice", route="full")
        self.assertIn(b"AllowedIPs = 0.0.0.0/0, ::/0", full)
        self.assertNotIn(b"AllowedIPs = 10.49.0.0/24", full)
        self.assertEqual(original.read_bytes(), self.manager._export_profile(state, "alice", route="split"))
        self.assertIn(client["private_key"].encode(), full)
        with self.assertRaisesRegex(ManagedVpnError, "Invalid VPN client route"):
            self.manager._export_profile(state, "alice", route="arbitrary")


if __name__ == "__main__":
    unittest.main()
