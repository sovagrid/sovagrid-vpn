# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Focused rootless checks for Amnezia provision preflight and recovery."""

from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from sovagrid_vpn.amnezia_admin import (AmneziaAdmin, AmneziaAdminError,
                                         PINNED_AWG_IMAGE, TARGETS, _config,
                                         _preview_awg_parameters)
from sovagrid_vpn.amnezia_provision import (ProvisionError, Provisioner, _bundle,
                                            _network, _read_state, _tar_bundle,
                                            _write_state)


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.container = None
        self.image = None

    def __call__(self, command, **_kwargs):
        command = tuple(command)
        self.calls.append(command)
        if command[:2] == ("docker", "info"):
            return subprocess.CompletedProcess(command, 0, b"linux amd64\n", b"")
        if command[:3] == ("docker", "image", "inspect"):
            if self.image:
                return subprocess.CompletedProcess(
                    command, 0, f"{self.image} linux amd64\n".encode(), b"")
            return subprocess.CompletedProcess(command, 1, b"", b"")
        if command[:3] == ("docker", "container", "inspect"):
            if self.container:
                return subprocess.CompletedProcess(command, 0, self.container, b"")
            return subprocess.CompletedProcess(command, 1, b"", b"")
        raise AssertionError(f"unexpected Docker operation: {command!r}")


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fake = FakeDocker()
        self.provisioner = Provisioner(state_root=Path(self.temp.name) / "provision",
                                       runner=self.fake, require_root=False,
                                       tun_available=lambda: True,
                                       udp_available=lambda _port: True)

    def pending_files(self):
        return {name: base64.b64encode(raw).decode("ascii") for name, raw in
                _bundle(_network("10.44.0.0/24"), 49311, "split").items()}

    def test_bundle_is_parseable_and_split_has_no_nat(self):
        split = _bundle(_network("10.44.0.0/24"), 49311, "split")
        config = _config(split["opt/amnezia/awg/awg0.conf"])
        self.assertEqual(config.listen_port, 49311)
        self.assertEqual(str(config.network), "10.44.0.0/24")
        self.assertEqual(config.peers, ())
        parameters, has_header_key = _preview_awg_parameters(config.interface_raw)
        header_values = [int(parameters[f"H{number}"]) for number in range(1, 5)]
        self.assertTrue(has_header_key)
        self.assertEqual(len(set(header_values)), 4)
        self.assertTrue(all(0x10000000 <= value <= 0xDFFFFFFF for value in header_values))
        another = _bundle(_network("10.44.0.0/24"), 49311, "split")
        another_parameters, _ = _preview_awg_parameters(
            _config(another["opt/amnezia/awg/awg0.conf"]).interface_raw)
        self.assertNotEqual(header_values,
                            [int(another_parameters[f"H{number}"]) for number in range(1, 5)])
        self.assertEqual(split["opt/amnezia/awg/clientsTable"], b"[]\n")
        self.assertNotIn(b"iptables", split["opt/amnezia/start.sh"])
        self.assertIn(b"iptables -t nat", _bundle(_network("10.44.0.0/24"),
                                                  49311, "full")["opt/amnezia/start.sh"])
        with tarfile.open(fileobj=io.BytesIO(_tar_bundle(split))) as archive:
            self.assertEqual(set(archive.getnames()) - {"opt", "opt/amnezia",
                                                         "opt/amnezia/awg"}, set(split))
            for name in split:
                self.assertEqual(archive.extractfile(name).read(), split[name])
                self.assertEqual(archive.getmember(name).mode,
                                 0o700 if name.endswith("start.sh") else 0o600)

    def test_preview_is_secret_free_and_cas_refuses_stale_apply(self):
        preview = self.provisioner.preview(49311, "10.44.0.0/24")
        self.assertTrue(preview["can_apply"])
        self.assertEqual(preview["route_mode"], "full")
        self.assertEqual(preview["image_digest"], PINNED_AWG_IMAGE.split("@", 1)[1])
        self.assertNotIn("PrivateKey", json.dumps(preview))
        self.assertNotEqual(preview["state_revision"],
                            self.provisioner.preview(49311, "10.44.0.0/24", "split")["state_revision"])
        with self.assertRaisesRegex(ProvisionError, "PREVIEW_STALE"):
            self.provisioner.apply(49311, "10.44.0.0/24", "0" * 64, confirm=True)
        self.assertFalse(any(call[1] in ("pull", "create", "start") for call in self.fake.calls))

    def test_existing_container_refuses_without_mutation(self):
        self.fake.container = ("a" * 64 + " sha256:" + "b" * 64 + " " + PINNED_AWG_IMAGE +
                               " unrelated true\n").encode()
        preview = self.provisioner.preview(49311, "10.44.0.0/24")
        self.assertEqual(preview["reason"], "CONTAINER_EXISTS")
        self.assertFalse(preview["can_apply"])
        with self.assertRaisesRegex(ProvisionError, "CONTAINER_EXISTS"):
            self.provisioner.apply(49311, "10.44.0.0/24", preview["state_revision"],
                                   confirm=True)
        self.assertFalse(any(call[1] in ("pull", "create", "start") for call in self.fake.calls))

    def test_busy_udp_port_refuses_without_docker_mutation(self):
        self.provisioner.udp_available = lambda _port: False
        preview = self.provisioner.preview(49311, "10.44.0.0/24")
        self.assertEqual(preview["reason"], "UDP_PORT_BUSY")
        with self.assertRaisesRegex(ProvisionError, "UDP_PORT_BUSY"):
            self.provisioner.apply(49311, "10.44.0.0/24", preview["state_revision"],
                                   confirm=True)
        self.assertFalse(any(call[1] in ("pull", "create", "start") for call in self.fake.calls))

    def test_recover_clears_prepared_journal_only_when_container_absent(self):
        self.provisioner.state_root.mkdir(mode=0o700)
        pending = {"schema_version": 1, "image_ref": PINNED_AWG_IMAGE,
                   "image_id": "sha256:" + "b" * 64, "nonce": "a" * 32,
                   "container_id": None, "files": self.pending_files(), "port": 49311,
                   "subnet": "10.44.0.0/24", "route_mode": "split"}
        path = self.provisioner.state_root / "pending.json"
        _write_state(path, pending, os.geteuid())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(_read_state(path, os.geteuid()), pending)
        result = self.provisioner.recover()
        self.assertEqual(result, {"schema_version": 1, "action": "recovered",
                                  "changed": True, "installed": False})
        self.assertFalse(path.exists())
        self.assertFalse(any(call[1] == "rm" for call in self.fake.calls))

    def test_recover_refuses_foreign_container(self):
        self.provisioner.state_root.mkdir(mode=0o700)
        pending = {"schema_version": 1, "image_ref": PINNED_AWG_IMAGE,
                   "image_id": "sha256:" + "b" * 64, "nonce": "a" * 32,
                   "container_id": "c" * 64, "files": self.pending_files(), "port": 49311,
                   "subnet": "10.44.0.0/24", "route_mode": "split"}
        path = self.provisioner.state_root / "pending.json"
        _write_state(path, pending, os.geteuid())
        self.fake.container = ("c" * 64 + " sha256:" + "b" * 64 + " " + PINNED_AWG_IMAGE +
                               " foreign false\n").encode()
        with self.assertRaisesRegex(ProvisionError, "CONTAINER_IDENTITY_INVALID"):
            self.provisioner.recover()
        self.assertTrue(path.exists())
        self.assertFalse(any(call[1] == "rm" for call in self.fake.calls))

    def test_subnet_rejects_non_private_and_non_24(self):
        for subnet in ("0.0.0.0/0", "8.8.8.0/24", "10.44.0.0/16", "127.0.0.0/24",
                       "not-a-network"):
            with self.subTest(subnet=subnet), self.assertRaisesRegex(ProvisionError,
                                                                    "INVALID_SUBNET"):
                _network(subnet)

    def test_split_provision_cannot_issue_full_route_profile(self):
        root = Path(self.temp.name) / "managed-route"
        root.mkdir(mode=0o700)
        path = root / "state.json"
        state = {"schema_version": 1, "route_mode": "split",
                 "container_id": "a" * 64, "image_id": "sha256:" + "b" * 64}
        _write_state(path, state, os.geteuid())
        admin = AmneziaAdmin(TARGETS["awg2"],
                             state_root=Path(self.temp.name) / "admin",
                             require_root=False)
        with patch("sovagrid_vpn.amnezia_admin.PROVISION_STATE", path):
            with self.assertRaisesRegex(AmneziaAdminError, "Full Amnezia route"):
                admin._check_provision_route(state, "full")
            admin._check_provision_route(state, "split")
            _write_state(path, {**state, "route_mode": "full"}, os.geteuid(), new=False)
            admin._check_provision_route(state, "full")
            with self.assertRaisesRegex(AmneziaAdminError, "Full Amnezia route"):
                admin._check_provision_route({**state, "container_id": "c" * 64}, "full")


if __name__ == "__main__":
    unittest.main()
