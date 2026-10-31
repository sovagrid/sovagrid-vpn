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


class StartingDocker(FakeDocker):
    """Only the Docker operations needed for failed-start rollback."""

    def __init__(self):
        super().__init__()
        self.image_id = "sha256:" + "b" * 64
        self.container_id = "c" * 64
        self.nonce = None
        self.running = False
        self.restart_policy = "no"
        self.fail_stop = False

    def __call__(self, command, **kwargs):
        command = tuple(command)
        if command[:3] == ("docker", "image", "inspect") and self.image:
            return super().__call__(command, **kwargs)
        if command[:3] == ("docker", "container", "inspect"):
            self.calls.append(command)
            if self.nonce is None:
                return subprocess.CompletedProcess(command, 1, b"", b"")
            fields = (self.container_id, self.image_id, PINNED_AWG_IMAGE,
                      self.nonce, str(self.running).lower())
            return subprocess.CompletedProcess(command, 0,
                                               (" ".join(fields) + "\n").encode(), b"")
        self.calls.append(command)
        if command[:2] == ("docker", "pull"):
            self.image = self.image_id
            return subprocess.CompletedProcess(command, 0, b"pulled\n", b"")
        if command[:2] == ("docker", "create"):
            label = command[command.index("--label") + 1]
            self.nonce = label.split("=", 1)[1]
            return subprocess.CompletedProcess(command, 0,
                                               (self.container_id + "\n").encode(), b"")
        if command[:2] == ("docker", "cp"):
            return subprocess.CompletedProcess(command, 0, b"", b"")
        if command[:2] == ("docker", "start"):
            self.running = True
            return subprocess.CompletedProcess(command, 0, b"started\n", b"")
        if command[:2] == ("docker", "update"):
            self.restart_policy = command[command.index("--restart") + 1]
            return subprocess.CompletedProcess(command, 0, b"updated\n", b"")
        if command[:2] == ("docker", "stop"):
            if self.fail_stop:
                return subprocess.CompletedProcess(command, 1, b"", b"stop failed")
            self.running = False
            return subprocess.CompletedProcess(command, 0, b"stopped\n", b"")
        if command[:2] == ("docker", "diff"):
            return subprocess.CompletedProcess(command, 0, b"", b"")
        if command[:2] == ("docker", "rm"):
            self.nonce = None
            return subprocess.CompletedProcess(command, 0, b"removed\n", b"")
        if command[:2] == ("docker", "info"):
            return subprocess.CompletedProcess(command, 0, b"linux amd64\n", b"")
        if command[:3] == ("docker", "image", "inspect"):
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

    def test_source_change_invalidates_preview_before_docker_mutation(self):
        preview = self.provisioner.preview(49311, "10.44.0.0/24")
        with patch.object(self.provisioner, "_source_revision", return_value="f" * 64):
            with self.assertRaisesRegex(ProvisionError, "PREVIEW_STALE"):
                self.provisioner.apply(49311, "10.44.0.0/24",
                                       preview["state_revision"], confirm=True)
        self.assertFalse(any(call[1] in ("pull", "create", "start") for call in self.fake.calls))

    def test_preview_rejects_writable_source(self):
        source = Path(self.temp.name) / "source"
        package = source / "sovagrid_vpn"
        package.mkdir(parents=True)
        deploy = source / "deploy"
        deploy.mkdir()
        for path in (package / "__init__.py", package / "amnezia_provision.py",
                     package / "amnezia_admin.py", package / "amnezia_install.py",
                     package / "amnezia_profile.py", package / "sealed.py",
                     deploy / "sovagrid-amnezia-provision"):
            path.write_text("safe source\n", encoding="ascii")
        (package / "amnezia_admin.py").chmod(0o666)
        with patch("sovagrid_vpn.amnezia_provision.__file__",
                   str(package / "amnezia_provision.py")):
            preview = self.provisioner.preview(49311, "10.44.0.0/24")
        self.assertEqual(preview["reason"], "SOURCE_UNTRUSTED")
        self.assertFalse(preview["can_apply"])

    def test_source_revision_tracks_transitive_module(self):
        source = Path(self.temp.name) / "source-hash"
        package = source / "sovagrid_vpn"
        package.mkdir(parents=True)
        deploy = source / "deploy"
        deploy.mkdir()
        for name in ("__init__.py", "amnezia_provision.py", "amnezia_admin.py",
                     "amnezia_install.py", "amnezia_profile.py", "sealed.py"):
            (package / name).write_text("safe source\n", encoding="ascii")
        (deploy / "sovagrid-amnezia-provision").write_text("safe wrapper\n",
                                                          encoding="ascii")
        with patch("sovagrid_vpn.amnezia_provision.__file__",
                   str(package / "amnezia_provision.py")):
            before = self.provisioner._source_revision()
            (package / "amnezia_install.py").write_text("changed source\n",
                                                       encoding="ascii")
            self.assertNotEqual(before, self.provisioner._source_revision())
            symlink = package / "extra.py"
            symlink.symlink_to(package / "amnezia_install.py")
            with self.assertRaisesRegex(ProvisionError, "SOURCE_UNTRUSTED"):
                self.provisioner._source_revision()

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

    def test_health_failure_stops_exact_new_container_then_recover_removes_it(self):
        docker = StartingDocker()
        provisioner = Provisioner(state_root=Path(self.temp.name) / "failed-start",
                                  runner=docker, require_root=False,
                                  tun_available=lambda: True,
                                  udp_available=lambda _port: True)
        revision = provisioner.preview(49311, "10.44.0.0/24")["state_revision"]
        with (patch.object(provisioner, "_finalize",
                           side_effect=ProvisionError("AWG_RUNTIME_UNVERIFIED")) as health,
              patch("sovagrid_vpn.amnezia_provision.time.sleep")):
            with self.assertRaisesRegex(ProvisionError, "AWG_RUNTIME_UNVERIFIED"):
                provisioner.apply(49311, "10.44.0.0/24", revision, confirm=True)
        self.assertEqual(health.call_count, 40)
        self.assertFalse(docker.running)
        self.assertEqual(docker.restart_policy, "no")
        self.assertIn(("docker", "stop", "--time", "10", docker.container_id), docker.calls)
        self.assertTrue((provisioner.state_root / "pending.json").exists())
        result = provisioner.recover()
        self.assertEqual(result["installed"], False)
        self.assertFalse((provisioner.state_root / "pending.json").exists())
        self.assertIn(("docker", "rm", docker.container_id), docker.calls)

    def test_failed_health_does_not_stop_foreign_container(self):
        pending = {"container_id": "c" * 64, "image_id": "sha256:" + "b" * 64,
                   "nonce": "a" * 32}
        self.fake.container = ("c" * 64 + " sha256:" + "b" * 64 + " " +
                               PINNED_AWG_IMAGE + " foreign true\n").encode()
        with self.assertRaisesRegex(ProvisionError, "CONTAINER_IDENTITY_INVALID"):
            self.provisioner._stop_unverified(pending)
        self.assertFalse(any(call[1] in ("update", "stop") for call in self.fake.calls))

    def test_stop_failure_keeps_pending_journal_for_manual_recovery(self):
        docker = StartingDocker()
        docker.fail_stop = True
        provisioner = Provisioner(state_root=Path(self.temp.name) / "stop-failed",
                                  runner=docker, require_root=False,
                                  tun_available=lambda: True,
                                  udp_available=lambda _port: True)
        revision = provisioner.preview(49311, "10.44.0.0/24")["state_revision"]
        with (patch.object(provisioner, "_finalize",
                           side_effect=ProvisionError("AWG_RUNTIME_UNVERIFIED")),
              patch("sovagrid_vpn.amnezia_provision.time.sleep")):
            with self.assertRaisesRegex(ProvisionError, "DOCKER_OPERATION_FAILED"):
                provisioner.apply(49311, "10.44.0.0/24", revision, confirm=True)
        self.assertTrue(docker.running)
        self.assertTrue((provisioner.state_root / "pending.json").exists())
        self.assertFalse(any(call[1] == "rm" for call in docker.calls))

    def test_finalize_checks_all_copied_files_before_restart(self):
        files = self.pending_files()
        pending = {"container_id": "c" * 64, "files": files}
        for changed in files:
            with self.subTest(changed=changed):
                expected = {name: base64.b64decode(raw) for name, raw in files.items()}
                expected[changed] += b"external change\n"
                with (patch.object(self.provisioner, "_health", return_value={}),
                      patch.object(self.provisioner, "_container_file",
                                   side_effect=lambda _id, name: expected[name])):
                    with self.assertRaisesRegex(ProvisionError, "AWG_RUNTIME_UNVERIFIED"):
                        self.provisioner._finalize(pending)
                self.assertFalse(any(call[1] == "update" for call in self.fake.calls))

    def test_installed_state_drift_never_reports_installed(self):
        self.provisioner.state_root.mkdir(mode=0o700)
        state = {"schema_version": 1, "installed": True,
                 "image_ref": PINNED_AWG_IMAGE, "image_id": "sha256:" + "b" * 64,
                 "nonce": "a" * 32, "container_id": "c" * 64}
        _write_state(self.provisioner.state_root / "state.json", state, os.geteuid())
        for container in (None,
                          ("c" * 64 + " sha256:" + "b" * 64 + " " +
                           PINNED_AWG_IMAGE + " foreign true\n").encode(),
                          ("c" * 64 + " sha256:" + "b" * 64 + " " +
                           PINNED_AWG_IMAGE + " " + "a" * 32 + " false\n").encode()):
            with self.subTest(container=container):
                self.fake.container = container
                preview = self.provisioner.preview(49311, "10.44.0.0/24")
                self.assertFalse(preview["can_apply"])
                self.assertEqual(preview["reason"], "INSTALLATION_DRIFT")
                with self.assertRaisesRegex(ProvisionError, "INSTALLATION_DRIFT"):
                    self.provisioner.recover()
        self.fake.container = ("c" * 64 + " sha256:" + "b" * 64 + " " +
                               PINNED_AWG_IMAGE + " " + "a" * 32 + " true\n").encode()
        self.assertEqual(self.provisioner.preview(49311, "10.44.0.0/24")["reason"],
                         "ALREADY_INSTALLED")
        self.assertTrue(self.provisioner.recover()["installed"])

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
