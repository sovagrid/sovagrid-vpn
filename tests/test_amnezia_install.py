# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Installer stays dormant and fails closed in a disposable filesystem tree."""

from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

from sovagrid_vpn.amnezia_install import (CONFIRM, CONFIRM_SETTINGS,
                                         CONFIRM_WIREGUARD, FILES,
                                         InstallError, Installer, Layout,
                                         SOURCE_LOCK)


CONTAINER_ID = "a" * 64


class FakeAdmin:
    def __init__(self, ready=True):
        self.ready = ready
        self.clients = 2
        self.calls = []

    def _load_state(self):
        self.calls.append("load")
        return {"container_id": CONTAINER_ID,
                "owned": {"phone": {}} if self.clients else {}}, b""

    def _require_no_pending(self):
        self.calls.append("pending")
        if not self.ready:
            from sovagrid_vpn.amnezia_admin import AmneziaAdminError
            raise AmneziaAdminError("An interrupted Amnezia operation requires recovery")

    def _snapshot(self):
        self.calls.append("snapshot")
        return b"", b"", None, [{} for _ in range(self.clients)], None, None, None

    def _check_state(self, *_):
        self.calls.append("check")

    def settings_preview(self):
        self.calls.append("settings_preview")
        return {"container_id": CONTAINER_ID, "configured_clients": self.clients,
                "awg3_required_parameters_present": True,
                "awg_parameters": {"Jc": "4"}, "config_sha256": "c" * 64,
                "generation": 0}

    def settings_plan(self, digest, generation, patch):
        self.calls.append("settings_plan")
        return {"apply_supported": self.clients == 0,
                "apply_blockers": [] if self.clients == 0 else
                ["CLIENT_PROFILES_REQUIRE_REISSUE"]}


class FakeSystemd:
    def __init__(self):
        self.commands = []
        self.socket_active = False
        self.service_active = False
        self.fail_enable = False
        self.fail_verify = False

    def __call__(self, command, **_):
        self.commands.append(tuple(command))
        status = 0
        if command[1] == "is-active":
            status = 0 if (self.socket_active if command[-1].endswith(".socket")
                           else self.service_active) else 3
        elif command[1:3] == ["enable", "--now"]:
            if self.fail_enable:
                status = 1
            else:
                self.socket_active = True
        elif command[1:3] == ["disable", "--now"]:
            self.socket_active = False
        elif command[1] == "verify" and self.fail_verify:
            status = 1
        return type("Completed", (), {"returncode": status})()


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.layout = Layout(self.root, self.root / "opt/sovagrid-src/sovagrid-vpn")
        source = Path(__file__).parents[1]
        (self.layout.repo / "deploy").mkdir(parents=True)
        (self.layout.repo / "sovagrid_vpn").mkdir()
        for name, _, _ in FILES:
            shutil.copy2(source / "deploy" / name, self.layout.repo / "deploy" / name)
        deployed = self.root / "opt/sovagrid-vpn/sovagrid_vpn"
        deployed.mkdir(parents=True)
        for file in (source / "sovagrid_vpn").glob("*.py"):
            shutil.copy2(file, self.layout.repo / "sovagrid_vpn" / file.name)
            shutil.copy2(file, deployed / file.name)
        (self.root / "usr/local/bin").mkdir(parents=True)
        (self.root / "etc/systemd/system").mkdir(parents=True)
        self.systemd = FakeSystemd()
        self.admin = FakeAdmin()
        self.wireguard_admin = FakeAdmin()
        self.installer = Installer(self.layout, owner=self.root.stat().st_uid,
                                   run=self.systemd, admin_factory=lambda: self.admin,
                                   wireguard_admin_factory=lambda: self.wireguard_admin)

    def test_preview_is_read_only_and_install_is_dormant(self):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*"))
        preview = self.installer.preview()
        after = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*"))
        self.assertEqual(before, after)
        self.assertEqual(self.installer.preview_settings()["reason"], "INSTALL_NOT_CURRENT")
        self.assertEqual(preview["marker"], "absent")
        self.assertTrue(preview["installer_ready"])
        self.assertFalse(preview["installed_current"])
        self.assertFalse(preview["can_arm"])
        self.assertEqual(self.admin.calls, ["load", "pending", "snapshot", "check"])
        installed = self.installer.install()
        self.assertEqual(installed["action"], "installed")
        self.assertFalse(self.systemd.socket_active)
        self.assertFalse((self.root / "etc/sovagrid-vpn/amnezia-control.enabled").exists())
        self.assertTrue((self.root / "usr/local/libexec/sovagrid-amnezia-broker").exists())
        self.assertTrue(self.installer.preview()["can_arm"])
        self.assertEqual(self.installer.install()["action"], "installed")
        self.assertNotIn(("/usr/bin/systemctl", "enable", "--now", "sovagrid-amnezia-control.socket"),
                         self.systemd.commands)

    def test_managed_remote_source_requires_safe_shared_lock(self):
        lock = self.root / SOURCE_LOCK.lstrip("/")
        lock.parent.mkdir(parents=True, mode=0o700)
        self.assertFalse(self.installer.preview()["installer_ready"])
        self.assertIn("lock unavailable", self.installer.preview()["reason"])
        with self.assertRaisesRegex(InstallError, "lock unavailable"):
            self.installer.install()
        lock.write_bytes(b"")
        lock.chmod(0o600)
        self.assertTrue(self.installer.preview()["installer_ready"])

    def test_arm_requires_exact_confirmation_and_ready_enrolled_target(self):
        self.installer.install()
        for container_id, confirmation in (("b" * 64, CONFIRM),
                                           (CONTAINER_ID, "wrong"), ("short", CONFIRM)):
            with self.subTest(container_id=container_id, confirmation=confirmation):
                with self.assertRaises(InstallError):
                    self.installer.arm(container_id, confirmation)
        self.admin.ready = False
        with self.assertRaises(InstallError):
            self.installer.arm(CONTAINER_ID, CONFIRM)
        self.admin.ready = True
        self.systemd.service_active = True
        with self.assertRaisesRegex(InstallError, "Stop the existing"):
            self.installer.arm(CONTAINER_ID, CONFIRM)
        self.systemd.service_active = False
        result = self.installer.arm(CONTAINER_ID, CONFIRM)
        self.assertEqual(result["action"], "armed")
        self.assertTrue(self.systemd.socket_active)
        marker = self.root / "etc/sovagrid-vpn/amnezia-control.enabled"
        self.assertEqual(marker.read_bytes(), b"enabled\n")
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.installer._marker(), "valid")
        with self.assertRaises(InstallError):
            self.installer.install()
        self.assertEqual(self.installer.disarm()["action"], "disarmed")
        self.assertFalse(marker.exists())
        self.assertFalse(self.systemd.socket_active)

    def test_failed_socket_activation_removes_marker(self):
        self.installer.install()
        self.systemd.fail_enable = True
        with self.assertRaises(InstallError):
            self.installer.arm(CONTAINER_ID, CONFIRM)
        self.assertFalse((self.root / "etc/sovagrid-vpn/amnezia-control.enabled").exists())
        self.assertFalse(self.systemd.socket_active)

    def test_awg_settings_need_separate_opt_in_and_disarm_with_base(self):
        self.installer.install()
        self.installer.arm(CONTAINER_ID, CONFIRM)
        settings = self.root / "etc/sovagrid-vpn/amnezia-awg-settings.enabled"
        before = self.installer.preview_settings()
        self.assertFalse(before["can_arm"])
        self.assertEqual(before["configured_clients"], 2)
        self.assertEqual(before["reason"], "CLIENTS_PRESENT")
        with self.assertRaisesRegex(InstallError, "empty container"):
            self.installer.arm_settings(CONTAINER_ID, CONFIRM_SETTINGS)
        self.admin.clients = 0
        ready = self.installer.preview_settings()
        self.assertTrue(ready["awg3_runtime_verified"])
        self.assertTrue(ready["can_arm"])
        self.assertIsNone(ready["reason"])
        with self.assertRaisesRegex(InstallError, "confirmation"):
            self.installer.arm_settings(CONTAINER_ID, "wrong")
        result = self.installer.arm_settings(CONTAINER_ID, CONFIRM_SETTINGS)
        self.assertEqual(result["settings_marker"], "valid")
        self.assertEqual(settings.read_bytes(), b"enabled\n")
        self.assertEqual(settings.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.installer.preview_settings()["reason"], "ALREADY_ARMED")
        with self.assertRaisesRegex(InstallError, "not ready"):  # marker cannot be replaced
            self.installer.arm_settings(CONTAINER_ID, CONFIRM_SETTINGS)
        with self.assertRaisesRegex(InstallError, "Disarm"):
            self.installer.install()
        self.assertEqual(self.installer.disarm_settings()["settings_marker"], "absent")
        self.assertFalse(settings.exists())
        self.assertTrue(self.systemd.socket_active)
        self.installer.arm_settings(CONTAINER_ID, CONFIRM_SETTINGS)
        self.installer.disarm("awg2")
        self.assertFalse(settings.exists())
        self.assertFalse(self.systemd.socket_active)

    def test_wireguard_requires_separate_opt_in_and_shared_socket_stays_active(self):
        self.installer.install()
        self.assertTrue(self.installer.preview("wireguard")["can_arm"])
        with self.assertRaises(InstallError):
            self.installer.arm_target("wireguard", CONTAINER_ID, CONFIRM)
        self.installer.arm_target("wireguard", CONTAINER_ID, CONFIRM_WIREGUARD)
        wg_marker = self.root / "etc/sovagrid-vpn/amnezia-wireguard-control.enabled"
        awg_marker = self.root / "etc/sovagrid-vpn/amnezia-control.enabled"
        self.assertEqual(wg_marker.read_bytes(), b"enabled\n")
        self.assertFalse(awg_marker.exists())
        self.assertFalse(self.installer.preview("wireguard")["can_arm"])
        self.assertTrue(self.installer.preview("awg2")["can_arm"])
        self.installer.arm(CONTAINER_ID, CONFIRM)
        self.assertTrue(awg_marker.exists())
        self.assertTrue(self.systemd.socket_active)
        self.installer.disarm("wireguard")
        self.assertFalse(wg_marker.exists())
        self.assertTrue(awg_marker.exists())
        self.assertTrue(self.systemd.socket_active)
        self.installer.disarm()
        self.assertFalse(self.systemd.socket_active)

    def test_unsafe_wireguard_marker_blocks_other_target_and_install(self):
        self.installer.install()
        directory = self.root / "etc/sovagrid-vpn"
        directory.mkdir(mode=0o700, exist_ok=True)
        marker = directory / "amnezia-wireguard-control.enabled"
        marker.write_bytes(b"enabled\n")
        marker.chmod(0o644)
        self.assertEqual(self.installer._marker("wireguard"), "unsafe")
        with self.assertRaises(InstallError):
            self.installer.arm(CONTAINER_ID, CONFIRM)
        with self.assertRaises(InstallError):
            self.installer.install()
        with self.assertRaises(InstallError):
            self.installer.disarm()
        self.assertTrue(marker.exists())

    def test_concurrent_arm_and_disarm_preserve_shared_socket(self):
        self.installer.install()
        self.installer.arm(CONTAINER_ID, CONFIRM)
        entered, release, disarmed = threading.Event(), threading.Event(), threading.Event()
        failures = []
        original_target = self.installer._target

        def delayed_target(target="awg2"):
            status = original_target(target)
            if target == "wireguard":
                entered.set()
                if not release.wait(2):
                    raise AssertionError("Concurrent test stalled")
            return status

        def arm_wireguard():
            try:
                self.installer.arm_target("wireguard", CONTAINER_ID, CONFIRM_WIREGUARD)
            except Exception as exc:
                failures.append(exc)

        def disarm_awg():
            try:
                self.installer.disarm()
            except Exception as exc:
                failures.append(exc)
            finally:
                disarmed.set()

        with patch.object(self.installer, "_target", side_effect=delayed_target):
            arm_thread = threading.Thread(target=arm_wireguard)
            disarm_thread = threading.Thread(target=disarm_awg)
            arm_thread.start()
            self.assertTrue(entered.wait(2))
            disarm_thread.start()
            self.assertFalse(disarmed.wait(0.05))
            release.set()
            arm_thread.join(timeout=2)
            disarm_thread.join(timeout=2)
        self.assertFalse(arm_thread.is_alive() or disarm_thread.is_alive())
        self.assertFalse(failures)
        self.assertTrue(self.systemd.socket_active)
        self.assertEqual(self.installer._marker("awg2"), "absent")
        self.assertEqual(self.installer._marker("wireguard"), "valid")

    def test_invalid_systemd_units_remain_unarmed(self):
        self.systemd.fail_verify = True
        with self.assertRaisesRegex(InstallError, "systemd command failed"):
            self.installer.install()
        self.assertFalse((self.root / "etc/sovagrid-vpn/amnezia-control.enabled").exists())
        self.assertFalse(self.systemd.socket_active)
        self.assertNotIn(("/usr/bin/systemctl", "daemon-reload"), self.systemd.commands)

    def test_foreign_unit_symlink_or_package_drift_blocks_install(self):
        foreign = self.root / "etc/systemd/system/sovagrid-amnezia-control.socket"
        foreign.write_text("foreign\n")
        with self.assertRaisesRegex(InstallError, "unmanaged"):
            self.installer.install()
        foreign.unlink()
        foreign.symlink_to(self.root / "etc/passwd")
        with self.assertRaises(InstallError):
            self.installer.install()
        foreign.unlink()
        installed = self.root / "opt/sovagrid-vpn/sovagrid_vpn/amnezia_control.py"
        installed.write_text("drift\n")
        with self.assertRaisesRegex(InstallError, "differs"):
            self.installer.install()

    def test_unsafe_existing_marker_never_arm_or_delete(self):
        self.installer.install()
        directory = self.root / "etc/sovagrid-vpn"
        directory.mkdir(mode=0o700, exist_ok=True)
        marker = directory / "amnezia-control.enabled"
        marker.write_bytes(b"enabled\n")
        marker.chmod(0o644)
        self.assertEqual(self.installer._marker(), "unsafe")
        with self.assertRaises(InstallError):
            self.installer.arm(CONTAINER_ID, CONFIRM)
        with self.assertRaises(InstallError):
            self.installer.disarm()
        self.assertTrue(marker.exists())

    def test_preview_redacts_unexpected_parser_errors(self):
        with patch.object(self.admin, "_snapshot", side_effect=ValueError("SECRET_KEY")):
            preview = self.installer.preview()
        self.assertEqual(preview["target"]["reason"], "AWG2 preflight failed")
        self.assertNotIn("SECRET_KEY", str(preview))

    def test_preview_reports_missing_enrollment_without_docker_or_writes(self):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*"))
        with patch.object(self.admin, "_load_state", side_effect=FileNotFoundError):
            preview = self.installer.preview()
        self.assertEqual(preview["target"], {"ready": False, "reason": "AWG2 is not enrolled"})
        self.assertFalse(preview["can_arm"])
        self.assertEqual(self.admin.calls, [])
        self.assertEqual(before, sorted(str(path.relative_to(self.root))
                                        for path in self.root.rglob("*")))

    def test_service_is_static_and_socket_requires_agent_group(self):
        source = Path(__file__).parents[1] / "deploy"
        launcher = (source / "install-amnezia-control.py").read_text()
        service = (source / "sovagrid-amnezia-control.service").read_text()
        socket = (source / "sovagrid-amnezia-control.socket").read_text()
        self.assertLess(launcher.index("sys.dont_write_bytecode = True"),
                        launcher.index("from sovagrid_vpn.amnezia_install import main"))
        self.assertNotIn("[Install]", service)
        self.assertIn("CapabilityBoundingSet=\n", service)
        self.assertIn("ProtectSystem=strict\n", service)
        self.assertIn("SocketGroup=sovagrid\n", socket)
        self.assertIn("SocketMode=0660\n", socket)
        self.assertIn("ListenStream=/run/sovagrid-vpn/amnezia-control.sock\n", socket)


if __name__ == "__main__":
    unittest.main()
