# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Fixed-path WireGuard broker setup in a disposable filesystem tree."""

from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from sovagrid_vpn.wireguard_install import (FILES, InstallError, Installer, Layout,
                                            JOURNAL, MARKER, SOURCE_LOCK)


class FakeSystem:
    def __init__(self):
        self.commands = []
        self.active = {"sovagrid-vpn-control.socket": False,
                       "sovagrid-vpn-control.service": False}
        self.enabled = False
        self.fail_service_once = False
        self.fail_apparmor_once = False
        self.fail_verify_once = False
        self.apt_installed = False

    def __call__(self, argv, **_):
        argv = tuple(argv)
        self.commands.append(argv)
        result = 0
        if argv[1] == "is-active":
            result = 0 if self.active[argv[-1]] else 3
        elif argv[1] == "is-enabled":
            result = 0 if self.enabled else 1
        elif argv[1:3] == ("enable", "--now"):
            self.active[argv[-1]] = True
            self.enabled = True
        elif argv[1:3] == ("disable", "--now"):
            self.active[argv[-1]] = False
            self.enabled = False
        elif argv[1] == "stop":
            self.active[argv[-1]] = False
        elif argv[1] == "start":
            if argv[-1].endswith(".service") and self.fail_service_once:
                self.fail_service_once = False
                result = 1
            else:
                self.active[argv[-1]] = True
        elif argv[0].endswith("apt-get") and argv[1] == "install":
            self.apt_installed = True
        elif argv[0] == "/usr/bin/python3" and argv[-1].endswith("install-wg-quick-apparmor.py"):
            if self.fail_apparmor_once:
                self.fail_apparmor_once = False
                result = 1
        elif argv[0].endswith("systemd-analyze") and argv[1] == "verify":
            if self.fail_verify_once:
                self.fail_verify_once = False
                result = 1
        return type("Completed", (), {"returncode": result})()


class WireGuardInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "opt/sovagrid-src/sovagrid-vpn"
        source = Path(__file__).parents[1]
        (self.repo / "deploy").mkdir(parents=True)
        (self.repo / "sovagrid_vpn").mkdir()
        deployed = self.root / "opt/sovagrid-vpn/sovagrid_vpn"
        deployed.mkdir(parents=True)
        for name, _, _ in FILES:
            shutil.copy2(source / "deploy" / name, self.repo / "deploy" / name)
        shutil.copy2(source / "deploy/install-wg-quick-apparmor.py",
                     self.repo / "deploy/install-wg-quick-apparmor.py")
        for file in (source / "sovagrid_vpn").glob("*.py"):
            shutil.copy2(file, self.repo / "sovagrid_vpn" / file.name)
            shutil.copy2(file, deployed / file.name)
        for directory in ("usr/local/bin", "etc/systemd/system", "var/lib"):
            (self.root / directory).mkdir(parents=True)
        source_lock = self.root / SOURCE_LOCK.lstrip("/")
        source_lock.parent.mkdir(parents=True, mode=0o700)
        source_lock.write_bytes(b"")
        source_lock.chmod(0o600)
        self.system = FakeSystem()
        self.installer = Installer(Layout(self.root, self.repo),
                                   owner=self.root.stat().st_uid, run=self.system,
                                   dependencies=lambda: ())

    def test_preview_is_read_only_and_apply_does_not_start_vpn_interface(self):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*"))
        preview = self.installer.preview()
        after = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*"))
        self.assertEqual(before, after)
        self.assertTrue(preview["can_apply"])
        self.assertFalse(preview["installed_current"])
        result = self.installer.apply(preview["state_revision"])
        self.assertTrue(result["socket_active"])
        self.assertFalse(result["vpn_interface_changed"])
        self.assertTrue((self.root / MARKER.lstrip("/")).exists())
        self.assertFalse((self.root / JOURNAL.lstrip("/")).exists())
        self.assertTrue(self.installer.preview()["installed_current"])
        self.assertFalse(any("wg-quick" in " ".join(command) for command in self.system.commands))

    def test_stale_preview_and_foreign_file_refused(self):
        preview = self.installer.preview()
        with self.assertRaisesRegex(InstallError, "stale"):
            self.installer.apply("a" * 64)
        target = self.root / "usr/local/bin/sovagrid-vpn-ctl"
        target.write_bytes(b"foreign")
        self.assertFalse(self.installer.preview()["can_apply"])
        with self.assertRaises(InstallError):
            self.installer.apply(preview["state_revision"])
        self.assertEqual(target.read_bytes(), b"foreign")

    def test_symlink_and_source_package_mismatch_refused(self):
        target = self.root / "usr/local/bin/sovagrid-vpn-ctl"
        target.symlink_to(self.repo / "deploy/sovagrid-vpn-ctl")
        self.assertFalse(self.installer.preview()["can_apply"])
        target.unlink()
        (self.root / "opt/sovagrid-vpn/sovagrid_vpn/control.py").write_bytes(b"changed")
        self.assertFalse(self.installer.preview()["can_apply"])

    def test_failed_start_rolls_back_owned_files_and_keeps_foreign_state(self):
        self.system.fail_service_once = True
        preview = self.installer.preview()
        with self.assertRaises(InstallError):
            self.installer.apply(preview["state_revision"])
        self.assertFalse(self.system.enabled)
        self.assertFalse((self.root / JOURNAL.lstrip("/")).exists())
        self.assertFalse((self.root / MARKER.lstrip("/")).exists())
        for _, absolute, _ in FILES:
            self.assertFalse((self.root / absolute.lstrip("/")).exists())
        self.assertFalse(self.installer.recover()["changed"])

    def test_upgrade_requires_inactive_broker_and_owned_manifest(self):
        preview = self.installer.preview()
        self.installer.apply(preview["state_revision"])
        (self.repo / "deploy/sovagrid-vpn-ctl").write_bytes(
            (self.repo / "deploy/sovagrid-vpn-ctl").read_bytes() + b"\n# update\n")
        blocked = self.installer.preview()
        self.assertFalse(blocked["can_apply"])
        self.assertEqual(blocked["reason"], "STOP_BROKER_BEFORE_UPGRADE")
        self.system.active["sovagrid-vpn-control.socket"] = False
        self.system.active["sovagrid-vpn-control.service"] = False
        self.system.enabled = False
        accepted = self.installer.preview()
        self.assertTrue(accepted["can_apply"])
        self.installer.apply(accepted["state_revision"])
        self.assertTrue(self.installer.preview()["installed_current"])

    def test_pending_journal_can_recover_after_interrupted_rollback(self):
        self.system.fail_service_once = True
        preview = self.installer.preview()
        with patch.object(self.installer, "_rollback", side_effect=InstallError("interrupted")):
            with self.assertRaises(InstallError):
                self.installer.apply(preview["state_revision"])
        self.assertTrue((self.root / JOURNAL.lstrip("/")).exists())
        self.assertEqual(self.installer.preview()["reason"], "RECOVERY_REQUIRED")
        self.assertTrue(self.installer.recover()["changed"])
        self.assertFalse((self.root / JOURNAL.lstrip("/")).exists())
        self.assertFalse(self.system.enabled)

    def test_recovery_refuses_foreign_change_before_stopping_broker(self):
        self.system.fail_service_once = True
        preview = self.installer.preview()
        with patch.object(self.installer, "_rollback", side_effect=InstallError("interrupted")):
            with self.assertRaises(InstallError):
                self.installer.apply(preview["state_revision"])
        target = self.root / "usr/local/bin/sovagrid-vpn-ctl"
        target.write_bytes(b"foreign")
        before = len(self.system.commands)
        with self.assertRaisesRegex(InstallError, "manual recovery"):
            self.installer.recover()
        self.assertEqual(len(self.system.commands), before)
        self.assertTrue((self.root / JOURNAL.lstrip("/")).exists())

    def test_source_lock_is_required(self):
        source_lock = self.root / SOURCE_LOCK.lstrip("/")
        source_lock.unlink()
        preview = self.installer.preview()
        self.assertFalse(preview["can_apply"])
        self.assertIn("lock unavailable", preview["reason"])

    def test_dependencies_and_apparmor_helper_are_explicit(self):
        self.installer.dependencies = lambda: (() if self.system.apt_installed else
                                               ("wg", "python3-cryptography"))
        profile = self.root / "etc/apparmor.d/wg-quick"
        profile.parent.mkdir(parents=True)
        profile.write_text("# test-only profile\n")
        preview = self.installer.preview()
        self.assertEqual(preview["missing_dependencies"], ["wg", "python3-cryptography"])
        self.assertTrue(preview["apparmor_profile_present"])
        self.installer.apply(preview["state_revision"])
        self.assertTrue(self.system.apt_installed)
        self.assertTrue(any(command[0].endswith("apt-get") and command[1] == "install"
                            for command in self.system.commands))
        self.assertTrue(any(command[0] == "/usr/bin/python3" and
                            command[-1].endswith("install-wg-quick-apparmor.py")
                            for command in self.system.commands))

    def test_failed_apparmor_setup_rolls_back_broker_files(self):
        profile = self.root / "etc/apparmor.d/wg-quick"
        profile.parent.mkdir(parents=True)
        profile.write_text("# test-only profile\n")
        self.system.fail_apparmor_once = True
        with self.assertRaises(InstallError):
            self.installer.apply(self.installer.preview()["state_revision"])
        self.assertFalse(self.system.enabled)
        self.assertFalse((self.root / MARKER.lstrip("/")).exists())
        self.assertFalse((self.root / JOURNAL.lstrip("/")).exists())

    def test_failed_unit_verification_restores_clean_state(self):
        self.system.fail_verify_once = True
        with self.assertRaises(InstallError):
            self.installer.apply(self.installer.preview()["state_revision"])
        self.assertFalse((self.root / MARKER.lstrip("/")).exists())
        self.assertFalse((self.root / JOURNAL.lstrip("/")).exists())
        self.assertFalse(self.system.enabled)

    def test_source_change_after_preview_is_stale(self):
        preview = self.installer.preview()
        source = self.repo / "deploy/sovagrid-vpn-broker"
        source.write_bytes(source.read_bytes() + b"\n# next revision\n")
        with self.assertRaisesRegex(InstallError, "stale"):
            self.installer.apply(preview["state_revision"])


if __name__ == "__main__":
    unittest.main()
