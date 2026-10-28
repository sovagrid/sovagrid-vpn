# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The explicit wg-quick AppArmor installer preserves unrelated policy."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "install-wg-quick-apparmor.py"
SPEC = importlib.util.spec_from_file_location("sovagrid_apparmor_setup", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


class AppArmorSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "apparmor.d"
        self.root.mkdir(mode=0o755)
        self.profile = self.root / "wg-quick"
        self.profile.write_text("profile wg-quick {\n  #include <local/wg-quick>\n}\n")
        self.local_dir = self.root / "local"
        self.local_dir.mkdir(mode=0o755)
        self.local = self.local_dir / "wg-quick"
        self.calls = []
        self.fail_validate = False
        self.fail_reload_once = False

    def runner(self, args, **kwargs):
        self.calls.append(tuple(args))
        if args[1] == "-Q" and self.fail_validate:
            return subprocess.CompletedProcess(args, 1, "", "private parser output")
        if args[1] == "-r" and self.fail_reload_once:
            self.fail_reload_once = False
            return subprocess.CompletedProcess(args, 1, "", "private parser output")
        return subprocess.CompletedProcess(args, 0, "", "")

    def install(self, **kwargs):
        return setup.install(profile=self.profile, local=self.local, runner=self.runner,
                             require_root=False, which=lambda _: "/usr/bin/fake", **kwargs)

    def test_preserves_unrelated_rules_and_is_idempotent(self):
        original = "  /srv/other/** r,\n"
        self.local.write_text(original)
        self.assertTrue(self.install())
        first = self.local.read_text()
        self.assertTrue(first.startswith(original))
        self.assertEqual(first.count(setup.RULE), 1)
        self.assertEqual([args[1] for args in self.calls], ["-Q", "-r"])
        self.assertFalse(self.install())
        self.assertEqual(self.local.read_text(), first)
        self.assertEqual(self.local.read_text().count(setup.RULE), 1)

    def test_validation_failure_restores_existing_rules_without_reload(self):
        original = "  /srv/other/** r,\n"
        self.local.write_text(original)
        self.fail_validate = True
        with self.assertRaisesRegex(setup.SetupError, "syntax validation"):
            self.install()
        self.assertEqual(self.local.read_text(), original)
        self.assertEqual([args[1] for args in self.calls], ["-Q"])

    def test_reload_failure_restores_existing_rules_and_previous_profile(self):
        original = "  /srv/other/** r,\n"
        self.local.write_text(original)
        self.fail_reload_once = True
        with self.assertRaisesRegex(setup.SetupError, "profile reload failed"):
            self.install()
        self.assertEqual(self.local.read_text(), original)
        self.assertEqual([args[1] for args in self.calls], ["-Q", "-r", "-r"])

    def test_missing_local_dir_created_and_validation_failure_removes_rule(self):
        self.local_dir.rmdir()
        self.fail_validate = True
        with self.assertRaisesRegex(setup.SetupError, "syntax validation"):
            self.install()
        self.assertTrue(self.local_dir.is_dir())
        self.assertFalse(self.local.exists())

    def test_missing_prerequisite_and_unsafe_files_fail_before_write(self):
        with self.assertRaisesRegex(setup.SetupError, "wg-quick"):
            setup.install(profile=self.profile, local=self.local, runner=self.runner,
                          require_root=False, which=lambda cmd: None if cmd == "wg-quick" else "/bin/x")
        self.assertFalse(self.local.exists())
        self.profile.write_text("profile wg-quick { }\n")
        with self.assertRaisesRegex(setup.SetupError, "does not include"):
            self.install()
        self.assertFalse(self.local.exists())
        self.profile.write_text("profile wg-quick {\n  #include <local/wg-quick>\n}\n")
        self.local.symlink_to(self.profile)
        with self.assertRaisesRegex(setup.SetupError, "Unsafe AppArmor file"):
            self.install()
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
