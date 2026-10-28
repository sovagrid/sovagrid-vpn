# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Dormant-by-default installer for the optional Amnezia control socket.

This module never enrolls a container or changes its files. Installation only
copies fixed root-owned units and launchers. Arming is a separate root action
after a read-only check of the exact enrolled AWG2 or WireGuard container.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Callable

from .amnezia_admin import AmneziaAdmin, AmneziaAdminError, TARGETS
from .amnezia_control import (ENABLE_FILE, SETTINGS_ENABLE_FILE,
                              WIREGUARD_ENABLE_FILE, _enabled, _marker_enabled)


CONFIRM = "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2"
CONFIRM_WIREGUARD = "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_WIREGUARD"
CONFIRM_SETTINGS = "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG3_SETTINGS"
LOCK_FILE = "/etc/sovagrid-vpn/amnezia-install.lock"
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_ANALYZE = "/usr/bin/systemd-analyze"
SOCKET_UNIT = "sovagrid-amnezia-control.socket"
SERVICE_UNIT = "sovagrid-amnezia-control.service"
MANAGED_HEADER = b"# Managed by SovaGrid optional Amnezia installer\n"
FILES = (
    ("sovagrid-amnezia-ctl", "/usr/local/bin/sovagrid-amnezia-ctl", 0o755),
    ("sovagrid-amnezia-broker", "/usr/local/libexec/sovagrid-amnezia-broker", 0o755),
    (SERVICE_UNIT, "/etc/systemd/system/" + SERVICE_UNIT, 0o644),
    (SOCKET_UNIT, "/etc/systemd/system/" + SOCKET_UNIT, 0o644),
)
HEX_ID = re.compile(r"[0-9a-f]{64}\Z")


class InstallError(RuntimeError):
    """A fixed, secret-free install or preflight failure."""


@dataclass(frozen=True)
class Layout:
    root: Path = Path("/")
    repo: Path = Path("/opt/sovagrid-src/sovagrid-vpn")

    def at(self, absolute: str) -> Path:
        return self.root / absolute.lstrip("/")


def _safe_dir(path: Path, owner: int, *, private: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallError("Required installer directory is missing") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or
            info.st_mode & (0o077 if private else 0o022)):
        raise InstallError("Installer directory has unsafe ownership or permissions")


def _read_regular(path: Path, owner: int, *, limit: int = 262144) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or
                    info.st_nlink != 1 or info.st_mode & 0o022 or
                    info.st_size > limit):
                raise InstallError("Installer file has unsafe ownership or permissions")
            raw = os.read(fd, limit + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        raise InstallError("Required installer file is missing or unsafe") from exc
    if len(raw) > limit:
        raise InstallError("Installer file exceeds size limit")
    return raw


def _atomic_install(path: Path, data: bytes, mode: int, owner: int) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".sovagrid-amnezia-", dir=path.parent)
    try:
        os.fchown(fd, owner, 0 if owner == 0 else os.getegid())
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(data)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = ""
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary:
            os.unlink(temporary)


class Installer:
    def __init__(self, layout: Layout = Layout(), *, owner: int = 0,
                 run: Callable = subprocess.run,
                 admin_factory: Callable = lambda: AmneziaAdmin(TARGETS["awg2"]),
                 wireguard_admin_factory: Callable = lambda: AmneziaAdmin(TARGETS["wireguard"])):
        self.layout = layout
        self.owner = owner
        self.run = run
        self.admin_factory = admin_factory
        self.wireguard_admin_factory = wireguard_admin_factory

    @contextmanager
    def _mutation_lock(self):
        """Serialize marker and shared socket decisions across installer processes."""
        directory = self.layout.at("/etc/sovagrid-vpn")
        if not directory.exists() and not directory.is_symlink():
            try:
                directory.mkdir(mode=0o700)
                os.chown(directory, self.owner, 0 if self.owner == 0 else os.getegid())
            except FileExistsError:
                pass
        _safe_dir(directory, self.owner, private=True)
        try:
            fd = os.open(self.layout.at(LOCK_FILE),
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            raise InstallError("Amnezia installer lock unavailable") from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise InstallError("Amnezia installer lock is unsafe")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError as exc:
                raise InstallError("Amnezia installer lock unavailable") from exc
            yield
        finally:
            os.close(fd)

    def _command(self, *argv: str, accepted: tuple[int, ...] = (0,)) -> int:
        try:
            result = self.run(list(argv), capture_output=True, check=False, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InstallError("systemd command unavailable") from exc
        if result.returncode not in accepted:
            raise InstallError("systemd command failed")
        return result.returncode

    def _active(self, unit: str) -> bool:
        return self._command(SYSTEMCTL, "is-active", "--quiet", unit,
                             accepted=(0, 3, 4)) == 0

    def _source(self) -> dict[str, bytes]:
        expected = self.layout.at("/opt/sovagrid-src/sovagrid-vpn")
        if self.layout.repo != expected:
            raise InstallError("Run installer from the root-owned deployed source tree")
        for path in (self.layout.at("/opt"), self.layout.at("/opt/sovagrid-src"),
                     self.layout.repo, self.layout.repo / "deploy"):
            _safe_dir(path, self.owner)
        sources = {}
        for name, _, _ in FILES:
            raw = _read_regular(self.layout.repo / "deploy" / name, self.owner)
            if name in (SERVICE_UNIT, SOCKET_UNIT):
                if not raw.startswith(MANAGED_HEADER):
                    raise InstallError("Amnezia unit template has no managed marker")
            elif raw.splitlines()[1:2] != [MANAGED_HEADER.rstrip(b"\n")]:
                raise InstallError("Amnezia launcher has no managed marker")
            sources[name] = raw
        package = self.layout.repo / "sovagrid_vpn"
        deployed = self.layout.at("/opt/sovagrid-vpn/sovagrid_vpn")
        _safe_dir(package, self.owner)
        for path in (self.layout.at("/opt/sovagrid-vpn"), deployed):
            _safe_dir(path, self.owner)
        for file in package.glob("*.py"):
            source = _read_regular(file, self.owner)
            if source != _read_regular(deployed / file.name, self.owner):
                raise InstallError("Deployed VPN code differs; rerun SovaGrid run.sh first")
        return sources

    def _destinations(self, sources: dict[str, bytes], *, exact: bool) -> None:
        for name, absolute, mode in FILES:
            path = self.layout.at(absolute)
            if path.parent == self.layout.at("/usr/local/libexec") and not path.parent.exists():
                if exact:
                    raise InstallError("Amnezia broker package is not installed")
                _safe_dir(path.parent.parent, self.owner)
            else:
                _safe_dir(path.parent, self.owner)
            if not path.exists() and not path.is_symlink():
                if exact:
                    raise InstallError("Amnezia broker package is not installed")
                continue
            raw = _read_regular(path, self.owner)
            info = path.lstat()
            if stat.S_IMODE(info.st_mode) != mode:
                raise InstallError("Amnezia installation has unsafe file mode")
            if name in (SERVICE_UNIT, SOCKET_UNIT):
                managed = raw.startswith(MANAGED_HEADER)
            else:
                managed = raw.splitlines()[1:2] == [MANAGED_HEADER.rstrip(b"\n")]
            if not managed:
                raise InstallError("Refusing to replace an unmanaged Amnezia file")
            if exact and raw != sources[name]:
                raise InstallError("Installed Amnezia package differs from source")

    def _marker(self, target: str = "awg2") -> str:
        if target not in TARGETS:
            raise InstallError("Unsupported Amnezia target")
        marker_path = ENABLE_FILE if target == "awg2" else WIREGUARD_ENABLE_FILE
        marker = self.layout.at(str(marker_path))
        if not marker.exists() and not marker.is_symlink():
            return "absent"
        if self.layout.root == Path("/"):
            return "valid" if _enabled(target) else "unsafe"
        try:
            _safe_dir(marker.parent, self.owner, private=True)
            raw = _read_regular(marker, self.owner, limit=8)
            info = marker.lstat()
            if stat.S_IMODE(info.st_mode) == 0o600 and raw == b"enabled\n":
                return "valid"
        except InstallError:
            pass
        return "unsafe"

    def _settings_marker(self) -> str:
        marker = self.layout.at(str(SETTINGS_ENABLE_FILE))
        if not marker.exists() and not marker.is_symlink():
            return "absent"
        if self.layout.root == Path("/"):
            return "valid" if _marker_enabled(SETTINGS_ENABLE_FILE) else "unsafe"
        try:
            _safe_dir(marker.parent, self.owner, private=True)
            raw = _read_regular(marker, self.owner, limit=8)
            if stat.S_IMODE(marker.lstat().st_mode) == 0o600 and raw == b"enabled\n":
                return "valid"
        except InstallError:
            pass
        return "unsafe"

    def _sync_marker_dir(self) -> None:
        directory = self.layout.at("/etc/sovagrid-vpn")
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _target(self, target: str = "awg2") -> dict:
        """Read-only checks: no state lock creation and no Docker writes."""
        if target not in TARGETS:
            raise InstallError("Unsupported Amnezia target")
        admin = (self.admin_factory() if target == "awg2" else
                 self.wireguard_admin_factory())
        label = "AWG2" if target == "awg2" else "WireGuard"
        try:
            try:
                state, _ = admin._load_state()
            except FileNotFoundError:
                # An absent enrollment file is the normal initial state. Keep
                # it distinct from a corrupt or inconsistent live container.
                return {"ready": False, "reason": label + " is not enrolled"}
            admin._require_no_pending()
            config_raw, table_raw, config, rows, _, _, _ = admin._snapshot()
            admin._check_state(state, config_raw, table_raw, config)
            return {"ready": True, "container_id": state["container_id"],
                    "configured_clients": len(rows), "owned_clients": sorted(state["owned"])}
        except AmneziaAdminError as exc:
            return {"ready": False, "reason": str(exc)}
        except (OSError, ValueError, UnicodeError):
            return {"ready": False, "reason": label + " preflight failed"}

    def preview(self, target: str = "awg2") -> dict:
        other = "wireguard" if target == "awg2" else "awg2"
        result = {"schema_version": 1, "action": "preview", "writes": False,
                  "selected_target": target, "marker": self._marker(target),
                  "other_marker": self._marker(other), "socket_active": False,
                  "service_active": False, "installer_ready": False,
                  "installed_current": False, "can_arm": False,
                  "target": self._target(target)}
        try:
            sources = self._source()
            self._destinations(sources, exact=False)
            result["installed_current"] = all(
                self.layout.at(absolute).exists() and
                _read_regular(self.layout.at(absolute), self.owner) == sources[name]
                for name, absolute, _ in FILES)
            result["socket_active"] = self._active(SOCKET_UNIT)
            result["service_active"] = self._active(SERVICE_UNIT)
            result["installer_ready"] = True
            result["can_arm"] = (result["installed_current"] and
                                 result["target"]["ready"] and
                                 result["marker"] == "absent" and
                                 result["other_marker"] != "unsafe" and
                                 (result["socket_active"] and
                                  result["other_marker"] == "valid" or
                                  not result["socket_active"] and
                                  not result["service_active"]))
        except InstallError as exc:
            result["reason"] = str(exc)
        return result

    @staticmethod
    def _settings_probe(admin: AmneziaAdmin, preview: dict) -> bool:
        if (preview["configured_clients"] != 0 or
                not preview["awg3_required_parameters_present"]):
            return False
        current = preview["awg_parameters"]["Jc"]
        patch = {"Jc": "2" if current == "1" else "1"}
        plan = admin.settings_plan(preview["config_sha256"], preview["generation"], patch)
        return plan["apply_supported"] is True and plan["apply_blockers"] == []

    def preview_settings(self) -> dict:
        """Read-only capability check for a separate AWG3 settings opt-in."""
        result = {"schema_version": 1, "action": "preview-settings",
                  "selected_target": "awg2", "settings_marker": self._settings_marker(),
                  "peer_marker": self._marker("awg2"),
                  "socket_active": False, "target_ready": False,
                  "container_id": None, "configured_clients": None,
                  "awg3_runtime_verified": False, "can_arm": False,
                  "reason": None}
        try:
            self._destinations(self._source(), exact=True)
        except InstallError:
            result["reason"] = "INSTALL_NOT_CURRENT"
            return result
        try:
            result["socket_active"] = self._active(SOCKET_UNIT)
            target = self._target("awg2")
            result["target_ready"] = target["ready"]
            if not target["ready"]:
                result["reason"] = "TARGET_UNAVAILABLE"
                return result
            result["container_id"] = target["container_id"]
            result["configured_clients"] = target["configured_clients"]
            if target["configured_clients"] != 0:
                result["reason"] = "CLIENTS_PRESENT"
                return result
            admin = self.admin_factory()
            preview = admin.settings_preview()
            if not preview["awg3_required_parameters_present"]:
                result["reason"] = "AWG3_INCOMPLETE"
                return result
            result["awg3_runtime_verified"] = self._settings_probe(admin, preview)
        except (InstallError, AmneziaAdminError, KeyError, TypeError):
            result["reason"] = "RUNTIME_UNVERIFIED"
            return result
        if (result["settings_marker"] == "unsafe" or result["peer_marker"] == "unsafe" or
                result["settings_marker"] == "valid" and result["peer_marker"] != "valid"):
            result["reason"] = "POLICY_UNSAFE"
        elif result["settings_marker"] == "valid":
            result["reason"] = "ALREADY_ARMED"
        elif result["peer_marker"] != "valid" or not result["socket_active"]:
            result["reason"] = "POLICY_NOT_READY"
        elif not result["awg3_runtime_verified"]:
            result["reason"] = "RUNTIME_UNVERIFIED"
        else:
            result["can_arm"] = True
        return result

    def install(self) -> dict:
        with self._mutation_lock():
            return self._install_locked()

    def _install_locked(self) -> dict:
        sources = self._source()
        self._destinations(sources, exact=False)
        if (any(self._marker(target) != "absent" for target in TARGETS) or
                self._settings_marker() != "absent"):
            raise InstallError("Disarm Amnezia control before installing or upgrading")
        if self._active(SOCKET_UNIT) or self._active(SERVICE_UNIT):
            raise InstallError("Stop the existing Amnezia broker before upgrading")
        libexec = self.layout.at("/usr/local/libexec")
        if not libexec.exists() and not libexec.is_symlink():
            libexec.mkdir(mode=0o755)
            os.chown(libexec, self.owner, 0 if self.owner == 0 else os.getegid())
        _safe_dir(libexec, self.owner)
        for name, absolute, mode in FILES:
            _atomic_install(self.layout.at(absolute), sources[name], mode, self.owner)
        self._command(SYSTEMD_ANALYZE, "verify",
                      str(self.layout.at("/etc/systemd/system/" + SERVICE_UNIT)),
                      str(self.layout.at("/etc/systemd/system/" + SOCKET_UNIT)))
        self._command(SYSTEMCTL, "daemon-reload")
        return {"action": "installed", "socket_active": False,
                "marker": "absent", "target_changed": False}

    def arm(self, container_id: str, confirmation: str) -> dict:
        return self.arm_target("awg2", container_id, confirmation)

    def arm_target(self, target: str, container_id: str, confirmation: str) -> dict:
        with self._mutation_lock():
            return self._arm_target_locked(target, container_id, confirmation)

    def _arm_target_locked(self, target: str, container_id: str,
                           confirmation: str) -> dict:
        if target not in TARGETS:
            raise InstallError("Unsupported Amnezia target")
        expected = CONFIRM if target == "awg2" else CONFIRM_WIREGUARD
        if not HEX_ID.fullmatch(container_id or "") or confirmation != expected:
            raise InstallError("Explicit Amnezia container and maintenance confirmation required")
        sources = self._source()
        self._destinations(sources, exact=True)
        other = "wireguard" if target == "awg2" else "awg2"
        if self._marker(target) != "absent" or self._marker(other) == "unsafe":
            raise InstallError("Amnezia control is already armed or has an unsafe marker")
        active = self._active(SOCKET_UNIT)
        if (active and self._marker(other) != "valid" or
                not active and self._active(SERVICE_UNIT)):
            raise InstallError("Stop the existing Amnezia broker before arming")
        target_status = self._target(target)
        if not target_status["ready"] or target_status["container_id"] != container_id:
            raise InstallError("Amnezia target is not ready or the confirmed container ID differs")
        directory = self.layout.at("/etc/sovagrid-vpn")
        if not directory.exists() and not directory.is_symlink():
            directory.mkdir(mode=0o700)
            os.chown(directory, self.owner, 0 if self.owner == 0 else os.getegid())
        _safe_dir(directory, self.owner, private=True)
        marker = self.layout.at(str(ENABLE_FILE if target == "awg2"
                                    else WIREGUARD_ENABLE_FILE))
        _atomic_install(marker, b"enabled\n", 0o600, self.owner)
        if not active:
            try:
                self._command(SYSTEMCTL, "enable", "--now", SOCKET_UNIT)
                if not self._active(SOCKET_UNIT):
                    raise InstallError("Amnezia control socket did not become active")
            except InstallError:
                marker.unlink(missing_ok=True)
                try:
                    self._command(SYSTEMCTL, "disable", "--now", SOCKET_UNIT)
                except InstallError:
                    pass
                raise
        elif not self._active(SOCKET_UNIT):
            marker.unlink(missing_ok=True)
            raise InstallError("Amnezia control socket is no longer active")
        return {"action": "armed", "socket_active": True,
                "marker": "valid", "selected_target": target, "target_changed": False}

    def disarm(self, target: str = "awg2") -> dict:
        with self._mutation_lock():
            return self._disarm_locked(target)

    def arm_settings(self, container_id: str, confirmation: str) -> dict:
        """Separate opt-in for AWG3 numeric mutations; peer arm is insufficient."""
        with self._mutation_lock():
            if (not HEX_ID.fullmatch(container_id or "") or
                    confirmation != CONFIRM_SETTINGS):
                raise InstallError("Explicit AWG3 settings maintenance confirmation required")
            self._destinations(self._source(), exact=True)
            if (self._marker("awg2") != "valid" or
                    self._settings_marker() != "absent" or
                    not self._active(SOCKET_UNIT)):
                raise InstallError("AWG3 settings control is not ready for arming")
            target = self._target("awg2")
            if (not target["ready"] or target["container_id"] != container_id or
                    target["configured_clients"] != 0):
                raise InstallError("AWG3 settings require the confirmed empty container")
            try:
                admin = self.admin_factory()
                preview = admin.settings_preview()
            except AmneziaAdminError as exc:
                raise InstallError(str(exc)) from exc
            if (preview["container_id"] != container_id or
                    preview["configured_clients"] != 0 or
                    not self._settings_probe(admin, preview)):
                raise InstallError("AWG3 settings preflight is incomplete")
            _atomic_install(self.layout.at(str(SETTINGS_ENABLE_FILE)),
                            b"enabled\n", 0o600, self.owner)
            return {"action": "settings_armed", "settings_marker": "valid",
                    "selected_target": "awg2", "container_id": container_id}

    def disarm_settings(self) -> dict:
        with self._mutation_lock():
            if self._settings_marker() == "unsafe":
                raise InstallError("AWG3 settings marker is unsafe; inspect it manually")
            if self._settings_marker() == "valid":
                self.layout.at(str(SETTINGS_ENABLE_FILE)).unlink()
                self._sync_marker_dir()
            return {"action": "settings_disarmed", "settings_marker": "absent",
                    "selected_target": "awg2"}

    def _disarm_locked(self, target: str) -> dict:
        if target not in TARGETS:
            raise InstallError("Unsupported Amnezia target")
        other = "wireguard" if target == "awg2" else "awg2"
        marker = self.layout.at(str(ENABLE_FILE if target == "awg2"
                                    else WIREGUARD_ENABLE_FILE))
        if self._marker(target) == "unsafe" or self._marker(other) == "unsafe":
            raise InstallError("Amnezia marker is unsafe; inspect it manually")
        if target == "awg2":
            if self._settings_marker() == "unsafe":
                raise InstallError("AWG3 settings marker is unsafe; inspect it manually")
            if self._settings_marker() == "valid":
                self.layout.at(str(SETTINGS_ENABLE_FILE)).unlink()
                self._sync_marker_dir()
        if self._marker(target) == "valid":
            marker.unlink()
            self._sync_marker_dir()
        if self._marker(other) != "valid":
            self._command(SYSTEMCTL, "disable", "--now", SOCKET_UNIT)
        return {"action": "disarmed", "marker": "absent",
                "selected_target": target, "service_may_remain_running": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Optional Amnezia broker installer")
    sub = parser.add_subparsers(dest="action", required=True)
    preview = sub.add_parser("preview")
    preview.add_argument("--target", choices=TARGETS, default="awg2")
    sub.add_parser("preview-settings")
    sub.add_parser("install")
    disarm = sub.add_parser("disarm")
    disarm.add_argument("--target", choices=TARGETS, default="awg2")
    arm = sub.add_parser("arm")
    arm.add_argument("--target", choices=TARGETS, default="awg2")
    arm.add_argument("--confirm-container-id", required=True)
    arm.add_argument("--confirm-maintenance-window", required=True)
    arm_settings = sub.add_parser("arm-settings")
    arm_settings.add_argument("--confirm-container-id", required=True)
    arm_settings.add_argument("--confirm-maintenance-window", required=True)
    sub.add_parser("disarm-settings")
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or sys.platform != "linux":
        print("Amnezia installer requires root on Linux", file=sys.stderr)
        return 2
    installer = Installer()
    try:
        if args.action == "preview":
            result = installer.preview(args.target)
        elif args.action == "preview-settings":
            result = installer.preview_settings()
        elif args.action == "install":
            result = installer.install()
        elif args.action == "arm":
            result = installer.arm_target(args.target, args.confirm_container_id,
                                          args.confirm_maintenance_window)
        elif args.action == "arm-settings":
            result = installer.arm_settings(args.confirm_container_id,
                                            args.confirm_maintenance_window)
        elif args.action == "disarm-settings":
            result = installer.disarm_settings()
        else:
            result = installer.disarm(args.target)
    except InstallError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Amnezia installer failed: {type(exc).__name__}", file=sys.stderr)
        return 3
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
