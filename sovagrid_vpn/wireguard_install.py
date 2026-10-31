# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in installation of the existing, narrowly scoped WireGuard broker.

This installer never creates a VPN interface or client.  A separate journal
allows an interrupted installation to be rolled back without overwriting a
file changed by another administrator after the interruption.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Callable


FILES = (
    ("sovagrid-vpn-ctl", "/usr/local/bin/sovagrid-vpn-ctl", 0o755),
    ("sovagrid-vpn-broker", "/usr/local/libexec/sovagrid-vpn-broker", 0o755),
    ("sovagrid-vpn-control.service", "/etc/systemd/system/sovagrid-vpn-control.service", 0o644),
    ("sovagrid-vpn-control.socket", "/etc/systemd/system/sovagrid-vpn-control.socket", 0o644),
)
SOCKET = "sovagrid-vpn-control.socket"
SERVICE = "sovagrid-vpn-control.service"
STATE_DIR = "/etc/sovagrid-vpn"
MARKER = STATE_DIR + "/wireguard-control-install.json"
JOURNAL = STATE_DIR + "/wireguard-control-install.pending.json"
LOCK = STATE_DIR + "/wireguard-control-install.lock"
SOURCE_LOCK = "/var/lib/sovagrid/vpn-source/.lock"
SYSTEMCTL = "/usr/bin/systemctl"
ANALYZE = "/usr/bin/systemd-analyze"
APT = "/usr/bin/apt-get"
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE = 256 * 1024
MAX_JOURNAL = 2 * 1024 * 1024


class InstallError(RuntimeError):
    """A fixed, secret-free preflight or installation failure."""


@dataclass(frozen=True)
class Layout:
    root: Path = Path("/")
    repo: Path = Path("/opt/sovagrid-src/sovagrid-vpn")

    def at(self, absolute: str) -> Path:
        return self.root / absolute.lstrip("/")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(data: object) -> bytes:
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _safe_dir(path: Path, owner: int, *, private: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallError("Required installer directory is missing") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or
            info.st_mode & (0o077 if private else 0o022)):
        raise InstallError("Installer directory has unsafe ownership or permissions")


def _read_file(path: Path, owner: int, *, private: bool = False,
               limit: int = MAX_FILE) -> tuple[bytes, int]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or
                    info.st_nlink != 1 or info.st_size > limit or
                    info.st_mode & (0o077 if private else 0o022)):
                raise InstallError("Installer file has unsafe ownership or permissions")
            raw = os.read(fd, limit + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        raise InstallError("Installer file is missing or unsafe") from exc
    if len(raw) > limit:
        raise InstallError("Installer file exceeds size limit")
    return raw, stat.S_IMODE(info.st_mode)


def _maybe_file(path: Path, owner: int, *, private: bool = False,
                limit: int = MAX_FILE) -> tuple[bytes, int] | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return _read_file(path, owner, private=private, limit=limit)


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic(path: Path, data: bytes, mode: int, owner: int) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".sovagrid-wg-install-", dir=path.parent)
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
        _sync_dir(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary:
            os.unlink(temporary)


def _remove(path: Path) -> None:
    path.unlink()
    _sync_dir(path.parent)


class Installer:
    def __init__(self, layout: Layout = Layout(), *, owner: int = 0,
                 run: Callable = subprocess.run,
                 dependencies: Callable[[], tuple[str, ...]] | None = None):
        self.layout = layout
        self.owner = owner
        self.run = run
        self.dependencies = dependencies or self._missing_dependencies

    def _command(self, *argv: str, accepted: tuple[int, ...] = (0,),
                 timeout: int = 30, env: dict | None = None) -> int:
        try:
            completed = self.run(list(argv), check=False, capture_output=True,
                                 timeout=timeout, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InstallError("Required system command unavailable") from exc
        if completed.returncode not in accepted:
            raise InstallError("Required system command failed")
        return completed.returncode

    @contextmanager
    def _source_lock(self):
        """A source update cannot replace either VPN code tree during setup."""
        for absolute in ("/var", "/var/lib", "/var/lib/sovagrid",
                         "/var/lib/sovagrid/vpn-source"):
            _safe_dir(self.layout.at(absolute), self.owner,
                      private=absolute.endswith("/vpn-source"))
        try:
            fd = os.open(self.layout.at(SOURCE_LOCK), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise InstallError("Verified VPN source lock unavailable") from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise InstallError("Verified VPN source lock is unsafe")
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except OSError as exc:
                raise InstallError("Verified VPN source is busy") from exc
            yield
        finally:
            os.close(fd)

    def _active(self, unit: str) -> bool:
        return self._command(SYSTEMCTL, "is-active", "--quiet", unit,
                             accepted=(0, 3, 4)) == 0

    def _enabled(self, unit: str) -> bool:
        return self._command(SYSTEMCTL, "is-enabled", "--quiet", unit,
                             accepted=(0, 1, 3, 4)) == 0

    @staticmethod
    def _missing_dependencies() -> tuple[str, ...]:
        missing = []
        for executable in ("wg", "wg-quick", "ip"):
            if shutil.which(executable) is None:
                missing.append(executable)
        try:
            probe = subprocess.run(["/usr/bin/python3", "-I", "-B", "-c", "import cryptography"],
                                   capture_output=True, timeout=10, check=False)
            if probe.returncode != 0:
                missing.append("python3-cryptography")
        except (OSError, subprocess.TimeoutExpired):
            missing.append("python3-cryptography")
        if Path("/etc/apparmor.d/wg-quick").exists() and shutil.which("apparmor_parser") is None:
            missing.append("apparmor_parser")
        return tuple(missing)

    def _source(self) -> dict[str, bytes]:
        if self.layout.repo != self.layout.at("/opt/sovagrid-src/sovagrid-vpn"):
            raise InstallError("Installer source path is not fixed")
        for directory in ("/opt", "/opt/sovagrid-src", "/opt/sovagrid-src/sovagrid-vpn",
                          "/opt/sovagrid-src/sovagrid-vpn/deploy",
                          "/opt/sovagrid-src/sovagrid-vpn/sovagrid_vpn",
                          "/opt/sovagrid-vpn", "/opt/sovagrid-vpn/sovagrid_vpn"):
            _safe_dir(self.layout.at(directory), self.owner)
        source_package = self.layout.repo / "sovagrid_vpn"
        deployed_package = self.layout.at("/opt/sovagrid-vpn/sovagrid_vpn")
        package_files = sorted(source_package.glob("*.py"))
        if not package_files or {p.name for p in package_files} != {
                p.name for p in deployed_package.glob("*.py")}:
            raise InstallError("VPN source and installed package differ")
        for source in package_files:
            raw, _ = _read_file(source, self.owner)
            if raw != _read_file(deployed_package / source.name, self.owner)[0]:
                raise InstallError("VPN source and installed package differ")
        sources = {}
        for name, _, _ in FILES:
            sources[name] = _read_file(self.layout.repo / "deploy" / name,
                                       self.owner)[0]
        sources["install-wg-quick-apparmor.py"] = _read_file(
            self.layout.repo / "deploy/install-wg-quick-apparmor.py", self.owner)[0]
        for name in ("sovagrid-vpn-ctl", "sovagrid-vpn-broker"):
            if sources[name].splitlines()[1:2] != [b"# Managed by SovaGrid run.sh"]:
                raise InstallError("VPN launcher has no managed header")
        return sources

    def _marker(self) -> dict | None:
        path = self.layout.at(MARKER)
        if not path.parent.exists() and not path.parent.is_symlink():
            return None
        _safe_dir(path.parent, self.owner, private=True)
        item = _maybe_file(path, self.owner, private=True)
        if item is None:
            return None
        raw, mode = item
        if mode != 0o600:
            raise InstallError("VPN installer marker has unsafe mode")
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise InstallError("VPN installer marker is invalid") from exc
        if (type(result) is not dict or result.get("schema_version") != 1 or
                type(result.get("files")) is not dict or
                set(result["files"]) != {absolute for _, absolute, _ in FILES} or
                any(not isinstance(value, str) or not HEX.fullmatch(value)
                    for value in result["files"].values())):
            raise InstallError("VPN installer marker is invalid")
        return result

    def _pending(self) -> bool:
        path = self.layout.at(JOURNAL)
        if not path.parent.exists() and not path.parent.is_symlink():
            return False
        _safe_dir(path.parent, self.owner, private=True)
        return _maybe_file(path, self.owner, private=True,
                           limit=MAX_JOURNAL) is not None

    def _destinations(self, sources: dict[str, bytes], marker: dict | None) -> dict:
        result = {}
        for name, absolute, mode in FILES:
            path = self.layout.at(absolute)
            if not path.parent.exists() and not path.parent.is_symlink():
                if path.parent != self.layout.at("/usr/local/libexec"):
                    raise InstallError("Required VPN destination directory is missing")
                if marker is not None:
                    raise InstallError("Managed VPN destination directory is missing")
                _safe_dir(path.parent.parent, self.owner)
                result[absolute] = None
                continue
            _safe_dir(path.parent, self.owner)
            item = _maybe_file(path, self.owner)
            if item is not None:
                raw, installed_mode = item
                if installed_mode != mode:
                    raise InstallError("VPN installation has unsafe file mode")
                expected = marker["files"][absolute] if marker else _sha(sources[name])
                if _sha(raw) != expected:
                    raise InstallError("Refusing to replace an unmanaged VPN file")
                result[absolute] = item
            else:
                if marker is not None:
                    raise InstallError("Managed VPN file is missing")
                result[absolute] = None
        return result

    def _observe(self) -> tuple[dict, dict[str, bytes], dict]:
        sources = self._source()
        marker = self._marker()
        destinations = self._destinations(sources, marker)
        pending = self._pending()
        active = self._active(SOCKET)
        service_active = self._active(SERVICE)
        enabled = self._enabled(SOCKET)
        missing = self.dependencies()
        current = all(destinations[absolute] is not None and
                      destinations[absolute][0] == sources[name]
                      for name, absolute, _ in FILES)
        state = {"source": {name: _sha(raw) for name, raw in sources.items()},
                 "files": {absolute: _sha(item[0]) if item else None
                           for absolute, item in destinations.items()},
                 "marker": _sha(_json(marker)) if marker else None,
                 "pending": pending, "socket_active": active,
                 "service_active": service_active, "socket_enabled": enabled,
                 "missing_dependencies": missing}
        mutation_needed = not current
        broker_busy = active or service_active or enabled
        preview = {"schema_version": 1, "action": "preview", "writes": False,
                   "state_revision": _sha(_json(state)), "source_revision":
                   _sha(_json(state["source"])), "installed_current": current,
                   "socket_active": active, "service_active": service_active,
                   "socket_enabled": enabled, "pending_recovery": pending,
                   "missing_dependencies": list(missing),
                   "apparmor_profile_present": self.layout.at("/etc/apparmor.d/wg-quick").exists(),
                   "can_apply": not pending and not (mutation_needed and broker_busy),
                   "requires_service_restart": mutation_needed and broker_busy}
        if pending:
            preview["reason"] = "RECOVERY_REQUIRED"
        elif mutation_needed and broker_busy:
            preview["reason"] = "STOP_BROKER_BEFORE_UPGRADE"
        return preview, sources, destinations

    def preview(self) -> dict:
        try:
            with self._source_lock():
                if self._pending():
                    return {"schema_version": 1, "action": "preview",
                            "writes": False, "can_apply": False,
                            "pending_recovery": True, "reason": "RECOVERY_REQUIRED"}
                return self._observe()[0]
        except InstallError as exc:
            return {"schema_version": 1, "action": "preview", "writes": False,
                    "can_apply": False, "reason": str(exc)}

    @contextmanager
    def _lock(self):
        directory = self.layout.at(STATE_DIR)
        if not directory.exists() and not directory.is_symlink():
            directory.mkdir(mode=0o700)
            os.chown(directory, self.owner, 0 if self.owner == 0 else os.getegid())
            _sync_dir(directory.parent)
        _safe_dir(directory, self.owner, private=True)
        try:
            fd = os.open(self.layout.at(LOCK), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            raise InstallError("VPN installer lock unavailable") from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise InstallError("VPN installer lock is unsafe")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _ensure_dependencies(self, missing: list[str]) -> None:
        if not missing:
            return
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "DEBIAN_FRONTEND": "noninteractive"}
        self._command(APT, "update", timeout=180, env=environment)
        self._command(APT, "install", "-y", "--no-install-recommends",
                      "wireguard-tools", "iproute2", "python3-cryptography",
                      *(("apparmor",) if "apparmor_parser" in missing else ()),
                      timeout=180, env=environment)
        if self.dependencies():
            raise InstallError("Required WireGuard dependencies remain unavailable")

    def _ensure_directories(self) -> None:
        for absolute, mode in (("/usr/local/libexec", 0o755),
                               ("/var/lib/sovagrid-vpn", 0o700),
                               ("/etc/wireguard", 0o700)):
            path = self.layout.at(absolute)
            if not path.exists() and not path.is_symlink():
                _safe_dir(path.parent, self.owner)
                path.mkdir(mode=mode)
                os.chown(path, self.owner, 0 if self.owner == 0 else os.getegid())
                _sync_dir(path.parent)
            _safe_dir(path, self.owner, private=mode == 0o700)

    @staticmethod
    def _encode(item: tuple[bytes, int] | None) -> dict | None:
        return {"data": base64.b64encode(item[0]).decode("ascii"), "mode": item[1]} if item else None

    @staticmethod
    def _decode(item: object) -> tuple[bytes, int] | None:
        if item is None:
            return None
        if (type(item) is not dict or set(item) != {"data", "mode"} or
                type(item["mode"]) is not int or item["mode"] not in (0o600, 0o644, 0o755) or
                type(item["data"]) is not str):
            raise InstallError("VPN installer journal is invalid")
        try:
            raw = base64.b64decode(item["data"], validate=True)
        except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
            raise InstallError("VPN installer journal is invalid") from exc
        if len(raw) > MAX_FILE:
            raise InstallError("VPN installer journal is invalid")
        return raw, item["mode"]

    def _journal(self) -> dict:
        raw, mode = _read_file(self.layout.at(JOURNAL), self.owner, private=True,
                               limit=MAX_JOURNAL)
        if mode != 0o600:
            raise InstallError("VPN installer journal has unsafe mode")
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise InstallError("VPN installer journal is invalid") from exc
        paths = {absolute for _, absolute, _ in FILES}
        if (type(value) is not dict or value.get("schema_version") != 1 or
                type(value.get("old_files")) is not dict or set(value["old_files"]) != paths or
                type(value.get("new_hashes")) is not dict or set(value["new_hashes"]) != paths or
                any(not isinstance(digest, str) or not HEX.fullmatch(digest)
                    for digest in value["new_hashes"].values()) or
                not isinstance(value.get("new_marker_hash"), str) or
                not HEX.fullmatch(value["new_marker_hash"]) or
                type(value.get("socket_active")) is not bool or
                type(value.get("socket_enabled")) is not bool or
                type(value.get("service_active")) is not bool):
            raise InstallError("VPN installer journal is invalid")
        for _, absolute, mode in FILES:
            old = self._decode(value["old_files"][absolute])
            if old is not None and old[1] != mode:
                raise InstallError("VPN installer journal is invalid")
        old_marker = self._decode(value.get("old_marker"))
        if old_marker is not None and old_marker[1] != 0o600:
            raise InstallError("VPN installer journal is invalid")
        return value

    def _rollback(self, value: dict) -> None:
        # Inspect *all* paths before touching a service or file. A later admin
        # edit must leave the original journal intact for manual resolution.
        old_files = {}
        for _, absolute, mode in FILES:
            path = self.layout.at(absolute)
            old = self._decode(value["old_files"][absolute])
            current = _maybe_file(path, self.owner)
            if old is not None and current is None:
                raise InstallError("VPN install changed externally; manual recovery required")
            if current is not None and (current[1] != mode or
                                        _sha(current[0]) not in
                                        {value["new_hashes"][absolute], _sha(old[0]) if old else ""}):
                raise InstallError("VPN install changed externally; manual recovery required")
            old_files[absolute] = (old, current)
        marker = self.layout.at(MARKER)
        old_marker = self._decode(value.get("old_marker"))
        current_marker = _maybe_file(marker, self.owner, private=True)
        if old_marker is not None and current_marker is None:
            raise InstallError("VPN install marker changed externally")
        if current_marker is not None and current_marker != old_marker:
            if _sha(current_marker[0]) != value.get("new_marker_hash"):
                raise InstallError("VPN install marker changed externally")
        # Stop only our fixed broker unit. No wg-quick or VPN interface is touched.
        if self._active(SERVICE):
            self._command(SYSTEMCTL, "stop", SERVICE)
        if self._active(SOCKET) or self._enabled(SOCKET):
            self._command(SYSTEMCTL, "disable", "--now", SOCKET)
        for _, absolute, _ in FILES:
            path = self.layout.at(absolute)
            old, current = old_files[absolute]
            if old is None:
                if current is not None:
                    _remove(path)
            elif current != old:
                _atomic(path, old[0], old[1], self.owner)
        if old_marker is None:
            if current_marker is not None:
                _remove(marker)
        elif current_marker != old_marker:
            _atomic(marker, old_marker[0], old_marker[1], self.owner)
        self._command(SYSTEMCTL, "daemon-reload")
        if value["socket_enabled"]:
            self._command(SYSTEMCTL, "enable", SOCKET)
        if value["socket_active"]:
            self._command(SYSTEMCTL, "start", SOCKET)
        if value["service_active"]:
            self._command(SYSTEMCTL, "start", SERVICE)
        _remove(self.layout.at(JOURNAL))

    def recover(self) -> dict:
        with self._lock():
            if not self._pending():
                return {"action": "recovered", "changed": False}
            with self._source_lock():
                self._rollback(self._journal())
            return {"action": "recovered", "changed": True}

    def apply(self, expected_state: str) -> dict:
        if not isinstance(expected_state, str) or not HEX.fullmatch(expected_state):
            raise InstallError("Exact reviewed VPN state revision is required")
        with self._lock():
            with self._source_lock():
                return self._apply_locked(expected_state)

    def _apply_locked(self, expected_state: str) -> dict:
        if self._pending():
            raise InstallError("RECOVERY_REQUIRED")
        preview, sources, destinations = self._observe()
        if expected_state != preview["state_revision"]:
            raise InstallError("VPN installation preview is stale")
        if not preview["can_apply"]:
            raise InstallError(preview["reason"])
        self._ensure_dependencies(preview["missing_dependencies"])
        self._ensure_directories()
        old_marker = _maybe_file(self.layout.at(MARKER), self.owner, private=True)
        new_marker = {"schema_version": 1,
                      "files": {absolute: _sha(sources[name]) for name, absolute, _ in FILES}}
        new_marker_raw = _json(new_marker)
        journal = {"schema_version": 1,
                   "old_files": {absolute: self._encode(item)
                                 for absolute, item in destinations.items()},
                   "new_hashes": new_marker["files"],
                   "old_marker": self._encode(old_marker),
                   "new_marker_hash": _sha(new_marker_raw),
                   "socket_active": preview["socket_active"],
                   "socket_enabled": preview["socket_enabled"],
                   "service_active": preview["service_active"]}
        _atomic(self.layout.at(JOURNAL), _json(journal), 0o600, self.owner)
        try:
            for name, absolute, mode in FILES:
                if destinations[absolute] is None or destinations[absolute][0] != sources[name]:
                    _atomic(self.layout.at(absolute), sources[name], mode, self.owner)
            # Verify after the fixed ExecStart launchers are installed. The
            # journal already covers every possible failure at this point.
            self._command(ANALYZE, "verify", *(str(self.layout.at("/etc/systemd/system") / name)
                       for name in (SERVICE, SOCKET)))
            self._command(SYSTEMCTL, "daemon-reload")
            self._command(SYSTEMCTL, "enable", "--now", SOCKET)
            self._command(SYSTEMCTL, "start", SERVICE)
            if not self._active(SOCKET) or not self._active(SERVICE):
                raise InstallError("WireGuard broker did not become active")
            if preview["apparmor_profile_present"]:
                self._command("/usr/bin/python3", "-I", "-B",
                              str(self.layout.repo / "deploy/install-wg-quick-apparmor.py"),
                              timeout=30)
            _atomic(self.layout.at(MARKER), new_marker_raw, 0o600, self.owner)
            _remove(self.layout.at(JOURNAL))
        except BaseException:
            try:
                self._rollback(journal)
            except Exception:
                # The durable journal deliberately remains for explicit recovery.
                pass
            raise
        return {"action": "installed", "socket_active": True,
                "service_active": True, "vpn_interface_changed": False,
                "source_revision": preview["source_revision"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install SovaGrid managed WireGuard broker")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("preview")
    apply = commands.add_parser("apply")
    apply.add_argument("--expected-state", required=True)
    commands.add_parser("recover")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("root is required")
    installer = Installer()
    try:
        if args.action == "preview":
            result = installer.preview()
        elif args.action == "apply":
            result = installer.apply(args.expected_state)
        else:
            result = installer.recover()
    except InstallError as exc:
        print(_json({"ok": False, "error": str(exc)}).decode(), end="")
        return 2
    print(_json({"ok": True, **result}).decode(), end="")
    return 0
