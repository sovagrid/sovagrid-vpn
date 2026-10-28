#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Install the narrow AppArmor read rule for SovaGrid's wg-quick symlink.

Run explicitly as root on Ubuntu hosts whose /etc/apparmor.d/wg-quick profile
includes local/wg-quick. This does not edit the packaged profile or any VPN.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Callable


PROFILE = Path("/etc/apparmor.d/wg-quick")
LOCAL = Path("/etc/apparmor.d/local/wg-quick")
RULE = "file r /var/lib/sovagrid-vpn/*/server.conf,"
BLOCK = ("\n# SovaGrid: read only the managed WireGuard server config target\n"
         f"  {RULE}\n")
INCLUDE = re.compile(r"^\s*(?:#include|include)(?:\s+if\s+exists)?\s+<local/wg-quick>\s*(?:#.*)?$", re.M)
EXISTING_RULE = re.compile(
    r"^\s*file\s+r\s+/var/lib/sovagrid-vpn/\*/server\.conf\s*,\s*(?:#.*)?$", re.M)
MAX_FILE = 1024 * 1024


class SetupError(RuntimeError):
    pass


def _safe_file(path: Path, *, required: bool, owner: int) -> os.stat_result | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if required:
            raise SetupError(f"Required AppArmor file is missing: {path}")
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner or
            info.st_mode & 0o022 or info.st_size > MAX_FILE):
        raise SetupError(f"Unsafe AppArmor file ownership, type, mode or size: {path}")
    return info


def _safe_dir(path: Path, *, owner: int) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise SetupError(f"Unsafe AppArmor directory: {path}")


def _read(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = os.read(fd, MAX_FILE + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_FILE:
        raise SetupError(f"AppArmor file is too large: {path}")
    return data


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _replace(path: Path, data: bytes, *, mode: int, group: int, owner: int) -> None:
    if len(data) > MAX_FILE:
        raise SetupError("AppArmor local override is too large")
    fd, temporary = tempfile.mkstemp(prefix=".sovagrid-apparmor-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        info = os.fstat(fd)
        if info.st_uid != owner or info.st_gid != group:
            os.fchown(fd, owner, group)
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = ""
        _sync_dir(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _command(runner: Callable, argv: tuple[str, ...], message: str) -> None:
    try:
        result = runner(argv, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SetupError(message) from exc
    if result.returncode != 0:
        raise SetupError(message)


def install(*, profile: Path = PROFILE, local: Path = LOCAL,
            runner: Callable = subprocess.run, require_root: bool = True,
            which: Callable[[str], str | None] = shutil.which) -> bool:
    """Return True if the rule was added, False if it was already present."""
    if require_root and os.geteuid() != 0:
        raise SetupError("This setup requires root")
    owner = 0 if require_root else os.geteuid()
    profile, local = Path(profile), Path(local)
    if not profile.is_absolute() or not local.is_absolute():
        raise SetupError("AppArmor paths must be absolute")
    for command in ("wg", "wg-quick", "ip", "apparmor_parser"):
        if which(command) is None:
            raise SetupError(f"Required command is not installed: {command}")
    _safe_dir(profile.parent, owner=owner)
    if local.parent != profile.parent / "local":
        raise SetupError("AppArmor local override must be in the profile's local directory")
    if not local.parent.exists() and not local.parent.is_symlink():
        local.parent.mkdir(mode=0o755)
        _sync_dir(profile.parent)
    _safe_dir(local.parent, owner=owner)
    _safe_file(profile, required=True, owner=owner)
    profile_text = _read(profile).decode("utf-8")
    if not INCLUDE.search(profile_text):
        raise SetupError("The wg-quick profile does not include local/wg-quick")

    lock_path = local.parent / ".sovagrid-wg-quick.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        lock_info = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1 or
                lock_info.st_uid != owner or lock_info.st_mode & 0o077):
            raise SetupError("Unsafe AppArmor setup lock")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        old_info = _safe_file(local, required=False, owner=owner)
        old_data = _read(local) if old_info else None
        old_text = old_data.decode("utf-8") if old_data is not None else ""
        changed = not EXISTING_RULE.search(old_text)
        if changed:
            payload = old_text.encode("utf-8")
            if payload and not payload.endswith(b"\n"):
                payload += b"\n"
            payload += BLOCK.encode("utf-8")
            mode = stat.S_IMODE(old_info.st_mode) if old_info else 0o644
            group = old_info.st_gid if old_info else os.getegid()
            _replace(local, payload, mode=mode, group=group, owner=owner)

        reload_attempted = False
        try:
            # Compile the full packaged profile and its local include before
            # replacing the profile currently loaded into the kernel.
            _command(runner, ("apparmor_parser", "-Q", "-T", str(profile)),
                     "AppArmor syntax validation failed")
            reload_attempted = True
            _command(runner, ("apparmor_parser", "-r", "-T", str(profile)),
                     "AppArmor profile reload failed")
        except SetupError as original_error:
            if changed:
                try:
                    if old_data is None:
                        local.unlink()
                        _sync_dir(local.parent)
                    else:
                        _replace(local, old_data, mode=mode, group=group, owner=owner)
                    # If the first reload partially applied, restore the
                    # previous policy. A validation failure never loaded it.
                    if reload_attempted:
                        _command(runner, ("apparmor_parser", "-r", "-T", str(profile)),
                                 "Cannot restore the previous AppArmor profile")
                except (OSError, SetupError) as exc:
                    raise SetupError("AppArmor setup failed and automatic rollback failed") from exc
            raise original_error
        return changed
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def main() -> int:
    try:
        changed = install()
    except (OSError, UnicodeError, SetupError) as exc:
        print(str(exc) if isinstance(exc, SetupError) else type(exc).__name__, file=sys.stderr)
        return 2
    print("SovaGrid wg-quick AppArmor rule installed" if changed else
          "SovaGrid wg-quick AppArmor rule already present; profile reloaded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
