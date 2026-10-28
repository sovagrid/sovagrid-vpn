# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read-only, secret-free status of SovaGrid-owned WireGuard instances.

The publisher takes a shared lock that already exists; it never creates or
recovers managed state. An interrupted transaction is reported as an error for
that instance, independent of the Docker/Amnezia inventory.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import stat
import subprocess
import time
from typing import Callable

from .managed import (ManagedWireGuard, STATE_ROOT, WIREGUARD_DIR,
                      _directory, _regular_private, interface_name, validate_name)


MAX_INSTANCES = 64
LOCK_WAIT_SECONDS = 5


def collect_managed_instances(*, state_root: Path = STATE_ROOT,
                              wireguard_dir: Path = WIREGUARD_DIR,
                              runner: Callable = subprocess.run,
                              require_root: bool = True) -> dict:
    """Return only public identity, network and count fields for each instance.

    A missing state directory means no managed instances. An unsafe state
    directory or contended management lock is a managed-source error; neither
    can affect the independently collected Amnezia source.
    """
    state_root = Path(state_root)
    empty = {"source_status": "ok", "instances": []}
    if not state_root.exists() and not state_root.is_symlink():
        return empty
    fd = None
    try:
        manager = ManagedWireGuard(state_root=state_root, wireguard_dir=wireguard_dir,
                                   runner=runner, require_root=require_root,
                                   check_network=False)
        _directory(state_root, uid=manager._uid, private=True)
        lock_path = state_root / ".lock"
        _regular_private(lock_path, uid=manager._uid)
        fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
        lock_info = os.fstat(fd)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1 or
                lock_info.st_mode & 0o077 or
                (manager._uid is not None and lock_info.st_uid != manager._uid)):
            raise ValueError("Unsafe inventory lock")
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        candidates = []
        for path in state_root.iterdir():
            if path.name == ".lock":
                continue
            # Ignore unrelated files; a candidate with a valid managed name
            # but incomplete state is visible as an error, never as active.
            try:
                validate_name(path.name)
            except Exception:
                continue
            if path.is_dir() or path.is_symlink():
                candidates.append(path)
        if len(candidates) > MAX_INSTANCES:
            return {"source_status": "error", "instances": []}
        snapshots = []
        for path in sorted(candidates):
            name = path.name
            item = {"name": name, "interface": interface_name(name),
                    "port": None, "subnet": None, "client_count": None,
                    "state": "error"}
            state = None
            fingerprint = None
            try:
                state = manager._state(name)
                info = (path / "state.json").lstat()
                fingerprint = (info.st_ino, info.st_mtime_ns, info.st_size, info.st_mode)
                item.update(port=state["port"], subnet=state["subnet"],
                            client_count=len(state["clients"]))
            except Exception:
                # Neither exception details nor the state file can leave this
                # process: they may contain private keys and peer addresses.
                item["state"] = "error"
                state = None
            snapshots.append((path, item, state, fingerprint))
        # Runtime probes can invoke several bounded systemctl/ip/wg reads per
        # instance. Release the management lock before those slow reads so a
        # status refresh cannot block a real VPN operation for minutes.
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        fd = None
        instances = []
        for path, item, state, fingerprint in snapshots:
            if state is not None:
                try:
                    active = manager._runtime(state, (state,))
                    info = (path / "state.json").lstat()
                    current = (info.st_ino, info.st_mtime_ns, info.st_size, info.st_mode)
                    if current != fingerprint or (path / "transaction.json").exists():
                        raise ValueError("Managed state changed during inventory")
                    item["state"] = "active" if active else "stopped"
                except Exception:
                    item.update(port=None, subnet=None, client_count=None, state="error")
            instances.append(item)
        return {"source_status": "ok", "instances": instances}
    except Exception:
        return {"source_status": "error", "instances": []}
    finally:
        if fd is not None:
            os.close(fd)
