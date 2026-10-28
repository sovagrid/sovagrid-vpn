# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Authenticate the live Agent process, not just its shared Unix user ID.

Arbitrary admin commands run as ``sovagrid``. A UID-only check would let those
commands call a root VPN broker directly and skip the Hub's structured flow.
"""

from __future__ import annotations

import re
import socket
import struct
import subprocess
from typing import Callable


AGENT_UNIT = "sovagrid-agent.service"
SYSTEMCTL = "/usr/bin/systemctl"


def peer_identity(connection: socket.socket) -> tuple[int, int]:
    """Return the kernel-supplied PID and UID captured when the peer connected."""
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("Linux peer credentials are required")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize("3i"))
    pid, uid, _gid = struct.unpack("3i", raw)
    return pid, uid


def agent_main_pid(runner: Callable = subprocess.run) -> int | None:
    """Get systemd's root-owned identity for the host Agent, failing closed."""
    argv = [SYSTEMCTL, "--system", "--no-pager", "--no-ask-password",
            "--property=MainPID", "show", AGENT_UNIT]
    try:
        result = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        text=True, timeout=3,
                        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not isinstance(result.stdout, str):
        return None
    raw = result.stdout.strip()
    if not re.fullmatch(r"MainPID=[1-9][0-9]{0,9}", raw):
        return None
    pid = int(raw[8:])
    return pid if pid <= 2**31 - 1 else None


def authorized_peer(peer: tuple[int, int], agent_uid: int) -> bool:
    """Allow local root administration or the exact live host Agent process."""
    pid, uid = peer
    if pid <= 0:
        return False
    if uid == 0:
        return True
    return uid == agent_uid and agent_main_pid() == pid
