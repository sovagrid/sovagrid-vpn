# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Strictly sanitized Docker inventory for existing Amnezia installations.

This module never asks Docker for container configs, logs, exec access, or
secrets. It only runs ``docker container ls --all`` and emits known fields for
an exact allowlist of service names.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from typing import Callable


SCHEMA_VERSION = 1
MAX_DOCKER_OUTPUT = 256 * 1024
MAX_CONTAINERS = 4096
DOCKER_COMMAND = ("docker", "container", "ls", "--all", "--format", "{{json .}}")

# These are Amnezia's conventional container names, not configurable Docker
# selectors. Unknown containers must never appear in the published snapshot.
SERVICES = {
    "amnezia-awg": "AmneziaWG",
    "amnezia-awg2": "AmneziaWG (awg2)",
    "amnezia-wireguard": "WireGuard (Amnezia)",
    "amnezia-openvpn": "OpenVPN (Amnezia)",
    "amnezia-ipsec": "IPsec (Amnezia)",
    "amnezia-xray": "Xray (Amnezia)",
    "amnezia-dns": "DNS (Amnezia)",
    "amnezia-socks5proxy": "SOCKS5 (Amnezia)",
}
STATES = {"created", "restarting", "running", "removing", "paused", "exited", "dead"}
PORT = re.compile(r"^(?:\S+:)?(?P<host>\d{1,5})->(?P<container>\d{1,5})/(?P<protocol>tcp|udp)$")


class InventoryError(RuntimeError):
    """Docker inventory could not be collected. Message contains no stderr."""


def _published_ports(raw: object) -> list[dict]:
    if not isinstance(raw, str):
        return []
    ports: set[tuple[int, str]] = set()
    for part in raw.split(","):
        match = PORT.fullmatch(part.strip())
        if not match:
            continue
        number = int(match.group("host"))
        container_number = int(match.group("container"))
        if 1 <= number <= 65535 and 1 <= container_number <= 65535:
            ports.add((number, match.group("protocol")))
    return [{"port": number, "protocol": protocol} for number, protocol in sorted(ports)]


def _image_matches(name: str, image: object) -> bool:
    if not isinstance(image, str):
        return False
    # A name alone does not prove ownership. Keep a mismatch visible so an
    # unrelated container reusing the name cannot be presented as Amnezia.
    return image == name or image.startswith(name + ":") or image.startswith(name + "@")


def parse_docker_ps(raw: str, *, timestamp: int | None = None) -> dict:
    """Project untrusted Docker CLI JSON to a small, fixed public schema."""
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_DOCKER_OUTPUT:
        raise InventoryError("Docker inventory exceeded size limit")
    rows = raw.splitlines()
    if len(rows) > MAX_CONTAINERS:
        raise InventoryError("Docker inventory exceeded container limit")
    seen: dict[str, dict] = {}
    for line in rows:
        try:
            row = json.loads(line)
        except (ValueError, TypeError) as exc:
            raise InventoryError("Docker inventory is malformed") from exc
        if not isinstance(row, dict):
            raise InventoryError("Docker inventory is malformed")
        name = row.get("Names")
        if not isinstance(name, str) or name not in SERVICES:
            continue
        if name in seen:
            raise InventoryError("Docker inventory contains duplicate service names")
        image_matches = _image_matches(name, row.get("Image"))
        state = row.get("State")
        if not isinstance(state, str) or state not in STATES:
            state = "unknown"
        status = row.get("Status")
        if not isinstance(status, str):
            status = ""
        if "(unhealthy)" in status:
            health = "unhealthy"
        elif "(healthy)" in status:
            health = "healthy"
        elif "(health: starting)" in status:
            health = "starting"
        else:
            health = "not_reported"
        seen[name] = {
            "name": name,
            "service": SERVICES[name],
            "state": state if image_matches else "identity_mismatch",
            "health": health if image_matches else "unknown",
            "published_ports": _published_ports(row.get("Ports")) if image_matches else [],
        }
    items = [seen.get(name, {"name": name, "service": label, "state": "absent",
                             "health": "unknown", "published_ports": []})
             for name, label in SERVICES.items()]
    return {"schema_version": SCHEMA_VERSION, "collected_at": int(time.time() if timestamp is None else timestamp),
            "source": "docker_cli", "source_status": "ok", "services": items}


def collect_snapshot(runner: Callable | None = None, *, timestamp: int | None = None) -> dict:
    """Run one read-only Docker command. Neither stderr nor command data escape."""
    if runner is None:
        runner = subprocess.run
    try:
        result = runner(DOCKER_COMMAND, capture_output=True, text=True,
                        timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError("Docker inventory unavailable") from exc
    if result.returncode != 0:
        raise InventoryError("Docker inventory unavailable")
    return parse_docker_ps(result.stdout, timestamp=timestamp)
