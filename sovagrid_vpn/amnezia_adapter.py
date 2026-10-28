# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read-only, redacted detail probe for three existing Amnezia containers.

No Docker socket is given to Hub or Agent. This module runs as root in the
status publisher, reads only fixed files/commands, and emits no client IDs,
keys, addresses, config fragments, Docker environment or command stderr.
It intentionally has no mutation function.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import subprocess
import time
import uuid
from typing import Callable

from .inventory import InventoryError, collect_snapshot


MAX_FILE_BYTES = 65536
MAX_DUMP_BYTES = 256 * 1024
MAX_PROBE_SECONDS = 20
KEY = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
SPECS = {
    "amnezia-awg2": ("awg", "awg0", "/opt/amnezia/awg/awg0.conf",
                     "/opt/amnezia/awg/clientsTable"),
    "amnezia-wireguard": ("wg", "wg0", "/opt/amnezia/wireguard/wg0.conf",
                          "/opt/amnezia/wireguard/clientsTable"),
    "amnezia-xray": ("xray", None, "/opt/amnezia/xray/server.json",
                     "/opt/amnezia/xray/clientsTable"),
}


class ProbeError(RuntimeError):
    """Safe, secret-free probe failure."""


def _result(runner: Callable, command: tuple[str, ...], limit: int) -> bytes:
    try:
        result = runner(command, capture_output=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError("Amnezia probe unavailable") from exc
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        raise ProbeError("Amnezia probe unavailable")
    if len(result.stdout) > limit:
        raise ProbeError("Amnezia probe exceeds size limit")
    return result.stdout


def _file(runner: Callable, container: str, path: str) -> bytes:
    raw = _result(runner, ("docker", "exec", container, "head", "-c",
                           str(MAX_FILE_BYTES + 1), path), MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ProbeError("Amnezia file exceeds size limit")
    return raw


def _valid_wg_key(value: str) -> bool:
    if not KEY.fullmatch(value):
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, base64.binascii.Error):
        return False


def parse_wg_config(raw: bytes) -> tuple[set[str], bool]:
    """Return peer public keys in memory and whether AWG3 fields are present."""
    if not isinstance(raw, bytes) or len(raw) > MAX_FILE_BYTES:
        raise ProbeError("Amnezia config invalid")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ProbeError("Amnezia config invalid") from exc
    section = ""
    peers: set[str] = set()
    peer_key = None
    peer_allowed = None
    allowed_ips: set[str] = set()
    awg3 = False

    def finish_peer() -> None:
        if section == "Peer":
            if peer_key is None or peer_allowed is None or peer_key in peers:
                raise ProbeError("Amnezia peer configuration invalid")
            if peer_allowed in allowed_ips:
                raise ProbeError("Amnezia peer address conflict")
            peers.add(peer_key)
            allowed_ips.add(peer_allowed)

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in ("[Interface]", "[Peer]"):
            finish_peer()
            section = stripped[1:-1]
            peer_key = None
            peer_allowed = None
            continue
        if "=" not in stripped:
            raise ProbeError("Amnezia config invalid")
        key, value = (part.strip() for part in stripped.split("=", 1))
        if section == "Interface" and key in ("HeaderProtectionKey", "RandomTrailers"):
            awg3 = True
        if section == "Peer":
            if key == "PublicKey":
                if peer_key is not None or not _valid_wg_key(value):
                    raise ProbeError("Amnezia peer configuration invalid")
                peer_key = value
            elif key == "AllowedIPs":
                if peer_allowed is not None:
                    raise ProbeError("Amnezia peer configuration invalid")
                try:
                    network = ipaddress.ip_network(value, strict=False)
                except ValueError as exc:
                    raise ProbeError("Amnezia peer configuration invalid") from exc
                peer_allowed = str(network)
    finish_peer()
    if not any(line.strip() == "[Interface]" for line in lines):
        raise ProbeError("Amnezia config invalid")
    return peers, awg3


def parse_clients_table(raw: bytes) -> set[str]:
    if not isinstance(raw, bytes) or len(raw) > MAX_FILE_BYTES:
        raise ProbeError("Amnezia client registry invalid")
    try:
        rows = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ProbeError("Amnezia client registry invalid") from exc
    if not isinstance(rows, list) or len(rows) > 2048:
        raise ProbeError("Amnezia client registry invalid")
    ids = [row.get("clientId") for row in rows if isinstance(row, dict)]
    if len(ids) != len(rows) or any(not isinstance(value, str) or len(value) > 128 for value in ids):
        raise ProbeError("Amnezia client registry invalid")
    if len(set(ids)) != len(ids):
        raise ProbeError("Amnezia client registry invalid")
    return set(ids)


def parse_wg_dump(raw: bytes, *, now: int) -> tuple[set[str], dict[str, int | None]]:
    """Discard secret-bearing interface row before parsing peer statistics."""
    if not isinstance(raw, bytes) or len(raw) > MAX_DUMP_BYTES:
        raise ProbeError("Amnezia runtime invalid")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ProbeError("Amnezia runtime invalid") from exc
    if not lines or len(lines[0].split("\t")) < 4:
        raise ProbeError("Amnezia runtime invalid")
    peers: set[str] = set()
    active = received = sent = latest = 0
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 8 or not _valid_wg_key(fields[0]) or fields[0] in peers:
            raise ProbeError("Amnezia runtime invalid")
        peers.add(fields[0])
        try:
            handshake, rx, tx = (int(fields[index]) for index in (4, 5, 6))
        except ValueError as exc:
            raise ProbeError("Amnezia runtime invalid") from exc
        if min(handshake, rx, tx) < 0 or handshake > now + 300:
            raise ProbeError("Amnezia runtime invalid")
        if handshake and now - handshake <= 180:
            active += 1
        latest = max(latest, handshake)
        received += rx
        sent += tx
    return peers, {"active_last_3m": active, "latest_handshake_at": latest or None,
                   "received_bytes": received, "sent_bytes": sent}


def parse_xray_config(raw: bytes) -> tuple[set[str], bool, bool]:
    if not isinstance(raw, bytes) or len(raw) > MAX_FILE_BYTES:
        raise ProbeError("Amnezia Xray config invalid")
    try:
        config = json.loads(raw)
        inbounds = config["inbounds"]
        if not isinstance(inbounds, list) or len(inbounds) > 64:
            raise ValueError("invalid inbounds")
        ids = [row["id"] for inbound in inbounds if inbound.get("protocol") == "vless"
               for row in inbound["settings"]["clients"]]
        if not ids:
            raise ValueError("no VLESS clients")
        canonical = {str(uuid.UUID(value)) for value in ids}
        if len(canonical) != len(ids) or any(value != str(uuid.UUID(value)) for value in ids):
            raise ValueError("duplicate or noncanonical client")
        api = config.get("api", {})
        return canonical, (isinstance(api, dict) and
                           "HandlerService" in api.get("services", [])), "stats" in config
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ProbeError("Amnezia Xray config invalid") from exc


def collect_amnezia_details(*, runner: Callable = subprocess.run,
                            timestamp: int | None = None,
                            inventory: dict | None = None) -> dict:
    """Return only fixed counts, aggregate traffic and explicit readiness states."""
    now = int(time.time() if timestamp is None else timestamp)
    try:
        inventory = inventory if inventory is not None else collect_snapshot(runner, timestamp=now)
    except InventoryError:
        return {"schema_version": 1, "collected_at": now,
                "source_status": "error", "services": []}
    if inventory.get("source_status") == "error":
        return {"schema_version": 1, "collected_at": now,
                "source_status": "error", "services": []}
    deadline = time.monotonic() + MAX_PROBE_SECONDS

    def limited_runner(command: tuple[str, ...], **kwargs):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("Amnezia probe budget exhausted")
        kwargs["timeout"] = min(kwargs.get("timeout", 8), remaining)
        return runner(command, **kwargs)

    rows = {row.get("name"): row for row in inventory.get("services", [])
            if isinstance(row, dict)}
    services = []
    for container, (binary, iface, config_path, table_path) in SPECS.items():
        row = rows.get(container, {})
        if row.get("state") == "identity_mismatch":
            services.append({"name": container, "status": "identity_mismatch",
                             "configured_clients": None, "runtime_clients": None})
            continue
        if row.get("state") != "running":
            services.append({"name": container, "status": "container_down",
                             "configured_clients": None, "runtime_clients": None})
            continue
        try:
            config_raw = _file(limited_runner, container, config_path)
            table_ids = parse_clients_table(_file(limited_runner, container, table_path))
            if iface is None:
                ids, api_enabled, stats_enabled = parse_xray_config(config_raw)
                default_raw = _file(limited_runner, container, "/opt/amnezia/xray/xray_uuid.key")
                default = default_raw.decode("ascii").strip()
                if default not in ids or default in table_ids:
                    raise ProbeError("Amnezia Xray default client invalid")
                process = limited_runner(("docker", "exec", container, "pgrep", "-x", binary),
                                         capture_output=True, timeout=8, check=False)
                status = ("registry_drift" if table_ids != ids - {default}
                          else "ready" if process.returncode == 0 else "process_down")
                services.append({"name": container, "status": status,
                                 "configured_clients": len(ids) - 1,
                                 "runtime_clients": None,
                                 "api_enabled": api_enabled,
                                 "stats_enabled": stats_enabled})
            else:
                config_keys, awg3_fields = parse_wg_config(config_raw)
                if any(not _valid_wg_key(value) for value in table_ids):
                    raise ProbeError("Amnezia client registry invalid")
                command = ("docker", "exec", container, binary, "show", iface, "dump")
                runtime = limited_runner(command, capture_output=True, timeout=8, check=False)
                if runtime.returncode != 0:
                    services.append({"name": container, "status": "interface_down",
                                     "configured_clients": len(config_keys),
                                     "runtime_clients": 0,
                                     "awg3_fields": awg3_fields})
                    continue
                if not isinstance(runtime.stdout, bytes):
                    raise ProbeError("Amnezia runtime invalid")
                live_keys, stats = parse_wg_dump(runtime.stdout, now=now)
                status = ("registry_drift" if table_ids != config_keys else
                          "runtime_drift" if live_keys != config_keys else "ready")
                services.append({"name": container, "status": status,
                                 "configured_clients": len(config_keys),
                                 "runtime_clients": len(live_keys),
                                 "awg3_fields": awg3_fields, **stats})
        except (ProbeError, OSError, subprocess.TimeoutExpired, UnicodeError):
            services.append({"name": container, "status": "error",
                             "configured_clients": None, "runtime_clients": None})
    return {"schema_version": 1, "collected_at": now,
            "source_status": "ok", "services": services}
