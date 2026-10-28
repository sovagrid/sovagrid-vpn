# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disposable in-memory Amnezia mutation experiment; never call on live containers.

There is deliberately no Docker, filesystem, subprocess or network access in
this module. A production broker needs version pinning, external ownership,
backups, atomic writes, command validation and runtime confirmation first.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import ipaddress
import json
import re
import uuid

from sovagrid_vpn.amnezia_adapter import parse_wg_config, parse_xray_config


MAX_BYTES = 65536
LABEL = re.compile(r"[A-Za-z0-9 _.-]{1,64}\Z")


@dataclass(frozen=True, repr=False)
class StagedChange:
    """Two file edits and their exact rollback bytes, confined to a fixture."""

    config_before: bytes
    registry_before: bytes
    config_after: bytes
    registry_after: bytes
    owned_before: frozenset[str]
    owned_after: frozenset[str]

    def rollback(self) -> tuple[bytes, bytes, frozenset[str]]:
        return self.config_before, self.registry_before, self.owned_before


def _reject() -> None:
    raise ValueError("fixture state or requested mutation invalid")


def _public_key(value: str) -> None:
    try:
        if not isinstance(value, str) or len(base64.b64decode(value, validate=True)) != 32:
            _reject()
    except (ValueError, TypeError, base64.binascii.Error):
        _reject()
    if len(value) != 44 or not value.endswith("="):
        _reject()


def _registry(raw: bytes) -> list[dict]:
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        _reject()
    try:
        rows = json.loads(raw)
    except (ValueError, UnicodeError):
        _reject()
    if not isinstance(rows, list) or any(not isinstance(row, dict) or
                                         not isinstance(row.get("clientId"), str)
                                         for row in rows):
        _reject()
    ids = [row["clientId"] for row in rows]
    if len(set(ids)) != len(ids):
        _reject()
    return rows


def _encode(value: object) -> bytes:
    raw = (json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(raw) > MAX_BYTES:
        _reject()
    return raw


def _wg_sections(raw: bytes) -> list[tuple[str, bytes, str | None, ipaddress._BaseNetwork | None]]:
    """Keep each existing section byte for byte, while checking all client IPs."""
    peers, _ = parse_wg_config(raw)
    lines = raw.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines)
              if line.strip() in (b"[Interface]", b"[Peer]")]
    if not starts or starts[0] != 0 or lines[0].strip() != b"[Interface]":
        _reject()
    sections = []
    for position, start in enumerate(starts):
        chunk = b"".join(lines[start:starts[position + 1] if position + 1 < len(starts) else len(lines)])
        kind = "interface" if lines[start].strip() == b"[Interface]" else "peer"
        key = None
        network = None
        if kind == "peer":
            for line in chunk.decode("ascii").splitlines():
                if "=" not in line:
                    continue
                field, value = (part.strip() for part in line.split("=", 1))
                if field == "PublicKey":
                    key = value
                elif field == "AllowedIPs":
                    try:
                        network = ipaddress.ip_network(value, strict=False)
                    except ValueError:
                        _reject()
            if key is None or network is None:
                _reject()
        sections.append((kind, chunk, key, network))
    if {key for kind, _, key, _ in sections if kind == "peer"} != peers:
        _reject()
    networks = [network for kind, _, _, network in sections if kind == "peer"]
    if any(left.overlaps(right) for i, left in enumerate(networks)
           for right in networks[i + 1:]):
        _reject()
    return sections


def _wg_state(config: bytes, registry: bytes, owned: frozenset[str]):
    sections = _wg_sections(config)
    rows = _registry(registry)
    keys = {key for kind, _, key, _ in sections if kind == "peer"}
    if {row["clientId"] for row in rows} != keys or not owned <= keys:
        _reject()
    return sections, rows


def stage_add_wg(config: bytes, registry: bytes, owned: frozenset[str],
                 public_key: str, allowed_ip: str, label: str) -> StagedChange:
    """Stage one AWG/WG peer and registry row, preserving all old section bytes."""
    sections, rows = _wg_state(config, registry, owned)
    _public_key(public_key)
    if not isinstance(label, str) or not LABEL.fullmatch(label):
        _reject()
    try:
        new_network = ipaddress.ip_network(allowed_ip, strict=True)
    except (ValueError, TypeError):
        _reject()
    if new_network.num_addresses != 1 or public_key in {row["clientId"] for row in rows}:
        _reject()
    if any(network.overlaps(new_network) for kind, _, _, network in sections
           if kind == "peer"):
        _reject()
    ending = b"" if config.endswith(b"\n") else b"\n"
    new_section = (f"[Peer]\nPublicKey = {public_key}\n"
                   f"AllowedIPs = {new_network}\n").encode("ascii")
    after = config + ending + new_section
    new_rows = rows + [{"clientId": public_key, "userData": {"clientName": label}}]
    _wg_state(after, _encode(new_rows), owned | {public_key})
    return StagedChange(config, registry, after, _encode(new_rows),
                        owned, owned | {public_key})


def stage_revoke_wg(config: bytes, registry: bytes, owned: frozenset[str],
                    public_key: str) -> StagedChange:
    """Refuse any peer that the SovaGrid fixture does not own."""
    sections, rows = _wg_state(config, registry, owned)
    if public_key not in owned:
        _reject()
    after = b"".join(chunk for kind, chunk, key, _ in sections
                     if kind != "peer" or key != public_key)
    new_rows = [row for row in rows if row["clientId"] != public_key]
    _wg_state(after, _encode(new_rows), owned - {public_key})
    return StagedChange(config, registry, after, _encode(new_rows),
                        owned, owned - {public_key})


def _xray_state(config: bytes, registry: bytes, owned: frozenset[str], default_uuid: str):
    ids, _, _ = parse_xray_config(config)
    rows = _registry(registry)
    if not isinstance(default_uuid, str) or default_uuid not in ids:
        _reject()
    guests = ids - {default_uuid}
    if {row["clientId"] for row in rows} != guests or not owned <= guests:
        _reject()
    try:
        data = json.loads(config)
        inbounds = [row for row in data["inbounds"] if row.get("protocol") == "vless"]
        if len(inbounds) != 1:
            _reject()
        clients = inbounds[0]["settings"]["clients"]
        if not isinstance(clients, list):
            _reject()
    except (ValueError, TypeError, KeyError, AttributeError):
        _reject()
    return data, clients, rows


def stage_add_xray(config: bytes, registry: bytes, owned: frozenset[str],
                   default_uuid: str, guest_uuid: str, label: str) -> StagedChange:
    """Stage one VLESS UUID; activation and syntax checking are deliberately absent."""
    data, clients, rows = _xray_state(config, registry, owned, default_uuid)
    try:
        if str(uuid.UUID(guest_uuid)) != guest_uuid or guest_uuid == default_uuid:
            _reject()
    except (ValueError, TypeError, AttributeError):
        _reject()
    if (guest_uuid in {row["clientId"] for row in rows} or
            not isinstance(label, str) or not LABEL.fullmatch(label)):
        _reject()
    template = next(row for row in clients if row["id"] == default_uuid)
    new_client = {"id": guest_uuid}
    if "flow" in template:
        new_client["flow"] = template["flow"]
    clients.append(new_client)
    new_rows = rows + [{"clientId": guest_uuid, "userData": {"clientName": label}}]
    after, table = _encode(data), _encode(new_rows)
    _xray_state(after, table, owned | {guest_uuid}, default_uuid)
    return StagedChange(config, registry, after, table, owned, owned | {guest_uuid})


def stage_revoke_xray(config: bytes, registry: bytes, owned: frozenset[str],
                      default_uuid: str, guest_uuid: str) -> StagedChange:
    """Never revoke the default UUID or any pre-existing Amnezia guest."""
    data, clients, rows = _xray_state(config, registry, owned, default_uuid)
    if guest_uuid == default_uuid or guest_uuid not in owned:
        _reject()
    clients[:] = [row for row in clients if row["id"] != guest_uuid]
    new_rows = [row for row in rows if row["clientId"] != guest_uuid]
    after, table = _encode(data), _encode(new_rows)
    _xray_state(after, table, owned - {guest_uuid}, default_uuid)
    return StagedChange(config, registry, after, table, owned, owned - {guest_uuid})


class DisposableFixture:
    """Simulate a two-file commit, injected failure and exact byte rollback."""

    def __init__(self, config: bytes, registry: bytes, owned: frozenset[str] = frozenset()):
        self.config = config
        self.registry = registry
        self.owned = owned

    def apply(self, change: StagedChange, *, fail_after_config: bool = False) -> None:
        if (self.config, self.registry, self.owned) != (
                change.config_before, change.registry_before, change.owned_before):
            _reject()
        try:
            self.config = change.config_after
            if fail_after_config:
                raise RuntimeError("injected fixture failure")
            self.registry = change.registry_after
            self.owned = change.owned_after
        except Exception:
            self.config, self.registry, self.owned = change.rollback()
            raise
