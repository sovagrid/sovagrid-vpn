# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in, root-only AWG/WG peer administration for pinned Amnezia containers.

The CLI is deliberately separate from Hub and the Agent broker. Enrolment pins
one exact container and image; only SovaGrid-added peers may be revoked. A
root-owned write-ahead backup permits recovery after an interrupted two-file
update. Generated AWG3 and WireGuard profiles leave only as sealed ciphertext.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Iterator


STATE_ROOT = Path("/var/lib/sovagrid-vpn/amnezia-admin")
PROVISION_STATE = Path("/var/lib/sovagrid-vpn/amnezia-provision/state.json")
MAX_OWNED_CLIENTS = 128  # Agent and Hub status contracts expose at most 128 names.
MAX_CONFIG = 65536
MAX_DUMP = 262144
MAX_SETTINGS_PREVIEW = 4096
KEY_PATTERN = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
NAME_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
HEX_ID = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
# Docker Hub manifest digest for the official amd64 AmneziaWG 3.1 userspace
# image. The SovaGrid provisioner assembles the fixed server layout in a
# container created from this immutable base; Docker may retain either form
# of the fully qualified reference in Config.Image.
PINNED_AWG_IMAGE = ("amneziavpn/amneziawg-go@sha256:"
                    "cbafc02b8373a83f428272db6d8001b37bc02e6211cbd8c0cb4e2e3759b12b72")
AWG_PREVIEW_NUMBERS = frozenset(("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"))
AWG_PREVIEW_RANGES = frozenset(("H1", "H2", "H3", "H4"))
AWG_PREVIEW_REQUIRED = AWG_PREVIEW_NUMBERS | AWG_PREVIEW_RANGES
AWG_HEADER_NONCE_SIZE = 12
SETTINGS_INTENT_TTL = 300
CONFIRMATION_ID = re.compile(r"[A-Za-z0-9_-]{43}\Z")
WRITE_SCRIPT = (
    'set -eu; umask 077; target="$1"; mode="$2"; '
    'tmp="$(mktemp "${target}.sovagrid.XXXXXXXX")"; '
    "trap 'rm -f \"$tmp\"' EXIT; "
    'cat > "$tmp"; chmod "$mode" "$tmp"; '
    'mv -f "$tmp" "$target"; trap - EXIT'
)


class AmneziaAdminError(RuntimeError):
    """A fixed, secret-free operational failure."""


@dataclass(frozen=True)
class Target:
    name: str
    container: str
    image_name: str
    binary: str
    interface: str
    config_path: str
    table_path: str
    psk_path: str


TARGETS = {
    "awg2": Target("awg2", "amnezia-awg2", "amnezia-awg2:latest", "awg", "awg0",
                   "/opt/amnezia/awg/awg0.conf", "/opt/amnezia/awg/clientsTable",
                   "/opt/amnezia/awg/wireguard_psk.key"),
    "wireguard": Target("wireguard", "amnezia-wireguard", "amnezia-wireguard:latest",
                        "wg", "wg0", "/opt/amnezia/wireguard/wg0.conf",
                        "/opt/amnezia/wireguard/clientsTable",
                        "/opt/amnezia/wireguard/wireguard_psk.key"),
}


def _error(message: str) -> None:
    raise AmneziaAdminError(message)


def _key(value: str) -> str:
    if not isinstance(value, str) or not KEY_PATTERN.fullmatch(value):
        _error("Invalid WireGuard public or preshared key")
    try:
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
            _error("Invalid WireGuard public or preshared key")
    except (ValueError, base64.binascii.Error):
        _error("Invalid WireGuard public or preshared key")
    return value


def _client_name(value: str) -> str:
    if not isinstance(value, str) or not NAME_PATTERN.fullmatch(value):
        _error("Invalid client name")
    return value


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: dict | list) -> bytes:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(raw) > MAX_CONFIG:
        _error("Administrative state exceeds size limit")
    return raw


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            _error("Invalid Amnezia settings proposal")
        value[key] = item
    return value


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _private_dir(path: Path, *, owner: int, create: bool = False) -> None:
    if create:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077:
        _error("Administrative directory has unsafe ownership or permissions")


def _private_file(path: Path, *, owner: int) -> None:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or
            info.st_nlink != 1 or info.st_mode & 0o077):
        _error("Administrative file has unsafe ownership or permissions")


def _read_private(path: Path, *, owner: int) -> bytes:
    _private_file(path, owner=owner)
    if path.stat().st_size > MAX_CONFIG:
        _error("Administrative file exceeds size limit")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = os.read(fd, MAX_CONFIG + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_CONFIG:
        _error("Administrative file exceeds size limit")
    return data


def _atomic_private(path: Path, data: bytes, *, owner: int, new: bool = False) -> None:
    if len(data) > MAX_CONFIG:
        _error("Administrative file exceeds size limit")
    if path.exists() or path.is_symlink():
        if new:
            _error("Administrative state already exists")
        _private_file(path, owner=owner)
    elif not new:
        _error("Administrative state is missing")
    fd, temporary = tempfile.mkstemp(prefix=".sovagrid-new-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if new:
            os.link(temporary, path)
            os.unlink(temporary)
            temporary = ""
        else:
            os.replace(temporary, path)
            temporary = ""
        _fsync_dir(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


@dataclass(frozen=True)
class Peer:
    key: str
    psk: str
    address: ipaddress.IPv4Address
    raw: bytes


@dataclass(frozen=True)
class Config:
    interface_raw: bytes
    peers: tuple[Peer, ...]
    network: ipaddress.IPv4Network
    server_address: ipaddress.IPv4Address
    private_key: str
    listen_port: int


def _config(raw: bytes) -> Config:
    if not isinstance(raw, bytes) or len(raw) > MAX_CONFIG:
        _error("Amnezia configuration invalid")
    try:
        lines = raw.decode("ascii").splitlines(keepends=True)
    except UnicodeDecodeError:
        _error("Amnezia configuration invalid")
    starts = [i for i, line in enumerate(lines) if line.strip() in ("[Interface]", "[Peer]")]
    if not starts or starts[0] != 0 or lines[0].strip() != "[Interface]":
        _error("Amnezia configuration invalid")
    chunks = ["".join(lines[start:starts[index + 1] if index + 1 < len(starts) else len(lines)])
              for index, start in enumerate(starts)]
    if sum(lines[index].strip() == "[Interface]" for index in starts) != 1:
        _error("Amnezia configuration invalid")
    interface = chunks[0]
    interface_values: dict[str, str] = {}
    for line in interface.splitlines():
        if "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            if key in ("Address", "PrivateKey", "ListenPort"):
                if key in interface_values:
                    _error("Amnezia interface configuration invalid")
                interface_values[key] = value
    if set(interface_values) != {"Address", "PrivateKey", "ListenPort"}:
        _error("Amnezia interface address invalid")
    try:
        server = ipaddress.IPv4Interface(interface_values["Address"])
    except (ValueError, ipaddress.AddressValueError):
        _error("Amnezia interface address invalid")
    private_key = _key(interface_values["PrivateKey"])
    try:
        port = int(interface_values["ListenPort"])
    except ValueError:
        _error("Amnezia interface port invalid")
    if not 1 <= port <= 65535:
        _error("Amnezia interface port invalid")
    peers = []
    seen_keys: set[str] = set()
    seen_addresses: set[ipaddress.IPv4Address] = set()
    for chunk in chunks[1:]:
        values: dict[str, str] = {}
        if chunk.splitlines()[0].strip() != "[Peer]":
            _error("Amnezia peer configuration invalid")
        for line in chunk.splitlines()[1:]:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if "=" not in line:
                _error("Amnezia peer configuration invalid")
            key, value = (part.strip() for part in line.split("=", 1))
            if key in values:
                _error("Amnezia peer configuration invalid")
            values[key] = value
        public = _key(values.get("PublicKey"))
        psk = _key(values.get("PresharedKey"))
        try:
            network = ipaddress.IPv4Network(values["AllowedIPs"], strict=True)
        except (KeyError, ValueError, ipaddress.AddressValueError):
            _error("Amnezia peer address invalid")
        if network.prefixlen != 32:
            _error("Amnezia peer address invalid")
        address = network.network_address
        if public in seen_keys or address in seen_addresses or address not in server.network:
            _error("Amnezia peer conflict")
        seen_keys.add(public)
        seen_addresses.add(address)
        peers.append(Peer(public, psk, address, chunk.encode("ascii")))
    return Config(interface.encode("ascii"), tuple(peers), server.network, server.ip,
                  private_key, port)


def _table(raw: bytes) -> list[dict]:
    if not isinstance(raw, bytes) or len(raw) > MAX_CONFIG:
        _error("Amnezia client registry invalid")
    try:
        rows = json.loads(raw)
    except (ValueError, UnicodeError):
        _error("Amnezia client registry invalid")
    if not isinstance(rows, list) or len(rows) > 2048:
        _error("Amnezia client registry invalid")
    ids = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("userData"), dict):
            _error("Amnezia client registry invalid")
        ids.append(_key(row.get("clientId")))
    if len(set(ids)) != len(ids):
        _error("Amnezia client registry invalid")
    return rows


def _runtime(raw: bytes) -> tuple[tuple[str, ...], dict[str, tuple[str, str, str]]]:
    if not isinstance(raw, bytes) or len(raw) > MAX_DUMP:
        _error("Amnezia runtime invalid")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _error("Amnezia runtime invalid")
    if not lines or len(lines[0].split("\t")) < 4:
        _error("Amnezia runtime invalid")
    interface = tuple(lines[0].split("\t")[:4])
    peers = {}
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 8:
            _error("Amnezia runtime invalid")
        public = _key(fields[0])
        if public in peers:
            _error("Amnezia runtime invalid")
        peers[public] = (fields[1], fields[3], fields[7])
    return interface, peers


def _consistent(config: Config, rows: list[dict], runtime: dict[str, tuple[str, str, str]],
                shared_psk: str) -> None:
    keys = {peer.key for peer in config.peers}
    if {row["clientId"] for row in rows} != keys or set(runtime) != keys:
        _error("Amnezia config, registry and runtime differ")
    for peer in config.peers:
        if peer.psk != shared_psk or runtime[peer.key][:2] != (
                peer.psk, f"{peer.address}/32"):
            _error("Amnezia peer settings differ")


def _consistent_interface(config: Config, interface: tuple[str, ...]) -> None:
    if (len(interface) != 4 or interface[0] != config.private_key or
            interface[2] != str(config.listen_port)):
        _error("Amnezia interface settings differ")


def _preview_awg_parameters(interface_raw: bytes) -> tuple[dict[str, str], bool]:
    """Expose only bounded numeric AWG values, never key or packet contents."""
    values: dict[str, str] = {}
    header_protection_key_present = False
    for line in interface_raw.decode("ascii").splitlines():
        if "=" not in line:
            continue
        name, value = (part.strip() for part in line.split("=", 1))
        if name == "HeaderProtectionKey":
            if header_protection_key_present:
                _error("Amnezia server parameters invalid")
            _key(value)
            header_protection_key_present = True
        elif name in AWG_PREVIEW_REQUIRED:
            if name in values or not re.fullmatch(r"[0-9]{1,10}(?:-[0-9]{1,10})?", value):
                _error("Amnezia server parameters invalid")
            parts = [int(part) for part in value.split("-")]
            maximum = 65535 if name in AWG_PREVIEW_NUMBERS else 4294967295
            if max(parts) > maximum or (
                    len(parts) == 2 and
                    (name in AWG_PREVIEW_NUMBERS or parts[0] > parts[1])):
                _error("Amnezia server parameters invalid")
            values[name] = value
    if ("Jmin" in values and "Jmax" in values and
            int(values["Jmin"]) > int(values["Jmax"])):
        _error("Amnezia server parameters invalid")
    return values, header_protection_key_present


def _awg_header_key(interface_raw: bytes) -> str:
    """Keep the server's header key in root memory, never in a public result."""
    found = None
    for line in interface_raw.decode("ascii").splitlines():
        if "=" not in line:
            continue
        name, value = (part.strip() for part in line.split("=", 1))
        if name == "HeaderProtectionKey":
            if found is not None:
                _error("Amnezia server parameters invalid")
            found = _key(value)
    if found is None:
        _error("AWG3 server settings are incomplete")
    return found


def _awg_patch(value: object, *, canonical: bool = True) -> dict[str, str]:
    """Accept only canonical, bounded public numeric AWG parameters."""
    if (not isinstance(value, dict) or not value or
            set(value) - AWG_PREVIEW_REQUIRED):
        _error("Invalid Amnezia settings proposal")
    result: dict[str, str] = {}
    for name, item in value.items():
        if not isinstance(item, str) or not re.fullmatch(r"[0-9]{1,10}(?:-[0-9]{1,10})?", item):
            _error("Invalid Amnezia settings proposal")
        parts = [int(part) for part in item.split("-")]
        if ((canonical and item != "-".join(str(part) for part in parts)) or
                max(parts) > (65535 if name in AWG_PREVIEW_NUMBERS else 4294967295) or
                (len(parts) == 2 and
                 (name in AWG_PREVIEW_NUMBERS or parts[0] > parts[1]))):
            _error("Invalid Amnezia settings proposal")
        result[name] = item
    return result


def _proposed_awg_config(raw: bytes, patch: dict[str, str]) -> bytes:
    """Build a memory-only candidate while preserving peers and unknown fields."""
    config = _config(raw)
    current, header_key = _preview_awg_parameters(config.interface_raw)
    if not AWG_PREVIEW_REQUIRED.issubset(current) or not header_key:
        _error("AWG3 server settings are incomplete")
    proposed = {**current, **patch}
    if int(proposed["Jmin"]) > int(proposed["Jmax"]):
        _error("Invalid Amnezia settings proposal")
    # AWG 3 header protection uses the first 12 bytes of each S-prefix as
    # its nonce. A shorter prefix makes the proposed server config unusable.
    if any(int(proposed[name]) < AWG_HEADER_NONCE_SIZE for name in ("S1", "S2", "S3", "S4")):
        _error("Invalid Amnezia settings proposal")
    updated: list[str] = []
    for line in config.interface_raw.decode("ascii").splitlines(keepends=True):
        prefix, separator, _old = line.partition("=")
        name = prefix.strip() if separator else ""
        if name in patch:
            ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            line = prefix + "= " + patch[name] + ending
        updated.append(line)
    candidate = "".join(updated).encode("ascii") + b"".join(peer.raw for peer in config.peers)
    if len(candidate) > MAX_CONFIG:
        _error("Amnezia settings proposal exceeds size limit")
    check = _config(candidate)
    if check.private_key != config.private_key or check.listen_port != config.listen_port or (
            tuple(peer.raw for peer in check.peers) != tuple(peer.raw for peer in config.peers)):
        _error("Amnezia settings proposal changed protected fields")
    candidate_values, candidate_header = _preview_awg_parameters(check.interface_raw)
    if candidate_values != proposed or candidate_header != header_key:
        _error("Amnezia settings proposal changed protected fields")
    return candidate


class AmneziaAdmin:
    """Explicitly enrolled container; never called by the Agent or Hub."""

    def __init__(self, target: Target, *, state_root: Path = STATE_ROOT,
                 runner: Callable = subprocess.run, require_root: bool = True):
        if target.name in TARGETS:
            if target != TARGETS[target.name]:
                _error("Amnezia target definition differs")
        else:
            if (not re.fullmatch(r"fixture-[a-z0-9-]{1,40}", target.name) or
                    not target.container.startswith("sg-amnezia-fixture-") or
                    not any(target == Target(target.name, target.container,
                                             canonical.image_name, canonical.binary,
                                             canonical.interface, canonical.config_path,
                                             canonical.table_path, canonical.psk_path)
                            for canonical in TARGETS.values())):
                _error("Unknown Amnezia fixture target")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", target.container):
            _error("Invalid Amnezia container")
        self.target = target
        self.state_root = Path(state_root)
        if not self.state_root.is_absolute():
            _error("Administrative state path must be absolute")
        self.runner = runner
        self.require_root = require_root

    @property
    def _owner(self) -> int:
        return 0 if self.require_root else os.geteuid()

    @property
    def _state_path(self) -> Path:
        return self.state_root / (self.target.name + ".json")

    @property
    def _pending_path(self) -> Path:
        return self.state_root / (self.target.name + ".pending")

    @property
    def _settings_intent_path(self) -> Path:
        return self.state_root / (self.target.name + ".settings-intent")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        if self.require_root and os.geteuid() != 0:
            _error("Amnezia administration requires root")
        _private_dir(self.state_root.parent, owner=self._owner, create=True)
        _private_dir(self.state_root, owner=self._owner, create=True)
        lock_path = self.state_root / ".lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            _private_file(lock_path, owner=self._owner)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _run(self, command: tuple[str, ...], *, input: bytes | None = None,
             limit: int = MAX_DUMP) -> bytes:
        if command[:2] == ("docker", "exec"):
            command = ("docker", "exec", "--user", "0:0", *command[2:])
        try:
            result = self.runner(command, input=input, capture_output=True,
                                 timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            _error("Amnezia Docker operation unavailable")
        if result.returncode != 0 or not isinstance(result.stdout, bytes):
            _error("Amnezia Docker operation failed")
        if len(result.stdout) > limit:
            _error("Amnezia Docker response exceeds size limit")
        return result.stdout

    def _identity(self) -> tuple[str, str]:
        fmt = "{{.Id}} {{.Image}} {{.Config.Image}} {{.Name}} {{.State.Running}}"
        raw = self._run(("docker", "container", "inspect", "--format", fmt,
                         self.target.container), limit=512)
        fields = raw.decode("ascii", "strict").strip().split()
        if (len(fields) != 5 or not HEX_ID.fullmatch(fields[0]) or
                not IMAGE_ID.fullmatch(fields[1]) or
                fields[2] not in ((self.target.image_name,
                                   self.target.image_name.removesuffix(":latest")) +
                                  ((PINNED_AWG_IMAGE, "docker.io/" + PINNED_AWG_IMAGE)
                                   if self.target.binary == "awg" else ())) or
                fields[3] != "/" + self.target.container or fields[4] != "true"):
            _error("Amnezia container identity or running state differs")
        mounts_raw = self._run(("docker", "container", "inspect", "--format",
                                "{{json .Mounts}}", self.target.container), limit=8192)
        try:
            mounts = json.loads(mounts_raw)
        except (ValueError, UnicodeError):
            _error("Amnezia mount inventory invalid")
        if not isinstance(mounts, list):
            _error("Amnezia mount inventory invalid")
        protected = (self.target.config_path, self.target.table_path, self.target.psk_path)
        for mount in mounts:
            if not isinstance(mount, dict) or not isinstance(mount.get("Destination"), str):
                _error("Amnezia mount inventory invalid")
            dest = mount["Destination"].rstrip("/")
            if mount.get("Type") != "tmpfs" and any(
                    path == dest or path.startswith(dest + "/") for path in protected):
                _error("Amnezia config path is mounted from outside the container")
        return fields[0], fields[1]

    def _mode_allowed(self, path: str, mode: int) -> bool:
        accepted = {
            self.target.config_path: (0o001, 0o600),
            self.target.table_path: (0o001, 0o600, 0o640),
            self.target.psk_path: (0o600, 0o640, 0o644),
        }
        return mode in accepted.get(path, ())

    def _file_mode(self, path: str) -> str:
        raw = self._run(("docker", "exec", self.target.container, "stat", "-c",
                         "%u:%g:%a:%F:%h", path), limit=128)
        fields = raw.decode("ascii", "strict").strip().split(":")
        if (len(fields) != 5 or fields[0:2] != ["0", "0"] or
                fields[3] != "regular file" or fields[4] != "1" or
                not re.fullmatch(r"[0-7]{1,4}", fields[2])):
            _error("Amnezia file ownership or type is unsafe")
        mode = int(fields[2], 8)
        # Existing Amnezia AWG2 releases have been observed using 0001 for
        # awg0.conf and clientsTable. Docker root can read these files; the
        # world-execute bit on a non-executable config does not grant read or
        # write. Preserve this odd mode exactly instead of silently changing
        # a live Amnezia file. Its PSK is observed as 0644; do not widen the
        # accepted mode of the server config to accommodate that PSK mode.
        if not self._mode_allowed(path, mode):
            _error("Amnezia file permissions are unsafe")
        return fields[2]

    def _read_file(self, path: str) -> bytes:
        self._file_mode(path)
        data = self._run(("docker", "exec", self.target.container, "head", "-c",
                          str(MAX_CONFIG + 1), path), limit=MAX_CONFIG + 1)
        if len(data) > MAX_CONFIG:
            _error("Amnezia file exceeds size limit")
        return data

    def _replace_file(self, path: str, data: bytes, mode: str) -> None:
        if len(data) > MAX_CONFIG:
            _error("Amnezia file exceeds size limit")
        self._run(("docker", "exec", "-i", self.target.container, "sh", "-c",
                   WRITE_SCRIPT, "sh", path, mode), input=data, limit=1024)
        if self._read_file(path) != data:
            _error("Amnezia file verification failed")

    def _dump(self) -> tuple[tuple[str, ...], dict[str, tuple[str, str, str]]]:
        raw = self._run(("docker", "exec", self.target.container,
                         self.target.binary, "show", self.target.interface, "dump"))
        return _runtime(raw)

    def _sync(self) -> None:
        binary, iface, path = self.target.binary, self.target.interface, self.target.config_path
        if binary not in ("wg", "awg") or iface not in ("wg0", "awg0"):
            _error("Amnezia target has invalid runtime command")
        script = f"set -e; {binary} syncconf {iface} <({binary}-quick strip {path})"
        self._run(("docker", "exec", self.target.container, "bash", "-c", script), limit=1024)

    def _snapshot(self):
        config_bytes = self._read_file(self.target.config_path)
        table_bytes = self._read_file(self.target.table_path)
        psk_bytes = self._read_file(self.target.psk_path)
        try:
            shared_psk = _key(psk_bytes.decode("ascii").strip())
        except UnicodeDecodeError:
            _error("Amnezia preshared key invalid")
        config = _config(config_bytes)
        rows = _table(table_bytes)
        iface, runtime = self._dump()
        _consistent(config, rows, runtime, shared_psk)
        _consistent_interface(config, iface)
        return config_bytes, table_bytes, config, rows, shared_psk, iface, runtime

    def _verify_awg_runtime_parameters(self, interface_raw: bytes,
                                       expected_identity: tuple[str, str]) -> None:
        """Fail closed if the live AWG3 device differs from the pinned file.

        `awg show ... dump` omits AWG parameters. Current amneziawg-tools
        exposes the individual numeric fields and header key via fixed `show`
        selectors. Every response is bounded and interpreted locally; the key
        never enters a result, exception or command argument.
        """
        if self.target.binary != "awg":
            _error("AWG3 runtime verification requires AmneziaWG")
        expected, present = _preview_awg_parameters(interface_raw)
        if not AWG_PREVIEW_REQUIRED.issubset(expected) or not present:
            _error("AWG3 server settings are incomplete")
        for name in sorted(AWG_PREVIEW_REQUIRED):
            raw = self._run(("docker", "exec", self.target.container, "awg", "show",
                             self.target.interface, name.lower()), limit=64)
            try:
                value = raw.decode("ascii").strip()
                _awg_patch({name: value}, canonical=False)
            except (UnicodeDecodeError, AmneziaAdminError):
                _error("AWG3 runtime parameters could not be verified")
            observed_parts = tuple(int(part) for part in value.split("-"))
            expected_parts = tuple(int(part) for part in expected[name].split("-"))
            # `awg show` may render a single-point H range as one number.
            if name in AWG_PREVIEW_RANGES:
                if len(observed_parts) == 1:
                    observed_parts *= 2
                if len(expected_parts) == 1:
                    expected_parts *= 2
            if observed_parts != expected_parts:
                _error("AWG3 runtime parameters differ from the pinned configuration")
        raw_key = self._run(("docker", "exec", self.target.container, "awg", "show",
                             self.target.interface, "header-protection-key"), limit=64)
        try:
            runtime_key = _key(raw_key.decode("ascii").strip())
        except (UnicodeDecodeError, AmneziaAdminError):
            _error("AWG3 runtime parameters could not be verified")
        if not hmac.compare_digest(runtime_key, _awg_header_key(interface_raw)):
            _error("AWG3 runtime parameters differ from the pinned configuration")
        if self._identity() != expected_identity:
            _error("Enrolled Amnezia container identity changed")

    def _load_state(self) -> tuple[dict, bytes]:
        raw = _read_private(self._state_path, owner=self._owner)
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            _error("Administrative state invalid")
        if (not isinstance(value, dict) or value.get("schema_version") != 1 or
                value.get("target") != self.target.name or
                not HEX_ID.fullmatch(value.get("container_id", "")) or
                not IMAGE_ID.fullmatch(value.get("image_id", "")) or
                not isinstance(value.get("owned"), dict) or
                not isinstance(value.get("generation"), int) or
                value["generation"] < 0):
            _error("Administrative state invalid")
        for name, entry in value["owned"].items():
            _client_name(name)
            basic = {"public_key", "address"}
            generated = basic | {"private_key", "endpoint_host", "route", "profile_sha256"}
            if not isinstance(entry, dict) or set(entry) not in (basic, generated):
                _error("Administrative state invalid")
            _key(entry["public_key"])
            try:
                ipaddress.IPv4Address(entry["address"])
            except (ValueError, TypeError):
                _error("Administrative state invalid")
            if set(entry) == generated:
                try:
                    from .amnezia_profile import endpoint, public_from_private
                    if (public_from_private(entry["private_key"]) != entry["public_key"] or
                            not isinstance(entry["profile_sha256"], str) or
                            not HEX_ID.fullmatch(entry["profile_sha256"]) or
                            entry["route"] not in ("split", "full")):
                        _error("Administrative state invalid")
                    endpoint(entry["endpoint_host"], 1)
                except (ValueError, TypeError, KeyError, ImportError):
                    _error("Administrative state invalid")
        if len({entry["public_key"] for entry in value["owned"].values()}) != len(value["owned"]):
            _error("Administrative state invalid")
        return value, raw

    def _check_state(self, state: dict, config_raw: bytes, table_raw: bytes,
                     config: Config) -> None:
        identity = self._identity()
        if identity != (state["container_id"], state["image_id"]):
            _error("Enrolled Amnezia container identity changed")
        if _sha(config_raw) != state.get("config_sha256") or _sha(table_raw) != state.get("table_sha256"):
            _error("Amnezia files changed outside SovaGrid; re-enrolment required")
        peer_map = {peer.key: str(peer.address) for peer in config.peers}
        if any(peer_map.get(entry["public_key"]) != entry["address"]
               for entry in state["owned"].values()):
            _error("SovaGrid-owned peer state differs")

    def _require_no_pending(self) -> None:
        if self._pending_path.exists() or self._pending_path.is_symlink():
            _error("An interrupted Amnezia operation requires recovery")

    def enroll_preview(self) -> dict:
        """Show the exact live container and files before an opt-in decision."""
        with self._locked():
            self._require_no_pending()
            if self._state_path.exists() or self._state_path.is_symlink():
                _error("Amnezia target is already enrolled")
            identity = self._identity()
            config_raw, table_raw, config, _, _, _, _ = self._snapshot()
            if self._identity() != identity:
                _error("Amnezia container identity changed during preview")
            return {"target": self.target.name, "container_id": identity[0],
                    "image_id": identity[1], "config_sha256": _sha(config_raw),
                    "table_sha256": _sha(table_raw), "configured_clients": len(config.peers),
                    "protocol": "amneziawg" if self.target.binary == "awg" else "wireguard",
                    "interface": self.target.interface, "listen_port": config.listen_port,
                    "server_subnet": str(config.network)}

    def enroll(self, confirm_container_id: str, *,
               confirm_image_id: str | None = None,
               confirm_config_sha256: str | None = None,
               confirm_table_sha256: str | None = None) -> dict:
        """Read-only container check followed by an explicit local opt-in record."""
        pins = (confirm_image_id, confirm_config_sha256, confirm_table_sha256)
        if any(value is not None for value in pins) and not all(value is not None for value in pins):
            _error("Complete Amnezia enrollment preview pins are required")
        with self._locked():
            self._require_no_pending()
            if self._state_path.exists() or self._state_path.is_symlink():
                _error("Amnezia target is already enrolled")
            identity = self._identity()
            if confirm_container_id != identity[0]:
                _error("Container confirmation does not match")
            config_raw, table_raw, config, rows, _, _, _ = self._snapshot()
            if self._identity() != identity:
                _error("Amnezia container identity changed during enrollment")
            if confirm_image_id is not None and (
                    confirm_image_id != identity[1] or
                    confirm_config_sha256 != _sha(config_raw) or
                    confirm_table_sha256 != _sha(table_raw)):
                _error("Amnezia enrollment preview changed")
            state = {"schema_version": 1, "target": self.target.name,
                     "container_id": identity[0], "image_id": identity[1],
                     "config_sha256": _sha(config_raw), "table_sha256": _sha(table_raw),
                     "owned": {}, "generation": 0}
            _atomic_private(self._state_path, _json_bytes(state), owner=self._owner, new=True)
            return {"target": self.target.name, "enrolled": True,
                    "configured_clients": len(config.peers)}

    def _prepare_pending(self, config_raw: bytes, table_raw: bytes,
                         state_raw: bytes, modes: tuple[str, str],
                         new_config: bytes, new_table: bytes,
                         *, kind: str | None = None) -> None:
        if kind not in (None, "awg_settings"):
            _error("Amnezia recovery journal invalid")
        temp = self.state_root / (self.target.name + ".prepare")
        if temp.exists() or temp.is_symlink():
            _error("Previous Amnezia preparation requires inspection")
        temp.mkdir(mode=0o700)
        try:
            _private_dir(temp, owner=self._owner)
            for filename, data in (("config", config_raw), ("table", table_raw),
                                   ("state", state_raw)):
                _atomic_private(temp / filename, data, owner=self._owner, new=True)
            # The new numeric settings must be available after a crash even
            # when the container file has already been rolled back to old.
            if kind == "awg_settings":
                _atomic_private(temp / "new-config", new_config,
                                owner=self._owner, new=True)
            intent = {"schema_version": 1, "target": self.target.name,
                      "container_id": self._identity()[0], "modes": list(modes),
                      "new_config_sha256": _sha(new_config),
                      "new_table_sha256": _sha(new_table),
                      "new_peer_keys": sorted(peer.key for peer in _config(new_config).peers),
                      "phase": "prepared"}
            if kind is not None:
                intent["kind"] = kind
            _atomic_private(temp / "intent", _json_bytes(intent), owner=self._owner, new=True)
            _fsync_dir(temp)
            os.rename(temp, self._pending_path)
            _fsync_dir(self.state_root)
        except Exception:
            if temp.exists():
                for child in temp.iterdir():
                    child.unlink()
                temp.rmdir()
            raise

    def _pending_intent(self) -> dict:
        _private_dir(self._pending_path, owner=self._owner)
        try:
            intent = json.loads(_read_private(self._pending_path / "intent", owner=self._owner))
        except (ValueError, UnicodeError):
            _error("Amnezia recovery journal invalid")
        if (not isinstance(intent, dict) or intent.get("schema_version") != 1 or
                intent.get("target") != self.target.name or
                intent.get("container_id") != self._identity()[0] or
                intent.get("phase") not in ("prepared", "committed", "rolled_back") or
                not HEX_ID.fullmatch(intent.get("new_config_sha256", "")) or
                not HEX_ID.fullmatch(intent.get("new_table_sha256", "")) or
                not isinstance(intent.get("new_peer_keys"), list) or
                len(intent["new_peer_keys"]) > 2048 or
                any(not isinstance(value, str) or not KEY_PATTERN.fullmatch(value)
                    for value in intent["new_peer_keys"]) or
                len(set(intent["new_peer_keys"])) != len(intent["new_peer_keys"]) or
                intent.get("kind") not in (None, "awg_settings") or
                not isinstance(intent.get("modes"), list) or len(intent["modes"]) != 2 or
                any(not isinstance(value, str) or
                    not re.fullmatch(r"[0-7]{1,4}", value) or
                    not self._mode_allowed(path, int(value, 8))
                    for path, value in zip((self.target.config_path,
                                            self.target.table_path), intent["modes"]))):
            _error("Amnezia recovery journal invalid")
        return intent

    def _pending(self) -> tuple[bytes, bytes, bytes, tuple[str, str]]:
        intent = self._pending_intent()
        if intent["phase"] != "prepared":
            _error("Amnezia recovery journal is no longer prepared")
        config = _read_private(self._pending_path / "config", owner=self._owner)
        table = _read_private(self._pending_path / "table", owner=self._owner)
        state = _read_private(self._pending_path / "state", owner=self._owner)
        return config, table, state, tuple(intent["modes"])

    def _pending_awg_settings(self, intent: dict, old_config: bytes,
                              old_table: bytes) -> bytes | None:
        if intent.get("kind") != "awg_settings":
            return None
        if self.target.binary != "awg":
            _error("Amnezia recovery journal invalid")
        candidate = _read_private(self._pending_path / "new-config", owner=self._owner)
        original, proposed = _config(old_config), _config(candidate)
        old_values, old_header = _preview_awg_parameters(original.interface_raw)
        new_values, new_header = _preview_awg_parameters(proposed.interface_raw)
        changes = {name: new_values[name] for name in AWG_PREVIEW_REQUIRED
                   if name in old_values and name in new_values and
                   old_values[name] != new_values[name]}
        if (_sha(candidate) != intent["new_config_sha256"] or
                intent["new_table_sha256"] != _sha(old_table) or
                original.peers or proposed.peers or intent["new_peer_keys"] or
                original.private_key != proposed.private_key or
                original.listen_port != proposed.listen_port or
                not old_header or not new_header or
                not AWG_PREVIEW_REQUIRED.issubset(old_values) or
                not AWG_PREVIEW_REQUIRED.issubset(new_values) or
                not changes or _proposed_awg_config(old_config, changes) != candidate):
            _error("Amnezia recovery journal invalid")
        return candidate

    def _mark_phase(self, phase: str) -> None:
        intent = self._pending_intent()
        if intent["phase"] != "prepared" or phase not in ("committed", "rolled_back"):
            _error("Amnezia recovery journal phase invalid")
        intent["phase"] = phase
        _atomic_private(self._pending_path / "intent", _json_bytes(intent), owner=self._owner)

    def _clear_pending(self) -> None:
        for filename in ("config", "table", "state", "new-config"):
            (self._pending_path / filename).unlink(missing_ok=True)
        (self._pending_path / "intent").unlink(missing_ok=True)
        self._pending_path.rmdir()
        _fsync_dir(self.state_root)

    def _recover_locked(self) -> None:
        intent = self._pending_intent()
        config_raw, table_raw, state_raw, modes = self._pending()
        old_state = json.loads(state_raw)
        identity = self._identity()
        original = _config(config_raw)
        proposed_settings = self._pending_awg_settings(intent, config_raw, table_raw)
        original_rows = _table(table_raw)
        if (not isinstance(old_state, dict) or old_state.get("schema_version") != 1 or
                old_state.get("target") != self.target.name or
                _sha(config_raw) != old_state.get("config_sha256") or
                _sha(table_raw) != old_state.get("table_sha256") or
                {row["clientId"] for row in original_rows} !=
                {peer.key for peer in original.peers}):
            _error("Amnezia recovery backup invalid")
        if identity != (old_state.get("container_id"), old_state.get("image_id")):
            _error("Recovery refused because container identity changed")
        psk = _key(self._read_file(self.target.psk_path).decode("ascii").strip())
        if any(peer.psk != psk for peer in original.peers):
            _error("Amnezia recovery preshared key changed")
        current_config = self._read_file(self.target.config_path)
        current_table = self._read_file(self.target.table_path)
        if (_sha(current_config) not in (old_state["config_sha256"],
                                        intent["new_config_sha256"]) or
                _sha(current_table) not in (old_state["table_sha256"],
                                         intent["new_table_sha256"])):
            _error("Recovery refused because Amnezia files changed externally")
        iface, current_runtime = self._dump()
        _consistent_interface(original, iface)
        old_keys = {peer.key for peer in original.peers}
        if set(current_runtime) not in (old_keys, set(intent["new_peer_keys"])):
            _error("Recovery refused because Amnezia runtime changed externally")
        for peer in original.peers:
            if peer.key in current_runtime and current_runtime[peer.key][:2] != (
                    peer.psk, f"{peer.address}/32"):
                _error("Recovery refused because Amnezia runtime changed externally")
        if proposed_settings is not None:
            pinned_identity = (old_state["container_id"], old_state["image_id"])
            matched = False
            for allowed in (config_raw, proposed_settings):
                try:
                    self._verify_awg_runtime_parameters(
                        _config(allowed).interface_raw, pinned_identity)
                except AmneziaAdminError:
                    continue
                matched = True
                break
            if not matched:
                _error("Recovery refused because Amnezia runtime settings changed externally")
        self._replace_file(self.target.config_path, config_raw, modes[0])
        self._replace_file(self.target.table_path, table_raw, modes[1])
        self._sync()
        iface, runtime = self._dump()
        _consistent(original, original_rows, runtime, psk)
        _consistent_interface(original, iface)
        if proposed_settings is not None:
            self._verify_awg_runtime_parameters(original.interface_raw,
                                                pinned_identity)
        _atomic_private(self._state_path, state_raw, owner=self._owner)
        self._mark_phase("rolled_back")
        self._clear_pending()

    def recover(self) -> dict:
        with self._locked():
            if not self._pending_path.exists():
                _error("No interrupted Amnezia operation to recover")
            intent_file = self._pending_path / "intent"
            if not intent_file.exists():
                if any(self._pending_path.iterdir()):
                    _error("Amnezia recovery journal incomplete")
                self._pending_path.rmdir()
                _fsync_dir(self.state_root)
                return {"target": self.target.name, "recovered": True}
            intent = self._pending_intent()
            if intent["phase"] == "committed":
                state, _ = self._load_state()
                config_raw, table_raw, config, _, _, _, _ = self._snapshot()
                self._check_state(state, config_raw, table_raw, config)
                if intent.get("kind") == "awg_settings":
                    if (self.target.binary != "awg" or config.peers or
                            _sha(config_raw) != intent["new_config_sha256"] or
                            _sha(table_raw) != intent["new_table_sha256"] or
                            intent["new_peer_keys"]):
                        _error("Amnezia recovery journal invalid")
                    self._verify_awg_runtime_parameters(config.interface_raw,
                                                        (state["container_id"], state["image_id"]))
                self._clear_pending()
                return {"target": self.target.name, "recovered": True,
                        "committed": True}
            if intent["phase"] == "rolled_back":
                self._clear_pending()
                return {"target": self.target.name, "recovered": True}
            self._recover_locked()
            return {"target": self.target.name, "recovered": True}

    def _commit(self, old_config: bytes, old_table: bytes, old_state: bytes,
                new_config: bytes, new_table: bytes, new_state: dict,
                old_interface: tuple[str, ...], new_peers: set[str],
                old_static: dict[str, tuple[str, str, str]],
                *, kind: str | None = None) -> bool:
        modes = (self._file_mode(self.target.config_path), self._file_mode(self.target.table_path))
        self._prepare_pending(old_config, old_table, old_state, modes,
                              new_config, new_table, kind=kind)
        wrote_any = False
        try:
            if (self._read_file(self.target.config_path) != old_config or
                    self._read_file(self.target.table_path) != old_table):
                _error("Amnezia files changed before write")
            wrote_any = True
            self._replace_file(self.target.config_path, new_config, modes[0])
            self._replace_file(self.target.table_path, new_table, modes[1])
            self._sync()
            verified_config, verified_table, _, _, _, current_interface, runtime = self._snapshot()
            if (current_interface != old_interface or set(runtime) != new_peers or
                    any(runtime.get(key) != value for key, value in old_static.items()) or
                    verified_config != new_config or verified_table != new_table):
                _error("Amnezia runtime verification failed")
            if kind == "awg_settings":
                self._verify_awg_runtime_parameters(
                    _config(new_config).interface_raw,
                    (new_state["container_id"], new_state["image_id"]))
            _atomic_private(self._state_path, _json_bytes(new_state), owner=self._owner)
            self._mark_phase("committed")
        except Exception:
            if wrote_any:
                try:
                    self._recover_locked()
                except Exception:
                    _error("Amnezia update failed; manual recovery required")
            else:
                self._clear_pending()
            _error("Amnezia update failed and was rolled back")
        try:
            self._clear_pending()
            return False
        except Exception:
            # The operation is already committed. A later recover finalizes
            # cleanup after confirming current files and runtime.
            return True

    def _render_owned_profile(self, entry: dict, config: Config, psk: str,
                              interface: tuple[str, ...]) -> bytes:
        try:
            from .amnezia_profile import render_awg3_profile, render_wireguard_profile
            common = dict(server_private_key=config.private_key,
                          runtime_server_public_key=interface[1], shared_psk=psk,
                          client_private_key=entry["private_key"],
                          client_address=ipaddress.IPv4Address(entry["address"]),
                          server_network=config.network, endpoint_host=entry["endpoint_host"],
                          port=config.listen_port, route=entry["route"])
            if self.target.binary == "awg":
                return render_awg3_profile(interface_raw=config.interface_raw, **common)
            return render_wireguard_profile(**common)
        except (ValueError, TypeError, KeyError, ImportError):
            _error(("AWG3" if self.target.binary == "awg" else "WireGuard") +
                   " profile generation failed")

    def add(self, name: str, public_key: str, address: str) -> dict:
        """Add a server peer for an externally generated public key, no profile."""
        return self._add(name, public_key, address)

    def create_profile(self, name: str, address: str, endpoint_host: str,
                       recipient_public_key: str, *, route: str = "split") -> dict:
        """Generate a target-specific client key and return only sealed .conf."""
        _client_name(name)
        try:
            from .amnezia_profile import endpoint, new_client_keypair
            from .sealed import decode_public_key
            endpoint(endpoint_host, 1)
            decode_public_key(recipient_public_key)
            if route not in ("split", "full"):
                _error("Invalid Amnezia profile route")
            private_key, public_key = new_client_keypair()
        except (RuntimeError, ValueError, TypeError, ImportError):
            _error("Invalid " + ("AWG3" if self.target.binary == "awg"
                                  else "WireGuard") + " profile request")
        return self._add(name, public_key, address,
                         generated=(private_key, endpoint_host, route, recipient_public_key))

    def _check_provision_route(self, state: dict, route: str) -> None:
        if self.target.name != "awg2" or route != "full":
            return
        if not PROVISION_STATE.exists() and not PROVISION_STATE.is_symlink():
            return
        _private_dir(PROVISION_STATE.parent, owner=self._owner)
        try:
            provision = json.loads(_read_private(PROVISION_STATE, owner=self._owner),
                                   object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError):
            _error("Amnezia provision state invalid")
        if (not isinstance(provision, dict) or provision.get("route_mode") != "full" or
                provision.get("container_id") != state.get("container_id") or
                provision.get("image_id") != state.get("image_id")):
            _error("Full Amnezia route is not enabled for this container")

    def _add(self, name: str, public_key: str, address: str,
             generated: tuple[str, str, str, str] | None = None) -> dict:
        _client_name(name)
        public_key = _key(public_key)
        try:
            client_ip = ipaddress.IPv4Address(address)
        except (ValueError, TypeError):
            _error("Invalid client IPv4 address")
        with self._locked():
            self._require_no_pending()
            state, state_raw = self._load_state()
            if generated is not None:
                self._check_provision_route(state, generated[2])
            if len(state["owned"]) >= MAX_OWNED_CLIENTS:
                _error("SovaGrid-owned Amnezia client limit reached")
            config_raw, table_raw, config, rows, psk, interface, runtime = self._snapshot()
            self._check_state(state, config_raw, table_raw, config)
            if (name in state["owned"] or public_key in runtime or
                    client_ip not in config.network or
                    client_ip in (config.server_address, config.network.network_address,
                                  config.network.broadcast_address) or
                    any(peer.address == client_ip for peer in config.peers)):
                _error("Client name, key or address is already in use")
            section = (f"[Peer]\nPublicKey = {public_key}\nPresharedKey = {psk}\n"
                       f"AllowedIPs = {client_ip}/32\n\n").encode("ascii")
            new_config = config_raw + (b"" if config_raw.endswith(b"\n") else b"\n") + section
            new_table = _json_bytes(rows + [{"clientId": public_key,
                                             "userData": {"clientName": name}}])
            new_state = dict(state)
            new_state["owned"] = dict(state["owned"])
            entry = {"public_key": public_key, "address": str(client_ip)}
            sealed_profile = None
            if generated is not None:
                private_key, endpoint_host, route, recipient = generated
                entry.update({"private_key": private_key, "endpoint_host": endpoint_host,
                              "route": route})
                profile = self._render_owned_profile(entry, config, psk, interface)
                try:
                    from .sealed import seal_profile
                    sealed_profile = seal_profile(profile, recipient, self.target.name, name)
                except (RuntimeError, ValueError, ImportError):
                    _error("Amnezia profile sealing failed")
                entry["profile_sha256"] = _sha(profile)
            new_state["owned"][name] = entry
            new_state["generation"] += 1
            new_state["config_sha256"] = _sha(new_config)
            new_state["table_sha256"] = _sha(new_table)
            _consistent(_config(new_config), _table(new_table),
                        {**runtime, public_key: (psk, f"{client_ip}/32", "off")}, psk)
            cleanup_required = self._commit(config_raw, table_raw, state_raw,
                                            new_config, new_table, new_state,
                                            interface, set(runtime) | {public_key}, runtime)
            result = {"target": self.target.name, "action": "added", "client": name,
                      "configured_clients": len(config.peers) + 1,
                      "cleanup_required": cleanup_required}
            if sealed_profile is not None:
                result["profile_format"] = ("awg3-conf" if self.target.binary == "awg"
                                            else "wg-conf")
                result["sealed_profile"] = sealed_profile
            return result

    def sealed_export(self, name: str, recipient_public_key: str) -> dict:
        """Regenerate a verified profile and emit only authenticated ciphertext."""
        _client_name(name)
        try:
            from .sealed import decode_public_key
            decode_public_key(recipient_public_key)
        except (RuntimeError, ValueError, TypeError, ImportError):
            _error("Invalid profile recipient key")
        with self._locked():
            self._require_no_pending()
            state, _ = self._load_state()
            entry = state["owned"].get(name)
            if entry is None or "private_key" not in entry:
                _error("Client has no SovaGrid " +
                       ("AWG3" if self.target.binary == "awg" else "WireGuard") +
                       " profile")
            config_raw, table_raw, config, _, psk, interface, _ = self._snapshot()
            self._check_state(state, config_raw, table_raw, config)
            profile = self._render_owned_profile(entry, config, psk, interface)
            if _sha(profile) != entry["profile_sha256"]:
                _error("Stored Amnezia profile state differs")
            try:
                from .sealed import seal_profile
                return seal_profile(profile, recipient_public_key, self.target.name, name)
            except (RuntimeError, ValueError, ImportError):
                _error("Amnezia profile sealing failed")

    def revoke(self, name: str) -> dict:
        _client_name(name)
        with self._locked():
            self._require_no_pending()
            state, state_raw = self._load_state()
            entry = state["owned"].get(name)
            if entry is None:
                _error("Client is not owned by SovaGrid")
            config_raw, table_raw, config, rows, psk, interface, runtime = self._snapshot()
            self._check_state(state, config_raw, table_raw, config)
            public = entry["public_key"]
            new_config = config.interface_raw + b"".join(peer.raw for peer in config.peers
                                                          if peer.key != public)
            new_table = _json_bytes([row for row in rows if row["clientId"] != public])
            new_state = dict(state)
            new_state["owned"] = dict(state["owned"])
            del new_state["owned"][name]
            new_state["generation"] += 1
            new_state["config_sha256"] = _sha(new_config)
            new_state["table_sha256"] = _sha(new_table)
            unchanged = {key: value for key, value in runtime.items() if key != public}
            _consistent(_config(new_config), _table(new_table), unchanged, psk)
            cleanup_required = self._commit(config_raw, table_raw, state_raw,
                                            new_config, new_table, new_state,
                                            interface, set(runtime) - {public}, unchanged)
            return {"target": self.target.name, "action": "revoked", "client": name,
                    "configured_clients": len(config.peers) - 1,
                    "cleanup_required": cleanup_required}

    def status(self) -> dict:
        with self._locked():
            state, _ = self._load_state()
            return {"target": self.target.name, "enrolled": True,
                    "recovery_required": self._pending_path.exists(),
                    "owned_clients": sorted(state["owned"])}

    def settings_preview(self) -> dict:
        """Inspect an enrolled, consistent server without exposing client identities."""
        with self._locked():
            self._require_no_pending()
            state, _ = self._load_state()
            config_raw, table_raw, config, _, _, _, _ = self._snapshot()
            self._check_state(state, config_raw, table_raw, config)
            parameters, header_key_present = (
                _preview_awg_parameters(config.interface_raw)
                if self.target.binary == "awg" else ({}, False))
            preview = {
                "target": self.target.name,
                "container_id": state["container_id"],
                "image_id": state["image_id"],
                "config_sha256": state["config_sha256"],
                "table_sha256": state["table_sha256"],
                "generation": state["generation"],
                "protocol": "amneziawg" if self.target.binary == "awg" else "wireguard",
                "interface": self.target.interface,
                "listen_port": config.listen_port,
                "server_address": str(config.server_address),
                "server_subnet": str(config.network),
                "configured_clients": len(config.peers),
                "managed_clients": len(state["owned"]),
                "external_clients": len(config.peers) - len(state["owned"]),
                "awg_parameters": parameters,
                "awg_parameters_runtime_verified": False,
                "header_protection_key_present": header_key_present,
                "awg3_required_parameters_present": (self.target.binary == "awg" and
                                                     AWG_PREVIEW_REQUIRED.issubset(parameters) and
                                                     header_key_present),
                "apply_supported": False,
                "apply_blockers": ["CLIENT_PROFILES_REQUIRE_REISSUE",
                                   "PORT_REQUIRES_CONTAINER_NETWORK_MIGRATION"],
            }
            if len(_json_bytes(preview)) > MAX_SETTINGS_PREVIEW:
                _error("Amnezia settings preview exceeds size limit")
            return preview

    def settings_plan(self, expected_config_sha256: str, expected_generation: int,
                      patch: dict[str, str]) -> dict:
        """Preview a CAS-pinned AWG change without writing config or runtime.

        Changing these fields invalidates existing client profiles. The current
        runtime contract cannot verify AWG3 parameters after syncconf, so this
        intentionally does not expose an apply operation.
        """
        if self.target.binary != "awg" or not isinstance(expected_config_sha256, str) or (
                HEX_ID.fullmatch(expected_config_sha256) is None or
                type(expected_generation) is not int or not 0 <= expected_generation <= 1_000_000_000):
            _error("Invalid Amnezia settings proposal")
        requested = _awg_patch(patch)
        with self._locked():
            self._require_no_pending()
            state, _ = self._load_state()
            config_raw, table_raw, config, _, _, _, _ = self._snapshot()
            self._check_state(state, config_raw, table_raw, config)
            if (state["config_sha256"] != expected_config_sha256 or
                    state["generation"] != expected_generation):
                _error("Amnezia settings preview changed")
            current, header_key = _preview_awg_parameters(config.interface_raw)
            if not AWG_PREVIEW_REQUIRED.issubset(current) or not header_key:
                _error("AWG3 server settings are incomplete")
            self._verify_awg_runtime_parameters(
                config.interface_raw, (state["container_id"], state["image_id"]))
            changed = sorted(name for name, item in requested.items() if current[name] != item)
            if not changed:
                _error("No Amnezia settings change requested")
            candidate = _proposed_awg_config(config_raw, requested)
            proposed = {**current, **requested}
            blockers = (["CLIENT_PROFILES_REQUIRE_REISSUE"] if config.peers else [])
            result = {"target": self.target.name,
                      "container_id": state["container_id"],
                      "image_id": state["image_id"],
                      "generation": state["generation"],
                      "config_sha256": state["config_sha256"],
                      "table_sha256": _sha(table_raw),
                      "proposed_config_sha256": _sha(candidate),
                      "current_awg_parameters": current,
                      "proposed_awg_parameters": proposed,
                      "changed_fields": changed,
                      "configured_clients": len(config.peers),
                      "apply_supported": not bool(config.peers),
                      "apply_blockers": blockers}
            if len(_json_bytes(result)) > MAX_SETTINGS_PREVIEW:
                _error("Amnezia settings plan exceeds size limit")
            return result

    def _settings_candidate_locked(self, expected_config_sha256: str,
                                   expected_generation: int,
                                   expected_proposed_config_sha256: str,
                                   requested: dict[str, str]) -> tuple:
        """Recheck all CAS pins and the zero-client invariant under the lock."""
        if (self.target.binary != "awg" or
                not isinstance(expected_proposed_config_sha256, str) or
                HEX_ID.fullmatch(expected_proposed_config_sha256) is None):
            _error("Invalid Amnezia settings proposal")
        self._require_no_pending()
        state, state_raw = self._load_state()
        config_raw, table_raw, config, rows, _, interface, runtime = self._snapshot()
        self._check_state(state, config_raw, table_raw, config)
        if (state["config_sha256"] != expected_config_sha256 or
                state["generation"] != expected_generation or
                state["generation"] >= 1_000_000_000 or
                config.peers or rows or runtime or state["owned"]):
            _error("Amnezia settings preview changed or client profiles require reissue")
        identity = (state["container_id"], state["image_id"])
        self._verify_awg_runtime_parameters(config.interface_raw, identity)
        candidate = _proposed_awg_config(config_raw, requested)
        if (candidate == config_raw or
                _sha(candidate) != expected_proposed_config_sha256 or
                self._identity() != identity):
            _error("Amnezia settings preview changed")
        return state, state_raw, config_raw, table_raw, interface, candidate

    def _settings_commit_locked(self, snapshot: tuple) -> dict:
        state, state_raw, config_raw, table_raw, interface, candidate = snapshot
        next_state = dict(state)
        next_state["generation"] += 1
        next_state["config_sha256"] = _sha(candidate)
        cleanup_required = self._commit(config_raw, table_raw, state_raw,
                                        candidate, table_raw, next_state,
                                        interface, set(), {},
                                        kind="awg_settings")
        return {"target": self.target.name, "action": "settings_updated",
                "generation": next_state["generation"],
                "config_sha256": next_state["config_sha256"],
                "cleanup_required": cleanup_required}

    def _load_settings_intent(self) -> dict | None:
        path = self._settings_intent_path
        if not path.exists() and not path.is_symlink():
            return None
        try:
            intent = json.loads(_read_private(path, owner=self._owner),
                                object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError):
            _error("Amnezia settings confirmation invalid")
        if (not isinstance(intent, dict) or set(intent) != {
                "schema_version", "target", "issued_at", "expires_at",
                "confirmation_sha256", "config_sha256", "proposed_config_sha256",
                "generation", "patch_sha256", "container_id", "image_id"} or
                type(intent["schema_version"]) is not int or intent["schema_version"] != 1 or
                intent["target"] != self.target.name or
                type(intent["issued_at"]) is not int or intent["issued_at"] < 0 or
                type(intent["expires_at"]) is not int or
                intent["expires_at"] != intent["issued_at"] + SETTINGS_INTENT_TTL or
                type(intent["generation"]) is not int or
                not 0 <= intent["generation"] <= 1_000_000_000 or
                any(not isinstance(intent[name], str) or HEX_ID.fullmatch(intent[name]) is None
                    for name in ("confirmation_sha256", "config_sha256",
                                 "proposed_config_sha256", "patch_sha256", "container_id")) or
                not isinstance(intent["image_id"], str) or
                IMAGE_ID.fullmatch(intent["image_id"]) is None):
            _error("Amnezia settings confirmation invalid")
        return intent

    def settings_intent(self, expected_config_sha256: str, expected_generation: int,
                        expected_proposed_config_sha256: str,
                        patch: dict[str, str]) -> dict:
        """Create one short-lived confirmation handle for an exact AWG3 plan."""
        requested = _awg_patch(patch)
        plan = self.settings_plan(expected_config_sha256, expected_generation,
                                  requested)
        if (plan["configured_clients"] != 0 or
                plan["proposed_config_sha256"] != expected_proposed_config_sha256):
            _error("Amnezia settings preview changed or client profiles require reissue")
        with self._locked():
            state = self._settings_candidate_locked(expected_config_sha256,
                                                    expected_generation,
                                                    expected_proposed_config_sha256,
                                                    requested)[0]
            previous = self._load_settings_intent()
            now = int(time.time())
            if previous is not None:
                if previous["expires_at"] > now:
                    _error("Amnezia settings confirmation already pending")
                self._settings_intent_path.unlink()
                _fsync_dir(self.state_root)
            handle = secrets.token_urlsafe(32)
            if CONFIRMATION_ID.fullmatch(handle) is None:
                _error("Amnezia settings confirmation unavailable")
            record = {"schema_version": 1, "target": self.target.name,
                      "issued_at": now, "expires_at": now + SETTINGS_INTENT_TTL,
                      "confirmation_sha256": _sha(handle.encode("ascii")),
                      "config_sha256": expected_config_sha256,
                      "proposed_config_sha256": expected_proposed_config_sha256,
                      "generation": expected_generation,
                      "patch_sha256": _sha(_json_bytes(requested)),
                      "container_id": state["container_id"],
                      "image_id": state["image_id"]}
            _atomic_private(self._settings_intent_path, _json_bytes(record),
                            owner=self._owner, new=True)
            return {"target": self.target.name, "action": "settings_intent",
                    "confirmation_id": handle, "expires_at": record["expires_at"],
                    "generation": expected_generation,
                    "config_sha256": expected_config_sha256,
                    "proposed_config_sha256": expected_proposed_config_sha256,
                    "changed_fields": plan["changed_fields"],
                    "configured_clients": 0}

    def settings_apply_confirmed(self, expected_config_sha256: str,
                                 expected_generation: int,
                                 expected_proposed_config_sha256: str,
                                 patch: dict[str, str], confirmation_id: str) -> dict:
        """Consume the exact broker confirmation before any config write."""
        if (not isinstance(confirmation_id, str) or
                CONFIRMATION_ID.fullmatch(confirmation_id) is None):
            _error("Invalid Amnezia settings confirmation")
        requested = _awg_patch(patch)
        with self._locked():
            snapshot = self._settings_candidate_locked(expected_config_sha256,
                                                       expected_generation,
                                                       expected_proposed_config_sha256,
                                                       requested)
            state = snapshot[0]
            intent = self._load_settings_intent()
            now = int(time.time())
            if (intent is None or not intent["issued_at"] <= now < intent["expires_at"] or
                    not hmac.compare_digest(intent["confirmation_sha256"],
                                            _sha(confirmation_id.encode("ascii"))) or
                    intent["config_sha256"] != expected_config_sha256 or
                    intent["generation"] != expected_generation or
                    intent["proposed_config_sha256"] != expected_proposed_config_sha256 or
                    intent["patch_sha256"] != _sha(_json_bytes(requested)) or
                    (intent["container_id"], intent["image_id"]) !=
                    (state["container_id"], state["image_id"])):
                _error("Amnezia settings confirmation expired or changed")
            self._settings_intent_path.unlink()
            _fsync_dir(self.state_root)
            return self._settings_commit_locked(snapshot)

    def settings_apply(self, expected_config_sha256: str, expected_generation: int,
                       expected_proposed_config_sha256: str,
                       patch: dict[str, str]) -> dict:
        """Root CLI numeric change; the Unix broker requires a one-use handle."""
        requested = _awg_patch(patch)
        plan = self.settings_plan(expected_config_sha256, expected_generation,
                                  requested)
        if (plan["configured_clients"] != 0 or
                plan["proposed_config_sha256"] != expected_proposed_config_sha256):
            _error("Amnezia settings preview changed or client profiles require reissue")
        with self._locked():
            snapshot = self._settings_candidate_locked(expected_config_sha256,
                                                       expected_generation,
                                                       expected_proposed_config_sha256,
                                                       requested)
            return self._settings_commit_locked(snapshot)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Root-only Amnezia AWG/WG peer administration")
    sub = parser.add_subparsers(dest="action", required=True)
    enroll = sub.add_parser("enroll", help="Pin a running container after inspecting its ID")
    enroll.add_argument("target", choices=TARGETS)
    enroll.add_argument("--confirm-container-id", required=True)
    enroll.add_argument("--confirm-image-id")
    enroll.add_argument("--confirm-config-sha256")
    enroll.add_argument("--confirm-table-sha256")
    add = sub.add_parser("add", help="Add an externally prepared public key; no client profile is created")
    add.add_argument("target", choices=TARGETS)
    add.add_argument("client")
    add.add_argument("public_key")
    add.add_argument("address")
    create_profile = sub.add_parser("create-profile", help="Create a peer and sealed client profile")
    create_profile.add_argument("target", choices=TARGETS)
    create_profile.add_argument("client")
    create_profile.add_argument("address")
    create_profile.add_argument("endpoint_host")
    create_profile.add_argument("recipient_public_key")
    create_profile.add_argument("--route", choices=("split", "full"), default="split")
    sealed_export = sub.add_parser("sealed-export", help="Re-encrypt a verified client profile")
    sealed_export.add_argument("target", choices=TARGETS)
    sealed_export.add_argument("client")
    sealed_export.add_argument("recipient_public_key")
    for action in ("revoke", "recover", "status", "settings-preview", "enroll-preview"):
        command = sub.add_parser(action)
        command.add_argument("target", choices=TARGETS)
        if action == "revoke":
            command.add_argument("client")
    settings_plan = sub.add_parser("settings-plan", help="Preview a CAS-pinned AWG3 change without applying it")
    settings_plan.add_argument("target", choices=("awg2",))
    settings_plan.add_argument("expected_config_sha256")
    settings_plan.add_argument("expected_generation", type=int)
    settings_plan.add_argument("parameters_json")
    settings_apply = sub.add_parser(
        "settings-apply", help="Apply reviewed AWG3 numeric settings only with zero clients")
    settings_apply.add_argument("target", choices=("awg2",))
    settings_apply.add_argument("expected_config_sha256")
    settings_apply.add_argument("expected_generation", type=int)
    settings_apply.add_argument("expected_proposed_config_sha256")
    settings_apply.add_argument("parameters_json")
    args = parser.parse_args(argv)
    admin = AmneziaAdmin(TARGETS[args.target])
    try:
        if args.action == "enroll":
            result = admin.enroll(args.confirm_container_id,
                                  confirm_image_id=args.confirm_image_id,
                                  confirm_config_sha256=args.confirm_config_sha256,
                                  confirm_table_sha256=args.confirm_table_sha256)
        elif args.action == "enroll-preview":
            result = admin.enroll_preview()
        elif args.action == "add":
            result = admin.add(args.client, args.public_key, args.address)
        elif args.action == "create-profile":
            result = admin.create_profile(args.client, args.address, args.endpoint_host,
                                          args.recipient_public_key, route=args.route)
        elif args.action == "sealed-export":
            result = admin.sealed_export(args.client, args.recipient_public_key)
        elif args.action == "revoke":
            result = admin.revoke(args.client)
        elif args.action == "recover":
            result = admin.recover()
        elif args.action == "settings-preview":
            result = admin.settings_preview()
        elif args.action == "settings-plan":
            try:
                patch = json.loads(args.parameters_json, object_pairs_hook=_unique_pairs)
            except (TypeError, ValueError, UnicodeError):
                _error("Invalid Amnezia settings proposal")
            result = admin.settings_plan(args.expected_config_sha256,
                                         args.expected_generation, patch)
        elif args.action == "settings-apply":
            try:
                patch = json.loads(args.parameters_json, object_pairs_hook=_unique_pairs)
            except (TypeError, ValueError, UnicodeError):
                _error("Invalid Amnezia settings proposal")
            result = admin.settings_apply(args.expected_config_sha256,
                                          args.expected_generation,
                                          args.expected_proposed_config_sha256, patch)
        else:
            result = admin.status()
    except AmneziaAdminError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception:
        print("Amnezia administration failed; inspect recovery state", file=sys.stderr)
        return 3
    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
