# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root-only, opt-in provisioning of a new AmneziaWG 3.1 server container.

The immutable official image is a userspace base, not a ready server. This
module supplies the compatible fixed layout, keys and startup script. It
never adopts or replaces an existing container and never logs key material.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Callable

from .amnezia_admin import AmneziaAdmin, AmneziaAdminError, PINNED_AWG_IMAGE, TARGETS


ROOT = Path("/var/lib/sovagrid-vpn/amnezia-provision")
CONTAINER = "amnezia-awg2"
LABEL = "io.sovagrid.amnezia-provision"
SCHEMA_VERSION = 1
MAX_STATE = 65536
HEX = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ProvisionError(RuntimeError):
    """A fixed, secret-free provisioning failure."""


def _fail(code: str) -> None:
    raise ProvisionError(code)


def _network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError):
        _fail("INVALID_SUBNET")
    private = (ipaddress.IPv4Network("10.0.0.0/8"),
               ipaddress.IPv4Network("172.16.0.0/12"),
               ipaddress.IPv4Network("192.168.0.0/16"))
    if (not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 24 or
            not any(network.subnet_of(block) for block in private)):
        _fail("INVALID_SUBNET")
    return network


def _port(value: object) -> int:
    if isinstance(value, bool):
        _fail("INVALID_PORT")
    try:
        port = int(value)
    except (TypeError, ValueError):
        _fail("INVALID_PORT")
    if not 1 <= port <= 65535 or str(port) != str(value):
        _fail("INVALID_PORT")
    return port


def _route(value: str) -> str:
    if value not in ("split", "full"):
        _fail("INVALID_ROUTE")
    return value


def _udp_port_available(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False


def _secure_dir(path: Path, owner: int, *, create: bool = False, private: bool = True) -> None:
    if create:
        try:
            path.mkdir(mode=0o700)
            os.chown(path, owner, 0 if owner == 0 else os.getegid())
        except FileExistsError:
            pass
    try:
        info = path.lstat()
    except OSError:
        _fail("UNSAFE_STATE")
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or
            info.st_mode & (0o077 if private else 0o022)):
        _fail("UNSAFE_STATE")


def _secure_file(path: Path, owner: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                    info.st_size > MAX_STATE):
                _fail("UNSAFE_STATE")
            raw = os.read(fd, MAX_STATE + 1)
        finally:
            os.close(fd)
    except OSError:
        _fail("UNSAFE_STATE")
    if len(raw) > MAX_STATE:
        _fail("UNSAFE_STATE")
    return raw


def _pairs(items: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, item in items:
        if key in value:
            _fail("UNSAFE_STATE")
        value[key] = item
    return value


def _read_state(path: Path, owner: int) -> dict | None:
    if not path.exists() and not path.is_symlink():
        return None
    try:
        value = json.loads(_secure_file(path, owner), object_pairs_hook=_pairs)
    except (ValueError, UnicodeError):
        _fail("UNSAFE_STATE")
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        _fail("UNSAFE_STATE")
    return value


def _write_state(path: Path, value: dict, owner: int, *, new: bool = True) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(raw) > MAX_STATE or (path.exists() or path.is_symlink()) and new:
        _fail("UNSAFE_STATE")
    if not new:
        _secure_file(path, owner)
    fd, temporary = tempfile.mkstemp(prefix=".provision-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        os.fchown(fd, owner, 0 if owner == 0 else os.getegid())
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if new:
            os.link(temporary, path)
            os.unlink(temporary)
        else:
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
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _remove_state(path: Path, owner: int) -> None:
    if path.exists() or path.is_symlink():
        _secure_file(path, owner)
        path.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def _key() -> str:
    # X25519 private keys use the same clamping as `awg genkey`.
    raw = bytearray(secrets.token_bytes(32))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return base64.b64encode(raw).decode("ascii")


def _random_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _headers() -> tuple[int, int, int, int]:
    values: set[int] = set()
    while len(values) != 4:
        # AWG accepts unsigned 32-bit message identifiers. Keep these far
        # from the conventional 1..4 defaults and unique per server.
        values.add(0x10000000 + secrets.randbelow(0xD0000000))
    return tuple(values)


def _bundle(network: ipaddress.IPv4Network, port: int, route: str = "full") -> dict[str, bytes]:
    route = _route(route)
    address = str(network.network_address + 1)
    h1, h2, h3, h4 = _headers()
    config = (f"[Interface]\nAddress = {address}/24\nPrivateKey = {_key()}\n"
              f"ListenPort = {port}\nJc = 3\nJmin = 10\nJmax = 30\n"
              "S1 = 76\nS2 = 47\nS3 = 33\nS4 = 12\n"
              f"H1 = {h1}\nH2 = {h2}\nH3 = {h3}\nH4 = {h4}\n"
              f"HeaderProtectionKey = {_random_key()}\n"
              "ContentPaddingAddition = 10-100\nRandomTrailers = on\n"
              "DisableCookies = on\n").encode("ascii")
    start = ("#!/bin/sh\nset -eu\numask 077\n"
             "amneziawg-go awg0 >/run/amneziawg-go.log 2>&1 &\n"
             "for attempt in $(seq 1 40); do\n"
             "  if awg show awg0 >/dev/null 2>&1; then break; fi\n"
             "  sleep 0.25\ndone\n"
             "awg show awg0 >/dev/null\n"
             "bash -c 'awg setconf awg0 <(awg-quick strip /opt/amnezia/awg/awg0.conf)' >/dev/null 2>&1\n"
             f"ip addr add {address}/24 dev awg0\n"
             "ip link set awg0 up\n"
             + ("iptables -A FORWARD -i awg0 -j ACCEPT\n"
                "iptables -A FORWARD -o awg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
                f"iptables -t nat -A POSTROUTING -s {network} -o eth0 -j MASQUERADE\n"
                if route == "full" else "")
             + "while :; do sleep 60; done\n").encode("ascii")
    return {
        "opt/amnezia/awg/awg0.conf": config,
        "opt/amnezia/awg/clientsTable": b"[]\n",
        "opt/amnezia/awg/wireguard_psk.key": (_random_key() + "\n").encode("ascii"),
        "opt/amnezia/start.sh": start,
    }


def _tar_bundle(bundle: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name in ("opt", "opt/amnezia", "opt/amnezia/awg"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o700
            info.uid = info.gid = 0
            archive.addfile(info)
        for name, contents in bundle.items():
            info = tarfile.TarInfo(name)
            info.size = len(contents)
            info.mode = 0o700 if name.endswith("start.sh") else 0o600
            info.uid = info.gid = 0
            archive.addfile(info, io.BytesIO(contents))
    return output.getvalue()


class Provisioner:
    def __init__(self, *, state_root: Path = ROOT, runner: Callable = subprocess.run,
                 admin_factory: Callable = lambda: AmneziaAdmin(TARGETS["awg2"]),
                 require_root: bool = True,
                 tun_available: Callable[[], bool] = lambda: Path("/dev/net/tun").exists(),
                 udp_available: Callable[[int], bool] = _udp_port_available):
        self.state_root = Path(state_root)
        self.runner = runner
        self.admin_factory = admin_factory
        self.require_root = require_root
        self.tun_available = tun_available
        self.udp_available = udp_available
        if not self.state_root.is_absolute():
            _fail("UNSAFE_STATE")

    @property
    def owner(self) -> int:
        return 0 if self.require_root else os.geteuid()

    def _root(self) -> None:
        if self.require_root and os.geteuid() != 0:
            _fail("ROOT_REQUIRED")

    @contextmanager
    def _locked(self):
        self._root()
        _secure_dir(self.state_root.parent, self.owner, create=True, private=False)
        _secure_dir(self.state_root, self.owner, create=True)
        path = self.state_root / ".lock"
        try:
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except OSError:
            _fail("UNSAFE_STATE")
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                _fail("UNSAFE_STATE")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _command(self, *argv: str, input: bytes | None = None, timeout: int = 20,
                 limit: int = 65536, accepted: tuple[int, ...] = (0,)) -> tuple[int, bytes]:
        try:
            result = self.runner(tuple(argv), input=input, capture_output=True,
                                 timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            _fail("DOCKER_UNAVAILABLE")
        if result.returncode not in accepted or not isinstance(result.stdout, bytes):
            _fail("DOCKER_OPERATION_FAILED")
        if len(result.stdout) > limit:
            _fail("DOCKER_RESPONSE_TOO_LARGE")
        return result.returncode, result.stdout

    def _docker_platform(self) -> str:
        _, raw = self._command("docker", "info", "--format", "{{.OSType}} {{.Architecture}}",
                               limit=128)
        return raw.decode("ascii", "strict").strip()

    def _image(self) -> str | None:
        code, raw = self._command("docker", "image", "inspect", "--format",
                                  "{{.Id}} {{.Os}} {{.Architecture}}", PINNED_AWG_IMAGE,
                                  accepted=(0, 1), limit=256)
        if code == 1:
            return None
        fields = raw.decode("ascii", "strict").strip().split()
        if len(fields) != 3 or not IMAGE_ID.fullmatch(fields[0]) or fields[1:] != ["linux", "amd64"]:
            _fail("IMAGE_IDENTITY_INVALID")
        return fields[0]

    def _container(self) -> dict | None:
        fmt = '{{.Id}} {{.Image}} {{.Config.Image}} {{index .Config.Labels "' + LABEL + '"}} {{.State.Running}}'
        code, raw = self._command("docker", "container", "inspect", "--format", fmt,
                                  CONTAINER, accepted=(0, 1), limit=512)
        if code == 1:
            return None
        parts = raw.decode("ascii", "strict").strip().split()
        if (len(parts) != 5 or not HEX.fullmatch(parts[0]) or
                not IMAGE_ID.fullmatch(parts[1]) or parts[4] not in ("true", "false")):
            _fail("CONTAINER_IDENTITY_INVALID")
        return {"id": parts[0], "image_id": parts[1], "image_ref": parts[2],
                "nonce": parts[3], "running": parts[4] == "true"}

    def _container_file(self, container_id: str, name: str) -> bytes:
        _, raw = self._command("docker", "cp", f"{container_id}:/{name}", "-",
                               limit=MAX_STATE)
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                members = archive.getmembers()
                if (len(members) != 1 or not members[0].isfile() or
                        Path(members[0].name).name != Path(name).name or
                        members[0].size > MAX_STATE):
                    _fail("MANUAL_RECOVERY_REQUIRED")
                extracted = archive.extractfile(members[0])
                if extracted is None:
                    _fail("MANUAL_RECOVERY_REQUIRED")
                return extracted.read(MAX_STATE + 1)
        except (tarfile.TarError, OSError):
            _fail("MANUAL_RECOVERY_REQUIRED")

    def _observe(self, port: int, subnet: str, route: str = "full") -> dict:
        self._root()
        network = _network(subnet)
        port = _port(port)
        route = _route(route)
        if self.state_root.exists() or self.state_root.is_symlink():
            _secure_dir(self.state_root.parent, self.owner, private=False)
            _secure_dir(self.state_root, self.owner)
        pending = _read_state(self.state_root / "pending.json", self.owner)
        state = _read_state(self.state_root / "state.json", self.owner)
        platform = self._docker_platform()
        image_id = self._image()
        container = self._container()
        reason = None
        if platform not in ("linux x86_64", "linux amd64"):
            reason = "UNSUPPORTED_PLATFORM"
        elif pending:
            reason = "RECOVERY_REQUIRED"
        elif state:
            reason = "ALREADY_INSTALLED"
        elif container:
            reason = "CONTAINER_EXISTS"
        elif not self.tun_available():
            reason = "TUN_UNAVAILABLE"
        elif not self.udp_available(port):
            reason = "UDP_PORT_BUSY"
        revision_body = {"schema_version": SCHEMA_VERSION, "image_ref": PINNED_AWG_IMAGE,
                         "image_id": image_id, "container_id": container["id"] if container else None,
                         "state": bool(state), "pending": bool(pending),
                         "platform": platform, "port": port, "subnet": str(network),
                         "route_mode": route}
        revision = hashlib.sha256(json.dumps(revision_body, sort_keys=True,
                                              separators=(",", ":")).encode()).hexdigest()
        result = {"schema_version": SCHEMA_VERSION, "action": "preview", "writes": False,
                  "target": "awg2", "container": CONTAINER,
                  "listen_port": port, "subnet": str(network), "route_mode": route,
                  "image_digest": PINNED_AWG_IMAGE.split("@", 1)[1],
                  "image_cached": image_id is not None,
                  "state_revision": revision, "can_apply": reason is None}
        if reason:
            result["reason"] = reason
        return result

    def preview(self, port: int, subnet: str, route: str = "full") -> dict:
        try:
            return self._observe(port, subnet, route)
        except ProvisionError as exc:
            return {"schema_version": SCHEMA_VERSION, "action": "preview", "writes": False,
                    "target": "awg2", "container": CONTAINER,
                    "can_apply": False, "reason": str(exc)}

    def _health(self, expected: dict) -> dict:
        admin = self.admin_factory()
        try:
            result = admin.enroll_preview()
            # A successful `awg show dump` verifies the peer set, private key
            # and port. AWG3's obfuscation fields are separate selectors and
            # must also match the pinned config before claiming readiness.
            with admin._locked():
                identity = admin._identity()
                config_raw, table_raw, config, *_ = admin._snapshot()
                if (identity != (expected["container_id"], expected["image_id"]) or
                        hashlib.sha256(config_raw).hexdigest() != expected["config_sha256"] or
                        hashlib.sha256(table_raw).hexdigest() != expected["table_sha256"]):
                    _fail("AWG_RUNTIME_UNVERIFIED")
                admin._verify_awg_runtime_parameters(config.interface_raw, identity)
        except AmneziaAdminError:
            _fail("AWG_RUNTIME_UNVERIFIED")
        if (result.get("target") != "awg2" or result.get("container_id") != expected["container_id"] or
                result.get("image_id") != expected["image_id"] or
                result.get("config_sha256") != expected["config_sha256"] or
                result.get("table_sha256") != expected["table_sha256"] or
                result.get("configured_clients") != 0 or result.get("listen_port") != expected["port"] or
                result.get("interface") != "awg0"):
            _fail("AWG_RUNTIME_UNVERIFIED")
        return result

    def _finalize(self, pending: dict) -> dict:
        self._health(pending)
        self._command("docker", "update", "--restart", "unless-stopped",
                      pending["container_id"], limit=128)
        _, policy = self._command("docker", "container", "inspect", "--format",
                                  "{{.HostConfig.RestartPolicy.Name}}",
                                  pending["container_id"], limit=64)
        if policy.strip() != b"unless-stopped":
            _fail("DOCKER_OPERATION_FAILED")
        state_path = self.state_root / "state.json"
        final_state = {**pending, "installed": True}
        existing = _read_state(state_path, self.owner)
        if existing is None:
            _write_state(state_path, final_state, self.owner)
        elif existing != final_state:
            _fail("UNSAFE_STATE")
        _remove_state(self.state_root / "pending.json", self.owner)
        return {"schema_version": SCHEMA_VERSION, "action": "installed", "target": "awg2",
                "container": CONTAINER, "container_id": pending["container_id"],
                "image_id": pending["image_id"], "listen_port": pending["port"],
                "subnet": pending["subnet"], "route_mode": pending["route_mode"],
                "recovery_required": False}

    def apply(self, port: int, subnet: str, expected_state: str, *, confirm: bool,
              route: str = "full") -> dict:
        if not confirm:
            _fail("CONFIRMATION_REQUIRED")
        if not isinstance(expected_state, str) or not HEX.fullmatch(expected_state):
            _fail("INVALID_REVISION")
        with self._locked():
            preview = self._observe(port, subnet, route)
            if "state_revision" not in preview:
                _fail(preview["reason"])
            if preview["state_revision"] != expected_state:
                _fail("PREVIEW_STALE")
            if not preview["can_apply"]:
                _fail(preview["reason"])
            network = _network(subnet)
            port = _port(port)
            route = _route(route)
            # Pull by the fixed registry digest, then verify the local image
            # ID. No mutable tag is ever executed or replaced.
            self._command("docker", "pull", "--platform", "linux/amd64", PINNED_AWG_IMAGE,
                          timeout=180, limit=4096)
            image_id = self._image()
            if image_id is None:
                _fail("IMAGE_IDENTITY_INVALID")
            if self._container() is not None:
                _fail("CONTAINER_EXISTS")
            bundle = _bundle(network, port, route)
            nonce = secrets.token_hex(16)
            pending = {"schema_version": SCHEMA_VERSION, "nonce": nonce,
                       "image_ref": PINNED_AWG_IMAGE, "image_id": image_id,
                       "container_id": None, "port": port, "subnet": str(network),
                       "route_mode": route,
                       "config_sha256": hashlib.sha256(bundle["opt/amnezia/awg/awg0.conf"]).hexdigest(),
                       "table_sha256": hashlib.sha256(bundle["opt/amnezia/awg/clientsTable"]).hexdigest(),
                       "files": {name: base64.b64encode(data).decode("ascii")
                                 for name, data in bundle.items()}}
            pending_path = self.state_root / "pending.json"
            _write_state(pending_path, pending, self.owner)
            create = ("docker", "create", "--platform", "linux/amd64", "--pull", "never",
                      "--name", CONTAINER, "--label", f"{LABEL}={nonce}",
                      "--restart", "no", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
                      "--device", "/dev/net/tun", "--pids-limit", "64", "--memory", "256m",
                      "--security-opt", "no-new-privileges", "--sysctl", "net.ipv4.ip_forward=1",
                      "--sysctl", "net.ipv4.conf.all.src_valid_mark=1",
                      "-p", f"{port}:{port}/udp", "--entrypoint", "/bin/sh",
                      PINNED_AWG_IMAGE, "/opt/amnezia/start.sh")
            _, raw = self._command(*create, limit=128)
            container_id = raw.decode("ascii", "strict").strip()
            if not HEX.fullmatch(container_id):
                _fail("CONTAINER_IDENTITY_INVALID")
            pending["container_id"] = container_id
            _write_state(pending_path, pending, self.owner, new=False)
            observed = self._container()
            if (not observed or observed["id"] != container_id or
                    observed["image_id"] != image_id or observed["nonce"] != nonce or
                    observed["image_ref"] not in (PINNED_AWG_IMAGE,
                                                   "docker.io/" + PINNED_AWG_IMAGE) or
                    observed["running"]):
                _fail("CONTAINER_IDENTITY_INVALID")
            self._command("docker", "cp", "-", f"{container_id}:/",
                          input=_tar_bundle(bundle), timeout=20, limit=1024)
            self._command("docker", "start", container_id, limit=128)
            for _ in range(40):
                try:
                    return self._finalize(pending)
                except ProvisionError as exc:
                    if str(exc) != "AWG_RUNTIME_UNVERIFIED":
                        raise
                    time.sleep(0.25)
            _fail("AWG_RUNTIME_UNVERIFIED")

    def recover(self) -> dict:
        with self._locked():
            pending = _read_state(self.state_root / "pending.json", self.owner)
            if pending is None:
                return {"schema_version": SCHEMA_VERSION, "action": "recovered",
                        "changed": False, "installed": _read_state(
                            self.state_root / "state.json", self.owner) is not None}
            if (pending.get("image_ref") != PINNED_AWG_IMAGE or
                    not IMAGE_ID.fullmatch(str(pending.get("image_id", ""))) or
                    not re.fullmatch(r"[0-9a-f]{32}", str(pending.get("nonce", ""))) or
                    not isinstance(pending.get("files"), dict) or
                    set(pending["files"]) != {
                        "opt/amnezia/awg/awg0.conf", "opt/amnezia/awg/clientsTable",
                        "opt/amnezia/awg/wireguard_psk.key", "opt/amnezia/start.sh"}):
                _fail("UNSAFE_STATE")
            observed = self._container()
            if observed is None:
                _remove_state(self.state_root / "pending.json", self.owner)
                return {"schema_version": SCHEMA_VERSION, "action": "recovered",
                        "changed": True, "installed": False}
            if pending.get("container_id") is None and observed["nonce"] == pending["nonce"]:
                pending["container_id"] = observed["id"]
                _write_state(self.state_root / "pending.json", pending, self.owner, new=False)
            if (observed["id"] != pending.get("container_id") or
                    observed["image_id"] != pending["image_id"] or
                    observed["nonce"] != pending["nonce"] or
                    observed["image_ref"] not in (PINNED_AWG_IMAGE,
                                                  "docker.io/" + PINNED_AWG_IMAGE)):
                _fail("CONTAINER_IDENTITY_INVALID")
            if observed["running"]:
                result = self._finalize(pending)
                return {"schema_version": SCHEMA_VERSION, "action": "recovered",
                        "changed": True, "installed": True,
                        "container_id": result["container_id"]}
            # A stopped but otherwise untouched container can be removed by
            # exact ID. Never force-remove a running container or one whose
            # layer contains unknown changes or established admin state.
            admin_state = Path("/var/lib/sovagrid-vpn/amnezia-admin/awg2.json")
            if admin_state.exists() or admin_state.is_symlink():
                _fail("MANUAL_RECOVERY_REQUIRED")
            _, raw = self._command("docker", "diff", observed["id"], limit=8192)
            allowed = {"/opt", "/opt/amnezia", "/opt/amnezia/awg",
                       "/opt/amnezia/start.sh", "/opt/amnezia/awg/awg0.conf",
                       "/opt/amnezia/awg/clientsTable",
                       "/opt/amnezia/awg/wireguard_psk.key", "/run",
                       "/run/amneziawg", "/run/amneziawg/awg0.sock",
                       "/run/amneziawg-go.log"}
            try:
                changed = {line[2:] for line in raw.decode("ascii").splitlines()
                           if line.startswith(("A ", "C ", "D "))}
            except UnicodeDecodeError:
                _fail("MANUAL_RECOVERY_REQUIRED")
            if changed - allowed:
                _fail("MANUAL_RECOVERY_REQUIRED")
            for name, encoded in pending["files"].items():
                if "/" + name not in changed:
                    continue
                if not isinstance(encoded, str):
                    _fail("UNSAFE_STATE")
                try:
                    expected = base64.b64decode(encoded, validate=True)
                except (ValueError, base64.binascii.Error):
                    _fail("UNSAFE_STATE")
                observed_file = self._container_file(observed["id"], name)
                if observed_file != expected:
                    _fail("MANUAL_RECOVERY_REQUIRED")
            self._command("docker", "rm", observed["id"], limit=128)
            _remove_state(self.state_root / "pending.json", self.owner)
            return {"schema_version": SCHEMA_VERSION, "action": "recovered",
                    "changed": True, "installed": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provision a new SovaGrid AmneziaWG server")
    commands = parser.add_subparsers(dest="action", required=True)
    preview = commands.add_parser("preview")
    preview.add_argument("--port", required=True)
    preview.add_argument("--subnet", required=True)
    preview.add_argument("--route", choices=("split", "full"), default="full")
    apply = commands.add_parser("apply")
    apply.add_argument("--port", required=True)
    apply.add_argument("--subnet", required=True)
    apply.add_argument("--route", choices=("split", "full"), default="full")
    apply.add_argument("--expected-state", required=True)
    apply.add_argument("--confirm", action="store_true")
    commands.add_parser("recover")
    args = parser.parse_args(argv)
    provisioner = Provisioner()
    try:
        if args.action == "preview":
            result = provisioner.preview(args.port, args.subnet, args.route)
        elif args.action == "apply":
            result = provisioner.apply(args.port, args.subnet, args.expected_state,
                                       confirm=args.confirm, route=args.route)
        else:
            result = provisioner.recover()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except ProvisionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception:
        print("AMNEZIA_PROVISION_FAILED", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
