# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root-owned, opt-in WireGuard instances. Existing VPNs are never adopted.

Only this module's state directory and the exact wg-quick symlink it creates
may be changed. The read-only Amnezia inventory has no dependency on it.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tempfile
from typing import Callable, Iterator

from .proposal import PRIVATE_NETWORKS


STATE_ROOT = Path("/var/lib/sovagrid-vpn")
WIREGUARD_DIR = Path("/etc/wireguard")
NAME = re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
CLIENT = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
DNS_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z")
KEY = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
MAX_STATE_BYTES = 256 * 1024


class ManagedVpnError(RuntimeError):
    """A safe, public error with no command output or key material."""


def validate_name(value: str) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ManagedVpnError("Instance name must be 2–32 lowercase letters, digits or hyphens")
    return value


def validate_client(value: str) -> str:
    if not isinstance(value, str) or not CLIENT.fullmatch(value):
        raise ManagedVpnError("Client name must be 1–32 lowercase letters, digits, _ or -")
    return value


def validate_endpoint(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ManagedVpnError("Endpoint must be an IPv4 address or DNS name")
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        pass
    if all(DNS_LABEL.fullmatch(label) for label in value.split(".")) and "." in value:
        return value.lower()
    raise ManagedVpnError("Endpoint must be an IPv4 address or DNS name")


def validate_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.IPv4Network(value, strict=True)
    except (ValueError, TypeError) as exc:
        raise ManagedVpnError("Subnet must be a canonical IPv4 CIDR") from exc
    if not 24 <= network.prefixlen <= 30 or not any(network.subnet_of(parent) for parent in PRIVATE_NETWORKS):
        raise ManagedVpnError("Subnet must be an RFC1918 IPv4 /24–/30")
    return network


def interface_name(name: str) -> str:
    return "sg" + hashlib.sha256(validate_name(name).encode("ascii")).hexdigest()[:11]


def _key(value: str) -> str:
    if not isinstance(value, str) or not KEY.fullmatch(value):
        raise ManagedVpnError("WireGuard returned an invalid key")
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError("wrong key length")
    except (ValueError, base64.binascii.Error) as exc:
        raise ManagedVpnError("WireGuard returned an invalid key") from exc
    return value


def _server_config(state: dict) -> bytes:
    network = validate_network(state["subnet"])
    server_ip = next(network.hosts())
    lines = [
        "# SovaGrid managed; edit with sovagrid_vpn.manage only",
        "[Interface]", f"Address = {server_ip}/{network.prefixlen}",
        f"ListenPort = {state['port']}", f"PrivateKey = {state['server_private_key']}", "",
    ]
    for name, client in sorted(state["clients"].items()):
        lines.extend([f"# client: {name}", "[Peer]", f"PublicKey = {client['public_key']}",
                      f"PresharedKey = {client['preshared_key']}",
                      f"AllowedIPs = {client['address']}/32", ""])
    return ("\n".join(lines) + "\n").encode("ascii")


def _client_config(state: dict, client: dict) -> bytes:
    lines = ["# SovaGrid client profile; keep this file private", "[Interface]",
             f"PrivateKey = {client['private_key']}", f"Address = {client['address']}/32", "",
             "[Peer]", f"PublicKey = {state['server_public_key']}",
             f"PresharedKey = {client['preshared_key']}",
             f"Endpoint = {state['endpoint']}:{state['port']}",
             f"AllowedIPs = {state['subnet']}", "PersistentKeepalive = 25", ""]
    return ("\n".join(lines) + "\n").encode("ascii")


def _regular_private(path: Path, *, uid: int | None) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
        raise ManagedVpnError("Managed file has unsafe type, links or permissions")
    if uid is not None and info.st_uid != uid:
        raise ManagedVpnError("Managed file has an unexpected owner")


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _directory(path: Path, *, uid: int | None, private: bool = False) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & (0o077 if private else 0o022):
        raise ManagedVpnError("Managed directory has unsafe type or permissions")
    if uid is not None and info.st_uid != uid:
        raise ManagedVpnError("Managed directory has an unexpected owner")


class ManagedWireGuard:
    """All public methods serialize through one lock and require root by default."""

    def __init__(self, *, state_root: Path = STATE_ROOT, wireguard_dir: Path = WIREGUARD_DIR,
                 runner: Callable = subprocess.run, require_root: bool = True,
                 check_network: bool = True):
        self.state_root = Path(state_root)
        self.wireguard_dir = Path(wireguard_dir)
        self.runner = runner
        self.require_root = require_root
        self.check_network = check_network
        if not self.state_root.is_absolute() or not self.wireguard_dir.is_absolute():
            raise ManagedVpnError("Managed directories must be absolute")

    @property
    def _uid(self) -> int | None:
        return 0 if self.require_root else None

    def _require_root(self) -> None:
        if self.require_root and os.geteuid() != 0:
            raise ManagedVpnError("This operation requires root")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._require_root()
        parent = self.state_root.parent
        _directory(parent, uid=self._uid)
        try:
            self.state_root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        _directory(self.state_root, uid=self._uid, private=True)
        lock = self.state_root / ".lock"
        flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
        fd = os.open(lock, flags, 0o600)
        try:
            _regular_private(lock, uid=self._uid)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _run(self, args: tuple[str, ...], *, input: str | None = None, timeout: int = 10) -> subprocess.CompletedProcess:
        try:
            result = self.runner(args, input=input, capture_output=True, text=True,
                                 timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ManagedVpnError(f"Command {args[0]} unavailable or timed out") from exc
        if result.returncode != 0:
            raise ManagedVpnError(f"Command {args[0]} failed")
        return result

    def _keypair(self) -> tuple[str, str]:
        private = _key(self._run(("wg", "genkey")).stdout.strip())
        public = _key(self._run(("wg", "pubkey"), input=private + "\n").stdout.strip())
        return private, public

    def _path(self, name: str) -> Path:
        return self.state_root / validate_name(name)

    def _read(self, path: Path) -> bytes:
        _regular_private(path, uid=self._uid)
        if path.stat().st_size > MAX_STATE_BYTES:
            raise ManagedVpnError("Managed file exceeds size limit")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            return os.read(fd, MAX_STATE_BYTES + 1)
        finally:
            os.close(fd)

    def _write(self, path: Path, data: bytes, *, new: bool = False) -> None:
        if len(data) > MAX_STATE_BYTES:
            raise ManagedVpnError("Managed file exceeds size limit")
        if path.exists() or path.is_symlink():
            if new:
                raise ManagedVpnError("Managed file already exists")
            _regular_private(path, uid=self._uid)
        elif not new:
            raise ManagedVpnError("Managed file is missing")
        fd, temporary = tempfile.mkstemp(prefix=".new-", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as output:
                fd = -1
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            if new:
                # link() creates the destination atomically without replacing a
                # competing file or following a symlink.
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

    def _unlink(self, path: Path) -> None:
        path.unlink()
        _fsync_dir(path.parent)

    @staticmethod
    def _state_bytes(state: dict) -> bytes:
        return (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")

    def _validate_state(self, state: dict, name: str) -> None:
        if not isinstance(state, dict) or state.get("schema_version") != 1 or state.get("name") != name:
            raise ManagedVpnError("Managed state is invalid")
        if state.get("interface") != interface_name(name) or state.get("endpoint") != validate_endpoint(state.get("endpoint")):
            raise ManagedVpnError("Managed state is invalid")
        network = validate_network(state.get("subnet"))
        port = state.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ManagedVpnError("Managed state is invalid")
        for field in ("server_private_key", "server_public_key"):
            _key(state.get(field))
        clients = state.get("clients")
        if not isinstance(clients, dict):
            raise ManagedVpnError("Managed state is invalid")
        used = set()
        for client_name, client in clients.items():
            validate_client(client_name)
            if not isinstance(client, dict):
                raise ManagedVpnError("Managed state is invalid")
            for field in ("private_key", "public_key", "preshared_key"):
                _key(client.get(field))
            try:
                address = ipaddress.IPv4Address(client.get("address"))
            except (ipaddress.AddressValueError, TypeError) as exc:
                raise ManagedVpnError("Managed client address is invalid") from exc
            if (address not in network or address in (network.network_address, network.broadcast_address,
                                                      next(network.hosts())) or address in used or
                    not isinstance(client.get("address"), str) or str(address) != client["address"]):
                raise ManagedVpnError("Managed client address is invalid")
            used.add(address)

    def _state(self, name: str) -> dict:
        path = self._path(name)
        _directory(path, uid=self._uid, private=True)
        if (path / "transaction.json").exists() or (path / "transaction.json").is_symlink():
            raise ManagedVpnError("Pending VPN transaction; retry the operation or run recover")
        try:
            state = json.loads(self._read(path / "state.json"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ManagedVpnError("Managed state is invalid") from exc
        self._validate_state(state, name)
        clients = state["clients"]
        client_dir = path / "clients"
        _directory(client_dir, uid=self._uid, private=True)
        expected_profiles = {f"{key}.conf" for key in clients}
        if {item.name for item in client_dir.iterdir()} != expected_profiles:
            raise ManagedVpnError("Managed client profile inventory does not match state")
        for client_name, client in clients.items():
            if self._read(client_dir / f"{client_name}.conf") != _client_config(state, client):
                raise ManagedVpnError("Managed client profile does not match state")
        if self._read(path / "server.conf") != _server_config(state):
            raise ManagedVpnError("Managed server configuration does not match state")
        return state

    def _save_state(self, state: dict, *, new: bool = False) -> None:
        self._write(self._path(state["name"]) / "state.json", self._state_bytes(state), new=new)

    def _preflight(self, network: ipaddress.IPv4Network, port: int, iface: str) -> None:
        if not self.check_network:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("0.0.0.0", port))
        except OSError as exc:
            raise ManagedVpnError("UDP port is already in use") from exc
        routes = self._run(("ip", "-j", "route", "show", "table", "all")).stdout
        addresses = self._run(("ip", "-j", "address", "show")).stdout
        try:
            route_rows = json.loads(routes)
            address_rows = json.loads(addresses)
            if not isinstance(route_rows, list) or not isinstance(address_rows, list):
                raise ValueError("wrong shape")
            existing = []
            for row in route_rows:
                if not isinstance(row, dict):
                    raise ValueError("wrong shape")
                dst = row.get("dst", "default")
                if dst != "default":
                    try:
                        existing.append(ipaddress.IPv4Network(dst, strict=False))
                    except ipaddress.AddressValueError:
                        pass  # IPv6 route
            for row in address_rows:
                for address in row.get("addr_info", []):
                    if address.get("family") == "inet":
                        existing.append(ipaddress.IPv4Network(
                            f"{address['local']}/{address['prefixlen']}", strict=False))
        except (ValueError, TypeError, KeyError) as exc:
            raise ManagedVpnError("Cannot validate host routes and addresses") from exc
        if any(network.overlaps(item) for item in existing):
            raise ManagedVpnError("VPN subnet overlaps a host route or address")
        link = self.runner(("ip", "link", "show", "dev", iface), capture_output=True,
                           text=True, timeout=10, check=False)
        if link.returncode == 0:
            raise ManagedVpnError("WireGuard interface name is already in use")
        if link.returncode != 1:
            raise ManagedVpnError("Cannot validate interface name")
        if shutil.which("docker"):
            rows = self._run(("docker", "container", "ls", "--all", "--format", "{{json .}}")).stdout
            if len(rows) > MAX_STATE_BYTES:
                raise ManagedVpnError("Docker inventory exceeds size limit")
            for line in rows.splitlines():
                try:
                    item = json.loads(line)
                    published = item.get("Ports", "")
                except (ValueError, AttributeError) as exc:
                    raise ManagedVpnError("Docker inventory is invalid") from exc
                if isinstance(published, str):
                    # Docker's human-readable Port field includes host mappings.
                    for start, end in re.findall(
                            r"(?:^|[, ])(?:\S+:)?(\d{1,5})(?:-(\d{1,5}))?->\d{1,5}(?:-\d{1,5})?/udp",
                            published):
                        if int(start) <= port <= int(end or start):
                            raise ManagedVpnError("UDP port is published by Docker")
            ids = self._run(("docker", "network", "ls", "-q")).stdout.splitlines()
            if len(ids) > 512 or any(not re.fullmatch(r"[a-f0-9]{12,64}", item) for item in ids):
                raise ManagedVpnError("Docker network inventory is invalid")
            if ids:
                configs = self._run(("docker", "network", "inspect", "--format", "{{json .IPAM.Config}}", *ids)).stdout
                for line in configs.splitlines():
                    try:
                        entries = json.loads(line) or []
                        for entry in entries:
                            subnet = entry.get("Subnet")
                            candidate = ipaddress.ip_network(subnet, strict=False) if subnet else None
                            if isinstance(candidate, ipaddress.IPv4Network) and network.overlaps(candidate):
                                raise ManagedVpnError("VPN subnet overlaps a Docker network")
                    except (ValueError, AttributeError, TypeError) as exc:
                        raise ManagedVpnError("Docker network inventory is invalid") from exc

    def create(self, name: str, port: int, subnet: str, endpoint: str) -> dict:
        name = validate_name(name)
        endpoint = validate_endpoint(endpoint)
        network = validate_network(subnet)
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ManagedVpnError("UDP port must be between 1024 and 65535")
        with self._locked():
            iface = interface_name(name)
            interface_config = self.wireguard_dir / f"{iface}.conf"
            if self._path(name).exists() or interface_config.exists() or interface_config.is_symlink():
                raise ManagedVpnError("Instance or interface configuration already exists")
            for item in self.state_root.iterdir():
                if item.is_dir() and (item / "state.json").exists():
                    other = self._state(item.name)
                    if other["interface"] == iface or other["port"] == port or network.overlaps(validate_network(other["subnet"])):
                        raise ManagedVpnError("Instance interface, UDP port or subnet conflicts with SovaGrid")
            self._preflight(network, port, iface)
            private, public = self._keypair()
            state = {"schema_version": 1, "name": name, "interface": iface, "port": port,
                     "subnet": str(network), "endpoint": endpoint,
                     "server_private_key": private, "server_public_key": public, "clients": {}}
            path = self._path(name)
            path.mkdir(mode=0o700)
            try:
                (path / "clients").mkdir(mode=0o700)
                self._write(path / "server.conf", _server_config(state), new=True)
                self._save_state(state, new=True)
            except Exception:
                shutil.rmtree(path)
                raise
            return self._public(state)

    def _managed_link(self, state: dict, *, required: bool) -> Path:
        link = self.wireguard_dir / f"{state['interface']}.conf"
        if link.is_symlink():
            if os.readlink(link) != str(self._path(state["name"]) / "server.conf"):
                raise ManagedVpnError("Interface configuration is not owned by SovaGrid")
        elif required or link.exists():
            raise ManagedVpnError("Interface configuration is not owned by SovaGrid")
        return link

    def _unit(self, state: dict) -> str:
        return f"wg-quick@{state['interface']}.service"

    def _active(self, state: dict) -> bool:
        result = self.runner(("systemctl", "is-active", "--quiet", self._unit(state)),
                             capture_output=True, text=True, timeout=10, check=False)
        if result.returncode not in (0, 3, 4):
            raise ManagedVpnError("Cannot determine WireGuard service state")
        return result.returncode == 0

    def _interface_present(self, state: dict) -> bool:
        try:
            result = self.runner(("ip", "link", "show", "dev", state["interface"]),
                                 capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ManagedVpnError("Cannot determine WireGuard interface state") from exc
        if result.returncode not in (0, 1):
            raise ManagedVpnError("Cannot determine WireGuard interface state")
        return result.returncode == 0

    @staticmethod
    def _dump_matches(raw: str, state: dict) -> bool:
        """Compare all stable wg settings; endpoints/counters are dynamic."""
        if not isinstance(raw, str) or len(raw) > MAX_STATE_BYTES:
            return False
        rows = [line.split("\t") for line in raw.splitlines()]
        if not rows or len(rows[0]) != 4:
            return False
        header = rows[0]
        if (header[0] != state["server_private_key"] or
                header[1] != state["server_public_key"] or
                header[2] != str(state["port"]) or header[3] not in ("off", "0")):
            return False
        expected = {item["public_key"]: (item["preshared_key"], f"{item['address']}/32")
                    for item in state["clients"].values()}
        if len(expected) != len(state["clients"]) or len(rows) - 1 != len(expected):
            return False
        seen = set()
        for row in rows[1:]:
            if len(row) != 8 or row[0] in seen or row[0] not in expected:
                return False
            seen.add(row[0])
            if (row[1], row[3]) != expected[row[0]] or row[7] not in ("off", "0"):
                return False
        return True

    def _runtime(self, state: dict, acceptable: tuple[dict, ...]) -> bool:
        active = self._active(state)
        present = self._interface_present(state)
        if active != present:
            raise ManagedVpnError("WireGuard interface and systemd service state disagree")
        if not active:
            return False
        self._managed_link(state, required=True)
        dump = self._run(("wg", "show", state["interface"], "dump")).stdout
        if not any(self._dump_matches(dump, candidate) for candidate in acceptable):
            raise ManagedVpnError("Active WireGuard configuration differs from managed state")
        address_rows = self._run(("ip", "-j", "address", "show", "dev", state["interface"])).stdout
        try:
            rows = json.loads(address_rows)
            addresses = {(item["local"], item["prefixlen"])
                         for row in rows for item in row["addr_info"] if item["family"] == "inet"}
        except (ValueError, TypeError, KeyError) as exc:
            raise ManagedVpnError("Cannot verify WireGuard interface address") from exc
        network = validate_network(state["subnet"])
        if addresses != {(str(next(network.hosts())), network.prefixlen)}:
            raise ManagedVpnError("Active WireGuard address differs from managed state")
        return True

    def _enabled(self, state: dict) -> bool:
        result = self.runner(("systemctl", "is-enabled", "--quiet", self._unit(state)),
                             capture_output=True, text=True, timeout=10, check=False)
        if result.returncode not in (0, 1, 4):
            raise ManagedVpnError("Cannot determine WireGuard unit ownership")
        return result.returncode == 0

    def activate(self, name: str) -> dict:
        with self._locked():
            self._recover(validate_name(name))
            state = self._state(validate_name(name))
            self._managed_link(state, required=False)
            if self._runtime(state, (state,)):
                return self._public(state, active=True)
            self._preflight(validate_network(state["subnet"]), state["port"], state["interface"])
            _directory(self.wireguard_dir, uid=self._uid)
            link = self._managed_link(state, required=False)
            created_link = False
            was_enabled = self._enabled(state)
            if not link.is_symlink():
                if was_enabled:
                    raise ManagedVpnError("An enabled unit already uses this interface name")
                os.symlink(str(self._path(name) / "server.conf"), link)
                created_link = True
            try:
                self._run(("systemctl", "enable", "--now", self._unit(state)), timeout=30)
                if not self._runtime(state, (state,)):
                    raise ManagedVpnError("WireGuard service did not start")
            except Exception:
                try:
                    if was_enabled:
                        self._run(("systemctl", "stop", self._unit(state)), timeout=30)
                    else:
                        self._run(("systemctl", "disable", "--now", self._unit(state)), timeout=30)
                except ManagedVpnError as exc:
                    raise ManagedVpnError("Activation failed; manual WireGuard recovery may be required") from exc
                if self._interface_present(state):
                    raise ManagedVpnError("Activation failed and interface remains; manual recovery required")
                if created_link and link.is_symlink() and os.readlink(link) == str(self._path(name) / "server.conf"):
                    self._unlink(link)
                raise
            return self._public(state, active=True)

    def _sync(self, before: dict, after: dict) -> None:
        if not self._runtime(after, (before, after)):
            return
        config = self._run(("wg-quick", "strip", str(self.wireguard_dir / f"{after['interface']}.conf"))).stdout
        _directory(self.wireguard_dir, uid=self._uid)
        fd, temporary = tempfile.mkstemp(prefix=".sgsync-", dir=self.wireguard_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as output:
                output.write(config)
                output.flush()
                os.fsync(output.fileno())
            self._run(("wg", "syncconf", after["interface"], temporary))
        finally:
            os.unlink(temporary)
            _fsync_dir(self.wireguard_dir)
        self._runtime(after, (after,))

    def _optional_read(self, path: Path) -> bytes | None:
        if not path.exists() and not path.is_symlink():
            return None
        return self._read(path)

    def _recover(self, name: str) -> dict | None:
        """Finish an interrupted client mutation, with each step idempotent.

        The journal is durable before any file or live interface changes. If
        either disk or runtime has an unknown value, keep the journal and
        refuse to touch it. A retry can therefore finish after a power loss.
        """
        path = self._path(name)
        _directory(path, uid=self._uid, private=True)
        journal_file = path / "transaction.json"
        raw = self._optional_read(journal_file)
        if raw is None:
            return None
        try:
            journal = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ManagedVpnError("Managed transaction journal is invalid") from exc
        if (not isinstance(journal, dict) or journal.get("schema_version") != 1 or
                journal.get("operation") not in ("add", "revoke") or
                journal.get("name") != name):
            raise ManagedVpnError("Managed transaction journal is invalid")
        client_name = validate_client(journal.get("client"))
        before, after = journal.get("before"), journal.get("after")
        self._validate_state(before, name)
        self._validate_state(after, name)
        if any(before.get(key) != after.get(key) for key in before.keys() - {"clients"}):
            raise ManagedVpnError("Managed transaction journal has inconsistent instance settings")
        if set(before) != set(after):
            raise ManagedVpnError("Managed transaction journal has inconsistent instance settings")
        old_clients, new_clients = before["clients"], after["clients"]
        common = set(old_clients) & set(new_clients)
        if any(old_clients[key] != new_clients[key] for key in common):
            raise ManagedVpnError("Managed transaction journal changes unrelated clients")
        if journal["operation"] == "add":
            if client_name in old_clients or set(new_clients) != set(old_clients) | {client_name}:
                raise ManagedVpnError("Managed add transaction is invalid")
        elif client_name not in old_clients or set(new_clients) != set(old_clients) - {client_name}:
            raise ManagedVpnError("Managed revoke transaction is invalid")

        state_file = path / "state.json"
        config_file = path / "server.conf"
        old_state, new_state = self._state_bytes(before), self._state_bytes(after)
        old_config, new_config = _server_config(before), _server_config(after)
        current_state, current_config = self._read(state_file), self._read(config_file)
        if current_state not in (old_state, new_state) or current_config not in (old_config, new_config):
            raise ManagedVpnError("Managed transaction files changed unexpectedly")
        client_dir = path / "clients"
        _directory(client_dir, uid=self._uid, private=True)
        names = {item.name for item in client_dir.iterdir()}
        required = {f"{key}.conf" for key in common}
        touched_name = f"{client_name}.conf"
        if names not in (required, required | {touched_name}):
            raise ManagedVpnError("Managed transaction profiles changed unexpectedly")
        for key in common:
            if self._read(client_dir / f"{key}.conf") != _client_config(before, old_clients[key]):
                raise ManagedVpnError("Managed transaction profiles changed unexpectedly")
        touched = client_dir / touched_name
        old_profile = (_client_config(before, old_clients[client_name])
                       if client_name in old_clients else None)
        new_profile = (_client_config(after, new_clients[client_name])
                       if client_name in new_clients else None)
        current_profile = self._optional_read(touched)
        if current_profile not in (old_profile, new_profile):
            raise ManagedVpnError("Managed transaction profile changed unexpectedly")
        # Detect an orphaned interface and refuse unknown live peer settings
        # before modifying any durable file or claiming a revocation.
        self._runtime(before, (before, after))

        if new_profile is not None and current_profile is None:
            self._write(touched, new_profile, new=True)
        if current_config != new_config:
            self._write(config_file, new_config)
        if current_state != new_state:
            self._save_state(after)
        self._sync(before, after)
        if new_profile is None and current_profile is not None:
            self._unlink(touched)
        self._unlink(journal_file)
        return journal

    def recover(self, name: str) -> dict:
        name = validate_name(name)
        with self._locked():
            journal = self._recover(name)
            state = self._state(name)
            return {"name": name, "recovered": journal is not None,
                    "active": self._runtime(state, (state,))}

    def add_client(self, name: str, client_name: str) -> dict:
        with self._locked():
            self._recover(validate_name(name))
            state = self._state(validate_name(name))
            client_name = validate_client(client_name)
            active = self._runtime(state, (state,))
            if client_name in state["clients"]:
                return {"name": client_name, "address": state["clients"][client_name]["address"],
                        "profile": str(self._path(name) / "clients" / f"{client_name}.conf"),
                        "active": active, "existing": True}
            network = validate_network(state["subnet"])
            used = {item["address"] for item in state["clients"].values()}
            address = next((str(ip) for ip in list(network.hosts())[1:] if str(ip) not in used), None)
            if address is None:
                raise ManagedVpnError("VPN subnet has no free client addresses")
            private, public = self._keypair()
            psk = _key(self._run(("wg", "genpsk")).stdout.strip())
            client = {"address": address, "private_key": private,
                      "public_key": public, "preshared_key": psk}
            updated = {**state, "clients": {**state["clients"], client_name: client}}
            profile = self._path(name) / "clients" / f"{client_name}.conf"
            journal = {"schema_version": 1, "operation": "add", "name": name,
                       "client": client_name, "before": state, "after": updated}
            self._write(self._path(name) / "transaction.json", self._state_bytes(journal), new=True)
            self._recover(name)
            return {"name": client_name, "address": address, "profile": str(profile),
                    "active": self._runtime(updated, (updated,)), "existing": False}

    def revoke_client(self, name: str, client_name: str) -> dict:
        with self._locked():
            self._recover(validate_name(name))
            state = self._state(validate_name(name))
            client_name = validate_client(client_name)
            self._runtime(state, (state,))
            if client_name not in state["clients"]:
                return {"name": client_name, "revoked": True, "already_absent": True}
            profile = self._path(name) / "clients" / f"{client_name}.conf"
            _regular_private(profile, uid=self._uid)
            updated = {**state, "clients": {key: value for key, value in state["clients"].items()
                                              if key != client_name}}
            journal = {"schema_version": 1, "operation": "revoke", "name": name,
                       "client": client_name, "before": state, "after": updated}
            self._write(self._path(name) / "transaction.json", self._state_bytes(journal), new=True)
            self._recover(name)
            return {"name": client_name, "revoked": True, "already_absent": False}

    def clients(self, name: str) -> list[dict]:
        with self._locked():
            state = self._state(validate_name(name))
            return [{"name": key, "address": value["address"]}
                    for key, value in sorted(state["clients"].items())]

    def instances(self) -> list[dict]:
        with self._locked():
            items = []
            for path in sorted(self.state_root.iterdir()):
                if path.is_dir() and (path / "state.json").exists():
                    state = self._state(path.name)
                    items.append(self._public(state, active=self._runtime(state, (state,))))
            return items

    def _public(self, state: dict, *, active: bool = False) -> dict:
        return {"name": state["name"], "interface": state["interface"],
                "endpoint": state["endpoint"], "port": state["port"],
                "subnet": state["subnet"], "clients": len(state["clients"]), "active": active}

    def _export_profile(self, state: dict, client_name: str, *, route: str) -> bytes:
        if route not in ("split", "full"):
            raise ManagedVpnError("Invalid VPN client route")
        source = self._path(state["name"]) / "clients" / f"{client_name}.conf"
        profile = self._read(source)
        if route == "split":
            return profile
        # A full-route profile is never issued merely because the client
        # requested one. The exact owned NAT rule, forwarding and boot policy
        # must still be present, and the managed interface must be live.
        from .routing import full_route_ready
        if not self._runtime(state, (state,)) or not full_route_ready(state):
            raise ManagedVpnError("Full-route gateway is not configured")
        split = f"AllowedIPs = {state['subnet']}\n".encode("ascii")
        if profile.count(split) != 1:
            raise ManagedVpnError("Managed client profile is invalid")
        return profile.replace(split, b"AllowedIPs = 0.0.0.0/0, ::/0\n", 1)

    def export_client(self, name: str, client_name: str, output: Path, *, route: str = "split") -> dict:
        with self._locked():
            state = self._state(validate_name(name))
            client_name = validate_client(client_name)
            if client_name not in state["clients"]:
                raise ManagedVpnError("Client does not exist")
            output = Path(output)
            if not output.is_absolute():
                raise ManagedVpnError("Export path must be absolute")
            _directory(output.parent, uid=self._uid, private=True)
            self._write(output, self._export_profile(state, client_name, route=route), new=True)
            return {"name": client_name, "profile": str(output)}

    def sealed_export(self, name: str, client_name: str,
                      recipient_public_key: str, *, route: str = "split") -> dict[str, str | int]:
        """Seal an intact client profile before it leaves this privileged process."""
        from .sealed import seal_profile

        name = validate_name(name)
        client_name = validate_client(client_name)
        with self._locked():
            state = self._state(name)
            if client_name not in state["clients"]:
                raise ManagedVpnError("Client does not exist")
            return seal_profile(self._export_profile(state, client_name, route=route),
                                recipient_public_key, name, client_name)

    def remove(self, name: str, confirm: str) -> dict:
        name = validate_name(name)
        if confirm != name:
            raise ManagedVpnError("Confirmation must exactly match the instance name")
        with self._locked():
            self._recover(name)
            state = self._state(name)
            if self.require_root:
                from .routing import routing_policy_tracks
                if routing_policy_tracks(state):
                    raise ManagedVpnError("Disable managed routing before removing VPN")
            link = self._managed_link(state, required=False)
            path = self._path(name)
            expected = {"state.json", "server.conf", "clients"}
            if {item.name for item in path.iterdir()} != expected:
                raise ManagedVpnError("Unexpected files in managed instance; removal refused")
            expected_clients = {f"{key}.conf" for key in state["clients"]}
            if {item.name for item in (path / "clients").iterdir()} != expected_clients:
                raise ManagedVpnError("Unexpected client profiles; removal refused")
            for client_name in state["clients"]:
                _regular_private(path / "clients" / f"{client_name}.conf", uid=self._uid)
            active = self._runtime(state, (state,))
            if active and not link.is_symlink():
                raise ManagedVpnError("Active interface has no managed configuration link")
            if not link.is_symlink() and self._enabled(state):
                raise ManagedVpnError("Enabled WireGuard unit has no managed configuration link")
            if link.is_symlink():
                self._run(("systemctl", "disable", "--now", self._unit(state)), timeout=30)
                if self._active(state) or self._interface_present(state):
                    raise ManagedVpnError("WireGuard service remains active")
                self._unlink(link)
            for client_name in state["clients"]:
                profile = path / "clients" / f"{client_name}.conf"
                self._unlink(profile)
            (path / "clients").rmdir()
            self._unlink(path / "server.conf")
            self._unlink(path / "state.json")
            path.rmdir()
            return {"name": name, "removed": True}
