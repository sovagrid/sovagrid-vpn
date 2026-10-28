# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in IPv4 egress for SovaGrid-owned WireGuard instances.

Each interface gets a private nftables table. No existing firewall table is
edited or adopted. A root-only policy and systemd oneshot restore those tables
after reboot. Full-route profiles are issued only while the live prerequisites
can be verified. Other firewall chains can still block forwarding, so clients
must verify connectivity after import.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
from typing import Callable, Iterator

from .managed import ManagedVpnError, ManagedWireGuard, interface_name, validate_name, validate_network


POLICY_VERSION = 1
SYSCTL_CONTENT = b"# SovaGrid managed WireGuard IPv4 egress\nnet.ipv4.ip_forward = 1\n"
UNIT_CONTENT = (b"[Unit]\nDescription=SovaGrid owned WireGuard IPv4 routing\n"
                b"After=systemd-sysctl.service nftables.service ufw.service\n\n"
                b"[Service]\nType=oneshot\nUser=root\nGroup=root\n"
                b"WorkingDirectory=/opt/sovagrid-vpn\n"
                b"ExecStart=/usr/bin/python3 -B -E -S -m sovagrid_vpn.routing sync\n"
                b"RemainAfterExit=yes\nNoNewPrivileges=true\nProtectSystem=strict\n"
                b"ReadWritePaths=/etc/sovagrid-vpn-routing /var/lib/sovagrid-vpn /proc/sys/net/ipv4/ip_forward\n\n"
                b"[Install]\nWantedBy=multi-user.target\n")
MAX_POLICY = 8192


class RoutingError(RuntimeError):
    """Safe public error; never includes firewall diagnostics or secrets."""


@dataclass(frozen=True)
class RoutingPaths:
    root: Path = Path("/etc/sovagrid-vpn-routing")
    unit: Path = Path("/etc/systemd/system/sovagrid-vpn-routing.service")
    sysctl: Path = Path("/etc/sysctl.d/70-sovagrid-vpn-routing.conf")
    forward: Path = Path("/proc/sys/net/ipv4/ip_forward")

    @property
    def policy(self) -> Path:
        return self.root / "policy.json"

    @property
    def lock(self) -> Path:
        return self.root / "lock"


def _table_name(state: dict) -> str:
    return "sgvpn_" + state["interface"]


def _expected_expr(state: dict) -> list[dict]:
    network = validate_network(state["subnet"])
    return [
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                   "right": {"prefix": {"addr": str(network.network_address), "len": network.prefixlen}}}},
        {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}},
                   "right": state["interface"]}},
        {"masquerade": {}},
    ]


class RoutingSetup:
    def __init__(self, *, manager: ManagedWireGuard | None = None, paths: RoutingPaths = RoutingPaths(),
                 runner: Callable = subprocess.run, require_root: bool = True):
        self.manager = manager or ManagedWireGuard(require_root=require_root)
        self.paths = paths
        self.runner = runner
        self.owner = 0 if require_root else os.geteuid()
        self.require_root = require_root
        if require_root and (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
            raise RoutingError("ROOT_REQUIRED")
        if any(not path.is_absolute() for path in (paths.root, paths.unit, paths.sysctl, paths.forward)):
            raise RoutingError("INVALID_PATHS")
        if require_root and (paths != RoutingPaths() or
                             Path(__file__).resolve() != Path("/opt/sovagrid-vpn/sovagrid_vpn/routing.py")):
            raise RoutingError("INVALID_PATHS")

    def _safe_parent(self, path: Path) -> None:
        """Refuse writable or symlinked ancestors of root-owned output files."""
        ancestors = (path.parent, *path.parent.parents) if self.require_root else (path.parent,)
        for parent in ancestors:
            try:
                info = parent.lstat()
            except OSError as exc:
                raise RoutingError("UNSAFE_DIRECTORY") from exc
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner or
                    stat.S_IMODE(info.st_mode) & 0o022):
                raise RoutingError("UNSAFE_DIRECTORY")

    def _read(self, path: Path, mode: int, *, limit: int = MAX_POLICY) -> bytes | None:
        self._safe_parent(path)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise RoutingError("UNSAFE_FILE") from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode or info.st_size > limit):
                raise RoutingError("UNSAFE_FILE")
            raw = os.read(fd, limit + 1)
            if len(raw) > limit:
                raise RoutingError("UNSAFE_FILE")
            return raw
        finally:
            os.close(fd)

    def _atomic(self, path: Path, content: bytes, mode: int) -> None:
        self._safe_parent(path)
        old = self._read(path, mode)
        if old == content:
            return
        fd, temporary = tempfile.mkstemp(prefix=".sovagrid-routing-", dir=path.parent)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            # _read above refused unsafe existing files. The private policy
            # directory is not writable by another UID; system directories
            # are root-owned. Recheck to reject a competing replacement.
            if self._read(path, mode) != old:
                raise RoutingError("CONCURRENT_CHANGE")
            os.replace(temporary, path)
            temporary = ""
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if fd >= 0:
                os.close(fd)
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    def _directory(self, *, create: bool) -> bool:
        try:
            info = self.paths.root.lstat()
        except FileNotFoundError:
            if not create:
                return False
            self._safe_parent(self.paths.root)
            self.paths.root.mkdir(mode=0o700)
            info = self.paths.root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise RoutingError("UNSAFE_DIRECTORY")
        self._safe_parent(self.paths.root)
        return True

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._directory(create=True)
        fd = os.open(self.paths.lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise RoutingError("UNSAFE_LOCK")
            deadline = time.monotonic() + 10
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RoutingError("ROUTING_BUSY") from None
                    time.sleep(0.05)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    def _policy(self) -> dict:
        if not self._directory(create=False):
            return {"version": POLICY_VERSION, "enabled": [], "pending_remove": []}
        raw = self._read(self.paths.policy, 0o600)
        if raw is None:
            return {"version": POLICY_VERSION, "enabled": [], "pending_remove": []}
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise RoutingError("INVALID_POLICY") from exc
        if (not isinstance(value, dict) or set(value) != {"version", "enabled", "pending_remove"} or
                value["version"] != POLICY_VERSION or type(value["version"]) is not int or
                not isinstance(value["enabled"], list) or not isinstance(value["pending_remove"], list) or
                len(value["enabled"]) > 64 or len(value["pending_remove"]) > 64):
            raise RoutingError("INVALID_POLICY")
        for field in ("enabled", "pending_remove"):
            names = value[field]
            if any(not isinstance(name, str) or name != validate_name(name) for name in names) or names != sorted(set(names)):
                raise RoutingError("INVALID_POLICY")
        if not set(value["pending_remove"]) <= set(value["enabled"]):
            raise RoutingError("INVALID_POLICY")
        return value

    def _save_policy(self, value: dict) -> None:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        if len(raw) > MAX_POLICY:
            raise RoutingError("INVALID_POLICY")
        self._atomic(self.paths.policy, raw, 0o600)

    def _run(self, argv: tuple[str, ...], *, input: str | None = None, timeout: int = 10,
             allow_failure: bool = False) -> subprocess.CompletedProcess:
        try:
            result = self.runner(argv, input=input, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RoutingError("ROUTING_TOOL_UNAVAILABLE") from exc
        if not allow_failure and result.returncode != 0:
            raise RoutingError("ROUTING_COMMAND_FAILED")
        if len(result.stdout) > 65536:
            raise RoutingError("ROUTING_OUTPUT_TOO_LARGE")
        return result

    def _nft_table(self, state: dict) -> str:
        table = _table_name(state)
        tables = self._run(("nft", "-j", "list", "tables")).stdout
        try:
            listing = json.loads(tables)["nftables"]
            present = any(row.get("table", {}).get("family") == "ip" and
                          row.get("table", {}).get("name") == table for row in listing)
        except (TypeError, ValueError, KeyError, AttributeError) as exc:
            raise RoutingError("NFT_STATE_UNKNOWN") from exc
        if not present:
            return "absent"
        raw = self._run(("nft", "-j", "list", "table", "ip", table)).stdout
        try:
            rows = [row for row in json.loads(raw)["nftables"] if "metainfo" not in row]
            if len(rows) != 3 or any(not isinstance(row, dict) or len(row) != 1 for row in rows):
                return "foreign"
            objects = {next(iter(row)): next(iter(row.values())) for row in rows}
            if set(objects) != {"table", "chain", "rule"}:
                return "foreign"
            actual_table, chain, rule = objects["table"], objects["chain"], objects["rule"]
            expr = rule.get("expr")
            expected_expr = _expected_expr(state)
            # nft versions serialize a no-argument masquerade as {} or null.
            expr_matches = (isinstance(expr, list) and len(expr) == 3 and
                            expr[:2] == expected_expr[:2] and
                            expr[2] in ({"masquerade": {}}, {"masquerade": None}))
            owned = (actual_table.get("family") == "ip" and actual_table.get("name") == table and
                     chain.get("family") == "ip" and chain.get("table") == table and
                     chain.get("name") == "postrouting" and chain.get("type") == "nat" and
                     chain.get("hook") == "postrouting" and chain.get("prio") == 100 and
                     chain.get("policy") == "accept" and rule.get("family") == "ip" and
                     rule.get("table") == table and rule.get("chain") == "postrouting" and
                     expr_matches)
            return "owned" if owned else "foreign"
        except (TypeError, ValueError, KeyError, AttributeError):
            raise RoutingError("NFT_STATE_UNKNOWN") from None

    def _add_table(self, state: dict) -> None:
        table = _table_name(state)
        network = validate_network(state["subnet"])
        program = (f"add table ip {table}\n"
                   f"add chain ip {table} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n"
                   f"add rule ip {table} postrouting ip saddr {network} oifname != \"{state['interface']}\" masquerade\n")
        self._run(("nft", "-f", "-"), input=program)
        if self._nft_table(state) != "owned":
            raise RoutingError("NFT_STATE_UNKNOWN")

    def _delete_table(self, state: dict) -> None:
        if self._nft_table(state) == "absent":
            return
        if self._nft_table(state) != "owned":
            raise RoutingError("FOREIGN_NFT_TABLE")
        self._run(("nft", "delete", "table", "ip", _table_name(state)))

    def _unit_enabled(self) -> bool:
        result = self._run(("systemctl", "is-enabled", "--quiet", "sovagrid-vpn-routing.service"),
                           allow_failure=True)
        if result.returncode not in (0, 1, 4):
            raise RoutingError("SYSTEMD_STATE_UNKNOWN")
        return result.returncode == 0

    def _unit_identity(self) -> bool:
        result = self._run(("systemctl", "show", "sovagrid-vpn-routing.service",
                            "--property=LoadState,FragmentPath,DropInPaths"), allow_failure=True)
        if result.returncode != 0:
            raise RoutingError("SYSTEMD_STATE_UNKNOWN")
        values = {}
        for line in result.stdout.splitlines():
            key, sep, value = line.partition("=")
            if sep and key not in values:
                values[key] = value
        if set(values) != {"LoadState", "FragmentPath", "DropInPaths"}:
            raise RoutingError("SYSTEMD_STATE_UNKNOWN")
        return (values["LoadState"] == "loaded" and
                values["FragmentPath"] == str(self.paths.unit) and
                values["DropInPaths"] == "")

    def _forwarding(self) -> bool:
        try:
            raw = self.paths.forward.read_bytes()
        except OSError as exc:
            raise RoutingError("FORWARDING_STATE_UNKNOWN") from exc
        if raw not in (b"0\n", b"1\n", b"0", b"1"):
            raise RoutingError("FORWARDING_STATE_UNKNOWN")
        return raw.startswith(b"1")

    def _enable_forwarding(self) -> None:
        if self._forwarding():
            return
        try:
            fd = os.open(self.paths.forward, os.O_WRONLY | os.O_NOFOLLOW)
            try:
                if os.write(fd, b"1\n") != 2:
                    raise RoutingError("FORWARDING_FAILED")
            finally:
                os.close(fd)
        except OSError as exc:
            raise RoutingError("FORWARDING_FAILED") from exc
        if not self._forwarding():
            raise RoutingError("FORWARDING_FAILED")

    def _snapshot(self, state: dict, policy: dict) -> dict:
        unit = self._read(self.paths.unit, 0o644, limit=4096)
        sysctl = self._read(self.paths.sysctl, 0o644, limit=4096)
        table = self._nft_table(state)
        enabled = self._unit_enabled()
        unit_identity = self._unit_identity()
        forwarding = self._forwarding()
        armed = state["name"] in policy["enabled"] and state["name"] not in policy["pending_remove"]
        orphan = (state["name"] not in policy["enabled"] and table != "absent") or (
            not policy["enabled"] and (unit is not None or sysctl is not None or enabled))
        configured = (armed and unit == UNIT_CONTENT and sysctl == SYSCTL_CONTENT and
                      table == "owned" and enabled and unit_identity and forwarding)
        revision = hashlib.sha256(json.dumps({"policy": policy,
            "instance": {"name": state["name"], "interface": state["interface"], "subnet": state["subnet"]},
            "unit": None if unit is None else hashlib.sha256(unit).hexdigest(),
            "sysctl": None if sysctl is None else hashlib.sha256(sysctl).hexdigest(),
            "table": table, "enabled": enabled, "unit_identity": unit_identity,
            "forwarding": forwarding},
            sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        return {"name": state["name"], "armed": armed, "routing_configured": configured,
                "recovery_required": bool(orphan or state["name"] in policy["pending_remove"] or
                                          armed and not configured),
                "forwarding": forwarding, "nat": table == "owned",
                "upstream_firewall_unverified": True,
                "state_revision": revision}

    def preview(self, name: str) -> dict:
        name = validate_name(name)
        # No lock file, directory or other host state is created by preview.
        # Atomic managed files may change while read; _state rejects partial
        # transactions and arm/disarm recompute the revision under both locks.
        try:
            state = self.manager._state(name)
        except OSError as exc:
            raise RoutingError("INSTANCE_UNAVAILABLE") from exc
        return self._snapshot(state, self._policy())

    def _require_expected(self, snapshot: dict, expected: str) -> None:
        if not isinstance(expected, str) or snapshot["state_revision"] != expected:
            raise RoutingError("STALE_PREVIEW")

    def arm(self, name: str, expected: str) -> dict:
        name = validate_name(name)
        with self.manager._locked(), self._locked():
            state = self.manager._state(name)
            policy = self._policy()
            before = self._snapshot(state, policy)
            self._require_expected(before, expected)
            if name in policy["pending_remove"]:
                raise RoutingError("RECOVERY_REQUIRED")
            if before["routing_configured"]:
                return before
            table = self._nft_table(state)
            if table == "foreign":
                raise RoutingError("FOREIGN_NFT_TABLE")
            if name not in policy["enabled"] and table != "absent":
                raise RoutingError("RECOVERY_REQUIRED")
            for path, content in ((self.paths.unit, UNIT_CONTENT), (self.paths.sysctl, SYSCTL_CONTENT)):
                existing = self._read(path, 0o644, limit=4096)
                if existing not in (None, content):
                    raise RoutingError("FOREIGN_CONFIGURATION")
            if not policy["enabled"] and before["recovery_required"]:
                raise RoutingError("RECOVERY_REQUIRED")
            if name not in policy["enabled"]:
                policy["enabled"] = sorted([*policy["enabled"], name])
                self._save_policy(policy)
            self._atomic(self.paths.unit, UNIT_CONTENT, 0o644)
            self._atomic(self.paths.sysctl, SYSCTL_CONTENT, 0o644)
            self._run(("systemctl", "daemon-reload"))
            if not self._unit_identity():
                raise RoutingError("FOREIGN_SYSTEMD_UNIT")
            if not self._unit_enabled():
                self._run(("systemctl", "enable", "sovagrid-vpn-routing.service"))
            self._enable_forwarding()
            if self._nft_table(state) == "absent":
                self._add_table(state)
            after = self._snapshot(state, policy)
            if not after["routing_configured"]:
                raise RoutingError("ROUTING_NOT_READY")
            return after

    def disarm(self, name: str, expected: str) -> dict:
        name = validate_name(name)
        with self.manager._locked(), self._locked():
            state = self.manager._state(name)
            policy = self._policy()
            before = self._snapshot(state, policy)
            self._require_expected(before, expected)
            if name not in policy["enabled"]:
                if before["recovery_required"]:
                    table = self._nft_table(state)
                    if table == "foreign":
                        raise RoutingError("FOREIGN_NFT_TABLE")
                    if table == "owned":
                        self._delete_table(state)
                    if not policy["enabled"]:
                        self._cleanup_global()
                    return self._snapshot(state, policy)
                return before
            for path, content in ((self.paths.unit, UNIT_CONTENT), (self.paths.sysctl, SYSCTL_CONTENT)):
                existing = self._read(path, 0o644, limit=4096)
                if existing not in (None, content):
                    raise RoutingError("FOREIGN_CONFIGURATION")
            if name not in policy["pending_remove"]:
                policy["pending_remove"] = sorted([*policy["pending_remove"], name])
                self._save_policy(policy)
            self._delete_table(state)
            policy["enabled"].remove(name)
            policy["pending_remove"].remove(name)
            self._save_policy(policy)
            if not policy["enabled"]:
                self._cleanup_global()
            return self._snapshot(state, policy)

    def _cleanup_global(self) -> None:
        for path, content in ((self.paths.unit, UNIT_CONTENT), (self.paths.sysctl, SYSCTL_CONTENT)):
            existing = self._read(path, 0o644, limit=4096)
            if existing not in (None, content):
                raise RoutingError("FOREIGN_CONFIGURATION")
        if self._unit_enabled():
            self._run(("systemctl", "disable", "--now", "sovagrid-vpn-routing.service"))
        for path in (self.paths.unit, self.paths.sysctl):
            if path.exists():
                path.unlink()
        self._run(("systemctl", "daemon-reload"))

    def sync(self) -> dict:
        """Boot-time replay of the exact policy; never discovers foreign VPNs."""
        with self.manager._locked(), self._locked():
            policy = self._policy()
            for name in list(policy["pending_remove"]):
                state = self.manager._state(name)
                self._delete_table(state)
                policy["enabled"].remove(name)
                policy["pending_remove"].remove(name)
                self._save_policy(policy)
            if not policy["enabled"]:
                self._cleanup_global()
            if policy["enabled"]:
                if (self._read(self.paths.unit, 0o644, limit=4096) != UNIT_CONTENT or
                        self._read(self.paths.sysctl, 0o644, limit=4096) != SYSCTL_CONTENT):
                    raise RoutingError("FOREIGN_CONFIGURATION")
                if not self._unit_identity():
                    raise RoutingError("FOREIGN_SYSTEMD_UNIT")
                self._enable_forwarding()
                for name in policy["enabled"]:
                    state = self.manager._state(name)
                    table = self._nft_table(state)
                    if table == "foreign":
                        raise RoutingError("FOREIGN_NFT_TABLE")
                    if table == "absent":
                        self._add_table(state)
            return {"enabled": list(policy["enabled"]), "routing_configured": all(
                self._snapshot(self.manager._state(name), policy)["routing_configured"] for name in policy["enabled"])}


def full_route_ready(state: dict, *, setup: RoutingSetup | None = None) -> bool:
    """Fail closed if owned NAT, forwarding, or boot persistence is absent."""
    try:
        setup = setup or RoutingSetup()
        return setup._snapshot(state, setup._policy())["routing_configured"]
    except (RoutingError, ManagedVpnError, OSError):
        return False


def routing_policy_tracks(state: dict, *, setup: RoutingSetup | None = None) -> bool:
    """Removal guard: a stale or disarming policy still owns the instance."""
    try:
        setup = setup or RoutingSetup()
        name = validate_name(state["name"])
        policy = setup._policy()
        if name in policy["enabled"]:
            return True
        # A clean never-armed installation does not require nftables. Once
        # any routing policy exists, refuse removal if its table is orphaned.
        if not setup._directory(create=False):
            return False
        return setup._nft_table(state) != "absent"
    except (RoutingError, OSError) as exc:
        raise ManagedVpnError("Managed routing policy must be repaired before removing VPN") from exc


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="SovaGrid-owned WireGuard IPv4 routing")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("preview", "arm", "disarm"):
        command = sub.add_parser(action)
        command.add_argument("name")
        if action != "preview":
            command.add_argument("--expected-state", required=True)
    sub.add_parser("sync")
    args = parser.parse_args(argv)
    try:
        setup = RoutingSetup()
        if args.action == "sync":
            result = setup.sync()
        elif args.action == "preview":
            result = setup.preview(args.name)
        else:
            result = getattr(setup, args.action)(args.name, args.expected_state)
    except (RoutingError, ManagedVpnError, OSError) as exc:
        print(str(exc) if isinstance(exc, (RoutingError, ManagedVpnError)) else
              "ROUTING_STATE_UNAVAILABLE", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
