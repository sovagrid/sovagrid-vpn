# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in Unix-socket broker for bounded SovaGrid-owned Amnezia operations.

The unprivileged client never receives Docker access. Enrolment and recovery
remain local root-only administrative steps and cannot cross this socket.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import sys
import time
from typing import Any

from .amnezia_admin import (AmneziaAdmin, AmneziaAdminError, TARGETS,
                            CONFIRMATION_ID, NAME_PATTERN, SETTINGS_INTENT_TTL,
                            _awg_patch)
from .control import _receive_line
from .peer_auth import authorized_peer, peer_identity


SOCKET_PATH = "/run/sovagrid-vpn/amnezia-control.sock"
ENABLE_FILE = Path("/etc/sovagrid-vpn/amnezia-control.enabled")
WIREGUARD_ENABLE_FILE = Path("/etc/sovagrid-vpn/amnezia-wireguard-control.enabled")
SETTINGS_ENABLE_FILE = Path("/etc/sovagrid-vpn/amnezia-awg-settings.enabled")
MAX_REQUEST = 4096
MAX_RESPONSE = 8192
MAX_OPERATION_SECONDS = 120
ENVELOPE_FIELDS = frozenset({"version", "ephemeral_public_key", "salt", "nonce", "ciphertext"})
TOKEN = re.compile(r"[A-Za-z0-9_-]+\Z")
PREVIEW_FIELDS = frozenset(("target", "container_id", "image_id", "config_sha256",
                            "table_sha256", "generation", "protocol", "interface",
                            "listen_port", "server_address", "server_subnet",
                            "configured_clients", "managed_clients", "external_clients",
                            "awg_parameters", "awg_parameters_runtime_verified",
                            "header_protection_key_present", "awg3_required_parameters_present",
                            "apply_supported", "apply_blockers"))
AWG_NUMBERS = frozenset(("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"))
AWG_RANGES = frozenset(("H1", "H2", "H3", "H4"))
PREVIEW_BLOCKERS = ["CLIENT_PROFILES_REQUIRE_REISSUE",
                    "PORT_REQUIRES_CONTAINER_NETWORK_MIGRATION"]
PLAN_FIELDS = frozenset(("target", "container_id", "image_id", "generation",
                         "config_sha256", "table_sha256", "proposed_config_sha256",
                         "current_awg_parameters", "proposed_awg_parameters",
                         "changed_fields", "configured_clients", "apply_supported",
                         "apply_blockers"))
INTENT_FIELDS = frozenset(("target", "action", "confirmation_id", "expires_at",
                           "generation", "config_sha256", "proposed_config_sha256",
                           "changed_fields", "configured_clients"))
SETTINGS_APPLY_FIELDS = frozenset(("target", "action", "generation",
                                   "config_sha256", "cleanup_required"))


class AmneziaControlError(ValueError):
    """A secret-free client or protocol error."""


def _client(value: str) -> str:
    if not isinstance(value, str) or not NAME_PATTERN.fullmatch(value):
        raise AmneziaControlError("Invalid Amnezia client name")
    return value


def _recipient(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{87}", value):
        raise AmneziaControlError("Invalid profile recipient key")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, item in pairs:
        if key in result:
            raise AmneziaControlError("Invalid Amnezia settings proposal")
        result[key] = item
    return result


def parse_action(argv: Any) -> tuple[str, tuple[Any, ...]]:
    """Accept exact grammar, with no paths, shell, Docker flags or enrolment."""
    if (not isinstance(argv, list) or not 2 <= len(argv) <= 8 or
            any(not isinstance(item, str) or len(item.encode("utf-8")) > 253 or
                any(ord(char) < 32 or ord(char) == 127 for char in item)
                for item in argv)):
        raise AmneziaControlError("Invalid Amnezia request")
    action, target = argv[:2]
    if target not in TARGETS:
        raise AmneziaControlError("Unsupported Amnezia target")
    if action == "add-profile" and len(argv) in (6, 8):
        if len(argv) == 8 and (argv[6] != "--route" or argv[7] not in ("split", "full")):
            raise AmneziaControlError("Invalid Amnezia route")
        client, address, endpoint_host, recipient = argv[2:6]
        _client(client)
        _recipient(recipient)
        # The root manager validates IPv4, endpoint and P-256 on-curve before writes.
        if not address.isascii() or len(address) > 15 or not re.fullmatch(r"[0-9.]+", address):
            raise AmneziaControlError("Invalid client IPv4 address")
        if not endpoint_host.isascii() or len(endpoint_host) > 253:
            raise AmneziaControlError("Invalid endpoint host")
        return action, (client, address, endpoint_host, recipient,
                        argv[7] if len(argv) == 8 else "split")
    if action == "sealed-export" and len(argv) == 4:
        return action, (_client(argv[2]), _recipient(argv[3]))
    if action == "revoke" and len(argv) == 3:
        return action, (_client(argv[2]),)
    if action in ("status", "settings-preview") and len(argv) == 2:
        return action, ()
    if action in ("settings-plan", "settings-intent", "settings-apply") and target == "awg2" and (
            len(argv) == {"settings-plan": 5, "settings-intent": 6,
                          "settings-apply": 7}[action]):
        digest, generation = argv[2:4]
        proposed = argv[4] if action != "settings-plan" else None
        encoded = argv[5] if action != "settings-plan" else argv[4]
        if (not re.fullmatch(r"[0-9a-f]{64}", digest) or
                not re.fullmatch(r"(?:0|[1-9][0-9]{0,8}|1000000000)", generation) or
                (proposed is not None and not re.fullmatch(r"[0-9a-f]{64}", proposed)) or
                (action == "settings-apply" and
                 CONFIRMATION_ID.fullmatch(argv[6]) is None)):
            raise AmneziaControlError("Invalid Amnezia settings proposal")
        try:
            patch = _awg_patch(json.loads(encoded, object_pairs_hook=_unique_pairs))
        except (ValueError, UnicodeError, AmneziaAdminError) as exc:
            raise AmneziaControlError("Invalid Amnezia settings proposal") from exc
        if action == "settings-plan":
            return action, (digest, int(generation), patch)
        if action == "settings-intent":
            return action, (digest, int(generation), proposed, patch)
        return action, (digest, int(generation), proposed, patch, argv[6])
    raise AmneziaControlError("Invalid Amnezia action arguments")


def _binary_field(value: Any, expected: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) > 5462 or not TOKEN.fullmatch(value):
        raise AmneziaControlError("Invalid sealed profile envelope")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise AmneziaControlError("Invalid sealed profile envelope") from exc
    if (base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value or
            (expected is not None and len(raw) != expected)):
        raise AmneziaControlError("Invalid sealed profile envelope")
    return raw


def _envelope(value: Any) -> dict[str, Any]:
    if (not isinstance(value, dict) or set(value) != ENVELOPE_FIELDS or
            type(value["version"]) is not int or value["version"] != 1):
        raise AmneziaControlError("Invalid sealed profile envelope")
    if _binary_field(value["ephemeral_public_key"], 65)[0] != 4:
        raise AmneziaControlError("Invalid sealed profile envelope")
    _binary_field(value["salt"], 16)
    _binary_field(value["nonce"], 12)
    ciphertext = _binary_field(value["ciphertext"])
    if not 17 <= len(ciphertext) <= 4096:
        raise AmneziaControlError("Invalid sealed profile envelope")
    return {field: value[field] for field in
            ("version", "ephemeral_public_key", "salt", "nonce", "ciphertext")}


def _settings_preview(value: dict[str, Any], target: str) -> dict[str, Any]:
    """Prevent any unexpected Docker/config material crossing the root socket."""
    if set(value) != PREVIEW_FIELDS or value["target"] != target:
        raise AmneziaControlError("Invalid Amnezia settings preview")
    for field in ("container_id", "config_sha256", "table_sha256"):
        if not isinstance(value[field], str) or not re.fullmatch(r"[0-9a-f]{64}", value[field]):
            raise AmneziaControlError("Invalid Amnezia settings preview")
    if not isinstance(value["image_id"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"]):
        raise AmneziaControlError("Invalid Amnezia settings preview")
    if (value["protocol"] != ("amneziawg" if target == "awg2" else "wireguard") or
            value["interface"] != ("awg0" if target == "awg2" else "wg0")):
        raise AmneziaControlError("Invalid Amnezia settings preview")
    for field, lower, upper in (("generation", 0, 1_000_000_000),
                                ("listen_port", 1, 65535),
                                ("configured_clients", 0, 2048),
                                ("managed_clients", 0, 2048),
                                ("external_clients", 0, 2048)):
        if type(value[field]) is not int or not lower <= value[field] <= upper:
            raise AmneziaControlError("Invalid Amnezia settings preview")
    if value["configured_clients"] != value["managed_clients"] + value["external_clients"]:
        raise AmneziaControlError("Invalid Amnezia settings preview")
    try:
        address = ipaddress.IPv4Address(value["server_address"])
        subnet = ipaddress.IPv4Network(value["server_subnet"], strict=True)
    except (TypeError, ValueError) as exc:
        raise AmneziaControlError("Invalid Amnezia settings preview") from exc
    if (str(address) != value["server_address"] or
            str(subnet) != value["server_subnet"] or address not in subnet):
        raise AmneziaControlError("Invalid Amnezia settings preview")
    for field in ("awg_parameters_runtime_verified", "header_protection_key_present",
                  "awg3_required_parameters_present", "apply_supported"):
        if type(value[field]) is not bool:
            raise AmneziaControlError("Invalid Amnezia settings preview")
    if (value["awg_parameters_runtime_verified"] or value["apply_supported"] or
            value["apply_blockers"] != PREVIEW_BLOCKERS):
        raise AmneziaControlError("Invalid Amnezia settings preview")
    parameters = value["awg_parameters"]
    if not isinstance(parameters, dict) or set(parameters) - (AWG_NUMBERS | AWG_RANGES):
        raise AmneziaControlError("Invalid Amnezia settings preview")
    for name, number in parameters.items():
        if not isinstance(number, str) or not re.fullmatch(r"[0-9]{1,10}(?:-[0-9]{1,10})?", number):
            raise AmneziaControlError("Invalid Amnezia settings preview")
        parts = [int(part) for part in number.split("-")]
        if max(parts) > (65535 if name in AWG_NUMBERS else 4294967295) or (
                len(parts) == 2 and (name in AWG_NUMBERS or parts[0] > parts[1])):
            raise AmneziaControlError("Invalid Amnezia settings preview")
    if ("Jmin" in parameters and "Jmax" in parameters and
            int(parameters["Jmin"]) > int(parameters["Jmax"])):
        raise AmneziaControlError("Invalid Amnezia settings preview")
    required_present = (AWG_NUMBERS | AWG_RANGES).issubset(parameters) and value["header_protection_key_present"]
    if (target == "wireguard" and (parameters or value["header_protection_key_present"] or
                                    value["awg3_required_parameters_present"])) or (
            target == "awg2" and value["awg3_required_parameters_present"] != required_present):
        raise AmneziaControlError("Invalid Amnezia settings preview")
    public = {field: value[field] for field in PREVIEW_FIELDS}
    if len((json.dumps(public, separators=(",", ":")) + "\n").encode("ascii")) > 4096:
        raise AmneziaControlError("Invalid Amnezia settings preview")
    return public


def _settings_plan(value: dict[str, Any], target: str) -> dict[str, Any]:
    if set(value) != PLAN_FIELDS or target != "awg2" or value["target"] != target:
        raise AmneziaControlError("Invalid Amnezia settings plan")
    for name in ("container_id", "config_sha256", "table_sha256",
                 "proposed_config_sha256"):
        if not isinstance(value[name], str) or not re.fullmatch(r"[0-9a-f]{64}", value[name]):
            raise AmneziaControlError("Invalid Amnezia settings plan")
    if (not isinstance(value["image_id"], str) or
            not re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"]) or
            value["proposed_config_sha256"] == value["config_sha256"] or
            type(value["generation"]) is not int or
            not 0 <= value["generation"] <= 1_000_000_000 or
            type(value["configured_clients"]) is not int or
            not 0 <= value["configured_clients"] <= 2048 or
            type(value["apply_supported"]) is not bool):
        raise AmneziaControlError("Invalid Amnezia settings plan")
    try:
        current = _awg_patch(value["current_awg_parameters"], canonical=False)
        proposed = _awg_patch(value["proposed_awg_parameters"], canonical=False)
    except AmneziaAdminError as exc:
        raise AmneziaControlError("Invalid Amnezia settings plan") from exc
    if (set(current) != AWG_NUMBERS | AWG_RANGES or
            set(proposed) != AWG_NUMBERS | AWG_RANGES or
            int(current["Jmin"]) > int(current["Jmax"]) or
            int(proposed["Jmin"]) > int(proposed["Jmax"])):
        raise AmneziaControlError("Invalid Amnezia settings plan")
    changed = sorted(name for name in current if current[name] != proposed[name])
    blockers = (["CLIENT_PROFILES_REQUIRE_REISSUE"] if value["configured_clients"] else [])
    if (not changed or value["changed_fields"] != changed or
            value["apply_blockers"] != blockers or
            value["apply_supported"] != (value["configured_clients"] == 0)):
        raise AmneziaControlError("Invalid Amnezia settings plan")
    public = {field: value[field] for field in PLAN_FIELDS}
    if len((json.dumps(public, separators=(",", ":")) + "\n").encode("ascii")) > 4096:
        raise AmneziaControlError("Invalid Amnezia settings plan")
    return public


def _settings_intent(value: dict[str, Any], target: str) -> dict[str, Any]:
    if (set(value) != INTENT_FIELDS or value["target"] != target or target != "awg2" or
            value["action"] != "settings_intent" or
            not isinstance(value["confirmation_id"], str) or
            CONFIRMATION_ID.fullmatch(value["confirmation_id"]) is None or
            type(value["expires_at"]) is not int or
            not int(time.time()) < value["expires_at"] <=
            int(time.time()) + SETTINGS_INTENT_TTL or
            type(value["generation"]) is not int or
            not 0 <= value["generation"] <= 1_000_000_000 or
            type(value["configured_clients"]) is not int or
            value["configured_clients"] != 0):
        raise AmneziaControlError("Invalid Amnezia settings intent")
    for name in ("config_sha256", "proposed_config_sha256"):
        if not isinstance(value[name], str) or re.fullmatch(r"[0-9a-f]{64}", value[name]) is None:
            raise AmneziaControlError("Invalid Amnezia settings intent")
    changed = value["changed_fields"]
    if (not isinstance(changed, list) or not changed or
            changed != sorted(set(changed)) or
            any(name not in AWG_NUMBERS | AWG_RANGES for name in changed)):
        raise AmneziaControlError("Invalid Amnezia settings intent")
    return {field: value[field] for field in INTENT_FIELDS}


def _settings_applied(value: dict[str, Any], target: str) -> dict[str, Any]:
    if (set(value) != SETTINGS_APPLY_FIELDS or value["target"] != target or
            target != "awg2" or value["action"] != "settings_updated" or
            type(value["generation"]) is not int or
            not 1 <= value["generation"] <= 1_000_000_000 or
            not isinstance(value["config_sha256"], str) or
            re.fullmatch(r"[0-9a-f]{64}", value["config_sha256"]) is None or
            type(value["cleanup_required"]) is not bool):
        raise AmneziaControlError("Invalid Amnezia settings result")
    return {field: value[field] for field in SETTINGS_APPLY_FIELDS}


def _public_result(action: str, result: Any, target: str) -> Any:
    """Return only fields explicitly approved for Agent and Hub."""
    if not isinstance(result, dict):
        raise AmneziaControlError("Invalid Amnezia result")
    if action == "sealed-export":
        return _envelope(result)
    if action == "settings-preview":
        return _settings_preview(result, target)
    if action == "settings-plan":
        return _settings_plan(result, target)
    if action == "settings-intent":
        return _settings_intent(result, target)
    if action == "settings-apply":
        return _settings_applied(result, target)
    if action == "add-profile":
        expected_format = "awg3-conf" if target == "awg2" else "wg-conf"
        if (result.get("target") != target or result.get("action") != "added" or
                result.get("profile_format") != expected_format or
                type(result.get("configured_clients")) is not int or
                not 0 <= result["configured_clients"] <= 100000 or
                type(result.get("cleanup_required")) is not bool):
            raise AmneziaControlError("Invalid Amnezia result")
        _client(result.get("client"))
        fields = ("target", "action", "client", "configured_clients",
                  "cleanup_required", "profile_format")
        public = {field: result[field] for field in fields}
        public["sealed_profile"] = _envelope(result["sealed_profile"])
        return public
    if action == "revoke":
        if (result.get("target") != target or result.get("action") != "revoked" or
                type(result.get("configured_clients")) is not int or
                not 0 <= result["configured_clients"] <= 100000 or
                type(result.get("cleanup_required")) is not bool):
            raise AmneziaControlError("Invalid Amnezia result")
        _client(result.get("client"))
        return {field: result[field] for field in
                ("target", "action", "client", "configured_clients", "cleanup_required")}
    if action == "status":
        if (result.get("target") != target or
                type(result.get("enrolled")) is not bool or
                type(result.get("recovery_required")) is not bool):
            raise AmneziaControlError("Invalid Amnezia result")
        clients = result["owned_clients"]
        if not isinstance(clients, list) or any(_client(client) != client for client in clients):
            raise AmneziaControlError("Invalid Amnezia result")
        return {field: result[field] for field in
                ("target", "enrolled", "recovery_required", "owned_clients")}
    raise AmneziaControlError("Unsupported Amnezia action")


def dispatch(argv: list[str], admin: AmneziaAdmin | None = None) -> Any:
    action, args = parse_action(argv)
    target = argv[1]
    admin = admin if admin is not None else AmneziaAdmin(TARGETS[target])
    if action == "add-profile":
        result = admin.create_profile(*args[:4], route=args[4])
    elif action == "sealed-export":
        result = admin.sealed_export(*args)
    elif action == "revoke":
        result = admin.revoke(*args)
    elif action == "settings-preview":
        result = admin.settings_preview()
    elif action == "settings-plan":
        result = admin.settings_plan(*args)
    elif action == "settings-intent":
        result = admin.settings_intent(*args)
    elif action == "settings-apply":
        result = admin.settings_apply_confirmed(*args)
    else:
        result = admin.status()
    public = _public_result(action, result, target)
    if action in ("add-profile", "revoke") and public["client"] != args[0]:
        raise AmneziaControlError("Invalid Amnezia result")
    if action in ("settings-intent", "settings-apply"):
        if (public["config_sha256"] != (args[0] if action == "settings-intent" else args[2]) or
                public["generation"] != (args[1] if action == "settings-intent" else args[1] + 1) or
                (action == "settings-intent" and
                 public["proposed_config_sha256"] != args[2])):
            raise AmneziaControlError("Invalid Amnezia settings result")
        if action == "settings-intent" and not set(public["changed_fields"]) <= set(args[3]):
            raise AmneziaControlError("Invalid Amnezia settings result")
    return public


def _marker_enabled(marker: Path) -> bool:
    try:
        directory = marker.parent.lstat()
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or
                directory.st_mode & 0o077):
            return False
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size != 8):
                return False
            return os.read(fd, 9) == b"enabled\n"
        finally:
            os.close(fd)
    except OSError:
        return False


def _enabled(target: str = "awg2") -> bool:
    """Require an independent root-owned opt-in marker for each target."""
    if target not in TARGETS:
        return False
    return _marker_enabled(ENABLE_FILE if target == "awg2" else WIREGUARD_ENABLE_FILE)


def _settings_enabled() -> bool:
    return _enabled("awg2") and _marker_enabled(SETTINGS_ENABLE_FILE)


def _encode_response(response: dict[str, Any]) -> bytes:
    payload = (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > MAX_RESPONSE:
        return b'{"ok":false,"error":"Amnezia response is too large"}\n'
    return payload


def serve_one(connection: socket.socket, agent_uid: int) -> None:
    connection.settimeout(5)
    try:
        peer = peer_identity(connection)
        if not authorized_peer(peer, agent_uid):
            raise AmneziaControlError("Amnezia access denied")
        request = json.loads(_receive_line(connection, MAX_REQUEST))
        if not isinstance(request, dict) or set(request) != {"argv"}:
            raise AmneziaControlError("Invalid Amnezia request")
        action, _ = parse_action(request["argv"])
        if not authorized_peer(peer, agent_uid):
            raise AmneziaControlError("Amnezia access denied")
        if not _enabled(request["argv"][1]):
            raise AmneziaControlError("Amnezia control is disabled")
        if action in ("settings-intent", "settings-apply") and not _settings_enabled():
            raise AmneziaControlError("Amnezia settings control is disabled")
        response = {"ok": True, "result": dispatch(request["argv"])}
    except (AmneziaControlError, AmneziaAdminError) as exc:
        response = {"ok": False, "error": str(exc)}
    except (ValueError, TypeError, UnicodeError):
        response = {"ok": False, "error": "Invalid Amnezia request"}
    except Exception as exc:
        print(f"Amnezia broker internal error: {type(exc).__name__}", file=sys.stderr)
        response = {"ok": False, "error": "Amnezia operation failed"}
    try:
        connection.sendall(_encode_response(response))
    except OSError:
        pass


def broker_main() -> int:
    if os.geteuid() != 0 or not (_enabled("awg2") or _enabled("wireguard")):
        print("Amnezia broker requires root and explicit opt-in", file=sys.stderr)
        return 1
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        print("Amnezia broker requires its systemd socket", file=sys.stderr)
        return 1
    listener = socket.socket(fileno=3)
    if (listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM or
            listener.getsockname() != SOCKET_PATH):
        print("Amnezia broker received an unexpected socket", file=sys.stderr)
        return 1
    agent_uid = pwd.getpwnam("sovagrid").pw_uid
    while True:
        connection, _ = listener.accept()
        with connection:
            child = os.fork()
            if child == 0:
                try:
                    os.setsid()
                    listener.close()
                    serve_one(connection, agent_uid)
                finally:
                    os._exit(0)
            deadline = time.monotonic() + MAX_OPERATION_SECONDS
            while True:
                done, _status = os.waitpid(child, os.WNOHANG)
                if done:
                    break
                if time.monotonic() >= deadline:
                    try:
                        os.killpg(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.waitpid(child, 0)
                    try:
                        connection.sendall(_encode_response({"ok": False,
                            "error": "Amnezia operation timed out; inspect recovery state"}))
                    except OSError:
                        pass
                    break
                time.sleep(0.05)


def client_main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        parse_action(argv)
        request = (json.dumps({"argv": argv}, separators=(",", ":")) + "\n").encode()
        if len(request) > MAX_REQUEST:
            raise AmneziaControlError("Amnezia request is too large")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(SOCKET_PATH)
            connection.sendall(request)
            connection.settimeout(MAX_OPERATION_SECONDS + 5)
            response = json.loads(_receive_line(connection, MAX_RESPONSE))
        if (not isinstance(response, dict) or
                set(response) != ({"ok", "result"} if response.get("ok") is True else {"ok", "error"})):
            raise AmneziaControlError("Invalid Amnezia broker response")
        if response["ok"] is not True:
            raise AmneziaControlError(str(response["error"]))
        output = json.dumps(response["result"], sort_keys=True, separators=(",", ":"))
        if len(output.encode()) > MAX_RESPONSE:
            raise AmneziaControlError("Amnezia response is too large")
        print(output)
        return 0
    except (AmneziaControlError, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, AmneziaControlError) else
              "Amnezia broker unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("broker", "client"):
        print("Usage: python3 -m sovagrid_vpn.amnezia_control broker|client ACTION ...",
              file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(broker_main() if sys.argv[1] == "broker" else client_main(sys.argv[2:]))
