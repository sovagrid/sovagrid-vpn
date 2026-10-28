# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Narrow Unix-socket control plane for SovaGrid-owned WireGuard only.

The client is unprivileged. A root systemd service repeats all validation and
performs the operation; neither side accepts paths, Python code, or commands.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import signal
import socket
import sys
import time
from typing import Any

from .managed import (ManagedVpnError, ManagedWireGuard, validate_client,
                      validate_endpoint, validate_name, validate_network)
from .peer_auth import authorized_peer, peer_identity


SOCKET_PATH = "/run/sovagrid-vpn/control.sock"
MAX_REQUEST = 4096
MAX_RESPONSE = 8192
MAX_OPERATION_SECONDS = 95
OPERATIONS = frozenset({"create", "activate", "add-client", "revoke-client",
                        "remove", "instances", "clients", "sealed-export"})


class ControlError(ValueError):
    """A safe public protocol or argument error."""


def parse_action(argv: Any) -> tuple[str, tuple[Any, ...]]:
    """Require one exact argv grammar, including the order of named fields."""
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 8 or
            any(not isinstance(item, str) or len(item.encode("utf-8")) > 253
                or any(ord(char) < 32 or ord(char) == 127 for char in item)
                for item in argv)):
        raise ControlError("Invalid VPN request")
    action = argv[0]
    if action not in OPERATIONS:
        raise ControlError("Unsupported VPN action")
    try:
        if action == "create" and len(argv) == 8 and argv[2] == "--port" and argv[4] == "--subnet" and argv[6] == "--endpoint":
            name = validate_name(argv[1])
            if not argv[3].isascii() or not argv[3].isdecimal() or len(argv[3]) > 5:
                raise ControlError("Invalid UDP port")
            port = int(argv[3])
            if not 1024 <= port <= 65535:
                raise ControlError("Invalid UDP port")
            subnet = str(validate_network(argv[5]))
            endpoint = validate_endpoint(argv[7])
            return action, (name, port, subnet, endpoint)
        if action in ("activate", "clients") and len(argv) == 2:
            return action, (validate_name(argv[1]),)
        if action in ("add-client", "revoke-client") and len(argv) == 3:
            return action, (validate_name(argv[1]), validate_client(argv[2]))
        if action == "sealed-export" and len(argv) in (4, 6):
            name, client, public_key = validate_name(argv[1]), validate_client(argv[2]), argv[3]
            # The on-curve check happens in the broker after this syntax/size check.
            if not re.fullmatch(r"[A-Za-z0-9_-]{87}", public_key):
                raise ControlError("Invalid profile recipient key")
            if len(argv) == 6:
                if argv[4:] != ["--route", "full"]:
                    raise ControlError("Invalid VPN client route")
                return action, (name, client, public_key, "full")
            return action, (name, client, public_key)
        if action == "remove" and len(argv) == 4 and argv[2] == "--confirm-name":
            name = validate_name(argv[1])
            if argv[3] != name:
                raise ControlError("Confirmation must match the instance name")
            return action, (name, name)
        if action == "instances" and len(argv) == 1:
            return action, ()
    except ManagedVpnError as exc:
        raise ControlError(str(exc)) from exc
    raise ControlError("Invalid VPN action arguments")


def _public_result(action: str, result: Any) -> Any:
    """Choose fields explicitly; never forward new manager fields by default."""
    if action in ("create", "activate"):
        fields = ("name", "interface", "endpoint", "port", "subnet", "clients", "active")
        return {key: result[key] for key in fields}
    if action == "add-client":
        return {key: result[key] for key in ("name", "address", "active", "existing")}
    if action == "revoke-client":
        return {key: result[key] for key in ("name", "revoked", "already_absent")}
    if action == "remove":
        return {key: result[key] for key in ("name", "removed")}
    if action == "clients":
        return [{key: row[key] for key in ("name", "address")} for row in result]
    if action == "instances":
        fields = ("name", "interface", "endpoint", "port", "subnet", "clients", "active")
        return [{key: row[key] for key in fields} for row in result]
    if action == "sealed-export":
        fields = ("version", "ephemeral_public_key", "salt", "nonce", "ciphertext")
        return {key: result[key] for key in fields}
    raise ControlError("Unsupported VPN action")


def dispatch(argv: list[str], manager: ManagedWireGuard | None = None) -> Any:
    action, arguments = parse_action(argv)
    manager = manager if manager is not None else ManagedWireGuard()
    method = getattr(manager, {"create": "create", "activate": "activate",
                               "add-client": "add_client", "revoke-client": "revoke_client",
                               "remove": "remove", "instances": "instances",
                               "clients": "clients", "sealed-export": "sealed_export"}[action])
    if action == "sealed-export" and len(arguments) == 4:
        return _public_result(action, method(*arguments[:3], route=arguments[3]))
    return _public_result(action, method(*arguments))


def _receive_line(connection: socket.socket, limit: int) -> bytes:
    payload = bytearray()
    while True:
        chunk = connection.recv(limit + 1 - len(payload))
        if not chunk:
            raise ControlError("Incomplete VPN request")
        payload.extend(chunk)
        if len(payload) > limit:
            raise ControlError("VPN message is too large")
        if b"\n" in chunk:
            if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
                raise ControlError("Invalid VPN message framing")
            return bytes(payload[:-1])


def _encode_response(response: dict[str, Any]) -> bytes:
    payload = (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > MAX_RESPONSE:
        payload = b'{"ok":false,"error":"VPN response is too large"}\n'
    return payload


def serve_one(connection: socket.socket, agent_uid: int) -> None:
    connection.settimeout(5)
    try:
        peer = peer_identity(connection)
        if not authorized_peer(peer, agent_uid):
            raise ControlError("VPN access denied")
        raw = _receive_line(connection, MAX_REQUEST)
        request = json.loads(raw)
        if not isinstance(request, dict) or set(request) != {"argv"}:
            raise ControlError("Invalid VPN request")
        # An Agent restart while a request is read invalidates the old peer.
        if not authorized_peer(peer, agent_uid):
            raise ControlError("VPN access denied")
        # Do not accept client-supplied identity, role, paths or environment.
        result = dispatch(request["argv"])
        response = {"ok": True, "result": result}
    except (ControlError, ManagedVpnError) as exc:
        response = {"ok": False, "error": str(exc)}
    except (ValueError, TypeError, UnicodeError):
        response = {"ok": False, "error": "Invalid VPN request"}
    except Exception as exc:
        # Never send subprocess stderr, file contents, keys or tracebacks.
        print(f"VPN broker internal error: {type(exc).__name__}", file=sys.stderr)
        response = {"ok": False, "error": "VPN operation failed"}
    try:
        connection.sendall(_encode_response(response))
    except OSError:
        pass


def broker_main() -> int:
    if os.geteuid() != 0:
        print("VPN broker requires root", file=sys.stderr)
        return 1
    agent_uid = pwd.getpwnam("sovagrid").pw_uid
    # systemd socket activation passes exactly one listening AF_UNIX socket at fd 3.
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        print("VPN broker requires its systemd socket", file=sys.stderr)
        return 1
    listener = socket.socket(fileno=3)
    if (listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM or
            listener.getsockname() != SOCKET_PATH):
        print("VPN broker received an unexpected socket", file=sys.stderr)
        return 1
    while True:
        connection, _ = listener.accept()
        with connection:
            # A separate process bounds the whole transaction, including a
            # sequence of individually timed-out wg/systemctl subprocesses.
            # Its process group is killed on timeout; the manager's durable
            # transaction journal can be recovered on the next request.
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
                        connection.sendall(_encode_response(
                            {"ok": False, "error": "VPN operation timed out; inspect state before retry"}))
                    except OSError:
                        pass
                    break
                time.sleep(0.05)


def client_main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        parse_action(argv)
        request = (json.dumps({"argv": argv}, separators=(",", ":")) + "\n").encode("utf-8")
        if len(request) > MAX_REQUEST:
            raise ControlError("VPN request is too large")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(SOCKET_PATH)
            connection.sendall(request)
            connection.settimeout(100)
            response = json.loads(_receive_line(connection, MAX_RESPONSE))
        if not isinstance(response, dict) or set(response) != ({"ok", "result"} if response.get("ok") is True else {"ok", "error"}):
            raise ControlError("Invalid VPN broker response")
        if response["ok"] is not True:
            raise ControlError(str(response["error"]))
        output = json.dumps(response["result"], sort_keys=True, separators=(",", ":"))
        if len(output.encode("utf-8")) > MAX_RESPONSE:
            raise ControlError("VPN response is too large")
        print(output)
        return 0
    except (ControlError, OSError, ValueError) as exc:
        message = str(exc) if isinstance(exc, ControlError) else "VPN broker unavailable"
        print(message, file=sys.stderr)
        return 2
