# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Minimal AWG 3.1 mobile profile renderer using Amnezia's native .conf keys.

Only the documented AWG interface fields are copied from the server. In
particular, server PrivateKey, shell hooks and routing scripts never enter a
client profile. The caller must keep the returned plaintext inside root memory
and immediately seal it for the recipient.
"""

from __future__ import annotations

import base64
import ipaddress
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


class ProfileError(ValueError):
    """A fixed error without configuration or key material."""


AWG_FIELDS = (
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey",
    "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
    "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts",
    "RandomTrailers", "DisableCookies",
)
REQUIRED_AWG3 = frozenset(("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
                          "H1", "H2", "H3", "H4", "HeaderProtectionKey"))
RANGE_FIELDS = frozenset(("H1", "H2", "H3", "H4", "ContentPaddingAddition",
                          "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
                          "KeepaliveTimeout", "MaxHandshakeAttempts"))
NUMBER_FIELDS = frozenset(("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"))
KEY_RE = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
RANGE_RE = re.compile(r"[0-9]{1,10}(?:-[0-9]{1,10})?\Z")
DOMAIN_RE = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\Z")


def _key(raw: str) -> bytes:
    if not isinstance(raw, str) or not KEY_RE.fullmatch(raw):
        raise ProfileError("Invalid AWG key")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ProfileError("Invalid AWG key") from exc
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != raw:
        raise ProfileError("Invalid AWG key")
    return decoded


def public_from_private(private_key: str) -> str:
    private = x25519.X25519PrivateKey.from_private_bytes(_key(private_key))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(public).decode("ascii")


def new_client_keypair() -> tuple[str, str]:
    private = x25519.X25519PrivateKey.generate()
    raw_private = private.private_bytes(serialization.Encoding.Raw,
                                        serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())
    encoded_private = base64.b64encode(raw_private).decode("ascii")
    return encoded_private, public_from_private(encoded_private)


def endpoint(host: str, port: int) -> str:
    if not isinstance(host, str) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ProfileError("Invalid AWG endpoint")
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        if (len(host) > 253 or not DOMAIN_RE.fullmatch(host) or
                any(not label or len(label) > 63 or label.startswith("-") or
                    label.endswith("-") for label in host.split("."))):
            raise ProfileError("Invalid AWG endpoint")
        return f"{host.lower()}:{port}"
    return f"[{parsed}]:{port}" if parsed.version == 6 else f"{parsed}:{port}"


def awg3_fields(interface_raw: bytes) -> dict[str, str]:
    if not isinstance(interface_raw, bytes) or len(interface_raw) > 16384:
        raise ProfileError("AWG3 server parameters invalid")
    try:
        source = interface_raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProfileError("AWG3 server parameters invalid") from exc
    values: dict[str, str] = {}
    for line in source.splitlines():
        if "=" not in line:
            continue
        name, value = (part.strip() for part in line.split("=", 1))
        if name not in AWG_FIELDS:
            continue
        if (name in values or not value or len(value) > 512 or
                any(ord(char) < 32 or ord(char) > 126 for char in value)):
            raise ProfileError("AWG3 server parameters invalid")
        if name in NUMBER_FIELDS and (not value.isascii() or not value.isdecimal() or
                                      int(value) > 65535):
            raise ProfileError("AWG3 server parameters invalid")
        if name in RANGE_FIELDS and not RANGE_RE.fullmatch(value):
            raise ProfileError("AWG3 server parameters invalid")
        if name in ("RandomTrailers", "DisableCookies") and value not in ("on", "off"):
            raise ProfileError("AWG3 server parameters invalid")
        if name == "HeaderProtectionKey":
            _key(value)
        values[name] = value
    if not REQUIRED_AWG3.issubset(values):
        raise ProfileError("AWG3 server parameters incomplete")
    if int(values["Jmin"]) > int(values["Jmax"]):
        raise ProfileError("AWG3 server parameters invalid")
    return values


def render_awg3_profile(*, interface_raw: bytes, server_private_key: str,
                        runtime_server_public_key: str, shared_psk: str,
                        client_private_key: str, client_address: ipaddress.IPv4Address,
                        server_network: ipaddress.IPv4Network, endpoint_host: str,
                        port: int, route: str) -> bytes:
    """Return a native AWG3 .conf with the exact server header settings."""
    if not isinstance(client_address, ipaddress.IPv4Address) or not isinstance(
            server_network, ipaddress.IPv4Network) or client_address not in server_network:
        raise ProfileError("Invalid AWG client address")
    if route not in ("split", "full"):
        raise ProfileError("Invalid AWG profile route")
    _key(client_private_key)
    _key(shared_psk)
    _key(runtime_server_public_key)
    server_public = public_from_private(server_private_key)
    if server_public != runtime_server_public_key:
        raise ProfileError("AWG server public key differs from runtime")
    fields = awg3_fields(interface_raw)
    allowed = str(server_network) if route == "split" else "0.0.0.0/0, ::/0"
    lines = ["[Interface]", f"Address = {client_address}/32", "MTU = 1280",
             f"PrivateKey = {client_private_key}"]
    lines += [f"{name} = {fields[name]}" for name in AWG_FIELDS if name in fields]
    lines += ["", "[Peer]", f"PublicKey = {server_public}",
              f"PresharedKey = {shared_psk}", f"AllowedIPs = {allowed}",
              f"Endpoint = {endpoint(endpoint_host, port)}", "PersistentKeepalive = 25", ""]
    profile = "\n".join(lines).encode("ascii")
    if len(profile) > 4096 - 16:
        raise ProfileError("AWG3 profile exceeds sealed export limit")
    return profile


def render_wireguard_profile(*, server_private_key: str,
                             runtime_server_public_key: str, shared_psk: str,
                             client_private_key: str,
                             client_address: ipaddress.IPv4Address,
                             server_network: ipaddress.IPv4Network,
                             endpoint_host: str, port: int, route: str) -> bytes:
    """Render only standard WireGuard fields from a verified Amnezia WG server."""
    if (not isinstance(client_address, ipaddress.IPv4Address) or
            not isinstance(server_network, ipaddress.IPv4Network) or
            client_address not in server_network):
        raise ProfileError("Invalid WireGuard client address")
    if route not in ("split", "full"):
        raise ProfileError("Invalid WireGuard profile route")
    _key(client_private_key)
    _key(shared_psk)
    _key(runtime_server_public_key)
    server_public = public_from_private(server_private_key)
    if server_public != runtime_server_public_key:
        raise ProfileError("WireGuard server public key differs from runtime")
    allowed = str(server_network) if route == "split" else "0.0.0.0/0, ::/0"
    profile = ("\n".join((
        "[Interface]", f"Address = {client_address}/32", "MTU = 1280",
        f"PrivateKey = {client_private_key}", "", "[Peer]",
        f"PublicKey = {server_public}", f"PresharedKey = {shared_psk}",
        f"AllowedIPs = {allowed}", f"Endpoint = {endpoint(endpoint_host, port)}",
        "PersistentKeepalive = 25", ""))).encode("ascii")
    if len(profile) > 4096 - 16:
        raise ProfileError("WireGuard profile exceeds sealed export limit")
    return profile
