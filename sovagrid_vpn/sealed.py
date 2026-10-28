# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Encrypt a managed client profile for a browser-generated P-256 key.

The private recipient key stays in the browser. Only this root-side module
sees plaintext; every broker/Agent/Hub result contains ciphertext alone.
"""

from __future__ import annotations

import base64
import os
import re

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .managed import ManagedVpnError, validate_client, validate_name


INFO = b"SovaGrid sealed WireGuard profile v1"
MAX_CIPHERTEXT_BYTES = 4096
PUBLIC_KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{87}\Z")


def _base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_public_key(value: str) -> ec.EllipticCurvePublicKey:
    """Require canonical, unpadded base64url of an uncompressed P-256 point."""
    if not isinstance(value, str) or not PUBLIC_KEY_PATTERN.fullmatch(value):
        raise ManagedVpnError("Invalid profile recipient key")
    try:
        encoded = base64.urlsafe_b64decode(value + "=")
        if len(encoded) != 65 or encoded[0] != 4 or _base64url(encoded) != value:
            raise ValueError("non-canonical point")
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded)
    except (ValueError, TypeError, base64.binascii.Error) as exc:
        raise ManagedVpnError("Invalid profile recipient key") from exc


def seal_profile(profile: bytes, recipient_public_key: str, name: str,
                 client: str) -> dict[str, str | int]:
    """Return authenticated ciphertext, with the instance and client bound as AAD."""
    name = validate_name(name)
    client = validate_client(client)
    recipient = decode_public_key(recipient_public_key)
    if not isinstance(profile, bytes) or not profile or len(profile) + 16 > MAX_CIPHERTEXT_BYTES:
        raise ManagedVpnError("Managed client profile exceeds sealed export limit")
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    salt = os.urandom(16)
    nonce = os.urandom(12)
    shared = ephemeral.exchange(ec.ECDH(), recipient)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=INFO).derive(shared)
    aad = b"SovaGrid profile\x00" + name.encode("ascii") + b"\x00" + client.encode("ascii")
    ciphertext = AESGCM(key).encrypt(nonce, profile, aad)
    ephemeral_public = ephemeral.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return {"version": 1, "ephemeral_public_key": _base64url(ephemeral_public),
            "salt": _base64url(salt), "nonce": _base64url(nonce),
            "ciphertext": _base64url(ciphertext)}
