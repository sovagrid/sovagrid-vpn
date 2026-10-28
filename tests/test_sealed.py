# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Client profiles leave the broker only as authenticated ciphertext."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sovagrid_vpn.control import ControlError, dispatch, parse_action
from sovagrid_vpn.managed import ManagedVpnError, ManagedWireGuard
from sovagrid_vpn.sealed import INFO, MAX_CIPHERTEXT_BYTES
from test_managed import FakeCommands


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SealedProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        wireguard_dir = self.root / "wireguard"
        wireguard_dir.mkdir(mode=0o700)
        fake = FakeCommands()
        fake.wg_dir = wireguard_dir
        self.manager = ManagedWireGuard(state_root=self.root / "state",
                                        wireguard_dir=wireguard_dir,
                                        runner=fake, require_root=False,
                                        check_network=False)
        self.manager.create("demo-vpn", 51821, "10.49.0.0/24", "8.8.8.8")
        self.profile_path = Path(self.manager.add_client("demo-vpn", "alice")["profile"])
        self.recipient = ec.generate_private_key(ec.SECP256R1())
        point = self.recipient.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.recipient_key = b64url(point)

    def decrypt(self, envelope: dict, aad: bytes) -> bytes:
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), unb64url(envelope["ephemeral_public_key"]))
        shared = self.recipient.exchange(ec.ECDH(), peer)
        key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=unb64url(envelope["salt"]), info=INFO).derive(shared)
        return AESGCM(key).decrypt(unb64url(envelope["nonce"]),
                                   unb64url(envelope["ciphertext"]), aad)

    def test_round_trip_and_authenticated_identity(self):
        envelope = dispatch(["sealed-export", "demo-vpn", "alice", self.recipient_key],
                            self.manager)
        self.assertEqual(set(envelope), {"version", "ephemeral_public_key", "salt",
                                         "nonce", "ciphertext"})
        self.assertEqual(envelope["version"], 1)
        self.assertEqual(len(unb64url(envelope["ephemeral_public_key"])), 65)
        self.assertEqual(len(unb64url(envelope["salt"])), 16)
        self.assertEqual(len(unb64url(envelope["nonce"])), 12)
        self.assertLessEqual(len(unb64url(envelope["ciphertext"])), MAX_CIPHERTEXT_BYTES)
        encoded = json.dumps(envelope)
        profile = self.profile_path.read_bytes()
        self.assertNotIn("PrivateKey", encoded)
        self.assertNotIn(profile.decode("ascii"), encoded)
        self.assertEqual(self.decrypt(envelope, b"SovaGrid profile\x00demo-vpn\x00alice"),
                         profile)
        again = dispatch(["sealed-export", "demo-vpn", "alice", self.recipient_key],
                         self.manager)
        self.assertNotEqual(again["ephemeral_public_key"], envelope["ephemeral_public_key"])
        self.assertNotEqual(again["nonce"], envelope["nonce"])
        with self.assertRaises(InvalidTag):
            self.decrypt(envelope, b"SovaGrid profile\x00other-vpn\x00alice")
        with self.assertRaises(InvalidTag):
            self.decrypt(envelope, b"SovaGrid profile\x00demo-vpn\x00bob")
        other = ec.generate_private_key(ec.SECP256R1())
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), unb64url(envelope["ephemeral_public_key"]))
        wrong_key = HKDF(algorithm=hashes.SHA256(), length=32,
                         salt=unb64url(envelope["salt"]), info=INFO).derive(
                             other.exchange(ec.ECDH(), peer))
        with self.assertRaises(InvalidTag):
            AESGCM(wrong_key).decrypt(unb64url(envelope["nonce"]),
                                      unb64url(envelope["ciphertext"]),
                                      b"SovaGrid profile\x00demo-vpn\x00alice")

    def test_rejects_malformed_or_wrong_curve_recipient_keys(self):
        for value in ("", "A" * 86, self.recipient_key + "=", "/etc/shadow",
                      b64url(b"\x04" + b"\x00" * 64), b64url(b"\x02" + b"\x00" * 64)):
            with self.subTest(value=value[:12]):
                try:
                    parse_action(["sealed-export", "demo-vpn", "alice", value])
                except ControlError:
                    continue
                with self.assertRaisesRegex(ManagedVpnError, "Invalid profile recipient key"):
                    dispatch(["sealed-export", "demo-vpn", "alice", value], self.manager)
        for argv in (["sealed-export", "demo-vpn", "alice", self.recipient_key, "extra"],
                     ["sealed-export", "../etc", "alice", self.recipient_key],
                     ["sealed-export", "demo-vpn", "alice/../bob", self.recipient_key]):
            with self.assertRaises(ControlError):
                parse_action(argv)

    def test_state_integrity_and_missing_client_are_enforced(self):
        with self.assertRaisesRegex(ManagedVpnError, "Client does not exist"):
            dispatch(["sealed-export", "demo-vpn", "bob", self.recipient_key], self.manager)
        self.profile_path.write_bytes(b"[Interface]\nPrivateKey = unexpected\n")
        with self.assertRaisesRegex(ManagedVpnError, "profile does not match"):
            dispatch(["sealed-export", "demo-vpn", "alice", self.recipient_key], self.manager)


if __name__ == "__main__":
    unittest.main()
