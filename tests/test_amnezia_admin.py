# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Fault-injected, rootless tests for opt-in Amnezia peer administration."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sovagrid_vpn.amnezia_admin import (AmneziaAdmin, AmneziaAdminError,
                                         TARGETS, Target, _awg_header_key,
                                         _config, _preview_awg_parameters)
from sovagrid_vpn.amnezia_profile import public_from_private
from sovagrid_vpn.sealed import INFO


def key(number: int) -> str:
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


CONTAINER_ID = "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
AWG3_FIELDS = (f"Jc = 4\nJmin = 10\nJmax = 50\nS1 = 24\nS2 = 24\n"
               f"S3 = 24\nS4 = 24\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"
               f"HeaderProtectionKey = {key(10)}\nContentPaddingAddition = 10-100\n"
               "RandomTrailers = on\nDisableCookies = on\n")


def recipient_key():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return private, base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii")


def decrypt_sealed(envelope, recipient, target, client):
    ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), base64.urlsafe_b64decode(envelope["ephemeral_public_key"] + "="))
    salt = base64.urlsafe_b64decode(envelope["salt"] + "==")
    nonce = base64.urlsafe_b64decode(envelope["nonce"] + "==")
    ciphertext = base64.urlsafe_b64decode(envelope["ciphertext"] + "==")
    secret = recipient.exchange(ec.ECDH(), ephemeral)
    key_bytes = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=INFO).derive(secret)
    aad = b"SovaGrid profile\0" + target.encode() + b"\0" + client.encode()
    return AESGCM(key_bytes).decrypt(nonce, ciphertext, aad)


class FakeDocker:
    def __init__(self, target: Target):
        self.target = target
        self.calls = []
        self.files = {
            target.config_path: (f"[Interface]\nAddress = 10.44.0.1/24\n"
                                 f"PrivateKey = {key(1)}\nListenPort = 49289\n\n"
                                 f"[Peer]\nPublicKey = {key(2)}\n"
                                 f"PresharedKey = {key(9)}\nAllowedIPs = 10.44.0.2/32\n\n").encode(),
            target.table_path: json.dumps([{"clientId": key(2), "userData": {
                "clientName": "Existing", "otherMetadata": "PRESERVE"}}]).encode() + b"\n",
            target.psk_path: (key(9) + "\n").encode(),
        }
        self.runtime_config = self.files[target.config_path]
        self.modes = {path: "600" for path in self.files}
        self.fail_write_once = None
        self.fail_sync_once = False
        self.ignore_sync_once = False
        self.image_name = target.image_name
        self.container_id = CONTAINER_ID
        self.mounts = []
        self.interface_down = False
        self.dynamic_runtime = False
        self.traffic_counter = 0
        self.unsupported_awg_selector = None
        self.awg_show_override = {}

    def __call__(self, command, **kwargs):
        command = tuple(command)
        self.calls.append(command)
        if command[:3] == ("docker", "exec", "--user"):
            if command[3] != "0:0":
                raise AssertionError("Docker exec must use container root")
            command = command[:2] + command[4:]
        data = b""
        code = 0
        if command[:3] == ("docker", "container", "inspect"):
            if command[4] == "{{json .Mounts}}":
                data = json.dumps(self.mounts).encode() + b"\n"
            else:
                data = (f"{self.container_id} {IMAGE_ID} {self.image_name} "
                        f"/{self.target.container} true\n").encode()
        elif command[:3] == ("docker", "exec", self.target.container):
            if command[3:6] == ("stat", "-c", "%u:%g:%a:%F:%h"):
                code = 0 if command[6] in self.files else 1
                data = (f"0:0:{self.modes[command[6]]}:regular file:1\n".encode()
                        if code == 0 else b"")
            elif command[3:6] == ("head", "-c", "65537"):
                raw = self.files.get(command[6])
                code = 0 if raw is not None else 1
                data = raw[:65537] if raw is not None else b""
            elif command[3:] == (self.target.binary, "show", self.target.interface, "dump"):
                if self.interface_down:
                    return subprocess.CompletedProcess(command, 1, b"", b"SECRET_PRIVATE_KEY")
                config = _config(self.runtime_config)
                lines = [f"{key(1)}\t{public_from_private(key(1))}\t49289\toff"]
                if self.dynamic_runtime:
                    self.traffic_counter += 1
                sequence = self.traffic_counter
                endpoint = f"192.0.2.{sequence % 200 + 1}:5555" if sequence else "(none)"
                lines += [f"{peer.key}\t{peer.psk}\t{endpoint}\t{peer.address}/32\t"
                          f"{sequence}\t{sequence * 128}\t{sequence * 256}\toff"
                          for peer in config.peers]
                data = ("\n".join(lines) + "\n").encode()
            elif (command[3:6] == (self.target.binary, "show", self.target.interface)
                  and len(command) == 7 and self.target.binary == "awg"):
                selector = command[6]
                if selector == self.unsupported_awg_selector:
                    code = 1
                elif selector in self.awg_show_override:
                    data = (self.awg_show_override[selector] + "\n").encode()
                elif selector == "header-protection-key":
                    data = (_awg_header_key(_config(self.runtime_config).interface_raw) + "\n").encode()
                else:
                    parameters, _ = _preview_awg_parameters(_config(self.runtime_config).interface_raw)
                    name = selector.upper() if selector[0] in ("s", "h") else selector.capitalize()
                    if name not in parameters:
                        code = 1
                    else:
                        data = (parameters[name] + "\n").encode()
            elif command[3:5] == ("bash", "-c"):
                if self.fail_sync_once:
                    self.fail_sync_once = False
                    code = 1
                elif self.ignore_sync_once:
                    # Model a successful syncconf that did not change AWG3
                    # parameters in the kernel.
                    self.ignore_sync_once = False
                else:
                    self.runtime_config = self.files[self.target.config_path]
            else:
                raise AssertionError(f"unexpected Docker operation {command!r}")
        elif command[:4] == ("docker", "exec", "-i", self.target.container):
            path = command[-2]
            if self.fail_write_once == path:
                self.fail_write_once = None
                code = 1
            else:
                self.files[path] = kwargs["input"]
        else:
            raise AssertionError(f"unexpected Docker operation {command!r}")
        return subprocess.CompletedProcess(command, code, data, b"SECRET_PRIVATE_KEY")


class AmneziaAdminTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        canonical = TARGETS["awg2"]
        self.target = Target("fixture-awg", "sg-amnezia-fixture-awg",
                             canonical.image_name, canonical.binary,
                             canonical.interface, canonical.config_path,
                             canonical.table_path, canonical.psk_path)
        self.fake = FakeDocker(self.target)
        self.admin = AmneziaAdmin(self.target, state_root=Path(self.temp.name) / "state",
                                  runner=self.fake, require_root=False)

    def enroll(self):
        self.assertTrue(self.admin.enroll(CONTAINER_ID)["enrolled"])

    def empty_awg3(self):
        self.fake.files[self.target.config_path] = (
            f"[Interface]\nAddress = 10.44.0.1/24\nPrivateKey = {key(1)}\n"
            f"ListenPort = 49289\n{AWG3_FIELDS}\n").encode()
        self.fake.files[self.target.table_path] = b"[]\n"
        self.fake.runtime_config = self.fake.files[self.target.config_path]
        self.enroll()

    def test_enroll_pins_identity_and_rejects_wrong_confirmation(self):
        with self.assertRaisesRegex(AmneziaAdminError, "confirmation"):
            self.admin.enroll("c" * 64)
        self.enroll()
        self.fake.container_id = "c" * 64
        with self.assertRaisesRegex(AmneziaAdminError, "identity changed"):
            self.admin.add("phone", key(3), "10.44.0.3")
        self.assertNotIn(key(3).encode(), self.fake.files[self.target.config_path])

    def test_enroll_preview_is_secret_free_and_pinned_at_confirmation(self):
        before = dict(self.fake.files)
        preview = self.admin.enroll_preview()
        self.assertEqual(preview["target"], self.target.name)
        self.assertEqual(preview["container_id"], CONTAINER_ID)
        self.assertEqual(preview["image_id"], IMAGE_ID)
        self.assertEqual(preview["configured_clients"], 1)
        self.assertEqual(preview["listen_port"], 49289)
        self.assertEqual(preview["server_subnet"], "10.44.0.0/24")
        self.assertEqual(self.fake.files, before)
        output = json.dumps(preview)
        for secret_or_identity in (key(1), key(2), key(9), "Existing", "PRESERVE"):
            self.assertNotIn(secret_or_identity, output)

        pins = {"confirm_image_id": preview["image_id"],
                "confirm_config_sha256": preview["config_sha256"],
                "confirm_table_sha256": preview["table_sha256"]}
        self.fake.files[self.target.table_path] += b" "
        with self.assertRaisesRegex(AmneziaAdminError, "preview changed"):
            self.admin.enroll(preview["container_id"], **pins)
        self.assertFalse(self.admin._state_path.exists())
        self.fake.files[self.target.table_path] = before[self.target.table_path]
        with self.assertRaisesRegex(AmneziaAdminError, "pins are required"):
            self.admin.enroll(preview["container_id"],
                              confirm_image_id=preview["image_id"])
        self.assertTrue(self.admin.enroll(preview["container_id"], **pins)["enrolled"])

    def test_add_revoke_preserve_existing_peer_and_registry(self):
        self.enroll()
        before_config = self.fake.files[self.target.config_path]
        before_table = self.fake.files[self.target.table_path]
        added = self.admin.add("phone", key(3), "10.44.0.3")
        self.assertEqual(added["configured_clients"], 2)
        self.assertTrue(self.fake.files[self.target.config_path].startswith(before_config))
        self.assertEqual(self.admin.status()["owned_clients"], ["phone"])
        rows = json.loads(self.fake.files[self.target.table_path])
        self.assertEqual(rows[0], json.loads(before_table)[0])
        self.assertEqual(rows[1]["userData"]["clientName"], "phone")
        revoked = self.admin.revoke("phone")
        self.assertEqual(revoked["configured_clients"], 1)
        self.assertEqual(self.fake.files[self.target.config_path], before_config)
        self.assertEqual(json.loads(self.fake.files[self.target.table_path]),
                         json.loads(before_table))
        self.assertEqual(self.admin.status()["owned_clients"], [])
        commands = "\n".join(" ".join(command) for command in self.fake.calls)
        self.assertNotIn(key(1), commands)
        self.assertNotIn(key(9), commands)

    def test_settings_preview_is_pinned_consistent_and_secret_free(self):
        self.fake.files[self.target.config_path] = self.fake.files[self.target.config_path].replace(
            b"ListenPort = 49289\n\n", b"ListenPort = 49289\n" + AWG3_FIELDS.encode() + b"\n")
        self.fake.runtime_config = self.fake.files[self.target.config_path]
        self.enroll()
        before_files = dict(self.fake.files)
        before_calls = len(self.fake.calls)
        state, _ = self.admin._load_state()
        preview = self.admin.settings_preview()
        self.assertEqual(preview["container_id"], CONTAINER_ID)
        self.assertEqual(preview["image_id"], IMAGE_ID)
        self.assertEqual(preview["config_sha256"], state["config_sha256"])
        self.assertEqual(preview["table_sha256"], state["table_sha256"])
        self.assertEqual(preview["listen_port"], 49289)
        self.assertEqual(preview["server_subnet"], "10.44.0.0/24")
        self.assertEqual(preview["configured_clients"], 1)
        self.assertEqual(preview["managed_clients"], 0)
        self.assertEqual(preview["external_clients"], 1)
        self.assertEqual(preview["awg_parameters"]["Jc"], "4")
        self.assertEqual(preview["awg_parameters"]["H4"], "4")
        self.assertFalse(preview["awg_parameters_runtime_verified"])
        self.assertTrue(preview["header_protection_key_present"])
        self.assertTrue(preview["awg3_required_parameters_present"])
        self.assertFalse(preview["apply_supported"])
        self.assertEqual(self.fake.files, before_files)
        later_calls = self.fake.calls[before_calls:]
        self.assertFalse(any("-i" in call or "syncconf" in " ".join(call)
                             for call in later_calls))
        serialized = json.dumps(preview)
        self.assertLessEqual(len(json.dumps(preview, sort_keys=True,
                                            separators=(",", ":")).encode()) + 1, 4096)
        for secret_or_identity in (key(1), key(2), key(9), key(10), "Existing",
                                   "HeaderProtectionKey", "otherMetadata"):
            self.assertNotIn(secret_or_identity, serialized)

    def test_settings_preview_rejects_pending_drift_and_identity_change(self):
        self.enroll()
        self.admin._pending_path.write_bytes(b"pending")
        with self.assertRaisesRegex(AmneziaAdminError, "requires recovery"):
            self.admin.settings_preview()
        self.admin._pending_path.unlink()
        self.fake.files[self.target.table_path] += b" "
        with self.assertRaisesRegex(AmneziaAdminError, "outside SovaGrid"):
            self.admin.settings_preview()
        self.fake.files[self.target.table_path] = self.fake.files[self.target.table_path][:-1]
        self.fake.container_id = "c" * 64
        with self.assertRaisesRegex(AmneziaAdminError, "identity changed"):
            self.admin.settings_preview()

    def test_settings_preview_rejects_invalid_awg_parameter(self):
        self.fake.files[self.target.config_path] = self.fake.files[self.target.config_path].replace(
            b"ListenPort = 49289\n\n", b"ListenPort = 49289\nJc = 65536\n\n")
        self.fake.runtime_config = self.fake.files[self.target.config_path]
        self.enroll()
        with self.assertRaisesRegex(AmneziaAdminError, "server parameters invalid"):
            self.admin.settings_preview()

    def test_settings_preview_rejects_runtime_peer_drift(self):
        self.enroll()
        self.fake.runtime_config = self.fake.runtime_config.split(b"[Peer]")[0]
        with self.assertRaisesRegex(AmneziaAdminError, "config, registry and runtime differ"):
            self.admin.settings_preview()

    def test_settings_plan_is_cas_pinned_read_only_and_requires_reissue(self):
        self.fake.files[self.target.config_path] = self.fake.files[self.target.config_path].replace(
            b"ListenPort = 49289\n\n", b"ListenPort = 49289\n" + AWG3_FIELDS.encode() + b"\n")
        self.fake.runtime_config = self.fake.files[self.target.config_path]
        self.enroll()
        preview = self.admin.settings_preview()
        before_files = dict(self.fake.files)
        before_calls = len(self.fake.calls)
        result = self.admin.settings_plan(preview["config_sha256"], preview["generation"],
                                          {"Jc": "5", "H1": "8-9"})
        self.assertEqual(result["changed_fields"], ["H1", "Jc"])
        self.assertEqual(result["proposed_awg_parameters"]["H1"], "8-9")
        self.assertNotEqual(result["proposed_config_sha256"], preview["config_sha256"])
        self.assertFalse(result["apply_supported"])
        self.assertEqual(result["apply_blockers"],
                         ["CLIENT_PROFILES_REQUIRE_REISSUE"])
        self.assertEqual(self.fake.files, before_files)
        self.assertFalse(any("-i" in call or "syncconf" in " ".join(call)
                             for call in self.fake.calls[before_calls:]))
        for invalid in ({"Jc": "65536"}, {"Jc": "04"}, {"Jmin": "51"},
                        {"S1": "11"},
                        {"PrivateKey": "secret"}, {"H1": "9-8"}):
            with self.subTest(invalid=invalid), self.assertRaises(AmneziaAdminError):
                self.admin.settings_plan(preview["config_sha256"], preview["generation"], invalid)
        boundary = self.admin.settings_plan(preview["config_sha256"], preview["generation"],
                                            {"S1": "12"})
        self.assertEqual(boundary["proposed_awg_parameters"]["S1"], "12")
        with self.assertRaisesRegex(AmneziaAdminError, "preview changed"):
            self.admin.settings_plan(preview["config_sha256"], preview["generation"] + 1,
                                     {"Jc": "5"})
        with self.assertRaisesRegex(AmneziaAdminError, "No Amnezia settings change"):
            self.admin.settings_plan(preview["config_sha256"], preview["generation"],
                                     {"Jc": "4"})

    def test_settings_plan_allows_only_zero_client_runtime_verified_apply(self):
        self.fake.files[self.target.config_path] = (
            f"[Interface]\nAddress = 10.44.0.1/24\nPrivateKey = {key(1)}\n"
            f"ListenPort = 49289\n{AWG3_FIELDS}\n").encode()
        self.fake.files[self.target.table_path] = b"[]\n"
        self.fake.runtime_config = self.fake.files[self.target.config_path]
        self.enroll()
        preview = self.admin.settings_preview()
        plan = self.admin.settings_plan(preview["config_sha256"], preview["generation"],
                                        {"Jc": "5"})
        self.assertEqual(plan["configured_clients"], 0)
        self.assertEqual(plan["apply_blockers"], [])
        self.assertTrue(plan["apply_supported"])

    def test_zero_client_awg3_numeric_apply_is_cas_pinned_and_verified(self):
        self.empty_awg3()
        old_config = self.fake.files[self.target.config_path]
        old_table = self.fake.files[self.target.table_path]
        preview = self.admin.settings_preview()
        patch = {"Jc": "5", "H1": "8-9"}
        plan = self.admin.settings_plan(preview["config_sha256"],
                                        preview["generation"], patch)
        result = self.admin.settings_apply(preview["config_sha256"],
                                           preview["generation"],
                                           plan["proposed_config_sha256"], patch)
        self.assertEqual(result["action"], "settings_updated")
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["config_sha256"], plan["proposed_config_sha256"])
        self.assertFalse(result["cleanup_required"])
        self.assertEqual(self.fake.files[self.target.table_path], old_table)
        self.assertEqual(self.fake.runtime_config, self.fake.files[self.target.config_path])
        self.assertEqual(self.admin.settings_preview()["awg_parameters"]["Jc"], "5")
        self.assertNotEqual(self.fake.files[self.target.config_path], old_config)
        self.assertFalse(self.admin._pending_path.exists())
        for secret in (key(1), key(9), key(10)):
            self.assertNotIn(secret, json.dumps(result))
        with self.assertRaisesRegex(AmneziaAdminError, "preview changed"):
            self.admin.settings_apply(preview["config_sha256"], preview["generation"],
                                      plan["proposed_config_sha256"], patch)

    def test_awg3_apply_refuses_clients_wrong_pin_and_unsupported_selector(self):
        self.fake.files[self.target.config_path] = self.fake.files[self.target.config_path].replace(
            b"ListenPort = 49289\n\n", b"ListenPort = 49289\n" + AWG3_FIELDS.encode() + b"\n")
        self.fake.runtime_config = self.fake.files[self.target.config_path]
        self.enroll()
        preview = self.admin.settings_preview()
        plan = self.admin.settings_plan(preview["config_sha256"], 0, {"Jc": "5"})
        before = dict(self.fake.files)
        with self.assertRaisesRegex(AmneziaAdminError, "client profiles require reissue"):
            self.admin.settings_apply(preview["config_sha256"], 0,
                                      plan["proposed_config_sha256"], {"Jc": "5"})
        self.assertEqual(self.fake.files, before)

        other = AmneziaAdmin(self.target, state_root=Path(self.temp.name) / "empty",
                             runner=FakeDocker(self.target), require_root=False)
        # Separate empty fixture exercises both pins and selector refusal.
        self.empty_awg3_fixture(other)
        empty_preview = other.settings_preview()
        empty_plan = other.settings_plan(empty_preview["config_sha256"], 0, {"Jc": "5"})
        with self.assertRaisesRegex(AmneziaAdminError, "preview changed"):
            other.settings_apply(empty_preview["config_sha256"], 0,
                                 "f" * 64, {"Jc": "5"})
        other.runner.unsupported_awg_selector = "h1"
        with self.assertRaisesRegex(AmneziaAdminError, "Docker operation failed"):
            other.settings_apply(empty_preview["config_sha256"], 0,
                                 empty_plan["proposed_config_sha256"], {"Jc": "5"})
        self.assertFalse(other._pending_path.exists())

    @staticmethod
    def empty_awg3_fixture(admin):
        fake = admin.runner
        fake.files[admin.target.config_path] = (
            f"[Interface]\nAddress = 10.44.0.1/24\nPrivateKey = {key(1)}\n"
            f"ListenPort = 49289\n{AWG3_FIELDS}\n").encode()
        fake.files[admin.target.table_path] = b"[]\n"
        fake.runtime_config = fake.files[admin.target.config_path]
        admin.enroll(CONTAINER_ID)

    def test_awg3_apply_rolls_back_when_syncconf_skips_numeric_change(self):
        self.empty_awg3()
        preview = self.admin.settings_preview()
        plan = self.admin.settings_plan(preview["config_sha256"], 0, {"Jc": "5"})
        original = dict(self.fake.files)
        self.fake.ignore_sync_once = True
        with self.assertRaisesRegex(AmneziaAdminError, "rolled back"):
            self.admin.settings_apply(preview["config_sha256"], 0,
                                      plan["proposed_config_sha256"], {"Jc": "5"})
        self.assertEqual(self.fake.files, original)
        self.assertEqual(self.fake.runtime_config, original[self.target.config_path])
        self.assertFalse(self.admin._pending_path.exists())

    def test_awg3_broker_confirmation_is_exact_short_lived_and_single_use(self):
        self.empty_awg3()
        preview = self.admin.settings_preview()
        patch_value = {"Jc": "5"}
        plan = self.admin.settings_plan(preview["config_sha256"], 0, patch_value)
        intent = self.admin.settings_intent(preview["config_sha256"], 0,
                                            plan["proposed_config_sha256"], patch_value)
        self.assertEqual(intent["action"], "settings_intent")
        self.assertEqual(intent["configured_clients"], 0)
        self.assertEqual(len(intent["confirmation_id"]), 43)
        self.assertNotIn(intent["confirmation_id"],
                         self.admin._settings_intent_path.read_text())
        self.assertEqual(self.admin._settings_intent_path.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(AmneziaAdminError, "already pending"):
            self.admin.settings_intent(preview["config_sha256"], 0,
                                       plan["proposed_config_sha256"], patch_value)
        with self.assertRaisesRegex(AmneziaAdminError, "confirmation expired or changed"):
            self.admin.settings_apply_confirmed(preview["config_sha256"], 0,
                                                plan["proposed_config_sha256"], patch_value,
                                                "A" * 43)
        result = self.admin.settings_apply_confirmed(
            preview["config_sha256"], 0, plan["proposed_config_sha256"],
            patch_value, intent["confirmation_id"])
        self.assertEqual(result["action"], "settings_updated")
        self.assertFalse(self.admin._settings_intent_path.exists())
        with self.assertRaises(AmneziaAdminError):
            self.admin.settings_apply_confirmed(preview["config_sha256"], 0,
                                                plan["proposed_config_sha256"], patch_value,
                                                intent["confirmation_id"])

    def test_awg3_confirmation_expires_and_failed_apply_cannot_replay(self):
        self.empty_awg3()
        preview = self.admin.settings_preview()
        plan = self.admin.settings_plan(preview["config_sha256"], 0, {"Jc": "5"})
        intent = self.admin.settings_intent(preview["config_sha256"], 0,
                                            plan["proposed_config_sha256"], {"Jc": "5"})
        with patch("sovagrid_vpn.amnezia_admin.time.time",
                   return_value=intent["expires_at"]):
            with self.assertRaisesRegex(AmneziaAdminError, "expired or changed"):
                self.admin.settings_apply_confirmed(preview["config_sha256"], 0,
                                                    plan["proposed_config_sha256"],
                                                    {"Jc": "5"}, intent["confirmation_id"])
        self.assertEqual(self.fake.files[self.target.config_path], self.fake.runtime_config)
        # Expired handle may be replaced; a failed sync consumes the replacement.
        with patch("sovagrid_vpn.amnezia_admin.time.time",
                   return_value=intent["expires_at"] + 1):
            second = self.admin.settings_intent(preview["config_sha256"], 0,
                                                plan["proposed_config_sha256"], {"Jc": "5"})
            self.fake.ignore_sync_once = True
            with self.assertRaisesRegex(AmneziaAdminError, "rolled back"):
                self.admin.settings_apply_confirmed(preview["config_sha256"], 0,
                                                    plan["proposed_config_sha256"], {"Jc": "5"},
                                                    second["confirmation_id"])
            self.assertFalse(self.admin._settings_intent_path.exists())
            with self.assertRaisesRegex(AmneziaAdminError, "expired or changed"):
                self.admin.settings_apply_confirmed(preview["config_sha256"], 0,
                                                    plan["proposed_config_sha256"], {"Jc": "5"},
                                                    second["confirmation_id"])

    def test_awg3_interrupted_and_committed_recovery_verifies_numeric_runtime(self):
        self.empty_awg3()
        preview = self.admin.settings_preview()
        plan = self.admin.settings_plan(preview["config_sha256"], 0, {"Jc": "5"})
        old = self.fake.files[self.target.config_path]
        proposed = old.replace(b"Jc = 4\n", b"Jc = 5\n")
        _, state_raw = self.admin._load_state()
        with self.admin._locked():
            self.admin._prepare_pending(old, self.fake.files[self.target.table_path],
                                        state_raw, ("600", "600"), proposed,
                                        self.fake.files[self.target.table_path],
                                        kind="awg_settings")
        self.fake.files[self.target.config_path] = proposed
        self.fake.runtime_config = proposed
        self.assertTrue(self.admin.recover()["recovered"])
        self.assertEqual(self.fake.files[self.target.config_path], old)
        self.assertEqual(self.fake.runtime_config, old)

        with patch.object(self.admin, "_clear_pending", side_effect=OSError("injected")):
            result = self.admin.settings_apply(preview["config_sha256"], 0,
                                               plan["proposed_config_sha256"], {"Jc": "5"})
        self.assertTrue(result["cleanup_required"])
        self.assertTrue(self.admin._pending_path.exists())
        # A crash can occur after some backup files were already unlinked.
        (self.admin._pending_path / "config").unlink()
        (self.admin._pending_path / "new-config").unlink()
        self.assertTrue(self.admin.recover()["committed"])
        self.assertFalse(self.admin._pending_path.exists())
        self.assertEqual(self.fake.runtime_config, self.fake.files[self.target.config_path])

    def test_awg3_recovery_refuses_foreign_numeric_runtime(self):
        self.empty_awg3()
        old = self.fake.files[self.target.config_path]
        proposed = old.replace(b"Jc = 4\n", b"Jc = 5\n")
        _, state_raw = self.admin._load_state()
        with self.admin._locked():
            self.admin._prepare_pending(old, self.fake.files[self.target.table_path],
                                        state_raw, ("600", "600"), proposed,
                                        self.fake.files[self.target.table_path],
                                        kind="awg_settings")
        self.fake.files[self.target.config_path] = proposed
        self.fake.awg_show_override["jc"] = "9"
        before_writes = sum("-i" in call for call in self.fake.calls)
        with self.assertRaisesRegex(AmneziaAdminError, "runtime settings changed externally"):
            self.admin.recover()
        self.assertEqual(sum("-i" in call for call in self.fake.calls), before_writes)
        self.assertTrue(self.admin._pending_path.exists())

    def test_settings_plan_verifies_live_awg3_parameters_without_exposing_key(self):
        self.fake.files[self.target.config_path] = self.fake.files[self.target.config_path].replace(
            b"ListenPort = 49289\n\n", b"ListenPort = 49289\n" + AWG3_FIELDS.encode() + b"\n")
        self.fake.runtime_config = self.fake.files[self.target.config_path]
        self.enroll()
        preview = self.admin.settings_preview()
        original_files = dict(self.fake.files)
        self.fake.awg_show_override["h1"] = "1-1"
        plan = self.admin.settings_plan(preview["config_sha256"], preview["generation"],
                                        {"Jc": "5"})
        self.assertEqual(self.fake.files, original_files)
        selectors = [call[-1] for call in self.fake.calls if
                     len(call) >= 9 and call[-4:-2] == ("awg", "show") and call[-1] != "dump"]
        self.assertEqual(set(selectors), {name.lower() for name in
                         ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")}
                         | {"header-protection-key"})
        public = json.dumps(plan)
        self.assertNotIn(key(10), public)
        self.assertFalse(any(key(10) in " ".join(call) for call in self.fake.calls))

        self.fake.runtime_config = self.fake.runtime_config.replace(b"Jc = 4", b"Jc = 9")
        with self.assertRaisesRegex(AmneziaAdminError, "runtime parameters differ") as drift:
            self.admin.settings_plan(preview["config_sha256"], preview["generation"], {"Jc": "5"})
        self.assertNotIn(key(10), str(drift.exception))
        self.assertEqual(self.fake.files, original_files)

        self.fake.runtime_config = self.fake.files[self.target.config_path].replace(
            key(10).encode(), key(11).encode())
        with self.assertRaisesRegex(AmneziaAdminError, "runtime parameters differ") as key_drift:
            self.admin.settings_plan(preview["config_sha256"], preview["generation"], {"Jc": "5"})
        self.assertNotIn(key(11), str(key_drift.exception))
        self.assertEqual(self.fake.files, original_files)

        self.fake.runtime_config = self.fake.files[self.target.config_path]
        self.fake.unsupported_awg_selector = "h1"
        with self.assertRaisesRegex(AmneziaAdminError, "Docker operation failed"):
            self.admin.settings_plan(preview["config_sha256"], preview["generation"], {"Jc": "5"})
        self.assertEqual(self.fake.files, original_files)

    def test_owned_client_limit_prevents_unreadable_hub_status(self):
        self.enroll()
        before = dict(self.fake.files)
        state, raw = self.admin._load_state()
        state["owned"] = {f"client{i}": {} for i in range(128)}
        with patch.object(self.admin, "_load_state", return_value=(state, raw)), patch.object(
                self.admin, "_snapshot") as snapshot:
            with self.assertRaisesRegex(AmneziaAdminError, "client limit"):
                self.admin.add("newclient", key(3), "10.44.0.3")
            snapshot.assert_not_called()
        self.assertEqual(self.fake.files, before)

    def test_rejects_unknown_revoke_address_collision_and_external_drift(self):
        self.enroll()
        with self.assertRaisesRegex(AmneziaAdminError, "not owned"):
            self.admin.revoke("existing")
        with self.assertRaisesRegex(AmneziaAdminError, "already in use"):
            self.admin.add("phone", key(3), "10.44.0.2")
        self.fake.files[self.target.table_path] += b" "
        with self.assertRaisesRegex(AmneziaAdminError, "outside SovaGrid"):
            self.admin.add("phone", key(3), "10.44.0.3")

    def test_rejects_noncanonical_public_key_before_docker_write(self):
        self.enroll()
        original = key(3)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        index = alphabet.index(original[-2])
        noncanonical = original[:-2] + alphabet[(index & ~3) | ((index + 1) & 3)] + "="
        self.assertEqual(base64.b64decode(noncanonical), base64.b64decode(original))
        before = self.fake.files[self.target.config_path]
        with self.assertRaisesRegex(AmneziaAdminError, "Invalid WireGuard"):
            self.admin.add("phone", noncanonical, "10.44.0.3")
        self.assertEqual(self.fake.files[self.target.config_path], before)

    def test_write_failure_restores_exact_old_bytes_and_runtime(self):
        self.enroll()
        before = (self.fake.files[self.target.config_path],
                  self.fake.files[self.target.table_path], self.fake.runtime_config)
        self.fake.fail_write_once = self.target.table_path
        with self.assertRaisesRegex(AmneziaAdminError, "rolled back") as raised:
            self.admin.add("phone", key(3), "10.44.0.3")
        self.assertNotIn(key(3), str(raised.exception))
        self.assertEqual((self.fake.files[self.target.config_path],
                          self.fake.files[self.target.table_path],
                          self.fake.runtime_config), before)
        self.assertEqual(self.admin.status()["owned_clients"], [])
        self.assertFalse(self.admin._pending_path.exists())

    def test_sync_failure_restores_runtime_and_original_files(self):
        self.enroll()
        before = (self.fake.files[self.target.config_path],
                  self.fake.files[self.target.table_path], self.fake.runtime_config)
        self.fake.fail_sync_once = True
        with self.assertRaisesRegex(AmneziaAdminError, "rolled back"):
            self.admin.add("phone", key(3), "10.44.0.3")
        self.assertEqual((self.fake.files[self.target.config_path],
                          self.fake.files[self.target.table_path],
                          self.fake.runtime_config), before)

    def test_dynamic_handshake_endpoint_and_traffic_do_not_block_update(self):
        self.enroll()
        self.fake.dynamic_runtime = True
        self.assertEqual(self.admin.add("phone", key(3), "10.44.0.3")["action"], "added")
        self.assertEqual(self.admin.revoke("phone")["action"], "revoked")
        self.assertGreater(self.fake.traffic_counter, 3)

    def test_recover_interrupted_transaction_and_preserve_backup_permissions(self):
        self.enroll()
        state, state_raw = self.admin._load_state()
        config = self.fake.files[self.target.config_path]
        table = self.fake.files[self.target.table_path]
        new_config = config + (f"[Peer]\nPublicKey = {key(3)}\n"
                               f"PresharedKey = {key(9)}\n"
                               "AllowedIPs = 10.44.0.3/32\n").encode()
        with self.admin._locked():
            self.admin._prepare_pending(config, table, state_raw, ("600", "600"),
                                        new_config, table)
        self.assertEqual(self.admin._pending_path.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.admin._pending_path / "config").stat().st_mode & 0o777, 0o600)
        self.fake.files[self.target.config_path] = new_config
        with self.assertRaisesRegex(AmneziaAdminError, "requires recovery"):
            self.admin.add("other", key(4), "10.44.0.4")
        self.assertTrue(self.admin.recover()["recovered"])
        self.assertEqual(self.fake.files[self.target.config_path], config)
        self.assertEqual(self.fake.runtime_config, config)
        self.assertFalse(self.admin._pending_path.exists())

    def test_committed_cleanup_failure_can_be_finalized_without_revoking_client(self):
        self.enroll()
        with patch.object(self.admin, "_clear_pending", side_effect=OSError("injected cleanup")):
            result = self.admin.add("phone", key(3), "10.44.0.3")
        self.assertTrue(result["cleanup_required"])
        self.assertTrue(self.admin._pending_path.exists())
        with self.assertRaisesRegex(AmneziaAdminError, "requires recovery"):
            self.admin.revoke("phone")
        self.assertTrue(self.admin.recover()["committed"])
        self.assertFalse(self.admin._pending_path.exists())
        self.assertEqual(self.admin.status()["owned_clients"], ["phone"])

    def test_standard_wireguard_fixture_uses_same_strict_transaction(self):
        canonical = TARGETS["wireguard"]
        target = Target("fixture-wg", "sg-amnezia-fixture-wg", canonical.image_name,
                        canonical.binary, canonical.interface, canonical.config_path,
                        canonical.table_path, canonical.psk_path)
        fake = FakeDocker(target)
        admin = AmneziaAdmin(target, state_root=Path(self.temp.name) / "wg-state",
                             runner=fake, require_root=False)
        admin.enroll(CONTAINER_ID)
        preview = admin.settings_preview()
        self.assertEqual(preview["protocol"], "wireguard")
        self.assertEqual(preview["awg_parameters"], {})
        self.assertFalse(preview["header_protection_key_present"])
        self.assertEqual(admin.add("tablet", key(3), "10.44.0.3")["configured_clients"], 2)
        self.assertEqual(admin.revoke("tablet")["configured_clients"], 1)

    def test_standard_wireguard_profile_is_sealed_and_excludes_server_hooks(self):
        canonical = TARGETS["wireguard"]
        target = Target("fixture-wg-profile", "sg-amnezia-fixture-wg-profile",
                        canonical.image_name, canonical.binary, canonical.interface,
                        canonical.config_path, canonical.table_path, canonical.psk_path)
        fake = FakeDocker(target)
        fake.files[target.config_path] = fake.files[target.config_path].replace(
            b"ListenPort = 49289\n\n",
            b"ListenPort = 49289\nPostUp = /bin/echo SERVER_ONLY\n\n")
        fake.runtime_config = fake.files[target.config_path]
        admin = AmneziaAdmin(target, state_root=Path(self.temp.name) / "wg-profile-state",
                             runner=fake, require_root=False)
        admin.enroll(CONTAINER_ID)
        recipient_private, recipient_public = recipient_key()
        added = admin.create_profile("phone", "10.44.0.3", "vpn.example.com",
                                     recipient_public, route="full")
        self.assertEqual(added["profile_format"], "wg-conf")
        self.assertNotIn("PrivateKey", str(added))
        profile = decrypt_sealed(added["sealed_profile"], recipient_private,
                                 target.name, "phone")
        self.assertIn(b"AllowedIPs = 0.0.0.0/0, ::/0", profile)
        self.assertIn(b"Endpoint = vpn.example.com:49289", profile)
        self.assertIn(b"PresharedKey = " + key(9).encode(), profile)
        self.assertNotIn(key(1).encode(), profile)
        self.assertNotIn(b"SERVER_ONLY", profile)
        self.assertNotIn(b"PostUp", profile)
        self.assertNotIn(b"HeaderProtectionKey", profile)
        exported = admin.sealed_export("phone", recipient_public)
        self.assertEqual(decrypt_sealed(exported, recipient_private, target.name,
                                        "phone"), profile)
        with self.assertRaises(Exception):
            decrypt_sealed(exported, recipient_private, "awg2", "phone")
        admin.revoke("phone")
        with self.assertRaisesRegex(AmneziaAdminError, "no SovaGrid WireGuard profile"):
            admin.sealed_export("phone", recipient_public)

    def test_enroll_refuses_external_config_mount_or_down_interface(self):
        self.fake.mounts = [{"Type": "bind", "Destination": "/opt/amnezia/awg"}]
        with self.assertRaisesRegex(AmneziaAdminError, "mounted"):
            self.admin.enroll(CONTAINER_ID)
        self.fake.mounts = []
        self.fake.interface_down = True
        with self.assertRaisesRegex(AmneziaAdminError, "Docker operation failed"):
            self.admin.enroll(CONTAINER_ID)

    def test_observed_awg_file_modes_are_preserved(self):
        self.fake.modes[self.target.config_path] = "1"
        self.fake.modes[self.target.table_path] = "1"
        self.fake.modes[self.target.psk_path] = "644"
        self.enroll()
        self.admin.add("phone", key(3), "10.44.0.3")
        writes = [command for command in self.fake.calls if "-i" in command]
        self.assertEqual([command[-1] for command in writes], ["1", "1"])
        self.admin.revoke("phone")
        writes = [command for command in self.fake.calls if "-i" in command]
        self.assertEqual([command[-1] for command in writes], ["1", "1", "1", "1"])

    def test_rejects_world_readable_server_private_key(self):
        self.fake.modes[self.target.config_path] = "644"
        with self.assertRaisesRegex(AmneziaAdminError, "permissions are unsafe"):
            self.admin.enroll(CONTAINER_ID)

    def test_corrupt_backup_is_rejected_before_container_overwrite(self):
        self.enroll()
        _, state_raw = self.admin._load_state()
        config = self.fake.files[self.target.config_path]
        table = self.fake.files[self.target.table_path]
        with self.admin._locked():
            self.admin._prepare_pending(config, table, state_raw, ("600", "600"),
                                        config, table)
        backup = self.admin._pending_path / "config"
        backup.write_bytes(backup.read_bytes() + b"# corrupt\n")
        before_calls = len([command for command in self.fake.calls if "-i" in command])
        with self.assertRaisesRegex(AmneziaAdminError, "backup invalid"):
            self.admin.recover()
        after_calls = len([command for command in self.fake.calls if "-i" in command])
        self.assertEqual(after_calls, before_calls)

    def test_recovery_refuses_external_config_and_runtime_drift(self):
        self.enroll()
        _, state_raw = self.admin._load_state()
        config = self.fake.files[self.target.config_path]
        table = self.fake.files[self.target.table_path]
        with self.admin._locked():
            self.admin._prepare_pending(config, table, state_raw, ("600", "600"),
                                        config, table)
        self.fake.files[self.target.config_path] += b"# external change\n"
        with self.assertRaisesRegex(AmneziaAdminError, "changed externally"):
            self.admin.recover()
        self.assertTrue(self.admin._pending_path.exists())
        self.fake.files[self.target.config_path] = config
        self.fake.runtime_config += (f"[Peer]\nPublicKey = {key(4)}\n"
                                     f"PresharedKey = {key(9)}\n"
                                     "AllowedIPs = 10.44.0.4/32\n").encode()
        with self.assertRaisesRegex(AmneziaAdminError, "runtime changed externally"):
            self.admin.recover()
        self.assertTrue(self.admin._pending_path.exists())

    def test_awg3_profile_create_sealed_export_and_revoke(self):
        config = self.fake.files[self.target.config_path]
        self.fake.files[self.target.config_path] = config.replace(
            b"ListenPort = 49289\n\n", b"ListenPort = 49289\n" + AWG3_FIELDS.encode() + b"\n")
        self.fake.runtime_config = self.fake.files[self.target.config_path]
        self.enroll()
        private, recipient = recipient_key()
        added = self.admin.create_profile("phone", "10.44.0.3", "198.51.100.7", recipient)
        self.assertEqual(added["profile_format"], "awg3-conf")
        self.assertEqual(set(added["sealed_profile"]),
                         {"version", "ephemeral_public_key", "salt", "nonce", "ciphertext"})
        profile = decrypt_sealed(added["sealed_profile"], private, self.target.name, "phone")
        self.assertIn(b"HeaderProtectionKey = " + key(10).encode(), profile)
        self.assertIn(b"AllowedIPs = 10.44.0.0/24", profile)
        self.assertIn(b"Endpoint = 198.51.100.7:49289", profile)
        self.assertNotIn(key(1).encode(), profile)
        again = self.admin.sealed_export("phone", recipient)
        self.assertEqual(decrypt_sealed(again, private, self.target.name, "phone"), profile)
        with self.assertRaises(Exception):
            decrypt_sealed(again, private, self.target.name, "other")
        self.assertEqual(self.admin.revoke("phone")["action"], "revoked")
        with self.assertRaisesRegex(AmneziaAdminError, "no SovaGrid AWG3 profile"):
            self.admin.sealed_export("phone", recipient)

    def test_awg3_profile_rejects_missing_parameters_before_write(self):
        self.enroll()
        _, recipient = recipient_key()
        with self.assertRaisesRegex(AmneziaAdminError, "profile generation failed"):
            self.admin.create_profile("phone", "10.44.0.3", "198.51.100.7", recipient)
        self.assertEqual(self.admin.status()["owned_clients"], [])
        self.assertEqual(len(_config(self.fake.files[self.target.config_path]).peers), 1)

    def test_awg3_profile_rejects_recipient_and_invalid_host_before_write(self):
        self.enroll()
        with self.assertRaisesRegex(AmneziaAdminError, "Invalid AWG3 profile request"):
            self.admin.create_profile("phone", "10.44.0.3", "198.51.100.7", "bad-key")
        _, recipient = recipient_key()
        with self.assertRaisesRegex(AmneziaAdminError, "Invalid AWG3 profile request"):
            self.admin.create_profile("phone", "10.44.0.3", "bad host", recipient)
        self.assertEqual(self.admin.status()["owned_clients"], [])

    def test_awg3_profile_full_route_omits_server_hooks_and_rolls_back(self):
        config = self.fake.files[self.target.config_path]
        self.fake.files[self.target.config_path] = config.replace(
            b"ListenPort = 49289\n\n",
            b"ListenPort = 49289\n" + AWG3_FIELDS.encode() +
            b"PostUp = /bin/echo SERVER_ONLY\n\n")
        self.fake.runtime_config = self.fake.files[self.target.config_path]
        self.enroll()
        original_config = self.fake.files[self.target.config_path]
        original_table = self.fake.files[self.target.table_path]
        private, recipient = recipient_key()
        self.fake.fail_sync_once = True
        with self.assertRaisesRegex(AmneziaAdminError, "rolled back"):
            self.admin.create_profile("phone", "10.44.0.3", "vpn.example.com",
                                      recipient, route="full")
        self.assertEqual(self.fake.files[self.target.config_path], original_config)
        self.assertEqual(self.fake.files[self.target.table_path], original_table)
        self.assertEqual(self.admin.status()["owned_clients"], [])
        added = self.admin.create_profile("phone", "10.44.0.3", "vpn.example.com",
                                          recipient, route="full")
        profile = decrypt_sealed(added["sealed_profile"], private, self.target.name, "phone")
        self.assertIn(b"AllowedIPs = 0.0.0.0/0, ::/0", profile)
        self.assertIn(b"Endpoint = vpn.example.com:49289", profile)
        self.assertNotIn(b"SERVER_ONLY", profile)
        self.assertNotIn(b"PostUp", profile)


if __name__ == "__main__":
    unittest.main()
