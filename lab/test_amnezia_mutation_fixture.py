# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disposable fixtures only; no Docker or production Amnezia state."""

from __future__ import annotations

import base64
import json
import unittest

from amnezia_mutation_fixture import (DisposableFixture, stage_add_wg,
                                      stage_revoke_wg, stage_add_xray,
                                      stage_revoke_xray)


def key(number: int) -> str:
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


DEFAULT = "11111111-1111-4111-8111-111111111111"
PREEXISTING = "22222222-2222-4222-8222-222222222222"
NEW = "33333333-3333-4333-8333-333333333333"


class MutationFixtureTests(unittest.TestCase):
    def setUp(self):
        self.awg_config = (f"[Interface]\nPrivateKey = {key(1)}\n"
                           "HeaderProtectionKey = AWG_PRIVATE\n"
                           f"[Peer]\nPublicKey = {key(2)}\nAllowedIPs = 10.8.1.2/32\n"
                           "# Keep this Amnezia comment\n").encode()
        self.awg_table = json.dumps([{"clientId": key(2), "userData": {
            "clientName": "Existing user", "privateMeta": "PRESERVE"}}],
            separators=(",", ":")).encode() + b"\n"
        self.xray_config = json.dumps({
            "inbounds": [{"protocol": "vless", "settings": {"clients": [
                {"id": DEFAULT, "flow": "xtls-rprx-vision"},
                {"id": PREEXISTING, "flow": "xtls-rprx-vision"}]},
                "streamSettings": {"realitySettings": {"privateKey": "XRAY_PRIVATE"}}}],
            "log": {"loglevel": "warning"}}, separators=(",", ":")).encode() + b"\n"
        self.xray_table = json.dumps([{"clientId": PREEXISTING, "userData": {
            "clientName": "Existing guest"}}], separators=(",", ":")).encode() + b"\n"

    def test_awg_and_wg_add_and_owned_revoke_preserve_existing_peer(self):
        for protocol in ("awg", "wg"):
            with self.subTest(protocol=protocol):
                fixture = DisposableFixture(self.awg_config, self.awg_table)
                staged = stage_add_wg(fixture.config, fixture.registry, fixture.owned,
                                      key(3), "10.8.1.3/32", "Phone")
                self.assertTrue(staged.config_after.startswith(self.awg_config))
                self.assertEqual(staged.config_after.count(b"[Peer]"), 2)
                fixture.apply(staged)
                self.assertIn(key(3), fixture.owned)
                revoked = stage_revoke_wg(fixture.config, fixture.registry,
                                          fixture.owned, key(3))
                fixture.apply(revoked)
                self.assertEqual(fixture.config, self.awg_config)
                self.assertEqual(fixture.registry, self.awg_table)
                self.assertEqual(fixture.owned, frozenset())

    def test_wg_refuses_existing_peer_address_collision_and_registry_drift(self):
        with self.assertRaises(ValueError):
            stage_revoke_wg(self.awg_config, self.awg_table, frozenset(), key(2))
        with self.assertRaises(ValueError):
            stage_add_wg(self.awg_config, self.awg_table, frozenset(),
                         key(3), "10.8.1.2/32", "Collision")
        with self.assertRaises(ValueError):
            stage_add_wg(self.awg_config, b"[]", frozenset(),
                         key(3), "10.8.1.3/32", "Drift")

    def test_xray_add_and_owned_revoke_preserve_default_and_existing_guest(self):
        fixture = DisposableFixture(self.xray_config, self.xray_table)
        staged = stage_add_xray(fixture.config, fixture.registry, fixture.owned,
                                DEFAULT, NEW, "Phone")
        fixture.apply(staged)
        ids = [row["id"] for row in json.loads(fixture.config)["inbounds"][0]
               ["settings"]["clients"]]
        self.assertEqual(ids, [DEFAULT, PREEXISTING, NEW])
        self.assertIn("XRAY_PRIVATE", fixture.config.decode())
        with self.assertRaises(ValueError):
            stage_revoke_xray(fixture.config, fixture.registry,
                              fixture.owned, DEFAULT, DEFAULT)
        with self.assertRaises(ValueError):
            stage_revoke_xray(fixture.config, fixture.registry,
                              fixture.owned, DEFAULT, PREEXISTING)
        revoked = stage_revoke_xray(fixture.config, fixture.registry,
                                    fixture.owned, DEFAULT, NEW)
        fixture.apply(revoked)
        self.assertEqual(json.loads(fixture.config), json.loads(self.xray_config))
        self.assertEqual(json.loads(fixture.registry), json.loads(self.xray_table))

    def test_two_file_failure_rolls_back_exact_bytes_and_ownership(self):
        fixture = DisposableFixture(self.awg_config, self.awg_table)
        staged = stage_add_wg(fixture.config, fixture.registry, fixture.owned,
                              key(3), "10.8.1.3/32", "Phone")
        with self.assertRaisesRegex(RuntimeError, "injected fixture failure"):
            fixture.apply(staged, fail_after_config=True)
        self.assertEqual((fixture.config, fixture.registry, fixture.owned),
                         (self.awg_config, self.awg_table, frozenset()))
        self.assertNotIn(key(1), repr(staged))


if __name__ == "__main__":
    unittest.main()
