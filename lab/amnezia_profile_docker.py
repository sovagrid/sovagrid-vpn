# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disposable AWG3 server/client handshake using the sealed admin profile.

Only creates sg-amnezia-fixture-* containers and an internal Docker network.
No live container or host VPN interface is read or modified by this lab.
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sovagrid_vpn.amnezia_admin import AmneziaAdmin, TARGETS, Target
from sovagrid_vpn.sealed import INFO


def run(command: tuple[str, ...], *, input: bytes | None = None,
        timeout: int = 25) -> bytes:
    result = subprocess.run(command, input=input, capture_output=True,
                            timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError("disposable AWG3 Docker fixture failed")
    return result.stdout


def inside(name: str, *command: str, input: bytes | None = None) -> bytes:
    args = ("docker", "exec", "-i", name, *command) if input is not None else (
        "docker", "exec", name, *command)
    return run(args, input=input)


def wait_interface(name: str) -> None:
    for _ in range(30):
        result = subprocess.run(("docker", "exec", name, "awg", "show", "awg0"),
                                capture_output=True, timeout=3, check=False)
        if result.returncode == 0:
            return
        time.sleep(0.2)
    raise RuntimeError("disposable AWG3 interface did not start")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decrypt(envelope: dict, recipient: ec.EllipticCurvePrivateKey,
            target_name: str, client: str) -> bytes:
    if set(envelope) != {"version", "ephemeral_public_key", "salt", "nonce", "ciphertext"}:
        raise RuntimeError("disposable sealed envelope shape differs")
    ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b64url_decode(envelope["ephemeral_public_key"]))
    key = HKDF(algorithm=hashes.SHA256(), length=32,
               salt=b64url_decode(envelope["salt"]), info=INFO).derive(
                   recipient.exchange(ec.ECDH(), ephemeral))
    aad = b"SovaGrid profile\0" + target_name.encode() + b"\0" + client.encode()
    return AESGCM(key).decrypt(b64url_decode(envelope["nonce"]),
                               b64url_decode(envelope["ciphertext"]), aad)


def create_container(name: str, network: str, target: Target) -> None:
    command = ("docker", "run", "-d", "--rm", "--pull", "never", "--network", network,
               "--device", "/dev/net/tun", "--cap-add", "NET_ADMIN", "--read-only",
               "--pids-limit", "64", "--memory", "128m", "--security-opt",
               "no-new-privileges", "--label", "io.sovagrid.disposable-amnezia-fixture=1",
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=4m",
               "--tmpfs", "/run:rw,nosuid,nodev,size=1m",
               "--tmpfs", str(Path(target.config_path).parent) + ":rw,nosuid,nodev,size=4m",
               "--name", name, "--entrypoint", "/bin/sh", "amnezia-awg2:latest",
               "-c", "amneziawg-go awg0 > /tmp/go.log 2>&1 & while :; do sleep 60; done")
    run(command)
    wait_interface(name)


def exercise() -> None:
    suffix = uuid.uuid4().hex[:10]
    network = "sg-amnezia-fixture-net-" + suffix
    server = "sg-amnezia-fixture-awg-server-" + suffix
    client = "sg-amnezia-fixture-awg-client-" + suffix
    canonical = TARGETS["awg2"]
    target = Target("fixture-awg-profile-" + suffix, server,
                    canonical.image_name, canonical.binary, canonical.interface,
                    canonical.config_path, canonical.table_path, canonical.psk_path)
    created: list[str] = []
    network_created = False
    try:
        run(("docker", "network", "create", "--internal", network))
        network_created = True
        for name in (server, client):
            create_container(name, network, target)
            created.append(name)
        server_ip = run(("docker", "inspect", "--format",
                         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                         server)).decode("ascii").strip()
        if not server_ip:
            raise RuntimeError("disposable server address missing")
        setup = f'''
set -eu
umask 077
awg genkey > /tmp/server-private
awg genpsk > {target.psk_path}
awg genkey > /tmp/header-protection
{{
  printf '[Interface]\\nAddress = 10.44.0.1/24\\nPrivateKey = %s\\nListenPort = 49289\\n' "$(cat /tmp/server-private)"
  printf 'Jc = 4\\nJmin = 10\\nJmax = 50\\nS1 = 24\\nS2 = 24\\nS3 = 24\\nS4 = 24\\n'
  printf 'H1 = 1\\nH2 = 2\\nH3 = 3\\nH4 = 4\\n'
  printf 'HeaderProtectionKey = %s\\n' "$(cat /tmp/header-protection)"
  printf 'ContentPaddingAddition = 10-100\\nRekeyAfterTime = 100-120\\n'
  printf 'RekeyTimeout = 3-7\\nRejectAfterTime = 150-180\\n'
  printf 'KeepaliveTimeout = 5-15\\nMaxHandshakeAttempts = 15-20\\n'
  printf 'RandomTrailers = on\\nDisableCookies = on\\n\\n'
}} > {target.config_path}
printf '[]\\n' > {target.table_path}
'''
        inside(server, "sh", "-c", setup)
        inside(server, "bash", "-c",
               f"set -e; awg setconf awg0 <(awg-quick strip {target.config_path}); "
               "ip addr add 10.44.0.1/24 dev awg0; ip link set awg0 up")

        with tempfile.TemporaryDirectory(prefix="sovagrid-awg3-profile-lab-") as temp:
            admin = AmneziaAdmin(target, state_root=Path(temp) / "state")
            container_id = run(("docker", "container", "inspect", "--format", "{{.Id}}",
                                server)).decode("ascii").strip()
            admin.enroll(container_id)
            recipient = ec.generate_private_key(ec.SECP256R1())
            public = recipient.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            public_b64 = base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii")
            created_result = admin.create_profile("phone", "10.44.0.2", server_ip,
                                                  public_b64)
            if created_result["profile_format"] != "awg3-conf":
                raise RuntimeError("disposable profile format differs")
            profile = decrypt(created_result["sealed_profile"], recipient,
                              target.name, "phone")
            if profile != decrypt(admin.sealed_export("phone", public_b64), recipient,
                                  target.name, "phone"):
                raise RuntimeError("disposable sealed re-export differs")
            # Only stdin transports plaintext into the one-off client. It is
            # never printed, written on the host or inserted into an argv.
            inside(client, "sh", "-c", "umask 077; cat > /tmp/client.conf", input=profile)
            inside(client, "bash", "-c",
                   "set -e; awg setconf awg0 <(awg-quick strip /tmp/client.conf); "
                   "ip addr add 10.44.0.2/24 dev awg0; ip link set awg0 up")
            inside(client, "ping", "-c", "3", "-W", "3", "10.44.0.1")
            peers = inside(server, "awg", "show", "awg0", "peers").decode("ascii").splitlines()
            if len(peers) != 1:
                raise RuntimeError("disposable server peer count differs")
            admin.revoke("phone")
            if inside(server, "awg", "show", "awg0", "peers").strip():
                raise RuntimeError("disposable AWG3 peer was not revoked")
            if admin.status()["owned_clients"]:
                raise RuntimeError("disposable profile state was not revoked")
        print("AWG3 sealed profile, disposable handshake, ping and revoke: pass")
    finally:
        for name in reversed(created):
            subprocess.run(("docker", "rm", "-f", name), capture_output=True,
                           timeout=20, check=False)
        if network_created:
            subprocess.run(("docker", "network", "rm", network), capture_output=True,
                           timeout=20, check=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--i-understand-this-runs-disposable-docker", action="store_true")
    args = parser.parse_args()
    if not args.i_understand_this_runs_disposable_docker:
        parser.error("explicit disposable Docker opt-in is required")
    exercise()


if __name__ == "__main__":
    main()
