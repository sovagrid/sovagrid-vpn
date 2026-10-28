# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in disposable Docker integration test for the Amnezia admin module.

Run as root on a Linux host with the two local Amnezia images. Each fixture
has an isolated network namespace, no published ports, no host mounts, and a
temporary config directory. No live container name occurs in a Docker write.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from amnezia_admin import AmneziaAdmin, AmneziaAdminError, TARGETS, Target


def run(command: tuple[str, ...], *, input: bytes | None = None,
        timeout: int = 20) -> bytes:
    result = subprocess.run(command, input=input, capture_output=True,
                            timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError("disposable Docker fixture failed")
    return result.stdout


def exec_fixture(name: str, *args: str) -> bytes:
    return run(("docker", "exec", name, *args))


def make_fixture(kind: str) -> tuple[Target, str]:
    canonical = TARGETS[kind]
    suffix = uuid.uuid4().hex[:12]
    name = f"sg-amnezia-fixture-{kind}-{suffix}"
    target = Target(f"fixture-{kind}-{suffix}", name, canonical.image_name,
                    canonical.binary, canonical.interface, canonical.config_path,
                    canonical.table_path, canonical.psk_path)
    init = ("amneziawg-go awg0 > /tmp/go.log 2>&1 & "
            "while :; do sleep 60; done") if kind == "awg2" else (
            "ip link add wg0 type wireguard; while :; do sleep 60; done")
    command = ["docker", "run", "-d", "--rm", "--pull", "never", "--network", "none",
               "--cap-add", "NET_ADMIN", "--read-only", "--pids-limit", "64",
               "--memory", "128m", "--security-opt", "no-new-privileges",
               "--label", "io.sovagrid.disposable-amnezia-fixture=1",
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=4m",
               "--tmpfs", "/run:rw,nosuid,nodev,size=1m",
               "--tmpfs", str(Path(canonical.config_path).parent) + ":rw,nosuid,nodev,size=4m"]
    if kind == "awg2":
        command.extend(("--device", "/dev/net/tun"))
    command.extend(("--name", name, "--entrypoint", "/bin/sh", canonical.image_name,
                    "-c", init))
    run(tuple(command))
    return target, name


def initialize(target: Target) -> str:
    for _ in range(30):
        result = subprocess.run(("docker", "exec", target.container, target.binary,
                                 "show", target.interface), capture_output=True,
                                timeout=3, check=False)
        if result.returncode == 0:
            break
        time.sleep(0.2)
    else:
        raise RuntimeError("disposable interface did not start")
    setup = f'''
set -eu
umask 077
{target.binary} genkey > /tmp/server-private
{target.binary} genkey > /tmp/old-client-private
{target.binary} pubkey < /tmp/old-client-private > /tmp/old-client-public
{target.binary} genpsk > {target.psk_path}
{{
  printf '[Interface]\\nAddress = 10.44.0.1/24\\nPrivateKey = %s\\nListenPort = 49289\\n\\n' "$(cat /tmp/server-private)"
  printf '[Peer]\\nPublicKey = %s\\nPresharedKey = %s\\nAllowedIPs = 10.44.0.2/32\\n\\n' "$(cat /tmp/old-client-public)" "$(cat {target.psk_path})"
}} > {target.config_path}
printf '[{{"clientId":"%s","userData":{{"clientName":"Existing"}}}}]\\n' "$(cat /tmp/old-client-public)" > {target.table_path}
'''
    exec_fixture(target.container, "sh", "-c", setup)
    script = (f"{target.binary} setconf {target.interface} "
              f"<({target.binary}-quick strip {target.config_path}); "
              f"ip addr add 10.44.0.1/24 dev {target.interface}; "
              f"ip link set {target.interface} up")
    exec_fixture(target.container, "bash", "-c", script)
    return exec_fixture(target.container, "cat", "/tmp/old-client-public").decode().strip()


def exercise(kind: str) -> None:
    target = None
    name = None
    try:
        target, name = make_fixture(kind)
        old_public = initialize(target)
        if kind == "awg2":
            # Mirror the file modes observed on the live AWG2 container,
            # without changing that container or its files.
            exec_fixture(name, "chmod", "1", target.config_path, target.table_path)
            exec_fixture(name, "chmod", "644", target.psk_path)
        with tempfile.TemporaryDirectory(prefix="sovagrid-amnezia-lab-") as temp:
            admin = AmneziaAdmin(target, state_root=Path(temp) / "state")
            container_id = run(("docker", "container", "inspect", "--format", "{{.Id}}",
                                name)).decode().strip()
            admin.enroll(container_id)
            original_config = exec_fixture(name, "cat", target.config_path)
            make_new = (f"umask 077; {target.binary} genkey > /tmp/new-client-private; "
                        f"{target.binary} pubkey < /tmp/new-client-private")
            new_public = exec_fixture(name, "sh", "-c", make_new).decode().strip()
            result = admin.add("phone", new_public, "10.44.0.3")
            assert result["configured_clients"] == 2
            peers = exec_fixture(name, target.binary, "show", target.interface, "peers")
            assert old_public.encode() in peers and new_public.encode() in peers
            result = admin.revoke("phone")
            assert result["configured_clients"] == 1
            assert exec_fixture(name, "cat", target.config_path) == original_config
            if kind == "awg2":
                assert exec_fixture(name, "stat", "-c", "%a", target.config_path).strip() == b"1"
                assert exec_fixture(name, "stat", "-c", "%a", target.table_path).strip() == b"1"
            after_revoke_table = exec_fixture(name, "cat", target.table_path)
            assert after_revoke_table != b""
            peers = exec_fixture(name, target.binary, "show", target.interface, "peers")
            assert peers.strip() == old_public.encode()

            real_sync = admin._sync
            attempts = 0

            def fail_first_sync() -> None:
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise AmneziaAdminError("injected fixture sync failure")
                real_sync()

            admin._sync = fail_first_sync
            try:
                admin.add("failure", new_public, "10.44.0.3")
            except AmneziaAdminError:
                pass
            else:
                raise AssertionError("fault injection unexpectedly succeeded")
            assert exec_fixture(name, "cat", target.config_path) == original_config
            assert exec_fixture(name, "cat", target.table_path) == after_revoke_table
            assert exec_fixture(name, target.binary, "show", target.interface,
                                "peers").strip() == old_public.encode()
            assert admin.status()["owned_clients"] == []
        print(f"{kind} disposable admin add/revoke and rollback: pass")
    finally:
        if name is not None:
            subprocess.run(("docker", "rm", "-f", name), capture_output=True,
                           timeout=20, check=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--i-understand-this-runs-disposable-docker", action="store_true")
    args = parser.parse_args()
    if not args.i_understand_this_runs_disposable_docker:
        parser.error("explicit disposable Docker opt-in is required")
    for kind in ("awg2", "wireguard"):
        exercise(kind)


if __name__ == "__main__":
    main()
