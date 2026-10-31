# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in disposable integration check against an isolated Docker daemon.

This is meant for a local disposable VM: the production container name and
UDP port are used briefly, then the owned test container is removed. It does
not inspect or remove any pre-existing container.

With --verify-client-traffic, a sealed full-route client profile is exercised
against a second disposable client and an HTTP endpoint on Docker's bridge.
The endpoint's /32 route is forced through awg0 to verify forwarding and NAT.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lab.amnezia_profile_docker import decrypt
from sovagrid_vpn.amnezia_admin import (AmneziaAdmin, AmneziaAdminError,
                                       PINNED_AWG_IMAGE, TARGETS)
from sovagrid_vpn.amnezia_provision import CONTAINER, Provisioner, _read_state


def _run(*args: str, input: bytes | None = None, timeout: int = 25) -> bytes:
    command = ("docker", *args)
    if input is not None and args[:1] == ("exec",):
        command = ("docker", "exec", "-i", *args[1:])
    result = subprocess.run(command, input=input, capture_output=True,
                            check=False, timeout=timeout)
    if result.returncode:
        # A failed command may contain client configuration on stderr.
        raise RuntimeError(f"disposable Docker check failed: {args[0]} (exit {result.returncode})")
    return result.stdout


def _docker_ip(container: str) -> str:
    value = _run("inspect", "--format",
                 '{{with index .NetworkSettings.Networks "bridge"}}{{.IPAddress}}{{end}}',
                 container).decode("ascii").strip()
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise RuntimeError("disposable Docker bridge address is missing") from exc
    return value


def _start_fixture_container(name: str, nonce: str,
                             containers: list[tuple[str, str]], *, client: bool) -> None:
    command = ["run", "-d", "--pull", "never", "--network", "bridge",
               "--read-only", "--pids-limit", "64", "--memory", "128m",
               "--security-opt", "no-new-privileges", "--tmpfs",
               "/tmp:rw,nosuid,nodev,size=4m", "--tmpfs",
               "/run:rw,nosuid,nodev,size=1m", "--label",
               f"io.sovagrid.disposable-amnezia-fixture={nonce}", "--name", name]
    if client:
        command += ["--device", "/dev/net/tun", "--cap-drop", "ALL",
                    "--cap-add", "NET_ADMIN", "--entrypoint", "/bin/sh",
                    PINNED_AWG_IMAGE, "-c", "amneziawg-go awg0 >/tmp/go.log 2>&1 & "
                    "while :; do sleep 60; done"]
    else:
        command += ["--cap-drop", "ALL", "--entrypoint", "/bin/sh",
                    PINNED_AWG_IMAGE, "-c", "mkdir -p /tmp/www; "
                    f"printf '%s' '{nonce}' > /tmp/www/index.html; "
                    "exec busybox httpd -f -p 18080 -h /tmp/www"]
    # Register the unique name before docker run: a timeout after creation
    # must still let finally locate and remove our labelled container.
    containers.append((name, nonce))
    container_id = _run(*command, timeout=40).decode("ascii").strip()
    if len(container_id) != 64 or any(char not in "0123456789abcdef" for char in container_id):
        raise RuntimeError("disposable Docker container ID invalid")


def _wait_awg(container: str) -> None:
    for _ in range(40):
        result = subprocess.run(("docker", "exec", container, "awg", "show", "awg0"),
                                capture_output=True, check=False, timeout=3)
        if result.returncode == 0:
            return
        time.sleep(0.25)
    raise RuntimeError("disposable AWG client interface did not start")


def _wait_endpoint(server_id: str, endpoint_ip: str, expected: bytes) -> None:
    for _ in range(20):
        result = subprocess.run(
            ("docker", "exec", server_id, "busybox", "wget", "-q", "-T", "2",
             "-O", "-", f"http://{endpoint_ip}:18080/"),
            capture_output=True, check=False, timeout=4)
        if result.returncode == 0 and result.stdout == expected:
            return
        time.sleep(0.25)
    raise RuntimeError("disposable HTTP endpoint did not start")


def _verify_full_route(provisioner: Provisioner,
                       containers: list[tuple[str, str]]) -> None:
    identity = provisioner._container()
    if not identity:
        raise RuntimeError("disposable AWG server is missing")
    server_id = identity["id"]
    if _run("exec", server_id, "cat", "/proc/sys/net/ipv4/ip_forward").strip() != b"1":
        raise RuntimeError("disposable AWG server IPv4 forwarding is disabled")
    _run("exec", server_id, "iptables", "-t", "nat", "-C", "POSTROUTING",
         "-s", "10.44.0.0/24", "-o", "eth0", "-j", "MASQUERADE")
    _run("exec", server_id, "iptables", "-C", "FORWARD", "-i", "awg0",
         "-j", "ACCEPT")
    _run("exec", server_id, "iptables", "-C", "FORWARD", "-o", "awg0",
         "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")

    nonce = uuid.uuid4().hex
    client = "sg-awg-provision-client-" + nonce[:12]
    endpoint = "sg-awg-provision-endpoint-" + nonce[:12]
    _start_fixture_container(client, nonce, containers, client=True)
    _start_fixture_container(endpoint, nonce, containers, client=False)
    _wait_awg(client)
    server_ip = _docker_ip(server_id)
    endpoint_ip = _docker_ip(endpoint)
    _wait_endpoint(server_id, endpoint_ip, nonce.encode("ascii"))
    admin = provisioner.admin_factory()
    preview = admin.enroll_preview()
    admin.enroll(preview["container_id"], confirm_image_id=preview["image_id"],
                 confirm_config_sha256=preview["config_sha256"],
                 confirm_table_sha256=preview["table_sha256"])
    recipient = ec.generate_private_key(ec.SECP256R1())
    public = recipient.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    public_b64 = base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii")
    created = admin.create_profile("ci-client", "10.44.0.2", server_ip,
                                   public_b64, route="full")
    if created["profile_format"] != "awg3-conf":
        raise RuntimeError("disposable AWG client profile format differs")
    profile = decrypt(created["sealed_profile"], recipient, "awg2", "ci-client")
    if b"AllowedIPs = 0.0.0.0/0, ::/0" not in profile:
        raise RuntimeError("disposable AWG profile is not full route")
    # The profile travels only through stdin; no key material enters argv or logs.
    _run("exec", client, "sh", "-c", "umask 077; cat > /tmp/client.conf",
         input=profile)
    _run("exec", client, "bash", "-c",
         "set -e; awg setconf awg0 <(awg-quick strip /tmp/client.conf); "
         "ip addr add 10.44.0.2/24 dev awg0; ip link set awg0 up")
    _run("exec", client, "ip", "route", "add", endpoint_ip + "/32", "dev", "awg0")
    route = _run("exec", client, "ip", "route", "get", endpoint_ip).decode("ascii")
    if "dev awg0" not in route:
        raise RuntimeError("disposable endpoint route bypasses AWG")
    response = _run("exec", client, "busybox", "wget", "-q", "-T", "12",
                    "-O", "-", f"http://{endpoint_ip}:18080/", timeout=20)
    if response != nonce.encode("ascii"):
        raise RuntimeError("disposable endpoint response differs")
    handshakes = _run("exec", server_id, "awg", "show", "awg0",
                      "latest-handshakes").decode("ascii").splitlines()
    if len(handshakes) != 1 or len(handshakes[0].split()) != 2 or not (
            handshakes[0].split()[1].isdigit() and
            int(handshakes[0].split()[1]) > 0):
        raise RuntimeError("disposable AWG peer handshake was not observed")
    print("Disposable full-route AWG profile, handshake, IPv4 forwarding and NAT: pass")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--i-understand-this-runs-disposable-docker", action="store_true")
    parser.add_argument("--route", choices=("full", "split"), default="full")
    parser.add_argument("--allow-amd64-emulation", action="store_true")
    parser.add_argument("--expect-full-startup-failure", action="store_true")
    parser.add_argument("--verify-client-traffic", action="store_true")
    args = parser.parse_args()
    if not args.i_understand_this_runs_disposable_docker:
        parser.error("explicit disposable Docker opt-in is required")
    if args.verify_client_traffic and (args.route != "full" or
                                       args.expect_full_startup_failure):
        parser.error("client traffic check requires a successful full-route install")
    inspect = subprocess.run(("docker", "container", "inspect", CONTAINER),
                             capture_output=True, check=False, timeout=15)
    if inspect.returncode == 0:
        raise RuntimeError("refusing to touch an existing Amnezia container")
    with TemporaryDirectory(prefix="sg-awg-provision-") as temporary:
        base = Path(temporary)
        options = {"state_root": base / "provision",
                   "admin_factory": lambda: AmneziaAdmin(
                       TARGETS["awg2"], state_root=base / "admin", require_root=False),
                   "require_root": False}
        if args.allow_amd64_emulation:
            options["tun_available"] = lambda: True
        provisioner = Provisioner(**options)
        # Only this explicit local-fixture flag bypasses the production
        # architecture and host TUN checks for an ARM VM with amd64 binfmt.
        if args.allow_amd64_emulation:
            provisioner._docker_platform = lambda: "linux amd64"
        port, subnet = 49311, "10.44.0.0/24"
        preview = provisioner.preview(port, subnet, args.route)
        if not preview.get("can_apply"):
            raise RuntimeError(f"disposable preflight failed: {preview.get('reason')}")
        fixture_containers: list[tuple[str, str]] = []
        try:
            result = provisioner.apply(port, subnet, preview["state_revision"],
                                       confirm=True, route=args.route)
            if result["action"] != "installed":
                raise RuntimeError("disposable install did not finish")
            check = provisioner.admin_factory().enroll_preview()
            if check["configured_clients"] != 0 or check["interface"] != "awg0":
                raise RuntimeError("disposable AWG runtime differs")
            if args.expect_full_startup_failure:
                raise RuntimeError("full routing unexpectedly succeeded in failure fixture")
            if args.verify_client_traffic:
                _verify_full_route(provisioner, fixture_containers)
            print("Disposable AmneziaWG provision and admin preview: pass")
        except Exception:
            identity = provisioner._container()
            if identity:
                state = subprocess.run(("docker", "container", "inspect", "--format",
                                        "{{.State.Status}} {{.State.ExitCode}}", identity["id"]),
                                       capture_output=True, check=False, timeout=15)
                print("Disposable container state:", state.stdout.decode("ascii", "replace").strip())
                try:
                    provisioner.admin_factory().enroll_preview()
                except AmneziaAdminError as exc:
                    print("Admin preview rejected disposable fixture:", str(exc))
                changes = subprocess.run(("docker", "diff", identity["id"]),
                                         capture_output=True, check=False, timeout=15)
                print("Disposable layer paths:", changes.stdout.decode("ascii", "replace")[-1000:])
                if args.expect_full_startup_failure:
                    recovery = provisioner.recover()
                    if recovery != {"schema_version": 1, "action": "recovered",
                                    "changed": True, "installed": False}:
                        raise RuntimeError("full-route failure did not safely roll back")
                    print("Disposable failed full-route install recovery: pass")
                    return
            raise
        finally:
            # Only uniquely labelled containers created by this fixture can
            # be removed, even if docker run timed out after creating one.
            cleanup_failed = False
            for name, nonce in reversed(fixture_containers):
                inspected = subprocess.run(
                    ("docker", "container", "inspect", "--format",
                     '{{.Id}} {{index .Config.Labels "io.sovagrid.disposable-amnezia-fixture"}}',
                     name), capture_output=True, check=False, timeout=15)
                if inspected.returncode != 0:
                    continue
                fields = inspected.stdout.decode("ascii", "replace").split()
                if len(fields) != 2 or fields[1] != nonce:
                    cleanup_failed = True
                    continue
                result = subprocess.run(("docker", "rm", "-f", fields[0]),
                                        capture_output=True, check=False, timeout=20)
                cleanup_failed |= result.returncode != 0
            try:
                identity = provisioner._container()
                state = _read_state(provisioner.state_root / "state.json", provisioner.owner)
                pending = _read_state(provisioner.state_root / "pending.json", provisioner.owner)
                owner_state = state or pending
                if (identity and owner_state and
                        identity["nonce"] == owner_state.get("nonce") and
                        identity["image_id"] == owner_state.get("image_id") and
                        owner_state.get("image_ref") == PINNED_AWG_IMAGE and
                        owner_state.get("container_id") in (None, identity["id"])):
                    result = subprocess.run(("docker", "rm", "-f", identity["id"]),
                                            capture_output=True, check=False, timeout=20)
                    cleanup_failed |= result.returncode != 0
            finally:
                if cleanup_failed:
                    raise RuntimeError("disposable Docker fixture cleanup failed")


if __name__ == "__main__":
    main()
