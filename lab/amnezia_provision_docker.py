# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in disposable integration check against an isolated Docker daemon.

This is meant for a local disposable VM: the production container name and
UDP port are used briefly, then the owned test container is removed. It does
not inspect or remove any pre-existing container.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from sovagrid_vpn.amnezia_admin import AmneziaAdmin, AmneziaAdminError, TARGETS
from sovagrid_vpn.amnezia_provision import CONTAINER, Provisioner, _read_state


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--i-understand-this-runs-disposable-docker", action="store_true")
    parser.add_argument("--route", choices=("full", "split"), default="full")
    parser.add_argument("--allow-amd64-emulation", action="store_true")
    parser.add_argument("--expect-full-startup-failure", action="store_true")
    args = parser.parse_args()
    if not args.i_understand_this_runs_disposable_docker:
        parser.error("explicit disposable Docker opt-in is required")
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
            identity = provisioner._container()
            state = _read_state(provisioner.state_root / "state.json", provisioner.owner)
            pending = _read_state(provisioner.state_root / "pending.json", provisioner.owner)
            owner_nonce = (state or pending or {}).get("nonce")
            if identity and identity["nonce"] == owner_nonce:
                subprocess.run(("docker", "rm", "-f", identity["id"]),
                               capture_output=True, check=True, timeout=20)


if __name__ == "__main__":
    main()
