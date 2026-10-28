# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Command-line entry point for a root-owned status publisher."""

from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time

from .amnezia_adapter import collect_amnezia_details
from .inventory import InventoryError, SCHEMA_VERSION, collect_snapshot
from .managed_inventory import collect_managed_instances
from .proposal import plan_wireguard


def write_snapshot(path: str, snapshot: dict, group: str | None = None) -> None:
    target = Path(path)
    if not target.is_absolute():
        raise ValueError("Output path must be absolute")
    parent = target.parent
    parent_info = parent.stat()
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_mode & 0o022:
        raise ValueError("Output directory must not be group/world writable")
    if os.geteuid() == 0 and parent_info.st_uid != 0:
        raise ValueError("Output directory must be root-owned")
    group_id = grp.getgrnam(group).gr_gid if group else None
    payload = (json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > 65536:
        raise ValueError("Snapshot exceeds size limit")
    fd, temporary = tempfile.mkstemp(prefix=".vpn-status-", dir=parent)
    try:
        os.fchmod(fd, 0o640 if group else 0o600)
        if group_id is not None:
            os.fchown(fd, -1, group_id)
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only sanitized VPN status")
    parser.add_argument("--output", help="Write snapshot atomically to an absolute path")
    parser.add_argument("--group", help="Group allowed to read the output file (requires --output)")
    parser.add_argument("--plan-wireguard", metavar="NAME", help="Print a non-executable WireGuard draft")
    parser.add_argument("--port", type=int, help="UDP port for --plan-wireguard")
    parser.add_argument("--subnet", help="Private IPv4 CIDR for --plan-wireguard")
    args = parser.parse_args(argv)
    if args.group and not args.output:
        parser.error("--group requires --output")
    if args.plan_wireguard and (args.output or args.group or args.port is None or args.subnet is None):
        parser.error("--plan-wireguard requires --port and --subnet, without --output")
    if not args.plan_wireguard and (args.port is not None or args.subnet is not None):
        parser.error("--port and --subnet require --plan-wireguard")
    try:
        snapshot = collect_snapshot()
        code = 0
    except InventoryError:
        snapshot = {"schema_version": SCHEMA_VERSION, "collected_at": int(time.time()),
                    "source": "docker_cli", "source_status": "error", "services": []}
        code = 2
    # An Amnezia probe failure cannot suppress the Docker or managed VPN data.
    # The nested schema can evolve without changing the existing snapshot API.
    try:
        snapshot["amnezia_details"] = collect_amnezia_details(
            inventory=snapshot, timestamp=snapshot["collected_at"])
    except Exception:
        snapshot["amnezia_details"] = {
            "schema_version": 1, "collected_at": snapshot["collected_at"],
            "source_status": "error", "services": [],
        }
    # Docker and managed WireGuard are independent sources. Always publish
    # both, including when either collector fails.
    snapshot["managed"] = collect_managed_instances()
    if args.plan_wireguard and not code:
        try:
            snapshot = plan_wireguard(args.plan_wireguard, args.port, args.subnet, snapshot)
        except ValueError:
            print("Invalid WireGuard plan or Docker port conflict data", file=sys.stderr)
            return 4
    try:
        if args.output:
            write_snapshot(args.output, snapshot, args.group)
        else:
            json.dump(snapshot, sys.stdout, ensure_ascii=False, separators=(",", ":"))
            sys.stdout.write("\n")
    except (OSError, ValueError, KeyError) as exc:
        print(f"Cannot publish VPN status: {type(exc).__name__}", file=sys.stderr)
        return 3
    if code:
        print("Docker inventory unavailable", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
