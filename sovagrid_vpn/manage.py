# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Explicit, root-only CLI for SovaGrid-owned standard WireGuard instances."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .managed import ManagedVpnError, ManagedWireGuard


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage SovaGrid-owned WireGuard instances")
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create", help="Generate a staged instance; no interface is started")
    create.add_argument("name")
    create.add_argument("--port", required=True, type=int)
    create.add_argument("--subnet", required=True)
    create.add_argument("--endpoint", required=True, help="Public IPv4 address or DNS name")
    activate = sub.add_parser("activate", help="Install and start this instance explicitly")
    activate.add_argument("name")
    add = sub.add_parser("add-client", help="Create a private client profile and sync an active interface")
    add.add_argument("name")
    add.add_argument("client")
    revoke = sub.add_parser("revoke-client", help="Remove a peer from the active interface and saved config")
    revoke.add_argument("name")
    revoke.add_argument("client")
    clients = sub.add_parser("clients", help="List client names and addresses without secrets")
    clients.add_argument("name")
    recovery = sub.add_parser("recover", help="Finish a pending client transaction after interruption")
    recovery.add_argument("name")
    sub.add_parser("instances", help="List managed instances without secrets")
    export = sub.add_parser("export-client", help="Copy a profile to a private root-owned directory")
    export.add_argument("name")
    export.add_argument("client")
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--route", choices=("split", "full"), default="split")
    remove = sub.add_parser("remove", help="Stop and delete only this managed instance")
    remove.add_argument("name")
    remove.add_argument("--confirm-name", required=True)
    args = parser.parse_args(argv)
    manager = ManagedWireGuard()
    try:
        if args.action == "create":
            result = manager.create(args.name, args.port, args.subnet, args.endpoint)
        elif args.action == "activate":
            result = manager.activate(args.name)
        elif args.action == "add-client":
            result = manager.add_client(args.name, args.client)
        elif args.action == "revoke-client":
            result = manager.revoke_client(args.name, args.client)
        elif args.action == "clients":
            result = manager.clients(args.name)
        elif args.action == "recover":
            result = manager.recover(args.name)
        elif args.action == "instances":
            result = manager.instances()
        elif args.action == "export-client":
            result = manager.export_client(args.name, args.client, args.output, route=args.route)
        else:
            result = manager.remove(args.name, args.confirm_name)
    except (ManagedVpnError, OSError, ValueError) as exc:
        # Never include subprocess stderr, config text or key material.
        message = str(exc) if isinstance(exc, ManagedVpnError) else type(exc).__name__
        print(message, file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
