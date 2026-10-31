#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Explicit root-only setup of the managed WireGuard broker on an Agent host."""

import sys

sys.dont_write_bytecode = True
sys.path.insert(0, "/opt/sovagrid-src/sovagrid-vpn")
from sovagrid_vpn.wireguard_install import main


if __name__ == "__main__":
    raise SystemExit(main())
