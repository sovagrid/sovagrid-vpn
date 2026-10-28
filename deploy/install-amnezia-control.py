#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Run from /opt/sovagrid-src/sovagrid-vpn after SovaGrid run.sh deployment."""

import sys

# `preview` promises no writes, including Python bytecode in the source tree.
sys.dont_write_bytecode = True
sys.path.insert(0, "/opt/sovagrid-src/sovagrid-vpn")
from sovagrid_vpn.amnezia_install import main


if __name__ == "__main__":
    raise SystemExit(main())
