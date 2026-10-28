# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Non-executable validation for a future SovaGrid-owned WireGuard service."""

from __future__ import annotations

import ipaddress
import re


PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(item) for item in
                         ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def plan_wireguard(name: str, port: int, subnet: str, snapshot: dict) -> dict:
    """Validate a draft and detect Docker-published UDP port conflicts.

    A successful plan does not imply that the host port, subnet, firewall,
    kernel support or routing have been checked. It can never start a VPN.
    """
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", name):
        raise ValueError("name must be 2–32 lowercase letters, digits or hyphens")
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("port must be an integer between 1024 and 65535")
    try:
        network = ipaddress.IPv4Network(subnet, strict=True)
    except (ValueError, TypeError, ipaddress.AddressValueError) as exc:
        raise ValueError("subnet must be a canonical IPv4 CIDR") from exc
    if not 24 <= network.prefixlen <= 30 or not any(network.subnet_of(item) for item in PRIVATE_NETWORKS):
        raise ValueError("subnet must be an RFC1918 IPv4 /24–/30")
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1 or snapshot.get("source_status") != "ok":
        raise ValueError("current Docker inventory is required for a plan")
    services = snapshot.get("services")
    if not isinstance(services, list):
        raise ValueError("current Docker inventory is invalid")
    conflicts = []
    for service in services:
        if not isinstance(service, dict):
            raise ValueError("current Docker inventory is invalid")
        ports = service.get("published_ports", [])
        if not isinstance(ports, list):
            raise ValueError("current Docker inventory is invalid")
        if any(isinstance(item, dict) and item.get("protocol") == "udp" and item.get("port") == port for item in ports):
            conflicts.append(service.get("name", "unknown"))
    return {
        "schema_version": 1, "kind": "wireguard", "name": name, "listen_port": port,
        "subnet": str(network), "can_apply": False,
        "docker_udp_port_conflicts": sorted(set(conflicts)),
        "remaining_checks": ["host_socket", "host_and_docker_subnets", "firewall", "kernel_wireguard", "client_ip_allocation"],
    }
