#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
# Runs inside a single disposable container with --network none.
set -eu
umask 077
iface=sgawglab
cleanup() {
  if [ "${awg_go_pid:-}" ]; then kill "$awg_go_pid" >/dev/null 2>&1 || :; fi
  ip link delete "$iface" >/dev/null 2>&1 || :
}
trap cleanup EXIT

amneziawg-go "$iface" > /tmp/awg-go.log 2>&1 &
awg_go_pid=$!
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if awg show "$iface" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
awg show "$iface" >/dev/null
ip link set "$iface" up
server_private=$(awg genkey)
old_private=$(awg genkey)
new_private=$(awg genkey)
old_public=$(printf '%s\n' "$old_private" | awg pubkey)
new_public=$(printf '%s\n' "$new_private" | awg pubkey)

{
  printf '[Interface]\nPrivateKey = %s\nListenPort = 49289\n' "$server_private"
  printf '[Peer]\nPublicKey = %s\nAllowedIPs = 10.49.250.2/32\n' "$old_public"
} > /tmp/initial.conf
awg setconf "$iface" /tmp/initial.conf
test "$(awg show "$iface" peers)" = "$old_public"

{
  cat /tmp/initial.conf
  printf '[Peer]\nPublicKey = %s\nAllowedIPs = 10.49.250.3/32\n' "$new_public"
} > /tmp/added.conf
awg syncconf "$iface" /tmp/added.conf
awg show "$iface" peers | grep -Fxq "$old_public"
awg show "$iface" peers | grep -Fxq "$new_public"
test "$(awg show "$iface" peers | wc -l | tr -d ' ')" = 2

awg syncconf "$iface" /tmp/initial.conf
test "$(awg show "$iface" peers)" = "$old_public"
test "$(awg show "$iface" listen-port)" = 49289
printf '%s\n' 'AWG disposable runtime add/revoke: pass; pre-existing peer and server port retained'
