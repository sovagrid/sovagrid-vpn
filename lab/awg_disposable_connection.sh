#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
# Remote VPS lab: two disposable containers on an internal Docker network.
# All keys are generated inside the containers. No live Amnezia container is used.
set -eu
umask 077
suffix=$(date +%s)-$$
network=sg-awg-lab-$suffix
server=sg-awg-server-$suffix
client=sg-awg-client-$suffix
network_created=0
server_created=0
client_created=0
cleanup() {
  if [ "$client_created" = 1 ]; then docker rm -f "$client" >/dev/null 2>&1 || :; fi
  if [ "$server_created" = 1 ]; then docker rm -f "$server" >/dev/null 2>&1 || :; fi
  if [ "$network_created" = 1 ]; then docker network rm "$network" >/dev/null 2>&1 || :; fi
}
trap cleanup EXIT

docker network create --internal "$network" >/dev/null
network_created=1
for role in server client; do
  if [ "$role" = server ]; then name=$server; else name=$client; fi
  docker run -d --rm --pull never \
    --network "$network" --device /dev/net/tun --cap-add NET_ADMIN \
    --read-only --tmpfs /tmp:rw,nosuid,nodev,size=4m \
    --tmpfs /run:rw,nosuid,nodev,size=1m \
    --pids-limit 64 --memory 128m --security-opt no-new-privileges \
    --name "$name" --entrypoint /bin/sh amnezia-awg2:latest \
    -c 'amneziawg-go sg0 > /tmp/awg-go.log 2>&1 & while :; do sleep 60; done' >/dev/null
  if [ "$role" = server ]; then server_created=1; else client_created=1; fi
done

for name in "$server" "$client"; do
  ready=0
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if docker exec "$name" awg show sg0 >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.2
  done
  test "$ready" = 1
  docker exec "$name" /bin/sh -c 'set -eu; umask 077; awg genkey > /tmp/private; awg pubkey < /tmp/private > /tmp/public'
done

server_public=$(docker exec "$server" cat /tmp/public)
client_public=$(docker exec "$client" cat /tmp/public)
server_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$server")
test -n "$server_ip"

docker exec -e PEER_PUBLIC="$client_public" "$server" /bin/sh -c '
  set -eu
  umask 077
  {
    printf "[Interface]\nPrivateKey = %s\nListenPort = 49289\n" "$(cat /tmp/private)"
    printf "[Peer]\nPublicKey = %s\nAllowedIPs = 10.212.0.2/32\n" "$PEER_PUBLIC"
  } > /tmp/initial.conf
  awg setconf sg0 /tmp/initial.conf
  ip address add 10.212.0.1/24 dev sg0
  ip link set sg0 up
'
docker exec -e PEER_PUBLIC="$server_public" -e PEER_ENDPOINT="$server_ip:49289" \
  "$client" /bin/sh -c '
  set -eu
  umask 077
  {
    printf "[Interface]\nPrivateKey = %s\nListenPort = 49290\n" "$(cat /tmp/private)"
    printf "[Peer]\nPublicKey = %s\nAllowedIPs = 10.212.0.1/32\nEndpoint = %s\nPersistentKeepalive = 1\n" "$PEER_PUBLIC" "$PEER_ENDPOINT"
  } > /tmp/client.conf
  awg setconf sg0 /tmp/client.conf
  ip address add 10.212.0.2/24 dev sg0
  ip link set sg0 up
'

docker exec "$client" ping -c 3 -W 3 10.212.0.1 >/dev/null
docker exec "$server" /bin/sh -c '
  set -eu
  umask 077
  awg genkey > /tmp/new-private
  awg pubkey < /tmp/new-private > /tmp/new-public
  cat /tmp/initial.conf > /tmp/added.conf
  printf "[Peer]\nPublicKey = %s\nAllowedIPs = 10.212.0.3/32\n" "$(cat /tmp/new-public)" >> /tmp/added.conf
  awg syncconf sg0 /tmp/added.conf
  awg show sg0 peers | grep -Fxq "$(cat /tmp/new-public)"
  test "$(awg show sg0 peers | wc -l | tr -d " ")" = 2
'
docker exec "$client" ping -c 3 -W 3 10.212.0.1 >/dev/null
docker exec "$server" /bin/sh -c '
  set -eu
  awg syncconf sg0 /tmp/initial.conf
  test "$(awg show sg0 peers | wc -l | tr -d " ")" = 1
'
docker exec "$client" ping -c 3 -W 3 10.212.0.1 >/dev/null
printf '%s\n' 'AWG isolated client handshake and original connection after add/revoke: pass'
