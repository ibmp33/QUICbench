#!/usr/bin/env bash
set -euo pipefail

CLIENT_NS="${CLIENT_NS:-quicbench-client}"
HOST_IF="${HOST_IF:-veth-c-host}"

echo "[+] deleting host veth: $HOST_IF"
sudo ip link del "$HOST_IF" 2>/dev/null || true

echo "[+] deleting namespace: $CLIENT_NS"
sudo ip netns del "$CLIENT_NS" 2>/dev/null || true

echo "[+] done"
