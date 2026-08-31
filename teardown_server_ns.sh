#!/usr/bin/env bash
set -euo pipefail

SERVER_NS="${SERVER_NS:-quicbench-server}"
HOST_IF="${HOST_IF:-veth-host}"

echo "[+] deleting veth: $HOST_IF"
sudo ip link del "$HOST_IF" 2>/dev/null || true

echo "[+] deleting namespace: $SERVER_NS"
sudo ip netns del "$SERVER_NS" 2>/dev/null || true

echo "[+] done"
