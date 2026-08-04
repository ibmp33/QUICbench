#!/usr/bin/env bash
set -euo pipefail

SERVER_NS="${SERVER_NS:-quicbench-server}"

HOST_IF="${HOST_IF:-veth-host}"
NS_IF="${NS_IF:-veth-server}"

HOST_IP="${HOST_IP:-198.19.0.1/24}"
NS_IP="${NS_IP:-198.19.0.2/24}"

NS_GW="${NS_GW:-198.19.0.1}"

disable_offloads() {
  local iface="$1"
  sudo ethtool -K "$iface" rx on tx on 2>/dev/null || true
  sudo ethtool -K "$iface" gro off gso off tso off 2>/dev/null || true
  sudo ethtool -K "$iface" ufo off lro off 2>/dev/null || true
  sudo ethtool -K "$iface" tx-udp-segmentation off 2>/dev/null || true
}

disable_ns_offloads() {
  local ns="$1"
  local iface="$2"
  sudo ip netns exec "$ns" ethtool -K "$iface" rx on tx on 2>/dev/null || true
  sudo ip netns exec "$ns" ethtool -K "$iface" gro off gso off tso off 2>/dev/null || true
  sudo ip netns exec "$ns" ethtool -K "$iface" ufo off lro off 2>/dev/null || true
  sudo ip netns exec "$ns" ethtool -K "$iface" tx-udp-segmentation off 2>/dev/null || true
}

echo "[+] creating server namespace: $SERVER_NS"
sudo ip netns add "$SERVER_NS" 2>/dev/null || true

echo "[+] creating veth pair: $HOST_IF <-> $NS_IF"
sudo ip link add "$HOST_IF" type veth peer name "$NS_IF" 2>/dev/null || true

echo "[+] moving $NS_IF into namespace $SERVER_NS"
sudo ip link set "$NS_IF" netns "$SERVER_NS" 2>/dev/null || true

echo "[+] configuring host side interface"

sudo ip addr flush dev "$HOST_IF" 2>/dev/null || true
sudo ip addr add "$HOST_IP" dev "$HOST_IF" 2>/dev/null || true
sudo ip link set "$HOST_IF" up
disable_offloads "$HOST_IF"

echo "[+] configuring server namespace interface"

sudo ip netns exec "$SERVER_NS" ip addr flush dev "$NS_IF" 2>/dev/null || true
sudo ip netns exec "$SERVER_NS" ip addr add "$NS_IP" dev "$NS_IF" 2>/dev/null || true

sudo ip netns exec "$SERVER_NS" ip link set "$NS_IF" up
sudo ip netns exec "$SERVER_NS" ip link set lo up
disable_ns_offloads "$SERVER_NS" "$NS_IF"

echo "[+] adding default route in server namespace"

sudo ip netns exec "$SERVER_NS" ip route replace default via "$NS_GW"

echo "[+] enabling IP forwarding"

sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "[+] server namespace setup complete"

echo
echo "Server namespace:"
echo "  namespace : $SERVER_NS"
echo "  interface : $NS_IF"
echo "  ip        : $NS_IP"

echo
echo "Host impairment side:"
echo "  interface : $HOST_IF"
echo "  ip        : $HOST_IP"
echo
echo "Offloads:"
echo "  $HOST_IF     : gro/gso/tso disabled"
echo "  $SERVER_NS/$NS_IF : gro/gso/tso disabled"
