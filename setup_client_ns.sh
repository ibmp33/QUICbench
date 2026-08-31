#!/usr/bin/env bash
set -euo pipefail

CLIENT_NS="${CLIENT_NS:-quicbench-client}"
HOST_IF="${HOST_IF:-veth-c-host}"
NS_IF="${NS_IF:-veth-client}"
HOST_IP="${HOST_IP:-198.19.1.1/24}"
NS_IP="${NS_IP:-198.19.1.2/24}"
NS_GW="${NS_GW:-198.19.1.1}"

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

echo "[+] creating namespace: $CLIENT_NS"
sudo ip netns add "$CLIENT_NS" 2>/dev/null || true

echo "[+] creating veth pair: $HOST_IF <-> $NS_IF"
sudo ip link add "$HOST_IF" type veth peer name "$NS_IF" 2>/dev/null || true

echo "[+] moving $NS_IF into namespace $CLIENT_NS"
sudo ip link set "$NS_IF" netns "$CLIENT_NS" 2>/dev/null || true

echo "[+] configuring host side: $HOST_IF = $HOST_IP"
sudo ip addr flush dev "$HOST_IF" 2>/dev/null || true
sudo ip addr add "$HOST_IP" dev "$HOST_IF" 2>/dev/null || true
sudo ip link set "$HOST_IF" up
disable_offloads "$HOST_IF"

echo "[+] configuring client namespace side: $NS_IF = $NS_IP"
sudo ip netns exec "$CLIENT_NS" ip addr flush dev "$NS_IF" 2>/dev/null || true
sudo ip netns exec "$CLIENT_NS" ip addr add "$NS_IP" dev "$NS_IF" 2>/dev/null || true
sudo ip netns exec "$CLIENT_NS" ip link set "$NS_IF" up
sudo ip netns exec "$CLIENT_NS" ip link set lo up
disable_ns_offloads "$CLIENT_NS" "$NS_IF"

echo "[+] adding default route in client namespace via $NS_GW"
sudo ip netns exec "$CLIENT_NS" ip route replace default via "$NS_GW"

echo "[+] enabling host forwarding"
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "[+] adding forwarding rules"
sudo iptables -C FORWARD -i "$HOST_IF" -o veth-host -j ACCEPT 2>/dev/null || \
  sudo iptables -A FORWARD -i "$HOST_IF" -o veth-host -j ACCEPT

sudo iptables -C FORWARD -i veth-host -o "$HOST_IF" -j ACCEPT 2>/dev/null || \
  sudo iptables -A FORWARD -i veth-host -o "$HOST_IF" -j ACCEPT

echo "[+] setup complete"
echo "    client namespace:"
echo "      $CLIENT_NS/$NS_IF = $NS_IP"
echo "    host impairment side:"
echo "      $HOST_IF = $HOST_IP"
echo "    offloads:"
echo "      $HOST_IF and $CLIENT_NS/$NS_IF: gro/gso/tso disabled"
