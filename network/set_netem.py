import subprocess
from operator import itemgetter


def _netem_clause(delay_ms, jitter_ms=0, loss_percent=0, reorder_percent=0):
    clause = "delay {}ms".format(delay_ms)
    if float(jitter_ms) > 0:
        clause += " {}ms distribution normal".format(jitter_ms)
    if float(loss_percent) > 0:
        clause += " loss random {}%".format(loss_percent)
    if float(reorder_percent) > 0:
        clause += " reorder {}%".format(reorder_percent)
    return clause


def resolve_netem_parameters(netem_conf):
    """Resolve an explicit Paper-v1 profile or a legacy RTT/BDP profile."""
    explicit_profile = "queue_size_bytes" in netem_conf
    if explicit_profile:
        forward_delay_ms = float(netem_conf["forward_delay_ms"])
        reverse_delay_ms = float(netem_conf["reverse_delay_ms"])
        bandwidth_mbps = float(netem_conf["forward_bandwidth_mbps"])
        queue_size_bytes = int(netem_conf["queue_size_bytes"])
    else:
        rtt_ms, bandwidth_mbps, buffer_bdp = itemgetter(
            "RTT_ms", "bandwidth_Mbps", "buffer_bdp"
        )(netem_conf)
        forward_delay_ms = float(rtt_ms) / 2.0
        reverse_delay_ms = float(rtt_ms) / 2.0
        bandwidth_mbps = float(bandwidth_mbps)
        queue_size_bytes = int(
            float(rtt_ms) * bandwidth_mbps * 1000 / 8 * float(buffer_bdp)
        )
    if min(forward_delay_ms, reverse_delay_ms, bandwidth_mbps, queue_size_bytes) <= 0:
        raise ValueError("delay, bandwidth and queue size must be positive")
    return {
        "forward_delay_ms": forward_delay_ms,
        "reverse_delay_ms": reverse_delay_ms,
        "bandwidth_mbps": bandwidth_mbps,
        "queue_size_bytes": queue_size_bytes,
        "forward_jitter_ms": float(netem_conf.get("jitter_ms", 0)) / 2.0,
        "reverse_jitter_ms": float(
            netem_conf.get(
                "reverse_jitter_ms",
                0 if explicit_profile else netem_conf.get("jitter_ms", 0),
            )
        ) / 2.0,
        "forward_loss_percent": float(
            netem_conf.get("random_loss_forward_percent", 0)
        ),
        "reverse_loss_percent": float(
            netem_conf.get("random_loss_reverse_percent", 0)
        ),
        "forward_reorder_percent": float(
            netem_conf.get("intentional_reordering_percent", 0)
        ),
        "reverse_reorder_percent": float(
            netem_conf.get("intentional_reordering_reverse_percent", 0)
        ),
        "reverse_bottleneck": bool(
            netem_conf.get("reverse_bottleneck", not explicit_profile)
        ),
    }

# for introducing delay for ingress packets
def run_local_sudo(cmd):
    subprocess.run(["sudo", "bash", "-lc", cmd], check=True)


def disable_interface_offloads(interface):
    # Turn off segmentation/aggregation features so tc sees packet timing
    # closer to what the transport stack actually emits.
    cmd = (
        "ethtool -K {interface} rx on tx on 2>/dev/null || true;"
        "ethtool -K {interface} gro off gso off tso off 2>/dev/null || true;"
        "ethtool -K {interface} ufo off lro off 2>/dev/null || true;"
        "ethtool -K {interface} tx-udp-segmentation off 2>/dev/null || true"
    ).format(interface=interface)
    run_local_sudo(cmd)


def ensure_ifb_interface(ingress_interface):
    cmd = (
        "set -e;"
        "modprobe ifb;"
        "ip link show dev {ingress_interface} >/dev/null 2>&1 || ip link add {ingress_interface} type ifb;"
        "ip link set dev {ingress_interface} up"
    ).format(ingress_interface=ingress_interface)
    run_local_sudo(cmd)


def add_ingress_interface(server_hostname, server_pw_path, interface, ingress_interface):
    cmd = (
        "set -e;"
        "tc qdisc add dev {interface} ingress;"
        "tc filter add dev {interface} parent ffff: protocol ip u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev {ingress_interface}"
    ).format(interface=interface, ingress_interface=ingress_interface)
    run_local_sudo(cmd)
    disable_interface_offloads(interface)
    disable_interface_offloads(ingress_interface)

# for capturing packets before qdisc egress to measure queuing delay/packets dropped by buffer
def add_virtual_interface(server_hostname, server_pw_path, server_ip, interface, virtual_interface):
    cmd = (
        "brctl addbr {virtual_interface};"
        "brctl addif {virtual_interface} {interface};"
        "ip link set dev {virtual_interface} up;"
        "ip addr add dev {virtual_interface} {server_ip}/8;"
        "ip addr flush dev {interface};"
    ).format(interface=interface, virtual_interface=virtual_interface, server_ip=server_ip)
    run_local_sudo(cmd)

def set_netem(server_hostname, server_pw_path, server_ip, interface, ingress_interface, netem_conf, virtual_interface=None):
    print("Setting network emulation:")
    # Clear any previous shaping/filter state so repeated runs don't stack
    # duplicate ingress redirects or leave an old ifb root qdisc behind.
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "root"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "handle", "ffff:", "ingress"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", ingress_interface, "root"], stderr=subprocess.DEVNULL)

    parameters = resolve_netem_parameters(netem_conf)
    bandwidth_Mbps = parameters["bandwidth_mbps"]
    reverse_bottleneck = parameters["reverse_bottleneck"]

    if virtual_interface:
        add_virtual_interface(server_hostname, server_pw_path, server_ip, interface, virtual_interface)

    ensure_ifb_interface(ingress_interface)
    add_ingress_interface(server_hostname, server_pw_path, interface, ingress_interface)

    buffer_bytes = parameters["queue_size_bytes"]
    bandwidth_Kbps = bandwidth_Mbps * 1000
    burst_bytes = int(bandwidth_Mbps * 1000000 / 250 / 8) # https://unix.stackexchange.com/questions/100785/bucket-size-in-tbf
    if buffer_bytes <= burst_bytes:
        raise ValueError("queue_size_bytes must exceed the TBF burst size")
    forward_delay_clause = _netem_clause(
        parameters["forward_delay_ms"],
        parameters["forward_jitter_ms"],
        parameters["forward_loss_percent"],
        parameters["forward_reorder_percent"],
    )
    reverse_delay_clause = _netem_clause(
        parameters["reverse_delay_ms"],
        parameters["reverse_jitter_ms"],
        parameters["reverse_loss_percent"],
        parameters["reverse_reorder_percent"],
    )

    reverse_qdisc_cmd = "tc qdisc add dev {interface} root handle 1:0 netem {reverse_delay_clause} limit 12500;".format(
        interface=interface, reverse_delay_clause=reverse_delay_clause
    )
    if reverse_bottleneck:
        reverse_qdisc_cmd += "tc qdisc add dev {interface} parent 1:1 handle 10: tbf rate {bandwidth_Kbps}kbit limit {buffer_bytes} burst {burst_bytes};".format(
            interface=interface,
            bandwidth_Kbps=bandwidth_Kbps,
            buffer_bytes=buffer_bytes,
            burst_bytes=burst_bytes,
        )

    cmd = (
        "set -e;"
        "{reverse_qdisc_cmd}"
        "tc qdisc add dev {ingress_interface} root handle 2:0 netem {forward_delay_clause} limit 12500;"
        "tc qdisc add dev {ingress_interface} parent 2:1 handle 20: tbf rate {bandwidth_Kbps}kbit limit {buffer_bytes} burst {burst_bytes};"
        "ip link show dev {ingress_interface};"
        "tc qdisc show dev {interface} && tc qdisc show dev {ingress_interface}"
    ).format(
        reverse_qdisc_cmd=reverse_qdisc_cmd,
        interface=interface,
        ingress_interface=ingress_interface,
        forward_delay_clause=forward_delay_clause,
        bandwidth_Kbps=bandwidth_Kbps,
        buffer_bytes=buffer_bytes,
        burst_bytes=burst_bytes,
    )
    run_local_sudo(cmd)
