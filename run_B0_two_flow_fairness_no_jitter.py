import argparse
import hashlib
import json
import os
import platform
import subprocess
import time
from datetime import datetime
from operator import itemgetter

from ack_policies import load_ack_policy_configs
from network.clear_netem import clear_netem
from network.set_netem import set_netem
from network.tcpdump import TCPDump
from stacks.mvfst import Mvfst
from stacks.quiche import Quiche
from stacks.quic_go import (
    QuicGo,
    QuicGoAck2,
    QuicGoAck5,
    QuicGoAck10,
    QuicGoPolicy,
)
from stacks.xquic import Xquic
from workloads import generated_target, load_workload_profiles, resolve_workload


STACK_CLASSES = {
    Mvfst.NAME: Mvfst,
    Quiche.NAME: Quiche,
    Xquic.NAME: Xquic,
    QuicGo.NAME: QuicGo,
    QuicGoAck2.NAME: QuicGoAck2,
    QuicGoAck5.NAME: QuicGoAck5,
    QuicGoAck10.NAME: QuicGoAck10,
    QuicGoPolicy.NAME: QuicGoPolicy,
}


def get_prog_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stacks_conf", "-s", type=str, default="./config/stacks_conf_default.json")
    parser.add_argument("--general_conf", "-k", type=str, default="./config/general_conf_default.json")
    parser.add_argument(
        "--workloads-conf",
        type=str,
        default="./config/workloads_conf_default.json",
        help="workload profile configuration",
    )
    parser.add_argument(
        "--ack-policies-conf",
        type=str,
        default="./config/ack_policies_default.json",
        help="ACK policy parameter configuration recorded in manifests",
    )
    parser.add_argument("--exp_conf", "-e", type=str, default="./config/B0_two_flow_fairness_no_jitter.json")
    parser.add_argument("--server-stack-name", type=str, help="override the shared server stack for all flows")
    parser.add_argument("--num-trials", type=int, help="override exp_conf num_trials")
    parser.add_argument(
        "--network-profile",
        action="append",
        dest="network_profiles",
        help="run one named network profile from exp_conf; repeat the flag to run multiple profiles",
    )
    parser.add_argument("--dry-run", action="store_true", help="validate config and print commands without launching processes")
    parser.add_argument(
        "--pcap-policy",
        choices=["all", "first-only", "none"],
        default=None,
        help="retain pcaps for all runs, only the first run of each policy pair, or none",
    )
    parser.add_argument(
        "--keep-pcap",
        action="store_true",
        help="deprecated compatibility alias for --pcap-policy all",
    )
    parser.add_argument(
        "--keep-run-artifacts",
        action="store_true",
        help="keep per-run directories (qlogs, logs, manifests, traces) after parsing",
    )
    parser.add_argument(
        "--qlog-policy",
        choices=["all", "first-only", "none"],
        default="all",
        help="retain qlogs for all runs, only the first run of each trial, or none",
    )
    return parser.parse_args()


def load_json(path):
    with open(path) as f:
        return json.load(f)


def now():
    return datetime.now().isoformat(timespec="seconds")


def log(message):
    print("[{}] {}".format(now(), message))


def fail(message):
    raise SystemExit(message)


def validate_required_fields(name, conf, fields):
    for field in fields:
        if not conf.get(field):
            fail("Stack '{}' is missing required field '{}' in stacks_conf.".format(name, field))


def validate_path_direction(name, conf):
    server_base = os.path.basename(conf["server_path"]).lower()
    client_base = os.path.basename(conf["client_path"]).lower()
    if "client" in server_base:
        fail("Stack '{}' looks misconfigured: server_path points to '{}'. Expected a server binary.".format(name, conf["server_path"]))
    if "server" in client_base:
        fail("Stack '{}' looks misconfigured: client_path points to '{}'. Expected a client binary.".format(name, conf["client_path"]))


def check_sudo_privileges():
    subprocess.run(["sudo", "-n", "true"], check=True)


def set_kernel_params(kernel_params):
    log("Setting local kernel parameters")
    for param, value in kernel_params.items():
        subprocess.run(["sudo", "sysctl", "-w", "{}={}".format(param, value)], check=True)


def instantiate_stacks(stacks_conf, general_conf):
    server_ip = general_conf["server_ip"]
    stacks = {}
    for name, conf in stacks_conf.items():
        cls = STACK_CLASSES.get(name)
        if not cls:
            fail("stacks_conf contains unsupported stack '{}'.".format(name))
        validate_required_fields(
            name,
            conf,
            [
                "server_path",
                "client_path",
                "server_cert_path",
                "server_key_path",
                "protocol",
            ],
        )
        validate_path_direction(name, conf)
        stacks[name] = cls(server_ip=server_ip, server_hostname="localhost", server_pw_path="", **conf)
    return stacks


def configure_qlog(stacks, enabled):
    for stack in stacks.values():
        setter = getattr(stack, "set_qlog_enabled", None)
        if setter:
            setter(enabled)
        else:
            stack.qlog_enabled = bool(enabled)


def base_stack_name(stack_name):
    return stack_name.split("-ack")[0]


def server_stack_family(server_stack_name):
    return "{}-server".format(base_stack_name(server_stack_name))


def detect_stack_family(exp_conf):
    fixed_parameters = exp_conf.get("fixed_parameters", {})
    server_stack_name = fixed_parameters.get("server_stack_name")
    if server_stack_name:
        return server_stack_family(server_stack_name)

    family = fixed_parameters.get("stack_family")
    if family:
        return family

    allowed = exp_conf.get("allowed_stack_names") or []
    if allowed:
        prefixes = {name.split("-ack")[0] for name in allowed}
        if len(prefixes) == 1:
            return next(iter(prefixes))

    trial_families = {
        flow["stack_name"].split("-ack")[0]
        for trial in exp_conf.get("trials", [])
        for flow in trial.get("flows", [])
    }
    if len(trial_families) == 1:
        return next(iter(trial_families))
    return "mixed"


def normalize_experiment_identity(exp_conf):
    family = detect_stack_family(exp_conf)
    suffix = "-{}".format(family)

    experiment_name = exp_conf["experiment_name"]
    if not experiment_name.endswith(suffix):
        exp_conf["experiment_name"] = "{}{}".format(experiment_name, suffix)

    results_dir = exp_conf["experiment_results_dir"].rstrip("/")
    base_name = os.path.basename(results_dir)
    if not base_name.endswith(suffix):
        exp_conf["experiment_results_dir"] = os.path.join(os.path.dirname(results_dir), "{}{}".format(base_name, suffix))

    exp_conf.setdefault("fixed_parameters", {})
    exp_conf["fixed_parameters"]["stack_family"] = family
    return family


def get_network_profiles(exp_conf):
    profiles = exp_conf.get("network_profiles")
    if profiles:
        return profiles
    return [
        {
            "name": "default",
            "netem_conf": exp_conf["netem_conf"],
        }
    ]


def validate_network_profiles(exp_conf):
    profiles = get_network_profiles(exp_conf)
    seen_names = set()
    for profile in profiles:
        profile_name = profile.get("name")
        if not profile_name:
            fail("Each network profile must define a non-empty 'name'.")
        if profile_name in seen_names:
            fail("Duplicate network profile name '{}'.".format(profile_name))
        seen_names.add(profile_name)
        netem_conf = profile.get("netem_conf")
        if not netem_conf:
            fail("Network profile '{}' is missing 'netem_conf'.".format(profile_name))
        for field in ["RTT_ms", "bandwidth_Mbps", "buffer_bdp"]:
            value = netem_conf.get(field)
            if value is None:
                fail("Network profile '{}' is missing netem_conf['{}'].".format(profile_name, field))
            if float(value) <= 0:
                fail("Network profile '{}' must set {} > 0.".format(profile_name, field))
        jitter_ms = netem_conf.get("jitter_ms", 0)
        if float(jitter_ms) < 0:
            fail("Network profile '{}' must set jitter_ms >= 0.".format(profile_name))
        reverse_jitter_ms = netem_conf.get("reverse_jitter_ms", jitter_ms)
        if float(reverse_jitter_ms) < 0:
            fail("Network profile '{}' must set reverse_jitter_ms >= 0.".format(profile_name))


def apply_runtime_overrides(args, exp_conf):
    exp_conf.setdefault("fixed_parameters", {})
    if args.server_stack_name:
        exp_conf["fixed_parameters"]["server_stack_name"] = args.server_stack_name
        exp_conf["fixed_parameters"]["stack_family"] = server_stack_family(args.server_stack_name)
    if args.num_trials is not None:
        if args.num_trials <= 0:
            fail("--num-trials must be > 0.")
        exp_conf["num_trials"] = args.num_trials


def resolve_pcap_policy(args):
    if args.keep_pcap and args.pcap_policy not in (None, "all"):
        fail("--keep-pcap cannot be combined with --pcap-policy {}.".format(args.pcap_policy))
    if args.keep_pcap:
        return "all"
    return args.pcap_policy or "none"


def activate_workload(exp_conf, workload_profiles):
    workload_name = exp_conf.get("workload_name")
    if not workload_name:
        # Preserve historical validation experiments that predate workload
        # profiles. New fairness configs must select a named profile.
        workload = {
            "name": "legacy-validation",
            "bytes": 16777216,
            "duration_s": int(exp_conf["flow_duration_s"]),
        }
    else:
        try:
            workload = resolve_workload(workload_profiles, workload_name)
        except ValueError as exc:
            fail(str(exc))
    exp_conf["workload"] = workload
    # Keep this derived field for the existing parser/network interfaces. The
    # profile remains the single source of truth.
    exp_conf["flow_duration_s"] = workload["duration_s"]
    exp_conf.setdefault("fixed_parameters", {})
    exp_conf["fixed_parameters"]["same_workload_name"] = workload["name"]
    exp_conf["fixed_parameters"]["same_runtime_seconds"] = workload["duration_s"]
    exp_conf["fixed_parameters"]["same_requested_bytes"] = workload["bytes"]
    return workload


def activate_ack_policy_configs(exp_conf, ack_policy_document):
    exp_conf["ack_policy_config_schema_version"] = ack_policy_document["schema_version"]
    exp_conf["ack_policy_configs"] = ack_policy_document["policies"]


def get_selected_network_profiles(args, exp_conf):
    profiles = get_network_profiles(exp_conf)
    profile_map = {profile["name"]: profile for profile in profiles}
    requested_names = args.network_profiles or [exp_conf.get("default_network_profile") or profiles[0]["name"]]
    missing = [name for name in requested_names if name not in profile_map]
    if missing:
        fail(
            "Unknown network profile(s): {}. Available profiles: {}.".format(
                ", ".join(sorted(missing)),
                ", ".join(sorted(profile_map.keys())),
            )
        )
    return [profile_map[name] for name in requested_names]


def activate_network_profile(exp_conf, profile):
    exp_conf["active_network_profile"] = profile["name"]
    exp_conf["netem_conf"] = dict(profile["netem_conf"])
    exp_conf.setdefault("fixed_parameters", {})
    exp_conf["fixed_parameters"]["same_rtt_ms"] = exp_conf["netem_conf"]["RTT_ms"]
    exp_conf["fixed_parameters"]["same_bottleneck_bandwidth_mbps"] = exp_conf["netem_conf"]["bandwidth_Mbps"]
    exp_conf["fixed_parameters"]["same_buffer_bdp"] = exp_conf["netem_conf"]["buffer_bdp"]
    exp_conf["fixed_parameters"]["same_jitter_ms"] = exp_conf["netem_conf"].get("jitter_ms", 0)


def validate_experiment(stacks_conf, exp_conf):
    allowed = set(exp_conf["allowed_stack_names"])
    server_stack_name = exp_conf.get("fixed_parameters", {}).get("server_stack_name")
    required = set(allowed)
    if server_stack_name:
        required.add(server_stack_name)
    missing = required.difference(stacks_conf.keys())
    if missing:
        fail("stacks_conf is missing required stack definitions: {}.".format(", ".join(sorted(missing))))
    validate_network_profiles(exp_conf)
    if int(exp_conf["flow_duration_s"]) <= 0:
        fail("flow_duration_s must be > 0.")
    workload = exp_conf.get("workload")
    if not workload:
        fail("An active workload profile is required.")
    validate_server_workload_capabilities(stacks_conf, exp_conf, check_files=False)
    ack_policy_configs = exp_conf.get("ack_policy_configs") or {}
    topology_mode = exp_conf.get("topology_mode")
    allowed_topologies = {
        "shared-server-shared-port",
        "same-implementation-different-ports-control",
    }
    if topology_mode not in allowed_topologies:
        fail(
            "topology_mode must be one of: {}.".format(
                ", ".join(sorted(allowed_topologies))
            )
        )
    for trial in exp_conf["trials"]:
        flows = trial["flows"]
        if len(flows) != 2:
            fail("Trial '{}' must define exactly 2 flows.".format(trial["name"]))
        port_server_map = {}
        local_ports = set()
        for flow in flows:
            if flow["stack_name"] not in allowed:
                fail("Trial '{}' uses unsupported stack '{}'.".format(trial["name"], flow["stack_name"]))
            per_flow_server_stack = flow.get("server_stack_name") or server_stack_name or flow["stack_name"]
            if per_flow_server_stack not in stacks_conf:
                fail(
                    "Trial '{}' uses undefined server stack '{}'.".format(
                        trial["name"], per_flow_server_stack
                    )
                )
            port_no = str(flow["port_no"])
            previous_server_stack = port_server_map.get(port_no)
            if previous_server_stack and previous_server_stack != per_flow_server_stack:
                fail(
                    "Trial '{}' reuses port {} across different server stacks ('{}' vs '{}'). "
                    "A shared server port must map to exactly one server stack.".format(
                        trial["name"], port_no, previous_server_stack, per_flow_server_stack
                    )
                )
            port_server_map[port_no] = per_flow_server_stack
            local_port = flow.get("local_port")
            ack_policy = flow.get("ack_policy")
            if flow["stack_name"] == QuicGoPolicy.NAME:
                if ack_policy not in QuicGoPolicy.ACK_POLICIES:
                    fail(
                        "Trial '{}' flow '{}' has unsupported ack_policy {!r}; valid values: {}.".format(
                            trial["name"],
                            flow["flow_id"],
                            ack_policy,
                            ", ".join(sorted(QuicGoPolicy.ACK_POLICIES)),
                        )
                    )
                if ack_policy not in ack_policy_configs:
                    fail(
                        "Trial '{}' flow '{}' has no manifest configuration for ACK policy '{}'.".format(
                            trial["name"], flow["flow_id"], ack_policy
                        )
                    )
            elif ack_policy is not None:
                fail(
                    "Trial '{}' flow '{}' sets ack_policy but client stack '{}' is not quic-go-policy.".format(
                        trial["name"], flow["flow_id"], flow["stack_name"]
                    )
                )
            if flow.get("ack_policy") and local_port is None:
                fail("Trial '{}' flow '{}' must define local_port for deterministic flow mapping.".format(trial["name"], flow["flow_id"]))
            if local_port is not None and int(local_port) in local_ports:
                fail("Trial '{}' reuses local_port {}.".format(trial["name"], local_port))
            if local_port is not None:
                local_ports.add(int(local_port))
        if any(flow["cc_algo"] != "cubic" for flow in flows):
            fail("Trial '{}' must keep cc_algo fixed at 'cubic'.".format(trial["name"]))
        if topology_mode == "shared-server-shared-port":
            server_endpoints = {
                (resolve_server_stack_name(exp_conf, flow), str(flow["port_no"]))
                for flow in flows
            }
            if len(server_endpoints) != 1:
                fail(
                    "Trial '{}' violates main fairness semantics: both flows must use "
                    "one server stack and one listening port.".format(trial["name"])
                )
            if len(local_ports) != len(flows):
                fail(
                    "Trial '{}' violates main fairness semantics: every flow must use "
                    "a distinct local UDP port.".format(trial["name"])
                )


def validate_server_workload_capabilities(stacks_conf, exp_conf, check_files):
    workload = exp_conf["workload"]
    workload_name = workload["name"]
    if workload_name in {"smoke", "legacy-validation"}:
        return
    server_names = {
        resolve_server_stack_name(exp_conf, flow)
        for trial in exp_conf["trials"]
        for flow in trial["flows"]
    }
    for server_name in server_names:
        capability = (
            stacks_conf[server_name]
            .get("workload_capabilities", {})
            .get(workload_name)
        )
        if not capability:
            fail(
                "Server stack '{}' does not declare support for workload '{}'.".format(
                    server_name, workload_name
                )
            )
        mode = capability.get("mode")
        if mode == "blocked":
            fail(
                "Server stack '{}' is not ready for workload '{}': {}".format(
                    server_name,
                    workload_name,
                    capability.get("reason", "adapter capability is blocked"),
                )
            )
        if mode not in {"dynamic-response", "static-file", "continuous-stream"}:
            fail(
                "Server stack '{}' has unsupported workload capability mode {!r}.".format(
                    server_name, mode
                )
            )
        if check_files and mode == "static-file":
            path = capability.get("path")
            if not path or not os.path.isfile(path):
                fail(
                    "Server stack '{}' requires fairness object {}. Create it before running.".format(
                        server_name, path or "<missing path>"
                    )
                )
            actual_bytes = os.path.getsize(path)
            requested_bytes = int(workload["bytes"])
            if actual_bytes < requested_bytes:
                fail(
                    "Server stack '{}' fairness object is too small: {} bytes at {}; need at least {}.".format(
                        server_name, actual_bytes, path, requested_bytes
                    )
                )


def get_required_stack_names(exp_conf):
    required = set(exp_conf.get("allowed_stack_names") or [])
    server_stack_name = exp_conf.get("fixed_parameters", {}).get("server_stack_name")
    if server_stack_name:
        required.add(server_stack_name)
    for trial in exp_conf.get("trials", []):
        for flow in trial.get("flows", []):
            required.add(flow["stack_name"])
            per_flow_server_stack = flow.get("server_stack_name")
            if per_flow_server_stack:
                required.add(per_flow_server_stack)
    return required


def validate_local_paths(stacks_conf, exp_conf):
    validate_server_workload_capabilities(stacks_conf, exp_conf, check_files=True)
    required_stack_names = get_required_stack_names(exp_conf)
    for stack_name, stack_conf in stacks_conf.items():
        if stack_name not in required_stack_names:
            continue
        for field in ["server_path", "client_path", "server_cert_path", "server_key_path"]:
            if not os.path.exists(stack_conf[field]):
                fail("Local preflight failed for stack '{}': '{}' does not exist at {}.".format(stack_name, field, stack_conf[field]))
        server_root = stack_conf.get("server_root")
        if server_root and not os.path.isdir(server_root):
            fail("Local preflight failed for stack '{}': 'server_root' does not exist at {}.".format(stack_name, server_root))
        protocol = stack_conf.get("protocol")
        if protocol == "http3" and not stack_conf.get("client_url_template"):
            fail("Stack '{}' must define client_url_template for HTTP/3.".format(stack_name))
        if protocol == "raw" and not stack_conf.get("client_addr_template"):
            fail("Stack '{}' must define client_addr_template for raw QUIC.".format(stack_name))


def netns_exists(namespace):
    result = subprocess.run(["sudo", "ip", "netns", "list"], capture_output=True, text=True, check=True)
    return any(line.split()[0] == namespace for line in result.stdout.splitlines() if line.strip())


def interface_exists(interface):
    return subprocess.run(["ip", "link", "show", interface], capture_output=True).returncode == 0


def validate_local_topology(general_conf, stacks_conf):
    client_ns = next(iter(stacks_conf.values())).get("client_netns", "quicbench-client")
    server_ns = next(iter(stacks_conf.values())).get("server_netns", "quicbench-server")
    interface = general_conf["interface"]
    ingress_interface = general_conf["server_ingress_interface"]

    if not netns_exists(client_ns):
        fail(
            "Local preflight failed: netns '{}' is missing. Run ./setup_client_ns.sh first.".format(
                client_ns
            )
        )
    if not netns_exists(server_ns):
        fail(
            "Local preflight failed: netns '{}' is missing. Run ./setup_server_ns.sh first.".format(
                server_ns
            )
        )
    if not interface_exists(interface):
        fail(
            "Local preflight failed: bottleneck interface '{}' is missing. "
            "The provided setup scripts create 'veth-host' for the server-side impairment link.".format(
                interface
            )
        )
    if interface == ingress_interface:
        fail("general_conf interface and server_ingress_interface must be different.")

    server_ip = general_conf["server_ip"]
    ping_cmd = [
        "sudo",
        "ip",
        "netns",
        "exec",
        client_ns,
        "ping",
        "-c",
        "1",
        "-W",
        "1",
        server_ip,
    ]
    result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode != 0:
        fail(
            "Local preflight failed: '{}' cannot reach server IP {}. "
            "Run ./setup_server_ns.sh and ./setup_client_ns.sh, then verify routing.".format(
                client_ns, server_ip
            )
        )


def ensure_local_dir(path):
    os.makedirs(path, exist_ok=True)


def interface_is_up(interface):
    result = subprocess.run(["ip", "-o", "link", "show", "dev", interface], capture_output=True, text=True)
    return result.returncode == 0 and "UP" in result.stdout


def dump_tc_state(interface, ingress_interface):
    log("Inspecting tc state on {} and {}".format(interface, ingress_interface))
    cmd = (
        "set -e;"
        "echo '--- ip link ---';"
        "ip link show dev {interface};"
        "ip link show dev {ingress_interface};"
        "echo '--- qdisc ---';"
        "tc qdisc show dev {interface};"
        "tc qdisc show dev {ingress_interface};"
        "echo '--- qdisc stats ---';"
        "tc -s qdisc show dev {interface};"
        "tc -s qdisc show dev {ingress_interface};"
        "echo '--- ingress filter ---';"
        "tc filter show dev {interface} parent ffff:;"
    ).format(interface=interface, ingress_interface=ingress_interface)
    subprocess.run(["sudo", "bash", "-lc", cmd], check=True)


def write_tc_state_snapshot(interface, ingress_interface, output_path):
    cmd = (
        "set -e;"
        "echo '--- ip link ---';"
        "ip link show dev {interface};"
        "ip link show dev {ingress_interface};"
        "echo '--- qdisc ---';"
        "tc qdisc show dev {interface};"
        "tc qdisc show dev {ingress_interface};"
        "echo '--- qdisc stats ---';"
        "tc -s qdisc show dev {interface};"
        "tc -s qdisc show dev {ingress_interface};"
        "echo '--- ingress filter ---';"
        "tc filter show dev {interface} parent ffff:;"
    ).format(interface=interface, ingress_interface=ingress_interface)
    with open(output_path, "w") as f:
        subprocess.run(["sudo", "bash", "-lc", cmd], check=True, stdout=f, text=True)


def get_netns_interfaces(namespace):
    result = subprocess.run(
        ["sudo", "ip", "netns", "exec", namespace, "ip", "-o", "link", "show"],
        capture_output=True,
        text=True,
        check=True,
    )
    interfaces = []
    for line in result.stdout.splitlines():
        name = line.split(": ", 2)[1].split("@", 1)[0]
        if name != "lo":
            interfaces.append(name)
    return interfaces


def assert_offload_features_disabled(output, scope):
    required_features = ["generic-segmentation-offload", "tcp-segmentation-offload", "generic-receive-offload", "tx-udp-segmentation"]
    for feature in required_features:
        for line in output.splitlines():
            if line.strip().startswith(feature + ":"):
                if line.split(":", 1)[1].strip().startswith("on"):
                    fail("Offload feature '{}' is still enabled on {}.".format(feature, scope))
                break


def write_offload_snapshot(stacks_conf, interface, ingress_interface, output_path):
    client_ns = next(iter(stacks_conf.values())).get("client_netns", "quicbench-client")
    server_ns = next(iter(stacks_conf.values())).get("server_netns", "quicbench-server")
    host_interfaces = []
    for candidate in [interface, ingress_interface, "veth-c-host"]:
        if candidate not in host_interfaces and interface_exists(candidate):
            host_interfaces.append(candidate)

    with open(output_path, "w") as f:
        for host_if in host_interfaces:
            f.write("=== host:{} ===\n".format(host_if))
            result = subprocess.run(["sudo", "ethtool", "-k", host_if], check=True, capture_output=True, text=True)
            f.write(result.stdout)
            assert_offload_features_disabled(result.stdout, "host:{}".format(host_if))
            f.write("\n")

        for namespace in [server_ns, client_ns]:
            f.write("=== netns:{} ===\n".format(namespace))
            for ns_if in get_netns_interfaces(namespace):
                f.write("--- iface:{} ---\n".format(ns_if))
                result = subprocess.run(
                    ["sudo", "ip", "netns", "exec", namespace, "ethtool", "-k", ns_if],
                    check=True,
                    text=True,
                    capture_output=True,
                )
                f.write(result.stdout)
                assert_offload_features_disabled(result.stdout, "netns:{} iface:{}".format(namespace, ns_if))
                f.write("\n")


def set_stack_run_root(stack, run_root):
    if hasattr(stack, "set_run_root"):
        stack.set_run_root(run_root)


def with_stack_run_root(stack, run_root, callback):
    previous_run_root = getattr(stack, "run_root", None)
    set_stack_run_root(stack, run_root)
    try:
        return callback()
    finally:
        set_stack_run_root(stack, previous_run_root)


def get_flow_client_run_root(run_results_dir, flow):
    return os.path.join(run_results_dir, "flows", flow["flow_id"], "client")


def get_flow_server_run_root(run_results_dir, server_stack_name, port_no):
    return os.path.join(run_results_dir, "servers", "{}-{}".format(server_stack_name, port_no))


def resolve_server_stack_name(exp_conf, flow):
    return flow.get("server_stack_name") or exp_conf.get("fixed_parameters", {}).get("server_stack_name") or flow["stack_name"]


def build_flow_plans(stacks, exp_conf, trial, run_results_dir):
    plans = []
    for flow in trial["flows"]:
        flow = dict(flow)
        if flow.get("ack_policy"):
            flow["ack_policy_config"] = exp_conf["ack_policy_configs"][flow["ack_policy"]]
            flow["ack_policy_config_schema_version"] = exp_conf["ack_policy_config_schema_version"]
        client_stack_name = flow["stack_name"]
        server_stack_name = resolve_server_stack_name(exp_conf, flow)
        plans.append(
            flow_plan(
                client_stack_name,
                stacks[client_stack_name],
                server_stack_name,
                stacks[server_stack_name],
                flow,
                exp_conf["flow_duration_s"],
                exp_conf["workload"],
                run_results_dir,
            )
        )
    return plans


def flow_plan(client_stack_name, client_stack, server_stack_name, server_stack, flow, flow_duration_s, workload, run_results_dir):
    port_no = str(flow["port_no"])
    client_run_root = get_flow_client_run_root(run_results_dir, flow)
    server_run_root = get_flow_server_run_root(run_results_dir, server_stack_name, port_no)
    client_paths = with_stack_run_root(client_stack, client_run_root, lambda: client_stack.get_flow_paths(port_no))
    server_paths = with_stack_run_root(server_stack, server_run_root, lambda: server_stack.get_flow_paths(port_no))
    client_target = server_stack.get_client_target(port_no, workload=workload)
    return {
        "flow_id": flow["flow_id"],
        "stack_name": client_stack_name,
        "client_stack_name": client_stack_name,
        "server_stack_name": server_stack_name,
        "cc_algo": flow["cc_algo"],
        "ack_policy": flow.get("ack_policy"),
        "ack_policy_config": dict(
            flow.get("ack_policy_config")
            or {}
        ),
        "ack_policy_config_schema_version": flow.get("ack_policy_config_schema_version"),
        "ack_freq": flow.get("ack_freq"),
        "local_port": flow.get("local_port"),
        "port_no": port_no,
        "protocol": client_target["protocol"],
        "workload_name": workload["name"],
        "requested_bytes": workload["bytes"],
        "duration_s": workload["duration_s"],
        "generated_target": generated_target(client_target),
        "client_target": client_target,
        "client_run_root": client_run_root,
        "server_run_root": server_run_root,
        "run_dir": client_paths["run_dir"],
        "server_qlog_dir": server_paths["server_qlog_dir"],
        "client_qlog_dir": client_paths["client_qlog_dir"],
        "server_log_path": server_paths["server_stderr_log"],
        "client_log_path": client_paths["client_stderr_log"],
        "client_metrics_path": client_paths.get("client_metrics_path"),
        "client_binary_path": client_stack.client_path,
        "server_binary_path": server_stack.server_path,
        "server_stdout_log": server_paths["server_stdout_log"],
        "client_stdout_log": client_paths["client_stdout_log"],
        "server_cmd": with_stack_run_root(
            server_stack,
            server_run_root,
            lambda: " ".join(
                server_stack.run_server_cmd(
                    port_no, flow_duration_s + 15, cc_algo=flow["cc_algo"]
                )
            ),
        ),
        "client_cmd": with_stack_run_root(
            client_stack,
            client_run_root,
            lambda: client_stack.run_client_cmd(
                port_no,
                flow_duration_s,
                local_port=flow.get("local_port"),
                ack_policy=flow.get("ack_policy"),
                target=client_target,
            ),
        ),
    }


def print_preflight_summary(exp_conf, general_conf, profile_name, trial_name, run_results_dir, flow_plans):
    print("=== Preflight Summary ===")
    print("experiment: {}".format(exp_conf["experiment_name"]))
    print("network_profile: {}".format(profile_name))
    print("trial: {}".format(trial_name))
    print("results_dir: {}".format(run_results_dir))
    print("server_ip: {}".format(general_conf["server_ip"]))
    print(
        "network: RTT={}ms jitter={}ms reverse_jitter={}ms bandwidth={}Mbps buffer={}BDP duration={}s interface={} ingress_if={} reverse_bottleneck={}".format(
            exp_conf["netem_conf"]["RTT_ms"],
            exp_conf["netem_conf"].get("jitter_ms", 0),
            exp_conf["netem_conf"].get("reverse_jitter_ms", exp_conf["netem_conf"].get("jitter_ms", 0)),
            exp_conf["netem_conf"]["bandwidth_Mbps"],
            exp_conf["netem_conf"]["buffer_bdp"],
            exp_conf["flow_duration_s"],
            general_conf["interface"],
            general_conf["server_ingress_interface"],
            exp_conf["netem_conf"].get("reverse_bottleneck", True),
        )
    )
    print("server_stack: {}".format(exp_conf.get("fixed_parameters", {}).get("server_stack_name")))
    print("num_trials: {}".format(exp_conf["num_trials"]))
    print(
        "workload: {} bytes={} duration_s={}".format(
            exp_conf["workload"]["name"],
            exp_conf["workload"]["bytes"],
            exp_conf["workload"]["duration_s"],
        )
    )
    print("topology_mode: {}".format(exp_conf["topology_mode"]))
    print("ack_policy_config_schema_version: {}".format(exp_conf["ack_policy_config_schema_version"]))
    unique_servers = sorted({(plan["server_stack_name"], plan["port_no"]) for plan in flow_plans})
    print("server_instances: {}".format(len(unique_servers)))
    for plan in flow_plans:
        print(
            "flow {}: client_stack={} server_stack={} policy={} ack={} server_port={} local_port={} run_dir={}".format(
                plan["flow_id"],
                plan["client_stack_name"],
                plan["server_stack_name"],
                plan["ack_policy"],
                plan["ack_freq"],
                plan["port_no"],
                plan["local_port"],
                plan["run_dir"],
            )
        )
        print("  ack_policy_config: {}".format(json.dumps(plan["ack_policy_config"], sort_keys=True)))
        print("  server_qlog: {}".format(plan["server_qlog_dir"]))
        print("  client_qlog: {}".format(plan["client_qlog_dir"]))
        print("  server_log: {}".format(plan["server_log_path"]))
        print("  client_log: {}".format(plan["client_log_path"]))
        print("  generated_target: {}".format(plan["generated_target"]))
        print("  server_cmd: {}".format(plan["server_cmd"]))
        print("  client_cmd: {}".format(plan["client_cmd"]))


def write_local_json(path, payload):
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def policy_client_git_commit(path):
    try:
        completed = subprocess.run(
            [path, "-version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == "commit":
            return value.strip() or None
    return None


def discover_server_pid(stack, server_binary_path):
    namespace = stack.server_netns
    completed = subprocess.run(
        ["sudo", "-n", "ip", "netns", "pids", namespace],
        check=True,
        capture_output=True,
        text=True,
    )
    expected_binary = os.path.realpath(server_binary_path)
    matching_pids = []
    for value in completed.stdout.split():
        if not value.isdigit():
            continue
        pid = int(value)
        resolved = subprocess.run(
            ["sudo", "-n", "readlink", "-f", "/proc/{}/exe".format(pid)],
            capture_output=True,
            text=True,
        )
        if resolved.returncode == 0 and resolved.stdout.strip() == expected_binary:
            matching_pids.append(pid)
    if len(matching_pids) != 1:
        fail(
            "Expected exactly one {} process in namespace '{}', found {}: {}.".format(
                server_binary_path,
                namespace,
                len(matching_pids),
                matching_pids,
            )
        )
    return matching_pids[0]


def read_log_excerpt(path, max_chars=1200):
    if not os.path.exists(path):
        return ""
    with open(path, "r", errors="replace") as f:
        content = f.read().strip()
    if len(content) <= max_chars:
        return content
    return content[-max_chars:]


def assert_server_processes_healthy(server_processes):
    failed = []
    for plan, proc in server_processes:
        code = proc.poll()
        if code is None:
            continue
        failed.append((plan, code, read_log_excerpt(plan["server_log_path"])))
    if failed:
        messages = []
        for plan, code, excerpt in failed:
            detail = excerpt or "no stderr captured"
            messages.append(
                "server {} on port {} exited early with code {}. stderr: {}".format(
                    plan["server_stack_name"], plan["port_no"], code, detail
                )
            )
        fail(" ; ".join(messages))


def run_trial(server_ip, capture_interface, flow_duration_s, run_results_dir, flow_plans, stacks, reverse_client_start_order=False):
    log("Creating run directory {}".format(run_results_dir))
    log("Capturing packets on interface {}".format(capture_interface))
    ensure_local_dir(run_results_dir)

    metadata = {
        "run_results_dir": run_results_dir,
        "pcap_path": os.path.join(run_results_dir, "packets.pcap"),
        "start_timestamp": now(),
        "client_start_order": [],
        "workload_name": flow_plans[0]["workload_name"],
        "requested_bytes": flow_plans[0]["requested_bytes"],
        "duration_s": flow_plans[0]["duration_s"],
        "duration": flow_plans[0]["duration_s"],
        "generated_target": flow_plans[0]["generated_target"],
        "topology_mode": "shared-server-shared-port"
        if len({(plan["server_stack_name"], plan["port_no"]) for plan in flow_plans}) == 1
        else "same-implementation-different-ports-control",
        "server_instance_count": len(
            {(plan["server_stack_name"], plan["port_no"]) for plan in flow_plans}
        ),
        "ack_policy_config_schema_version": flow_plans[0]["ack_policy_config_schema_version"],
        "host": {
            "platform": platform.platform(),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "flows": [],
    }
    for plan in flow_plans:
        metadata["flows"].append(
            {
                "flow_id": plan["flow_id"],
                "stack_name": plan["client_stack_name"],
                "server_stack_name": plan["server_stack_name"],
                "server_stack": plan["server_stack_name"],
                "port": plan["port_no"],
                "local_port": plan["local_port"],
                "ack_policy": plan["ack_policy"],
                "ack_policy_config": plan["ack_policy_config"],
                "protocol": plan["protocol"],
                "workload_name": plan["workload_name"],
                "requested_bytes": plan["requested_bytes"],
                "duration_s": plan["duration_s"],
                "duration": plan["duration_s"],
                "generated_target": plan["generated_target"],
                "client_target": plan["client_target"],
                "server_qlog_path": plan["server_qlog_dir"],
                "client_qlog_path": plan["client_qlog_dir"],
                "server_log_path": plan["server_log_path"],
                "client_log_path": plan["client_log_path"],
                "client_metrics_path": plan["client_metrics_path"],
                "client_binary_path": plan["client_binary_path"],
                "client_binary": plan["client_binary_path"],
                "client_binary_sha256": file_sha256(plan["client_binary_path"]),
                "client_git_commit": policy_client_git_commit(plan["client_binary_path"]),
                "server_binary_path": plan["server_binary_path"],
                "server_binary": plan["server_binary_path"],
                "server_binary_sha256": file_sha256(plan["server_binary_path"]),
                "server_protocol": plan["protocol"],
                "server_config": stacks[
                    plan["server_stack_name"]
                ].get_server_runtime_config(plan["cc_algo"]),
                "server_command": plan["server_cmd"],
                "client_command": plan["client_cmd"],
                "command": plan["client_cmd"],
                "timestamp": now(),
                "start_timestamp": None,
                "end_timestamp": None,
            }
        )
    write_local_json(os.path.join(run_results_dir, "run_manifest.json"), metadata)

    processes = []
    server_processes = []
    tcpdump_started = False
    tcpdump = TCPDump("localhost", server_ip, capture_interface, os.path.join(run_results_dir, "packets.pcap"))

    try:
        started_servers = set()
        for plan in flow_plans:
            server_key = (plan["server_stack_name"], plan["port_no"])
            if server_key in started_servers:
                continue
            log("Starting server {} on port {}".format(plan["server_stack_name"], plan["port_no"]))
            log("server_cmd: {}".format(plan["server_cmd"]))
            proc = with_stack_run_root(
                stacks[plan["server_stack_name"]],
                plan["server_run_root"],
                lambda: stacks[plan["server_stack_name"]].run_remote_server(
                    plan["port_no"], plan["cc_algo"], flow_duration_s + 15
                ),
            )
            processes.append(proc)
            server_processes.append((plan, proc))
            started_servers.add(server_key)

        time.sleep(2)
        assert_server_processes_healthy(server_processes)
        server_runtime = {}
        for server_plan, server_proc in server_processes:
            server_key = (server_plan["server_stack_name"], server_plan["port_no"])
            server_runtime[server_key] = {
                "server_stack": server_plan["server_stack_name"],
                "port": server_plan["port_no"],
                "server_pid": discover_server_pid(
                    stacks[server_plan["server_stack_name"]],
                    server_plan["server_binary_path"],
                ),
                "server_launcher_pid": server_proc.pid,
            }
        metadata["servers"] = list(server_runtime.values())
        metadata["server_pids"] = [server["server_pid"] for server in metadata["servers"]]
        if len(metadata["servers"]) == 1:
            metadata["server_pid"] = metadata["servers"][0]["server_pid"]
        for plan, flow_metadata in zip(flow_plans, metadata["flows"]):
            runtime = server_runtime[(plan["server_stack_name"], plan["port_no"])]
            flow_metadata["server_pid"] = runtime["server_pid"]
            flow_metadata["server_launcher_pid"] = runtime["server_launcher_pid"]
        write_local_json(os.path.join(run_results_dir, "run_manifest.json"), metadata)
        if not interface_is_up(capture_interface):
            fail("Capture interface '{}' is down after netem setup; aborting before tcpdump.".format(capture_interface))
        log("Starting tcpdump for {}".format(run_results_dir))
        tcpdump.start()
        tcpdump_started = True

        client_launch_order = list(enumerate(flow_plans))
        if reverse_client_start_order:
            client_launch_order.reverse()

        synchronized_start_unix_ns = time.time_ns() + 2_000_000_000
        metadata["synchronized_start_unix_ns"] = synchronized_start_unix_ns
        for idx, plan in client_launch_order:
            metadata["flows"][idx]["start_timestamp"] = now()
            metadata["flows"][idx]["scheduled_start_unix_ns"] = synchronized_start_unix_ns
            metadata["client_start_order"].append(plan["flow_id"])
            actual_client_cmd = with_stack_run_root(
                stacks[plan["client_stack_name"]],
                plan["client_run_root"],
                lambda: stacks[plan["client_stack_name"]].run_client_cmd(
                    plan["port_no"],
                    flow_duration_s,
                    start_at_unix_ns=synchronized_start_unix_ns,
                    local_port=plan["local_port"],
                    ack_policy=plan["ack_policy"],
                    target=plan["client_target"],
                ),
            )
            metadata["flows"][idx]["client_command"] = actual_client_cmd
            metadata["flows"][idx]["command"] = actual_client_cmd
            log("Starting client {} on port {}".format(plan["client_stack_name"], plan["port_no"]))
            log("client_cmd: {}".format(actual_client_cmd))
            proc = with_stack_run_root(
                stacks[plan["client_stack_name"]],
                plan["client_run_root"],
                lambda: stacks[plan["client_stack_name"]].run_client(
                    plan["port_no"],
                    plan["cc_algo"],
                    flow_duration_s,
                    start_at_unix_ns=synchronized_start_unix_ns,
                    local_port=plan["local_port"],
                    ack_policy=plan["ack_policy"],
                    target=plan["client_target"],
                ),
            )
            processes.append(proc)
        write_local_json(os.path.join(run_results_dir, "run_manifest.json"), metadata)

        for proc in processes:
            proc.wait()

        for flow_meta in metadata["flows"]:
            flow_meta["end_timestamp"] = now()
        metadata["end_timestamp"] = now()
        write_local_json(os.path.join(run_results_dir, "run_manifest.json"), metadata)
    finally:
        if tcpdump_started:
            tcpdump.stop()


def parse_trial(exp_conf_path, general_conf_path, profile_name, trial_name, trial_dir):
    repo_root = os.path.dirname(os.path.abspath(__file__))
    cmd = [
        "python3",
        os.path.join(repo_root, "parse", "parse_pcap_min.py"),
        "--exp_conf={}".format(exp_conf_path),
        "--general_conf={}".format(general_conf_path),
        "--network_profile_name={}".format(profile_name),
        "--trial_name={}".format(trial_name),
        "--trial_dir={}".format(trial_dir),
    ]
    log("parse_cmd: {}".format(" ".join(cmd)))
    subprocess.run(cmd, check=True)


def cleanup_trial_artifacts(trial_dir, pcap_policy, run_idx):
    if should_keep_artifact(pcap_policy, run_idx):
        return
    pcap_path = os.path.join(trial_dir, "packets.pcap")
    if os.path.exists(pcap_path):
        os.remove(pcap_path)
        log("Deleted {}".format(pcap_path))


def cleanup_qlog_artifacts(run_results_dir):
    removed = 0
    for root, dirs, _ in os.walk(run_results_dir):
        for dirname in dirs:
            if dirname != "qlogs":
                continue
            qlog_dir = os.path.join(root, dirname)
            subprocess.run(["sudo", "rm", "-rf", qlog_dir], check=True)
            removed += 1
    if removed:
        log("Deleted {} qlog directorie(s) under {}".format(removed, run_results_dir))


def cleanup_run_results_dir(run_results_dir):
    if os.path.exists(run_results_dir):
        subprocess.run(["sudo", "rm", "-rf", run_results_dir], check=True)
        log("Deleted run directory {}".format(run_results_dir))


def should_keep_qlogs(qlog_policy, run_idx):
    return should_keep_artifact(qlog_policy, run_idx)


def should_keep_artifact(policy, run_idx):
    if policy == "all":
        return True
    if policy == "first-only":
        return run_idx == 1
    return False


def main():
    args = get_prog_args()
    pcap_policy = resolve_pcap_policy(args)
    stacks_conf = load_json(args.stacks_conf)
    general_conf = load_json(args.general_conf)
    exp_conf = load_json(args.exp_conf)
    workload_profiles = load_workload_profiles(args.workloads_conf)
    ack_policy_document = load_ack_policy_configs(args.ack_policies_conf)
    apply_runtime_overrides(args, exp_conf)
    activate_workload(exp_conf, workload_profiles)
    activate_ack_policy_configs(exp_conf, ack_policy_document)
    stack_family = normalize_experiment_identity(exp_conf)

    validate_experiment(stacks_conf, exp_conf)

    server_ip, interface, server_ingress_interface = itemgetter("server_ip", "interface", "server_ingress_interface")(general_conf)
    stacks = instantiate_stacks(stacks_conf, general_conf)
    configure_qlog(stacks, exp_conf.get("enable_qlog", False))
    selected_profiles = get_selected_network_profiles(args, exp_conf)

    for profile in selected_profiles:
        activate_network_profile(exp_conf, profile)
        for trial in exp_conf["trials"]:
            run_id = "01-{}".format(datetime.now().strftime("%Y-%m-%d_%H-%M-%S")) if args.dry_run else "pending"
            run_results_dir = os.path.join(exp_conf["experiment_results_dir"], profile["name"], trial["name"], run_id)
            flow_plans = build_flow_plans(stacks, exp_conf, trial, run_results_dir)
            print_preflight_summary(exp_conf, general_conf, profile["name"], trial["name"], run_results_dir, flow_plans)

    if args.dry_run:
        print("Dry run complete. No processes launched.")
        return

    validate_local_paths(stacks_conf, exp_conf)
    validate_local_topology(general_conf, stacks_conf)
    check_sudo_privileges()
    set_kernel_params(general_conf["kernel_params"])

    try:
        ensure_local_dir(exp_conf["experiment_results_dir"])
        for profile in selected_profiles:
            activate_network_profile(exp_conf, profile)
            log("Applying netem with shared bottleneck settings for {} profile {}".format(stack_family, profile["name"]))
            set_netem("localhost", "", server_ip, interface, server_ingress_interface, exp_conf["netem_conf"])
            dump_tc_state(interface, server_ingress_interface)

            profile_results_dir = os.path.join(exp_conf["experiment_results_dir"], profile["name"])
            ensure_local_dir(profile_results_dir)

            for trial in exp_conf["trials"]:
                trial_name = trial["name"]
                trial_results_dir = os.path.join(profile_results_dir, trial_name)
                ensure_local_dir(trial_results_dir)

                for run_idx in range(1, exp_conf["num_trials"] + 1):
                    run_id = "{:02d}-{}".format(run_idx, datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
                    run_results_dir = os.path.join(trial_results_dir, run_id)
                    flow_plans = build_flow_plans(stacks, exp_conf, trial, run_results_dir)
                    print_preflight_summary(exp_conf, general_conf, profile["name"], trial_name, run_results_dir, flow_plans)
                    log("Run start: {}".format(run_id))
                    ensure_local_dir(run_results_dir)
                    write_local_json(
                        os.path.join(run_results_dir, "effective_experiment_config.json"),
                        exp_conf,
                    )
                    write_local_json(
                        os.path.join(run_results_dir, "effective_general_config.json"),
                        general_conf,
                    )
                    write_offload_snapshot(
                        stacks_conf,
                        interface,
                        server_ingress_interface,
                        os.path.join(run_results_dir, "offload_state.before.txt"),
                    )
                    write_tc_state_snapshot(
                        interface,
                        server_ingress_interface,
                        os.path.join(run_results_dir, "tc_state.before.txt"),
                    )
                    # Capture on the redirected ingress interface so download
                    # throughput is measured after the server->client bottleneck.
                    run_trial(
                        server_ip,
                        server_ingress_interface,
                        exp_conf["flow_duration_s"],
                        run_results_dir,
                        flow_plans,
                        stacks,
                        reverse_client_start_order=(run_idx % 2 == 0),
                    )
                    write_offload_snapshot(
                        stacks_conf,
                        interface,
                        server_ingress_interface,
                        os.path.join(run_results_dir, "offload_state.after.txt"),
                    )
                    write_tc_state_snapshot(
                        interface,
                        server_ingress_interface,
                        os.path.join(run_results_dir, "tc_state.after.txt"),
                    )
                    dump_tc_state(interface, server_ingress_interface)
                    parse_trial(
                        os.path.join(run_results_dir, "effective_experiment_config.json"),
                        os.path.abspath(args.general_conf),
                        profile["name"],
                        trial_name,
                        run_results_dir,
                    )
                    if args.keep_run_artifacts:
                        cleanup_trial_artifacts(run_results_dir, pcap_policy, run_idx)
                        if not should_keep_qlogs(args.qlog_policy, run_idx):
                            cleanup_qlog_artifacts(run_results_dir)
                    else:
                        cleanup_run_results_dir(run_results_dir)
                    log("Run end: {}".format(run_id))

        log("Completed fairness experiment {}".format(exp_conf["experiment_name"]))
    finally:
        log("Clearing netem")
        clear_netem("localhost", "", server_ip, interface, server_ingress_interface)


if __name__ == "__main__":
    main()
