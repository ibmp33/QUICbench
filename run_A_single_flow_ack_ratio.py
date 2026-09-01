import argparse
import json
import os
import subprocess
import time
from datetime import datetime
from operator import itemgetter

from network.clear_netem import clear_netem
from network.set_netem import add_ingress_interface, run_local_sudo
from network.tcpdump import TCPDump
from stacks.mvfst import Mvfst
from stacks.quiche import Quiche
from stacks.quic_go import QuicGo, QuicGoAck2, QuicGoAck5, QuicGoAck10, QuicGoPolicy
from stacks.xquic import Xquic


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
    parser.add_argument("--exp_conf", "-e", type=str, default="./config/A0_single_flow_no_jitter.json")
    parser.add_argument("--server-stack-name", type=str, help="override the shared server stack for all trials")
    parser.add_argument("--num-trials", type=int, help="override exp_conf num_trials")
    parser.add_argument(
        "--network-profile",
        action="append",
        dest="network_profiles",
        help="run one named network profile from exp_conf; repeat the flag to run multiple profiles",
    )
    parser.add_argument("--dry-run", action="store_true", help="validate config and print commands without launching processes")
    parser.add_argument("--keep-pcap", action="store_true", help="keep packets.pcap after parsing")
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
        prefixes = {base_stack_name(name) for name in allowed}
        if len(prefixes) == 1:
            return "{}-clients".format(next(iter(prefixes)))
    return "single-flow"


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
    return [{"name": "default", "netem_conf": exp_conf["netem_conf"]}]


def validate_network_profiles(exp_conf):
    seen_names = set()
    for profile in get_network_profiles(exp_conf):
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
        reverse_jitter_ms = netem_conf.get("reverse_jitter_ms", 0)
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
    if not exp_conf.get("large_test_object"):
        fail("large_test_object must be documented in the experiment config.")
    for trial in exp_conf["trials"]:
        flows = trial["flows"]
        if len(flows) != 1:
            fail("Trial '{}' must define exactly 1 flow.".format(trial["name"]))
        flow = flows[0]
        if flow["stack_name"] not in allowed:
            fail("Trial '{}' uses unsupported stack '{}'.".format(trial["name"], flow["stack_name"]))
        per_flow_server_stack = flow.get("server_stack_name") or server_stack_name or flow["stack_name"]
        if per_flow_server_stack not in stacks_conf:
            fail("Trial '{}' uses undefined server stack '{}'.".format(trial["name"], per_flow_server_stack))
        ack_policy = flow.get("ack_policy")
        if flow["stack_name"] == QuicGoPolicy.NAME and ack_policy not in QuicGoPolicy.ACK_POLICIES:
            fail(
                "Trial '{}' has unsupported ack_policy {!r}; valid values: {}.".format(
                    trial["name"], ack_policy, ", ".join(sorted(QuicGoPolicy.ACK_POLICIES))
                )
            )
        if flow["cc_algo"] != "cubic":
            fail("Trial '{}' must keep cc_algo fixed at 'cubic'.".format(trial["name"]))


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
        if stack_conf.get("protocol") == "http3" and not stack_conf.get("client_url_template"):
            fail("Stack '{}' must define client_url_template for HTTP/3.".format(stack_name))
        if stack_conf.get("protocol") == "raw" and not stack_conf.get("client_addr_template"):
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
        fail("Local preflight failed: netns '{}' is missing. Run ./setup_client_ns.sh first.".format(client_ns))
    if not netns_exists(server_ns):
        fail("Local preflight failed: netns '{}' is missing. Run ./setup_server_ns.sh first.".format(server_ns))
    if not interface_exists(interface):
        fail("Local preflight failed: bottleneck interface '{}' is missing.".format(interface))
    if not interface_exists(ingress_interface):
        fail("Local preflight failed: ingress interface '{}' is missing.".format(ingress_interface))
    if interface == ingress_interface:
        fail("general_conf interface and server_ingress_interface must be different.")

    server_ip = general_conf["server_ip"]
    ping_cmd = ["sudo", "ip", "netns", "exec", client_ns, "ping", "-c", "1", "-W", "1", server_ip]
    result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode != 0:
        fail(
            "Local preflight failed: '{}' cannot reach server IP {}. "
            "Run ./setup_server_ns.sh and ./setup_client_ns.sh, then verify routing.".format(client_ns, server_ip)
        )


def ensure_local_dir(path):
    os.makedirs(path, exist_ok=True)


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


def build_flow_plan(stacks, exp_conf, trial, run_results_dir):
    flow = trial["flows"][0]
    client_stack_name = flow["stack_name"]
    server_stack_name = resolve_server_stack_name(exp_conf, flow)
    client_stack = stacks[client_stack_name]
    server_stack = stacks[server_stack_name]
    port_no = str(flow["port_no"])
    client_run_root = get_flow_client_run_root(run_results_dir, flow)
    server_run_root = get_flow_server_run_root(run_results_dir, server_stack_name, port_no)
    client_paths = with_stack_run_root(client_stack, client_run_root, lambda: client_stack.get_flow_paths(port_no))
    server_paths = with_stack_run_root(server_stack, server_run_root, lambda: server_stack.get_flow_paths(port_no))
    client_target = server_stack.get_client_target(port_no)
    return {
        "trial_name": trial["name"],
        "flow_id": flow["flow_id"],
        "stack_name": client_stack_name,
        "client_stack_name": client_stack_name,
        "server_stack_name": server_stack_name,
        "cc_algo": flow["cc_algo"],
        "ack_freq": flow.get("ack_freq"),
        "ack_policy": flow.get("ack_policy"),
        "local_port": flow.get("local_port"),
        "protocol": client_target["protocol"],
        "client_target": client_target,
        "port_no": port_no,
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
            lambda: " ".join(server_stack.run_server_cmd(port_no, exp_conf["flow_duration_s"] + 5)),
        ),
        "client_cmd": with_stack_run_root(
            client_stack,
            client_run_root,
            lambda: client_stack.run_client_cmd(
                port_no,
                exp_conf["flow_duration_s"],
                local_port=flow.get("local_port"),
                ack_policy=flow.get("ack_policy"),
                target=client_target,
            ),
        ),
    }


def print_preflight_summary(exp_conf, general_conf, profile_name, run_results_dir, plan):
    print("=== Preflight Summary ===")
    print("experiment: {}".format(exp_conf["experiment_name"]))
    print("network_profile: {}".format(profile_name))
    print("trial: {}".format(plan["trial_name"]))
    print("results_dir: {}".format(run_results_dir))
    print("server_ip: {}".format(general_conf["server_ip"]))
    print(
        "network: RTT={}ms jitter={}ms reverse_jitter={}ms bandwidth={}Mbps buffer={}BDP duration={}s interface={} ingress_if={} reverse_bottleneck={}".format(
            exp_conf["netem_conf"]["RTT_ms"],
            exp_conf["netem_conf"].get("jitter_ms", 0),
            exp_conf["netem_conf"].get("reverse_jitter_ms", 0),
            exp_conf["netem_conf"]["bandwidth_Mbps"],
            exp_conf["netem_conf"]["buffer_bdp"],
            exp_conf["flow_duration_s"],
            general_conf["interface"],
            general_conf["server_ingress_interface"],
            False,
        )
    )
    print("server_stack: {}".format(exp_conf.get("fixed_parameters", {}).get("server_stack_name")))
    print("num_trials: {}".format(exp_conf["num_trials"]))
    print(
        "flow {}: client_stack={} server_stack={} ack={} port={} run_dir={}".format(
            plan["flow_id"], plan["client_stack_name"], plan["server_stack_name"], plan["ack_freq"], plan["port_no"], plan["run_dir"]
        )
    )
    print("  server_qlog: {}".format(plan["server_qlog_dir"]))
    print("  client_qlog: {}".format(plan["client_qlog_dir"]))
    print("  server_log: {}".format(plan["server_log_path"]))
    print("  client_log: {}".format(plan["client_log_path"]))
    print("  server_cmd: {}".format(plan["server_cmd"]))
    print("  client_cmd: {}".format(plan["client_cmd"]))


def write_local_json(path, payload):
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def set_forward_only_netem(interface, ingress_interface, netem_conf):
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "root"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "handle", "ffff:", "ingress"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", ingress_interface, "root"], stderr=subprocess.DEVNULL)

    add_ingress_interface("localhost", "", interface, ingress_interface)

    rtt_ms, bandwidth_mbps, buffer_bdp = itemgetter("RTT_ms", "bandwidth_Mbps", "buffer_bdp")(netem_conf)
    jitter_ms = float(netem_conf.get("jitter_ms", 0))
    reverse_jitter_ms = float(netem_conf.get("reverse_jitter_ms", 0))
    delay_ms = rtt_ms // 2
    jitter_one_way_ms = jitter_ms / 2.0
    reverse_jitter_one_way_ms = reverse_jitter_ms / 2.0
    buffer_bytes = int(rtt_ms * bandwidth_mbps * 1000 / 8 * buffer_bdp)
    bandwidth_kbps = bandwidth_mbps * 1000
    burst_bytes = int(bandwidth_mbps * 1000000 / 250 / 8)
    forward_delay_clause = "delay {}ms".format(delay_ms)
    if jitter_one_way_ms > 0:
        forward_delay_clause = "delay {}ms {}ms distribution normal".format(delay_ms, jitter_one_way_ms)
    reverse_delay_clause = "delay {}ms".format(delay_ms)
    if reverse_jitter_one_way_ms > 0:
        reverse_delay_clause = "delay {}ms {}ms distribution normal".format(delay_ms, reverse_jitter_one_way_ms)
    cmd = (
        "tc qdisc add dev {interface} root handle 1:0 netem {reverse_delay_clause} limit 12500;"
        "tc qdisc add dev {ingress_interface} root handle 2:0 netem {forward_delay_clause} limit 12500;"
        "tc qdisc add dev {ingress_interface} parent 2:1 handle 20: tbf rate {bandwidth_kbps}kbit limit {buffer_bytes} burst {burst_bytes};"
        "tc qdisc show dev {interface} && tc qdisc show dev {ingress_interface}"
    ).format(
        interface=interface,
        ingress_interface=ingress_interface,
        reverse_delay_clause=reverse_delay_clause,
        forward_delay_clause=forward_delay_clause,
        bandwidth_kbps=bandwidth_kbps,
        buffer_bytes=buffer_bytes,
        burst_bytes=burst_bytes,
    )
    run_local_sudo(cmd)


def run_trial(server_ip, capture_interface, flow_duration_s, run_results_dir, plan, stacks):
    log("Creating run directory {}".format(run_results_dir))
    log("Capturing packets on interface {}".format(capture_interface))
    ensure_local_dir(run_results_dir)

    metadata = {
        "run_results_dir": run_results_dir,
        "pcap_path": os.path.join(run_results_dir, "packets.pcap"),
        "start_timestamp": now(),
        "flows": [
            {
                "flow_id": plan["flow_id"],
                "stack_name": plan["client_stack_name"],
                "server_stack_name": plan["server_stack_name"],
                "server_stack": plan["server_stack_name"],
                "port_no": plan["port_no"],
                "local_port": plan["local_port"],
                "ack_policy": plan["ack_policy"],
                "protocol": plan["protocol"],
                "client_target": plan["client_target"],
                "server_qlog_path": plan["server_qlog_dir"],
                "client_qlog_path": plan["client_qlog_dir"],
                "server_log_path": plan["server_log_path"],
                "client_log_path": plan["client_log_path"],
                "client_metrics_path": plan["client_metrics_path"],
                "client_binary": plan["client_binary_path"],
                "server_binary": plan["server_binary_path"],
                "server_command": plan["server_cmd"],
                "client_command": plan["client_cmd"],
                "command": plan["client_cmd"],
                "timestamp": now(),
                "start_timestamp": None,
                "end_timestamp": None,
            }
        ],
    }
    write_local_json(os.path.join(run_results_dir, "run_manifest.json"), metadata)

    tcpdump_started = False
    tcpdump = TCPDump("localhost", server_ip, capture_interface, os.path.join(run_results_dir, "packets.pcap"))
    processes = []

    try:
        log("Starting server {} on port {}".format(plan["server_stack_name"], plan["port_no"]))
        log("server_cmd: {}".format(plan["server_cmd"]))
        server_proc = with_stack_run_root(
            stacks[plan["server_stack_name"]],
            plan["server_run_root"],
            lambda: stacks[plan["server_stack_name"]].run_remote_server(plan["port_no"], plan["cc_algo"], flow_duration_s + 5),
        )
        processes.append(server_proc)

        time.sleep(2)
        log("Starting tcpdump for {}".format(run_results_dir))
        tcpdump.start()
        tcpdump_started = True

        metadata["flows"][0]["start_timestamp"] = now()
        log("Starting client {} on port {}".format(plan["client_stack_name"], plan["port_no"]))
        log("client_cmd: {}".format(plan["client_cmd"]))
        client_proc = with_stack_run_root(
            stacks[plan["client_stack_name"]],
            plan["client_run_root"],
            lambda: stacks[plan["client_stack_name"]].run_client(
                plan["port_no"],
                plan["cc_algo"],
                flow_duration_s,
                local_port=plan["local_port"],
                ack_policy=plan["ack_policy"],
                target=plan["client_target"],
            ),
        )
        processes.append(client_proc)

        for proc in processes:
            proc.wait()

        metadata["flows"][0]["end_timestamp"] = now()
        metadata["end_timestamp"] = now()
        write_local_json(os.path.join(run_results_dir, "run_manifest.json"), metadata)
    finally:
        if tcpdump_started:
            tcpdump.stop()


def parse_trial(exp_conf_path, general_conf_path, profile_name, trial_name, trial_dir):
    repo_root = os.path.dirname(os.path.abspath(__file__))
    cmd = [
        "python3",
        os.path.join(repo_root, "parse", "parse_pcap_single_flow.py"),
        "--exp_conf={}".format(exp_conf_path),
        "--general_conf={}".format(general_conf_path),
        "--network_profile_name={}".format(profile_name),
        "--trial_name={}".format(trial_name),
        "--trial_dir={}".format(trial_dir),
    ]
    log("parse_cmd: {}".format(" ".join(cmd)))
    subprocess.run(cmd, check=True)


def cleanup_trial_artifacts(trial_dir, keep_pcap):
    if keep_pcap:
        return
    pcap_path = os.path.join(trial_dir, "packets.pcap")
    if os.path.exists(pcap_path):
        os.remove(pcap_path)
        log("Deleted {}".format(pcap_path))


def main():
    args = get_prog_args()
    stacks_conf = load_json(args.stacks_conf)
    general_conf = load_json(args.general_conf)
    exp_conf = load_json(args.exp_conf)
    apply_runtime_overrides(args, exp_conf)
    stack_family = normalize_experiment_identity(exp_conf)

    validate_experiment(stacks_conf, exp_conf)
    validate_local_paths(stacks_conf, exp_conf)
    validate_local_topology(general_conf, stacks_conf)

    server_ip, interface, server_ingress_interface = itemgetter("server_ip", "interface", "server_ingress_interface")(general_conf)
    stacks = instantiate_stacks(stacks_conf, general_conf)
    selected_profiles = get_selected_network_profiles(args, exp_conf)

    for profile in selected_profiles:
        activate_network_profile(exp_conf, profile)
        for trial in exp_conf["trials"]:
            run_id = "01-{}".format(datetime.now().strftime("%Y-%m-%d_%H-%M-%S")) if args.dry_run else "pending"
            run_results_dir = os.path.join(exp_conf["experiment_results_dir"], profile["name"], trial["name"], run_id)
            plan = build_flow_plan(stacks, exp_conf, trial, run_results_dir)
            print_preflight_summary(exp_conf, general_conf, profile["name"], run_results_dir, plan)

    if args.dry_run:
        print("Dry run complete. No processes launched.")
        return

    check_sudo_privileges()
    set_kernel_params(general_conf["kernel_params"])

    try:
        ensure_local_dir(exp_conf["experiment_results_dir"])
        for profile in selected_profiles:
            activate_network_profile(exp_conf, profile)
            log("Applying forward-only netem for {} profile {}".format(stack_family, profile["name"]))
            set_forward_only_netem(interface, server_ingress_interface, exp_conf["netem_conf"])
            dump_tc_state(interface, server_ingress_interface)

            profile_results_dir = os.path.join(exp_conf["experiment_results_dir"], profile["name"])
            ensure_local_dir(profile_results_dir)

            for trial in exp_conf["trials"]:
                trial_results_dir = os.path.join(profile_results_dir, trial["name"])
                ensure_local_dir(trial_results_dir)

                for run_idx in range(1, exp_conf["num_trials"] + 1):
                    run_id = "{:02d}-{}".format(run_idx, datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
                    run_results_dir = os.path.join(trial_results_dir, run_id)
                    plan = build_flow_plan(stacks, exp_conf, trial, run_results_dir)
                    print_preflight_summary(exp_conf, general_conf, profile["name"], run_results_dir, plan)
                    log("Run start: {}".format(run_id))
                    run_trial(server_ip, server_ingress_interface, exp_conf["flow_duration_s"], run_results_dir, plan, stacks)
                    dump_tc_state(interface, server_ingress_interface)
                    parse_trial(os.path.abspath(args.exp_conf), os.path.abspath(args.general_conf), profile["name"], trial["name"], run_results_dir)
                    cleanup_trial_artifacts(run_results_dir, args.keep_pcap)
                    log("Run end: {}".format(run_id))

        log("Completed single-flow ACK ratio experiment {}".format(exp_conf["experiment_name"]))
    finally:
        log("Clearing netem")
        clear_netem("localhost", "", server_ip, interface, server_ingress_interface)


if __name__ == "__main__":
    main()
