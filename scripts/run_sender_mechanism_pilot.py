#!/usr/bin/env python3
"""Run a small CC x pacing factorial ACK-policy experiment."""

import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
RUNNER = REPO_ROOT / "run_B0_two_flow_fairness_no_jitter.py"
BASE_EXPERIMENT = REPO_ROOT / "config" / "P2_sender_mechanism_pilot.json"
BASE_STACKS = REPO_ROOT / "config" / "stacks_conf_default.json"
RESULTS_ROOT = Path("/home/ioio33/QUIC_project/results")
BIN_DIR = Path("/home/ioio33/QUIC_project/bin")

CAPABILITIES = {
    "quiche": {"cc": {"cubic", "reno"}, "pacing": True, "protocol": "http3"},
    "xquic": {"cc": {"cubic", "reno"}, "pacing": True, "protocol": "http3"},
    "mvfst": {"cc": {"cubic", "reno", "bbr"}, "pacing": True, "protocol": "raw"},
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run sender CC x pacing mechanism pilot with role-reversed ACK policies."
    )
    parser.add_argument(
        "--server",
        action="append",
        choices=sorted(CAPABILITIES),
        help="server to run; repeat as needed (default: quiche and xquic)",
    )
    parser.add_argument(
        "--cc",
        action="append",
        choices=["cubic", "reno", "bbr"],
        help="congestion control treatment; repeat (default: cubic and reno)",
    )
    parser.add_argument(
        "--pacing",
        action="append",
        choices=["on", "off"],
        help="pacing treatment; repeat (default: on and off)",
    )
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument(
        "--pcap-policy", choices=["all", "first-only", "none"], default="none"
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def load_json(path):
    with path.open() as handle:
        return json.load(handle)


def write_json(path, value):
    with path.open("w") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def validate_matrix(servers, cc_algos, pacing_modes):
    for server in servers:
        capability = CAPABILITIES[server]
        unsupported = set(cc_algos).difference(capability["cc"])
        if unsupported:
            raise SystemExit(
                "{} does not support requested CC {}; supported: {}".format(
                    server,
                    ",".join(sorted(unsupported)),
                    ",".join(sorted(capability["cc"])),
                )
            )
        if len(pacing_modes) > 1 and not capability["pacing"]:
            raise SystemExit("{} cannot switch pacing at runtime".format(server))


def ensure_quiche_object(dry_run):
    path = BIN_DIR / "64MB.bin"
    required = 64 * 1024 * 1024
    if dry_run:
        return
    if not path.exists():
        print("Creating sparse quiche pilot object: {}".format(path))
        with path.open("wb") as handle:
            handle.truncate(required)
    if path.stat().st_size < required:
        raise SystemExit("quiche object is too small: {}".format(path))


def condition_documents(base_exp, base_stacks, server, cc_algo, pacing):
    exp = copy.deepcopy(base_exp)
    stacks = copy.deepcopy(base_stacks)
    condition = "{}-{}-pacing-{}".format(server, cc_algo, pacing)
    exp["experiment_name"] = "P2-sender-mechanism-{}-pacing-{}".format(
        cc_algo, pacing
    )
    exp["experiment_results_dir"] = str(
        RESULTS_ROOT / "P2-sender-mechanism-{}-pacing-{}".format(cc_algo, pacing)
    )
    exp["fixed_parameters"]["server_stack_name"] = server
    exp["fixed_parameters"]["same_cc_algo"] = cc_algo
    exp["fixed_parameters"]["server_pacing"] = pacing
    exp["fixed_parameters"]["condition_id"] = condition
    for trial in exp["trials"]:
        for flow in trial["flows"]:
            flow["cc_algo"] = cc_algo
    stacks[server]["server_pacing"] = pacing == "on"
    return exp, stacks


def run_condition(args, base_exp, base_stacks, server, cc_algo, pacing):
    exp, stacks = condition_documents(
        base_exp, base_stacks, server, cc_algo, pacing
    )
    with tempfile.TemporaryDirectory(prefix="quicbench-p2-") as temp_dir:
        temp_root = Path(temp_dir)
        exp_path = temp_root / "experiment.json"
        stacks_path = temp_root / "stacks.json"
        write_json(exp_path, exp)
        write_json(stacks_path, stacks)
        command = [
            sys.executable,
            str(RUNNER),
            "--exp_conf",
            str(exp_path),
            "--stacks_conf",
            str(stacks_path),
            "--server-stack-name",
            server,
            "--network-profile",
            "50rtt-20bw-0.5bdp",
            "--num-trials",
            str(args.trials),
            "--keep-run-artifacts",
            "--pcap-policy",
            args.pcap_policy,
            "--qlog-policy",
            "none",
        ]
        if args.dry_run:
            command.append("--dry-run")
        print(
            "\n===== server={} protocol={} cc={} pacing={} =====".format(
                server, CAPABILITIES[server]["protocol"], cc_algo, pacing
            )
        )
        subprocess.run(command, cwd=str(REPO_ROOT), check=True)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    args = parse_args()
    if args.trials <= 0:
        raise SystemExit("--trials must be positive")
    servers = args.server or ["quiche", "xquic"]
    cc_algos = args.cc or ["cubic", "reno"]
    pacing_modes = args.pacing or ["on", "off"]
    validate_matrix(servers, cc_algos, pacing_modes)

    condition_count = len(servers) * len(cc_algos) * len(pacing_modes)
    total_runs = condition_count * 2 * args.trials
    print("P2 sender mechanism pilot")
    print("servers={}".format(" ".join(servers)))
    print("cc_algos={}".format(" ".join(cc_algos)))
    print("pacing={}".format(" ".join(pacing_modes)))
    print("policy_pairs=neqo/chromium chromium/neqo")
    print("trials_per_pair={}".format(args.trials))
    print("conditions={} total_runs={}".format(condition_count, total_runs))
    print("pcap_policy={}".format(args.pcap_policy))
    print("minimum_payload_time_minutes={:.1f}".format(total_runs * 20 / 60))
    if "mvfst" in servers:
        print("warning=mvfst is raw QUIC and must be reported separately from H3")

    if not args.dry_run:
        subprocess.run(["sudo", "-v"], check=True)
    if "quiche" in servers:
        ensure_quiche_object(args.dry_run)

    base_exp = load_json(BASE_EXPERIMENT)
    base_stacks = load_json(BASE_STACKS)
    for server in servers:
        for cc_algo in cc_algos:
            for pacing in pacing_modes:
                run_condition(
                    args, base_exp, base_stacks, server, cc_algo, pacing
                )

    print("\nP2 mechanism pilot complete.")
    print("Analyze with: python3 scripts/analyze_sender_mechanism_pilot.py {}".format(RESULTS_ROOT))


if __name__ == "__main__":
    main()
