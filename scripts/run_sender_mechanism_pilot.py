#!/usr/bin/env python3
"""Run a sequential, resumable CC x pacing ACK-policy experiment."""

import argparse
import copy
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading


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
        description="Run a sequential sender CC x pacing mechanism experiment."
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
        help="CC treatment; repeat as needed (default: cubic and reno)",
    )
    parser.add_argument(
        "--pacing",
        action="append",
        choices=["on", "off"],
        help="pacing treatment; repeat as needed (default: on and off)",
    )
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument(
        "--pcap-policy", choices=["all", "first-only", "none"], default="none"
    )
    parser.add_argument(
        "--qlog-policy",
        choices=["all", "first-only", "none"],
        default="first-only",
        help="retain qlogs for all repetitions, first repetition per pair, or none",
    )
    parser.add_argument(
        "--canary",
        action="store_true",
        help="run one heterogeneous pair once for every selected condition",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="check binaries, options, sudo, and disk without launching experiments",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="rerun conditions even when all expected valid artifacts already exist",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="stop after the first failed condition (default: continue and report)",
    )
    parser.add_argument("--min-free-gb", type=float, default=5.0)
    parser.add_argument("--status-file", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def load_json(path):
    with path.open() as handle:
        return json.load(handle)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(str(temporary), str(path))


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


def require_free_disk(min_free_gb):
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    free_bytes = shutil.disk_usage(str(RESULTS_ROOT)).free
    free_gb = free_bytes / (1024.0 ** 3)
    if free_gb < min_free_gb:
        raise RuntimeError(
            "free disk {:.2f} GiB is below --min-free-gb {:.2f}".format(
                free_gb, min_free_gb
            )
        )
    return free_gb


def probe_help(binary, help_arg):
    try:
        result = subprocess.run(
            [str(binary), help_arg],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return exc.stdout or ""
    return result.stdout or ""


def preflight(servers, stacks_conf, min_free_gb, dry_run):
    print("\nPreflight:")
    if not RUNNER.is_file() or not BASE_EXPERIMENT.is_file():
        raise RuntimeError("runner or P2 config is missing")
    if dry_run:
        print("  local dry-run: Linux binary/sudo/disk probes skipped")
        return
    subprocess.run(["sudo", "-v"], check=True)
    subprocess.run(["sudo", "-n", "true"], check=True)
    free_gb = require_free_disk(min_free_gb)
    print("  disk_free_gib={:.2f}".format(free_gb))
    checks = {
        "quiche": ("--help", ["--cc-algorithm", "--disable-pacing"]),
        "xquic": ("-h", ["-c", "-C"]),
        "mvfst": ("--help", ["congestion", "pacing"]),
    }
    for server in servers:
        binary = Path(stacks_conf[server]["server_path"])
        if not binary.is_file() or not os.access(str(binary), os.X_OK):
            raise RuntimeError("{} binary is not executable: {}".format(server, binary))
        help_arg, required = checks[server]
        output = probe_help(binary, help_arg)
        missing = [token for token in required if token not in output]
        if missing:
            raise RuntimeError(
                "{} help is missing required controls: {}".format(
                    server, ", ".join(missing)
                )
            )
        print("  {}=PASS controls={}".format(server, ",".join(required)))


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
        raise RuntimeError("quiche object is too small: {}".format(path))


def condition_prefix(canary):
    return "P2-sender-canary" if canary else "P2-sender-mechanism"


def condition_documents(base_exp, base_stacks, server, cc_algo, pacing, canary):
    exp = copy.deepcopy(base_exp)
    stacks = copy.deepcopy(base_stacks)
    prefix = condition_prefix(canary)
    condition = "{}-{}-pacing-{}".format(server, cc_algo, pacing)
    exp["experiment_name"] = "{}-{}-pacing-{}".format(prefix, cc_algo, pacing)
    exp["experiment_results_dir"] = str(
        RESULTS_ROOT / "{}-{}-pacing-{}".format(prefix, cc_algo, pacing)
    )
    exp["fixed_parameters"]["server_stack_name"] = server
    exp["fixed_parameters"]["same_cc_algo"] = cc_algo
    exp["fixed_parameters"]["server_pacing"] = pacing
    exp["fixed_parameters"]["condition_id"] = condition
    if canary:
        exp["trials"] = [
            trial
            for trial in exp["trials"]
            if trial["name"] == "M1_neqo_vs_chromium"
        ]
    for trial in exp["trials"]:
        for flow in trial["flows"]:
            flow["cc_algo"] = cc_algo
    stacks[server]["server_pacing"] = pacing == "on"
    return exp, stacks


def result_root(server, cc_algo, pacing, canary):
    return RESULTS_ROOT / "{}-{}-pacing-{}-{}-server".format(
        condition_prefix(canary), cc_algo, pacing, server
    )


def condition_complete(root, trial_names, repetitions):
    profile_root = root / "50rtt-20bw-0.5bdp"
    for trial_name in trial_names:
        trial_root = profile_root / trial_name
        for repetition in range(1, repetitions + 1):
            candidates = sorted(
                trial_root.glob("{:02d}-*/run_manifest.json".format(repetition)),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            complete = False
            for manifest_path in candidates:
                summary_path = manifest_path.parent / "summary.csv"
                if not summary_path.is_file():
                    continue
                try:
                    manifest = json.loads(manifest_path.read_text())
                except (OSError, ValueError):
                    continue
                if (
                    manifest.get("experiment_valid") is True
                    and manifest.get("saturation_validation", {}).get("valid") is True
                ):
                    complete = True
                    break
            if not complete:
                return False
    return True


class SudoKeepalive:
    def __init__(self):
        self.stop_event = threading.Event()
        self.failed = threading.Event()
        self.thread = None

    def start(self):
        def refresh():
            while not self.stop_event.wait(45):
                result = subprocess.run(
                    ["sudo", "-n", "-v"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                if result.returncode != 0:
                    self.failed.set()
                    return

        self.thread = threading.Thread(target=refresh, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)


def run_condition(args, exp, stacks, server, trial_count):
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
            str(trial_count),
            "--keep-run-artifacts",
            "--pcap-policy",
            args.pcap_policy,
            "--qlog-policy",
            args.qlog_policy,
        ]
        if args.dry_run:
            command.append("--dry-run")
        subprocess.run(command, cwd=str(REPO_ROOT), check=True)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    args = parse_args()
    if args.trials <= 0:
        raise SystemExit("--trials must be positive")
    if args.min_free_gb < 0:
        raise SystemExit("--min-free-gb must not be negative")
    servers = args.server or ["quiche", "xquic"]
    cc_algos = args.cc or ["cubic", "reno"]
    pacing_modes = args.pacing or ["on", "off"]
    validate_matrix(servers, cc_algos, pacing_modes)
    base_exp = load_json(BASE_EXPERIMENT)
    base_stacks = load_json(BASE_STACKS)
    preflight(servers, base_stacks, args.min_free_gb, args.dry_run)
    if args.preflight_only:
        print("PREFLIGHT=PASS")
        return 0

    trial_count = 1 if args.canary else args.trials
    pair_count = 1 if args.canary else len(base_exp["trials"])
    condition_count = len(servers) * len(cc_algos) * len(pacing_modes)
    total_runs = condition_count * pair_count * trial_count
    print("\nP2 sender mechanism {}".format("canary" if args.canary else "full"))
    print("servers={}".format(" ".join(servers)))
    print("cc_algos={}".format(" ".join(cc_algos)))
    print("pacing={}".format(" ".join(pacing_modes)))
    print("policy_pairs={}".format(pair_count))
    print("trials_per_pair={}".format(trial_count))
    print("conditions={} total_runs={}".format(condition_count, total_runs))
    print("pcap_policy={}".format(args.pcap_policy))
    print("qlog_policy={}".format(args.qlog_policy))
    print("sequential=true resume={}".format(not args.no_resume))
    print("minimum_payload_time_minutes={:.1f}".format(total_runs * 20 / 60))
    if "mvfst" in servers:
        print("warning=mvfst is raw QUIC and must be reported separately from H3")

    if "quiche" in servers:
        ensure_quiche_object(args.dry_run)
    if args.status_file:
        status_path = args.status_file
    elif args.dry_run:
        status_path = Path(tempfile.gettempdir()) / (
            "P2_sender_canary_status.json"
            if args.canary
            else "P2_sender_mechanism_status.json"
        )
    else:
        status_path = RESULTS_ROOT / (
            "P2_sender_canary_status.json"
            if args.canary
            else "P2_sender_mechanism_status.json"
        )
    status = {
        "started_at": datetime.now().isoformat(),
        "mode": "canary" if args.canary else "full",
        "planned_runs": total_runs,
        "conditions": [],
    }
    keepalive = SudoKeepalive()
    if not args.dry_run:
        keepalive.start()
    failures = 0
    try:
        for server in servers:
            for cc_algo in cc_algos:
                for pacing in pacing_modes:
                    condition_id = "{}-{}-pacing-{}".format(
                        server, cc_algo, pacing
                    )
                    exp, stacks = condition_documents(
                        base_exp,
                        base_stacks,
                        server,
                        cc_algo,
                        pacing,
                        args.canary,
                    )
                    exp["enable_qlog"] = args.qlog_policy != "none"
                    root = result_root(
                        server, cc_algo, pacing, args.canary
                    )
                    trial_names = [trial["name"] for trial in exp["trials"]]
                    record = {
                        "condition": condition_id,
                        "protocol": CAPABILITIES[server]["protocol"],
                        "result_root": str(root),
                        "started_at": datetime.now().isoformat(),
                    }
                    status["conditions"].append(record)
                    if (
                        not args.no_resume
                        and not args.dry_run
                        and condition_complete(root, trial_names, trial_count)
                    ):
                        record["status"] = "skipped-complete"
                        record["ended_at"] = datetime.now().isoformat()
                        print("\n===== {} SKIP complete =====".format(condition_id))
                        write_json(status_path, status)
                        continue
                    print(
                        "\n===== {} protocol={} =====".format(
                            condition_id, CAPABILITIES[server]["protocol"]
                        )
                    )
                    try:
                        if not args.dry_run:
                            if keepalive.failed.is_set():
                                raise RuntimeError("sudo keepalive failed")
                            free_gb = require_free_disk(args.min_free_gb)
                            print("disk_free_gib={:.2f}".format(free_gb))
                        run_condition(args, exp, stacks, server, trial_count)
                        if not args.dry_run and not condition_complete(
                            root, trial_names, trial_count
                        ):
                            raise RuntimeError(
                                "runner returned but expected valid, saturated artifacts are incomplete"
                            )
                        record["status"] = "passed"
                    except (RuntimeError, subprocess.CalledProcessError) as exc:
                        failures += 1
                        record["status"] = "failed"
                        record["error"] = str(exc)
                        print("CONDITION_FAILED {}: {}".format(condition_id, exc), file=sys.stderr)
                        if args.fail_fast:
                            raise
                    finally:
                        record["ended_at"] = datetime.now().isoformat()
                        write_json(status_path, status)
    finally:
        keepalive.stop()
    status["ended_at"] = datetime.now().isoformat()
    status["failed_conditions"] = failures
    write_json(status_path, status)
    print("\nstatus_file={}".format(status_path))
    print("failed_conditions={}".format(failures))
    if failures:
        print("P2_SUITE=COMPLETED_WITH_FAILURES")
        return 1
    print("P2_SUITE=PASS")
    if not args.canary:
        print(
            "Analyze with: python3 scripts/analyze_sender_mechanism_pilot.py {}".format(
                RESULTS_ROOT
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
