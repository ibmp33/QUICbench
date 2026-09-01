#!/usr/bin/env python3
"""Run the isolated mvfst BBR1 ACK_FREQUENCY mitigation pilot."""

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


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
RUNNER = REPO_ROOT / "run_B0_two_flow_fairness_no_jitter.py"
BASE_EXPERIMENT = REPO_ROOT / "config" / "P4_mvfst_ack_frequency.json"
BASE_STACKS = REPO_ROOT / "config" / "stacks_conf_default.json"
RESULTS_ROOT = Path("/home/ioio33/QUIC_project/results")

TREATMENTS = {
    "receiver-controlled": {
        "server_ack_frequency": False,
        "client_ack_frequency_mode": "disabled",
        "client_min_ack_delay": None,
    },
    "sender-requested": {
        "server_ack_frequency": True,
        "client_ack_frequency_mode": "mvfst-draft",
        "client_min_ack_delay": "1ms",
    },
}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("preflight", "canary", "full"))
    parser.add_argument(
        "--treatment",
        action="append",
        choices=sorted(TREATMENTS),
        help="treatment to run; repeat as needed (default: both)",
    )
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--min-free-gb", type=float, default=10.0)
    parser.add_argument("--qlog-policy", choices=("all", "first-only", "none"), default="first-only")
    parser.add_argument("--pcap-policy", choices=("all", "first-only", "none"), default="none")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--status-file", type=Path)
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


def probe(binary, flag, required):
    result = subprocess.run(
        [str(binary), flag],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )
    missing = [token for token in required if token not in (result.stdout or "")]
    if missing:
        raise RuntimeError("{} help missing: {}".format(binary, ", ".join(missing)))


def preflight(stacks, args):
    if args.dry_run:
        print("preflight=SKIPPED_LOCAL_DRY_RUN")
        return
    subprocess.run(["sudo", "-v"], check=True)
    subprocess.run(["sudo", "-n", "true"], check=True)
    free_gb = shutil.disk_usage(str(RESULTS_ROOT)).free / (1024.0 ** 3)
    if free_gb < args.min_free_gb:
        raise RuntimeError(
            "disk free {:.2f} GiB is below {:.2f} GiB".format(free_gb, args.min_free_gb)
        )
    probe(
        Path(stacks["mvfst"]["server_path"]),
        "--help",
        ["ack_frequency", "ack_frequency_threshold", "server_qlogger_path"],
    )
    probe(
        Path(stacks["quic-go-policy"]["client_path"]),
        "-h",
        ["ack-frequency-mode", "min-ack-delay", "mvfst-draft"],
    )
    print("preflight=PASS disk_free_gib={:.2f}".format(free_gb))


def documents(base_exp, base_stacks, treatment, canary):
    exp = copy.deepcopy(base_exp)
    stacks = copy.deepcopy(base_stacks)
    settings = TREATMENTS[treatment]
    suffix = "canary" if canary else "pilot"
    identity = "P4-mvfst-ack-frequency-{}-{}".format(treatment, suffix)
    exp["experiment_name"] = identity
    exp["experiment_results_dir"] = str(RESULTS_ROOT / identity)
    exp["fixed_parameters"]["ack_frequency_treatment"] = treatment
    exp["fixed_parameters"]["receiver_feedback_control"] = (
        "receiver-policy" if treatment == "receiver-controlled" else "mvfst-bbr1-request"
    )
    if canary:
        exp["trials"] = [
            trial for trial in exp["trials"] if trial["name"] == "P4_neqo_vs_chromium"
        ]
    stacks["mvfst"].update(
        {
            "server_cc_algo": "bbr",
            "server_pacing": True,
            "server_ack_frequency": settings["server_ack_frequency"],
            "server_ack_frequency_threshold": 10,
            "server_ack_frequency_reordering_threshold": 3,
            "server_ack_frequency_min_rtt_divisor": 2,
            "server_ack_frequency_startup_ack2": True,
        }
    )
    stacks["quic-go-policy"].update(
        {
            "client_ack_frequency_mode": settings["client_ack_frequency_mode"],
            "client_min_ack_delay": settings["client_min_ack_delay"],
        }
    )
    return exp, stacks


def result_root(treatment, canary):
    suffix = "canary" if canary else "pilot"
    return RESULTS_ROOT / "P4-mvfst-ack-frequency-{}-{}-mvfst-server".format(
        treatment, suffix
    )


def verify_artifacts(treatment, canary, trials, qlog_policy):
    root = result_root(treatment, canary)
    manifests = sorted(root.rglob("run_manifest.json"))
    expected = 1 if canary else 4 * trials
    if len(manifests) < expected:
        raise RuntimeError(
            "{} produced {}/{} manifests under {}".format(
                treatment, len(manifests), expected, root
            )
        )
    saw_server_qlog = False
    for manifest_path in manifests[-expected:]:
        manifest = load_json(manifest_path)
        if manifest.get("experiment_valid") is not True:
            raise RuntimeError("invalid P4 run: {}".format(manifest_path))
        if manifest.get("fixed_parameters", {}).get("ack_frequency_treatment") != treatment:
            raise RuntimeError("manifest treatment mismatch: {}".format(manifest_path))
        for flow in manifest.get("flows", []):
            stdout_path = Path(flow["client_stdout_log"])
            stdout = stdout_path.read_text(errors="replace") if stdout_path.is_file() else ""
            applied = '"event":"ack_frequency_applied"' in stdout
            if treatment == "sender-requested" and not applied:
                raise RuntimeError(
                    "sender request was not observed by {} in {}".format(
                        flow.get("flow_id"), stdout_path
                    )
                )
            if treatment == "receiver-controlled" and applied:
                raise RuntimeError(
                    "receiver-controlled run unexpectedly applied ACK_FREQUENCY: {}".format(
                        stdout_path
                    )
                )
            qlog_dir = Path(flow["server_qlog_path"])
            if qlog_dir.is_dir() and any(path.is_file() for path in qlog_dir.iterdir()):
                saw_server_qlog = True
    if qlog_policy != "none" and not saw_server_qlog:
        raise RuntimeError("no retained mvfst server qlog found under {}".format(root))


def runner_command(args, exp_path, stacks_path, trials):
    command = [
        sys.executable,
        str(RUNNER),
        "--exp_conf",
        str(exp_path),
        "--stacks_conf",
        str(stacks_path),
        "--server-stack-name",
        "mvfst",
        "--network-profile",
        "50rtt-20bw-0.5bdp",
        "--num-trials",
        str(trials),
        "--keep-run-artifacts",
        "--pcap-policy",
        args.pcap_policy,
        "--qlog-policy",
        args.qlog_policy,
    ]
    if args.dry_run:
        command.append("--dry-run")
    return command


def main():
    args = parse_args()
    if args.trials <= 0:
        raise SystemExit("--trials must be positive")
    treatments = args.treatment or list(TREATMENTS)
    base_exp = load_json(BASE_EXPERIMENT)
    base_stacks = load_json(BASE_STACKS)
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True) if not args.dry_run else None
    preflight(base_stacks, args)
    planned = 0 if args.mode == "preflight" else len(treatments) * (1 if args.mode == "canary" else 4) * (1 if args.mode == "canary" else args.trials)
    status_path = args.status_file or RESULTS_ROOT / "P4_mvfst_ack_frequency_status.json"
    if args.dry_run and args.status_file is None:
        status_path = Path(tempfile.gettempdir()) / status_path.name
    status = {
        "started_at": datetime.now().isoformat(),
        "mode": args.mode,
        "treatments": treatments,
        "planned_runs": planned,
        "jobs": [],
    }
    if args.mode == "preflight":
        status.update({"ended_at": datetime.now().isoformat(), "status": "passed"})
        write_json(status_path, status)
        print("status_file={}".format(status_path))
        return 0
    print("P4 mvfst BBR1 ACK_FREQUENCY")
    print("mode={} planned_runs={} protocol=raw".format(args.mode, planned))
    print("qlog_policy={} pcap_policy={}".format(args.qlog_policy, args.pcap_policy))
    failures = 0
    for treatment in treatments:
        exp, stacks = documents(base_exp, base_stacks, treatment, args.mode == "canary")
        with tempfile.TemporaryDirectory(prefix="quicbench-p4-") as temp_dir:
            temp_root = Path(temp_dir)
            exp_path = temp_root / "experiment.json"
            stacks_path = temp_root / "stacks.json"
            write_json(exp_path, exp)
            write_json(stacks_path, stacks)
            command = runner_command(
                args, exp_path, stacks_path, 1 if args.mode == "canary" else args.trials
            )
            record = {
                "treatment": treatment,
                "command": command,
                "started_at": datetime.now().isoformat(),
            }
            status["jobs"].append(record)
            write_json(status_path, status)
            print("\n===== {} =====".format(treatment))
            result = subprocess.run(command, cwd=str(REPO_ROOT), check=False)
            if result.returncode == 0 and not args.dry_run:
                try:
                    verify_artifacts(
                        treatment,
                        args.mode == "canary",
                        1 if args.mode == "canary" else args.trials,
                        args.qlog_policy,
                    )
                except (OSError, ValueError, RuntimeError) as exc:
                    print("P4_ARTIFACT_VALIDATION_FAILED {}: {}".format(treatment, exc), file=sys.stderr)
                    result = subprocess.CompletedProcess(command, 1)
            record.update(
                {
                    "ended_at": datetime.now().isoformat(),
                    "returncode": result.returncode,
                    "status": "passed" if result.returncode == 0 else "failed",
                }
            )
            if result.returncode:
                failures += 1
            write_json(status_path, status)
    status.update(
        {
            "ended_at": datetime.now().isoformat(),
            "failed_jobs": failures,
            "status": "passed" if failures == 0 else "completed-with-failures",
        }
    )
    write_json(status_path, status)
    print("\nstatus_file={}".format(status_path))
    print("failed_jobs={}".format(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
