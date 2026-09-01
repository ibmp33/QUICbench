#!/usr/bin/env python3
"""Run the missing xquic-BBR and mvfst sender mechanism experiments.

This wrapper delegates individual conditions to the existing resumable P2
launcher. It keeps mvfst (raw QUIC) separate from xquic (HTTP/3), performs a
real canary before full collection, and never treats help output as proof that
a BBR condition is scientifically valid.
"""

import argparse
from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
WORKER = SCRIPT_DIR / "run_sender_mechanism_pilot.py"
RESULTS_ROOT = Path("/home/ioio33/QUIC_project/results")

MATRICES = {
    "bbr-core": {"xquic": ["bbr"], "mvfst": ["bbr"]},
    "mvfst-cc": {"mvfst": ["cubic", "reno", "bbr"]},
    "all-missing": {
        "xquic": ["bbr"],
        "mvfst": ["cubic", "reno", "bbr"],
    },
}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("preflight", "canary", "full"))
    parser.add_argument("--matrix", choices=sorted(MATRICES), default="all-missing")
    parser.add_argument(
        "--suite",
        choices=("both", "realistic", "fixed-ratio"),
        default="realistic",
        help=(
            "policy suite (default: realistic Neqo/Chromium only); "
            "fixed-ratio is a legacy stress-test opt-in"
        ),
    )
    parser.add_argument("--pacing", choices=("both", "on", "off"), default="both")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--min-free-gb", type=float, default=20.0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--status-file", type=Path)
    return parser.parse_args()


def write_status(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temporary.replace(path)


def selected_suites(value):
    return ["realistic", "fixed-ratio"] if value == "both" else [value]


def selected_pacing(value):
    return ["on", "off"] if value == "both" else [value]


def expected_runs(args):
    pair_count = 1 if args.mode == "canary" else 4
    trials = 1 if args.mode == "canary" else args.trials
    conditions = sum(len(ccs) for ccs in MATRICES[args.matrix].values())
    conditions *= len(selected_pacing(args.pacing))
    return conditions * len(selected_suites(args.suite)) * pair_count * trials


def worker_command(args, suite, server, cc_algos, status_path):
    command = [
        sys.executable,
        str(WORKER),
        "--suite",
        suite,
        "--server",
        server,
    ]
    for cc_algo in cc_algos:
        command.extend(["--cc", cc_algo])
    for pacing in selected_pacing(args.pacing):
        command.extend(["--pacing", pacing])
    command.extend(
        [
            "--trials",
            str(args.trials),
            "--min-free-gb",
            str(args.min_free_gb),
            "--status-file",
            str(status_path),
        ]
    )
    if server == "xquic":
        command.extend(["--pcap-policy", "none", "--qlog-policy", "first-only"])
    else:
        # tperf does not currently emit a compatible server qlog. Preserve one
        # pcap per pair instead of creating empty qlog directories as evidence.
        command.extend(["--pcap-policy", "first-only", "--qlog-policy", "none"])
    if args.mode == "preflight":
        command.append("--preflight-only")
    elif args.mode == "canary":
        command.append("--canary")
    if args.dry_run:
        command.append("--dry-run")
    if args.fail_fast:
        command.append("--fail-fast")
    if args.no_resume:
        command.append("--no-resume")
    return command


def main():
    args = parse_args()
    if args.trials <= 0:
        raise SystemExit("--trials must be positive")
    if args.mode == "full" and args.trials < 3:
        print("warning=full mode with fewer than 3 trials is a pilot, not a final matrix")
    status_path = args.status_file or RESULTS_ROOT / "P3_bbr_mvfst_extension_status.json"
    if args.dry_run:
        status_path = args.status_file or Path("/tmp/P3_bbr_mvfst_extension_status.json")
    planned = expected_runs(args)
    status = {
        "started_at": datetime.now().isoformat(),
        "mode": args.mode,
        "matrix": args.matrix,
        "suite": args.suite,
        "pacing": args.pacing,
        "trials": 1 if args.mode == "canary" else args.trials,
        "planned_runs": planned,
        "semantic_groups": {
            "xquic": "HTTP/3",
            "mvfst": "raw QUIC stream; report separately from HTTP/3",
        },
        "jobs": [],
    }
    print("P3 missing sender extension")
    print("mode={} matrix={} planned_runs={}".format(args.mode, args.matrix, planned))
    print("minimum_payload_minutes={:.1f}".format(planned * 20 / 60))
    print("warning=wall time is usually 1.7-2.5x payload time")
    failures = 0
    for suite in selected_suites(args.suite):
        for server, cc_algos in MATRICES[args.matrix].items():
            child_status = RESULTS_ROOT / "P3-status" / "{}-{}-{}.json".format(
                args.mode, suite, server
            )
            if args.dry_run:
                child_status = Path("/tmp") / child_status.name
            command = worker_command(args, suite, server, cc_algos, child_status)
            record = {
                "suite": suite,
                "server": server,
                "protocol": "raw" if server == "mvfst" else "http3",
                "cc_algos": cc_algos,
                "command": command,
                "started_at": datetime.now().isoformat(),
            }
            status["jobs"].append(record)
            write_status(status_path, status)
            print("\n===== {} {} =====".format(suite, server))
            print("command={}".format(" ".join(command)))
            result = subprocess.run(command, cwd=str(REPO_ROOT), check=False)
            record["ended_at"] = datetime.now().isoformat()
            record["returncode"] = result.returncode
            record["status"] = "passed" if result.returncode == 0 else "failed"
            if result.returncode != 0:
                failures += 1
                if args.fail_fast:
                    break
            write_status(status_path, status)
        if failures and args.fail_fast:
            break
    status["ended_at"] = datetime.now().isoformat()
    status["failed_jobs"] = failures
    status["status"] = "passed" if failures == 0 else "completed-with-failures"
    write_status(status_path, status)
    print("\nstatus_file={}".format(status_path))
    print("failed_jobs={}".format(failures))
    if args.mode == "preflight" and failures == 0:
        print("next=python3 scripts/run_bbr_mvfst_extension.py canary --matrix {}".format(args.matrix))
    elif args.mode == "canary" and failures == 0:
        print("CANARY=PASS; inspect manifests before full mode")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
