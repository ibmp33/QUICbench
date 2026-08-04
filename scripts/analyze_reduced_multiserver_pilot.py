#!/usr/bin/env python3
"""Summarize the reduced ACK-policy pilot across server implementations."""

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path


PAIRS = [
    ("neqo", "neqo"),
    ("neqo", "chromium"),
    ("chromium", "neqo"),
    ("neqo", "fixed10"),
    ("fixed10", "neqo"),
]


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "results_root",
        type=Path,
        nargs="?",
        default=Path("/home/ioio33/QUIC_project/results"),
    )
    parser.add_argument("--trials", type=int, default=3)
    return parser.parse_args()


def server_name(profile_root):
    prefix = "P1-reduced-policy-pilot-"
    suffix = "-server"
    name = profile_root.parent.name
    if name.startswith(prefix) and name.endswith(suffix):
        return name[len(prefix) : -len(suffix)]
    return name


def selected_manifests(profile_root):
    selected = {}
    for path in profile_root.rglob("run_manifest.json"):
        run_dir = path.parent
        try:
            repetition = int(run_dir.name.split("-", 1)[0])
        except ValueError:
            continue
        key = (run_dir.parent.name, repetition)
        previous = selected.get(key)
        if previous is None or path.stat().st_mtime > previous.stat().st_mtime:
            selected[key] = path
    return selected


def load_runs(profile_root):
    runs = []
    incomplete = []
    for (trial_name, repetition), manifest_path in sorted(
        selected_manifests(profile_root).items()
    ):
        summary_path = manifest_path.parent / "summary.csv"
        if not summary_path.is_file():
            incomplete.append(str(manifest_path.parent))
            continue
        try:
            manifest = json.loads(manifest_path.read_text())
            with summary_path.open(newline="") as summary_file:
                rows = list(csv.DictReader(summary_file))
        except (OSError, json.JSONDecodeError, csv.Error):
            incomplete.append(str(manifest_path.parent))
            continue
        by_flow = {row.get("flow_id"): row for row in rows}
        if set(by_flow) != {"flow_a", "flow_b"}:
            incomplete.append(str(manifest_path.parent))
            continue
        row_a = by_flow["flow_a"]
        row_b = by_flow["flow_b"]
        manifest_flows = manifest.get("flows", [])
        server_configs = [
            flow.get("server_config")
            for flow in manifest_flows
            if isinstance(flow.get("server_config"), dict)
        ]
        normalized_configs = {
            json.dumps(config, sort_keys=True) for config in server_configs
        }
        server_config = server_configs[0] if server_configs else {}
        runs.append(
            {
                "trial": trial_name,
                "repetition": repetition,
                "pair": (row_a["ack_policy"], row_b["ack_policy"]),
                "share_a": float(row_a["share"]),
                "share_b": float(row_b["share"]),
                "valid": manifest.get("experiment_valid") is True,
                "saturated": manifest.get("saturation_validation", {}).get("valid")
                is True,
                "protocol": manifest.get("protocol"),
                "server_config": server_config,
                "server_config_consistent": len(server_configs) == 2
                and len(normalized_configs) == 1,
            }
        )
    return runs, incomplete


def pct(value):
    return "n/a" if math.isnan(value) else "{:.2%}".format(value)


def avg(values):
    return statistics.mean(values) if values else float("nan")


def summarize_contrast(runs, target, peer):
    shares = []
    role_a = []
    role_b = []
    for run in runs:
        if set(run["pair"]) != {target, peer}:
            continue
        target_share = (
            run["share_a"] if run["pair"][0] == target else run["share_b"]
        )
        shares.append(target_share)
        (role_a if run["pair"][0] == target else role_b).append(target_share)
    role_difference = abs(avg(role_a) - avg(role_b)) if role_a and role_b else float("nan")
    return shares, role_difference


def main():
    args = get_args()
    if args.trials <= 0:
        raise SystemExit("--trials must be positive")
    roots = sorted(
        args.results_root.glob(
            "P1-reduced-policy-pilot-*-server/50rtt-20bw-0.5bdp"
        )
    )
    if not roots:
        raise SystemExit("No reduced pilot result roots found under {}".format(args.results_root))

    print("Reduced multi-server ACK-policy pilot")
    print("expected_runs_per_server={}".format(len(PAIRS) * args.trials))
    print()

    any_incomplete = False
    for root in roots:
        server = server_name(root)
        runs, incomplete = load_runs(root)
        any_incomplete = any_incomplete or bool(incomplete)
        protocols = sorted({run["protocol"] for run in runs if run["protocol"]})
        observed_configs = {
            json.dumps(run["server_config"], sort_keys=True)
            for run in runs
            if run["server_config"]
        }
        print("server={} protocol={}".format(server, ",".join(protocols) or "unknown"))
        print(
            "  completion={}/{} valid={}/{} saturated={}/{}".format(
                len(runs),
                len(PAIRS) * args.trials,
                sum(run["valid"] for run in runs),
                len(runs),
                sum(run["saturated"] for run in runs),
                len(runs),
            )
        )
        print(
            "  server_config_consistent={}/{} distinct_conditions={}".format(
                sum(run["server_config_consistent"] for run in runs),
                len(runs),
                len(observed_configs),
            )
        )
        for encoded in sorted(observed_configs):
            config = json.loads(encoded)
            print(
                "  sender_condition cc={} requested_cc={} pacing={} gso={} control={}".format(
                    config.get("cc", "unknown"),
                    config.get("requested_cc", "unknown"),
                    config.get("pacing", "unknown"),
                    config.get("gso", "unknown"),
                    config.get("control_source", "unknown"),
                )
            )
        if len(observed_configs) > 1:
            print("  WARNING: sender conditions drifted across selected runs")
        grouped = defaultdict(list)
        for run in runs:
            grouped[run["pair"]].append(run)
        for pair in PAIRS:
            samples = grouped[pair]
            print(
                "  {:<20} n={:<2} share_A={} mean_gap={}".format(
                    "{}/{}".format(*pair),
                    len(samples),
                    pct(avg([sample["share_a"] for sample in samples])),
                    pct(
                        avg(
                            [
                                abs(sample["share_a"] - sample["share_b"])
                                for sample in samples
                            ]
                        )
                    ),
                )
            )
        for peer in ("chromium", "fixed10"):
            shares, role_difference = summarize_contrast(runs, "neqo", peer)
            print(
                "  contrast neqo/{:<8} n={:<2} neqo_share={} wins={}/{} role_diff={}".format(
                    peer,
                    len(shares),
                    pct(avg(shares)),
                    sum(value > 0.5 for value in shares),
                    len(shares),
                    pct(role_difference),
                )
            )
        if incomplete:
            print("  incomplete_runs={}".format(len(incomplete)))
        if "raw" in protocols:
            print("  note=raw QUIC exploratory result; do not treat as H3-equivalent")
        print()

    if any_incomplete:
        print("NOTE: incomplete run directories were ignored.")


if __name__ == "__main__":
    main()
