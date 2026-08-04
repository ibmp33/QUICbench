#!/usr/bin/env python3
"""Read-only, policy-centered analysis for partial or complete P0 results."""

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path


ORDERED_PAIRS = [
    ("fixed2", "fixed2"),
    ("fixed10", "fixed10"),
    ("fixed2", "fixed10"),
    ("fixed10", "fixed2"),
    ("neqo", "neqo"),
    ("chromium", "chromium"),
    ("neqo", "chromium"),
    ("chromium", "neqo"),
]

CONTRASTS = [
    ("fixed2", "fixed10"),
    ("neqo", "chromium"),
]


def arguments():
    parser = argparse.ArgumentParser(
        description="Analyze P0 runs without modifying experiment artifacts."
    )
    parser.add_argument("results_root", type=Path)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument(
        "--csv-output",
        type=Path,
        help="optional destination for one flattened row per selected run",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="return nonzero unless all eight ordered pairs have the requested repetitions",
    )
    return parser.parse_args()


def mean(values):
    return statistics.mean(values) if values else float("nan")


def sample_sd(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0


def percent(value):
    return "n/a" if math.isnan(value) else "{:.2%}".format(value)


def normal_ci(values):
    if not values:
        return float("nan"), float("nan")
    center = mean(values)
    if len(values) < 2:
        return center, center
    half_width = 1.96 * sample_sd(values) / math.sqrt(len(values))
    return center - half_width, center + half_width


def select_latest_manifests(root):
    selected = {}
    for path in root.rglob("run_manifest.json"):
        run_dir = path.parent
        repetition_text = run_dir.name.split("-", 1)[0]
        try:
            repetition = int(repetition_text)
        except ValueError:
            continue
        key = (run_dir.parent.parent.name, run_dir.parent.name, repetition)
        previous = selected.get(key)
        if previous is None or path.stat().st_mtime > previous.stat().st_mtime:
            selected[key] = path
    return selected


def load_runs(selected):
    runs = []
    problems = []
    for (_, trial_name, repetition), manifest_path in sorted(selected.items()):
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            problems.append("{}: unreadable manifest ({})".format(manifest_path, exc))
            continue
        summary_path = manifest_path.parent / "summary.csv"
        if not summary_path.is_file():
            problems.append("{}: missing summary.csv".format(manifest_path.parent))
            continue
        with summary_path.open(newline="") as summary_file:
            rows = list(csv.DictReader(summary_file))
        if len(rows) != 2:
            problems.append(
                "{}: expected two summary rows, found {}".format(
                    manifest_path.parent, len(rows)
                )
            )
            continue
        by_flow = {row["flow_id"]: row for row in rows}
        if set(by_flow) != {"flow_a", "flow_b"}:
            problems.append("{}: flow_a/flow_b missing".format(manifest_path.parent))
            continue

        row_a = by_flow["flow_a"]
        row_b = by_flow["flow_b"]
        pair = (row_a["ack_policy"], row_b["ack_policy"])
        share_a = float(row_a["share"])
        share_b = float(row_b["share"])
        share_square_sum = share_a * share_a + share_b * share_b
        calculated_jain = 1.0 / (2.0 * share_square_sum) if share_square_sum else 0.0
        first_flow = (manifest.get("client_start_order") or [""])[0]
        first_share = share_a if first_flow == "flow_a" else share_b if first_flow == "flow_b" else float("nan")
        ack_observed = bool(row_a.get("realized_ack_ratio")) and bool(
            row_b.get("realized_ack_ratio")
        )
        runs.append(
            {
                "profile": manifest_path.parent.parent.parent.name,
                "trial_name": trial_name,
                "repetition": repetition,
                "run_id": manifest_path.parent.name,
                "policy_a": pair[0],
                "policy_b": pair[1],
                "share_a": share_a,
                "share_b": share_b,
                "share_gap": abs(share_a - share_b),
                "jain": float(row_a.get("jain_index") or calculated_jain),
                "first_flow": first_flow,
                "first_share": first_share,
                "valid": manifest.get("experiment_valid") is True,
                "saturated": manifest.get("saturation_validation", {}).get("valid") is True,
                "ack_observed": ack_observed,
                "path": str(manifest_path.parent),
            }
        )
    return runs, problems


def print_completeness(runs, requested_trials):
    expected = len(ORDERED_PAIRS) * requested_trials
    print("Completeness")
    print("  selected runs: {}/{}".format(len(runs), expected))
    print("  valid: {}/{}".format(sum(run["valid"] for run in runs), len(runs)))
    print("  saturated: {}/{}".format(sum(run["saturated"] for run in runs), len(runs)))
    print(
        "  ACK telemetry present: {}/{}".format(
            sum(run["ack_observed"] for run in runs), len(runs)
        )
    )
    print()


def print_ordered_pairs(runs):
    grouped = defaultdict(list)
    for run in runs:
        grouped[(run["policy_a"], run["policy_b"])].append(run)

    print("Ordered policy pairs")
    print("  pair                         n   share_A   mean_gap   mean_Jain")
    for pair in ORDERED_PAIRS:
        samples = grouped[pair]
        if not samples:
            print("  {:<28} {:>2}   MISSING".format("{}/{}".format(*pair), 0))
            continue
        print(
            "  {:<28} {:>2}   {:>7}   {:>8}   {:.5f}".format(
                "{}/{}".format(*pair),
                len(samples),
                percent(mean([sample["share_a"] for sample in samples])),
                percent(mean([sample["share_gap"] for sample in samples])),
                mean([sample["jain"] for sample in samples]),
            )
        )
    print()


def print_policy_contrasts(runs):
    print("Policy-centered heterogeneous contrasts")
    for target, peer in CONTRASTS:
        samples = []
        role_a = []
        role_b = []
        for run in runs:
            pair = {run["policy_a"], run["policy_b"]}
            if pair != {target, peer}:
                continue
            target_share = run["share_a"] if run["policy_a"] == target else run["share_b"]
            samples.append(target_share)
            (role_a if run["policy_a"] == target else role_b).append(target_share)
        if not samples:
            print("  {} vs {}: MISSING".format(target, peer))
            continue
        low, high = normal_ci(samples)
        role_difference = abs(mean(role_a) - mean(role_b)) if role_a and role_b else float("nan")
        print(
            "  {} vs {}: n={} {}_share={} CI95=[{}, {}] wins={}/{} "
            "allocation_gap={} role_difference={}".format(
                target,
                peer,
                len(samples),
                target,
                percent(mean(samples)),
                percent(low),
                percent(high),
                sum(value > 0.5 for value in samples),
                len(samples),
                percent(2 * mean(samples) - 1),
                percent(role_difference),
            )
        )
    print()


def print_homogeneous_baselines(runs):
    print("Homogeneous baselines")
    print("  policy       n   mean_A    sd_A    mean_abs_gap   odd_A    even_A")
    for policy in ("fixed2", "fixed10", "neqo", "chromium"):
        samples = [
            run
            for run in runs
            if run["policy_a"] == policy and run["policy_b"] == policy
        ]
        shares = [sample["share_a"] for sample in samples]
        odd = [sample["share_a"] for sample in samples if sample["repetition"] % 2]
        even = [sample["share_a"] for sample in samples if sample["repetition"] % 2 == 0]
        print(
            "  {:<11} {:>2}   {:>7}  {:>7}      {:>7}   {:>7}   {:>7}".format(
                policy,
                len(samples),
                percent(mean(shares)),
                percent(sample_sd(shares) if shares else float("nan")),
                percent(mean([sample["share_gap"] for sample in samples])),
                percent(mean(odd)),
                percent(mean(even)),
            )
        )
    print()


def print_launch_order_audit(runs):
    observed = [run for run in runs if not math.isnan(run["first_share"])]
    homogeneous = [
        run for run in observed if run["policy_a"] == run["policy_b"]
    ]
    print("Launch-order audit")
    for label, samples in (("all", observed), ("homogeneous", homogeneous)):
        first_shares = [sample["first_share"] for sample in samples]
        print(
            "  {}: n={} first-launched_mean_share={} first-launched_wins={}/{}".format(
                label,
                len(samples),
                percent(mean(first_shares)),
                sum(value > 0.5 for value in first_shares),
                len(first_shares),
            )
        )
    print()


def write_flat_csv(path, runs):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(runs[0].keys()) if runs else []
    with path.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        if fields:
            writer.writeheader()
            writer.writerows(runs)


def main():
    args = arguments()
    root = args.results_root.resolve()
    if not root.is_dir():
        raise SystemExit("Results directory does not exist: {}".format(root))
    if args.trials <= 0:
        raise SystemExit("--trials must be positive")

    selected = select_latest_manifests(root)
    runs, problems = load_runs(selected)
    if not runs:
        raise SystemExit("No completed two-flow runs found under {}".format(root))

    print("P0 fairness analysis")
    print("results_root={}".format(root))
    print()
    print_completeness(runs, args.trials)
    print_ordered_pairs(runs)
    print_policy_contrasts(runs)
    print_homogeneous_baselines(runs)
    print_launch_order_audit(runs)

    if not all(run["ack_observed"] for run in runs):
        print(
            "NOTE: fairness ACK telemetry is incomplete; retain the separate ACK-policy "
            "validation evidence and manifest policy provenance."
        )
    if problems:
        print("Problems:")
        for problem in problems[:20]:
            print("- " + problem)
    if args.csv_output:
        write_flat_csv(args.csv_output, runs)
        print("Flattened CSV: {}".format(args.csv_output))

    counts = defaultdict(int)
    for run in runs:
        counts[(run["policy_a"], run["policy_b"])] += 1
    complete = all(counts[pair] >= args.trials for pair in ORDERED_PAIRS)
    if args.require_complete and not complete:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
