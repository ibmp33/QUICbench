#!/usr/bin/env python3
"""Report fixed2/fixed10 sender and pacing mechanism effects."""

import argparse
import csv
import json
import math
from pathlib import Path
import statistics


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "results_root",
        nargs="?",
        type=Path,
        default=Path("/home/ioio33/QUIC_project/results"),
    )
    parser.add_argument("--csv-out", type=Path)
    return parser.parse_args()


def latest_manifests(root):
    selected = {}
    pattern = (
        "P2-fixed-ratio-mechanism-*-server/"
        "50rtt-20bw-0.5bdp/*/*/run_manifest.json"
    )
    for path in root.glob(pattern):
        run_dir = path.parent
        try:
            repetition = int(run_dir.name.split("-", 1)[0])
        except ValueError:
            continue
        key = (path.parents[3].name, run_dir.parent.name, repetition)
        previous = selected.get(key)
        if previous is None or path.stat().st_mtime > previous.stat().st_mtime:
            selected[key] = path
    return sorted(selected.values())


def mean(values):
    return statistics.mean(values) if values else float("nan")


def stddev(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0


def pct(value):
    return "n/a" if math.isnan(value) else "{:.2%}".format(value)


def resolve_jain(row_a, row_b, share_a, share_b):
    recorded = row_a.get("jain_index") or row_b.get("jain_index")
    if recorded:
        return float(recorded)
    square_sum = share_a * share_a + share_b * share_b
    return 1.0 / (2.0 * square_sum) if square_sum else 0.0


def load_runs(root):
    runs = []
    incomplete = []
    for manifest_path in latest_manifests(root):
        summary_path = manifest_path.parent / "summary.csv"
        if not summary_path.is_file():
            incomplete.append(str(manifest_path.parent))
            continue
        try:
            manifest = json.loads(manifest_path.read_text())
            with summary_path.open(newline="") as handle:
                rows = list(csv.DictReader(handle))
        except (OSError, ValueError, csv.Error):
            incomplete.append(str(manifest_path.parent))
            continue
        by_flow = {row.get("flow_id"): row for row in rows}
        manifest_flows = {
            flow.get("flow_id"): flow for flow in manifest.get("flows", [])
        }
        if set(by_flow) != {"flow_a", "flow_b"} or set(manifest_flows) != {
            "flow_a",
            "flow_b",
        }:
            incomplete.append(str(manifest_path.parent))
            continue
        row_a = by_flow["flow_a"]
        row_b = by_flow["flow_b"]
        flow_a = manifest_flows["flow_a"]
        flow_b = manifest_flows["flow_b"]
        config_a = flow_a.get("server_config", {})
        config_b = flow_b.get("server_config", {})
        if config_a != config_b:
            incomplete.append(str(manifest_path.parent))
            continue
        try:
            share_a = float(row_a["share"])
            share_b = float(row_b["share"])
        except (KeyError, TypeError, ValueError):
            incomplete.append(str(manifest_path.parent))
            continue
        pair = (row_a.get("ack_policy"), row_b.get("ack_policy"))
        if pair == ("fixed2", "fixed10"):
            fixed2_share = share_a
        elif pair == ("fixed10", "fixed2"):
            fixed2_share = share_b
        else:
            fixed2_share = None
        runs.append(
            {
                "server": flow_a.get("server_stack_name")
                or flow_a.get("server_stack"),
                "protocol": flow_a.get("protocol") or manifest.get("protocol"),
                "cc": config_a.get("cc"),
                "pacing": config_a.get("pacing"),
                "pair": pair,
                "fixed2_share": fixed2_share,
                "share_gap": abs(share_a - share_b),
                "jain": resolve_jain(row_a, row_b, share_a, share_b),
                "valid": manifest.get("experiment_valid") is True,
                "saturated": manifest.get("saturation_validation", {}).get("valid")
                is True,
            }
        )
    return runs, incomplete


def condition_rows(runs):
    grouped = {}
    for run in runs:
        if run["fixed2_share"] is None:
            continue
        key = (run["server"], run["protocol"], run["cc"], run["pacing"])
        grouped.setdefault(key, []).append(run)
    rows = []
    for key, samples in sorted(grouped.items()):
        usable = [sample for sample in samples if sample["valid"] and sample["saturated"]]
        values = [sample["fixed2_share"] for sample in usable]
        when_a = [
            sample["fixed2_share"]
            for sample in usable
            if sample["pair"] == ("fixed2", "fixed10")
        ]
        when_b = [
            sample["fixed2_share"]
            for sample in usable
            if sample["pair"] == ("fixed10", "fixed2")
        ]
        rows.append(
            {
                "server": key[0],
                "protocol": key[1],
                "cc": key[2],
                "pacing": key[3],
                "n": len(samples),
                "analysis_n": len(usable),
                "valid_n": sum(sample["valid"] for sample in samples),
                "saturated_n": sum(sample["saturated"] for sample in samples),
                "fixed2_share_mean": mean(values),
                "fixed2_share_stddev": stddev(values),
                "fixed2_share_when_a": mean(when_a),
                "fixed2_share_when_b": mean(when_b),
                "role_difference": (
                    abs(mean(when_a) - mean(when_b))
                    if when_a and when_b
                    else float("nan")
                ),
                "fixed2_wins": sum(value > 0.5 for value in values),
                "share_gap_mean": mean([sample["share_gap"] for sample in usable]),
                "jain_mean": mean([sample["jain"] for sample in usable]),
            }
        )
    return rows


def baseline_rows(runs):
    grouped = {}
    for run in runs:
        if run["pair"][0] != run["pair"][1]:
            continue
        key = (
            run["server"],
            run["protocol"],
            run["cc"],
            run["pacing"],
            run["pair"][0],
        )
        grouped.setdefault(key, []).append(run)
    rows = []
    for key, samples in sorted(grouped.items()):
        usable = [sample for sample in samples if sample["valid"] and sample["saturated"]]
        rows.append(
            {
                "server": key[0],
                "protocol": key[1],
                "cc": key[2],
                "pacing": key[3],
                "baseline_policy": key[4],
                "n": len(samples),
                "analysis_n": len(usable),
                "valid_n": sum(sample["valid"] for sample in samples),
                "saturated_n": sum(sample["saturated"] for sample in samples),
                "share_gap_mean": mean([sample["share_gap"] for sample in usable]),
                "jain_mean": mean([sample["jain"] for sample in usable]),
            }
        )
    return rows


def effect_rows(conditions):
    cells = {
        (row["server"], row["protocol"], row["cc"], row["pacing"]): row[
            "fixed2_share_mean"
        ]
        for row in conditions
        if not math.isnan(row["fixed2_share_mean"])
    }
    effects = []
    servers = sorted({key[0] for key in cells})
    protocols = {key[0]: key[1] for key in cells}
    for server in servers:
        for cc_algo in sorted({key[2] for key in cells if key[0] == server}):
            enabled = (server, protocols[server], cc_algo, "enabled")
            disabled = (server, protocols[server], cc_algo, "disabled")
            if enabled in cells and disabled in cells:
                effects.append(
                    {
                        "server": server,
                        "protocol": protocols[server],
                        "cc": cc_algo,
                        "effect": "pacing_on_minus_off",
                        "stratum": "fixed2_share",
                        "estimate": cells[enabled] - cells[disabled],
                    }
                )
    for cc_algo in sorted({key[2] for key in cells}):
        for pacing in ("enabled", "disabled"):
            quiche = ("quiche", "http3", cc_algo, pacing)
            xquic = ("xquic", "http3", cc_algo, pacing)
            if quiche in cells and xquic in cells:
                effects.append(
                    {
                        "server": "xquic-minus-quiche",
                        "protocol": "http3",
                        "cc": cc_algo,
                        "effect": "implementation_difference",
                        "stratum": "pacing_{}".format(pacing),
                        "estimate": cells[xquic] - cells[quiche],
                    }
                )
    return effects


def write_csv(path, conditions, baselines, effects):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "row_type",
        "server",
        "protocol",
        "cc",
        "pacing",
        "n",
        "analysis_n",
        "valid_n",
        "saturated_n",
        "fixed2_share_mean",
        "fixed2_share_stddev",
        "fixed2_share_when_a",
        "fixed2_share_when_b",
        "role_difference",
        "fixed2_wins",
        "share_gap_mean",
        "jain_mean",
        "baseline_policy",
        "effect",
        "stratum",
        "estimate",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in conditions:
            writer.writerow(dict(row, row_type="condition"))
        for row in baselines:
            writer.writerow(dict(row, row_type="baseline"))
        for row in effects:
            writer.writerow(dict(row, row_type="effect"))


def main():
    args = parse_args()
    runs, incomplete = load_runs(args.results_root)
    if not runs:
        raise SystemExit("No completed P2F fixed-ratio runs found")
    conditions = condition_rows(runs)
    baselines = baseline_rows(runs)
    effects = effect_rows(conditions)
    print("P2F fixed-ratio mechanism numeric analysis")
    for row in conditions:
        print(
            "server={} cc={} pacing={} usable={}/{} fixed2_share={} std={} "
            "role_A={} role_B={} role_diff={} wins={}/{} jain={:.5f}".format(
                row["server"],
                row["cc"],
                row["pacing"],
                row["analysis_n"],
                row["n"],
                pct(row["fixed2_share_mean"]),
                pct(row["fixed2_share_stddev"]),
                pct(row["fixed2_share_when_a"]),
                pct(row["fixed2_share_when_b"]),
                pct(row["role_difference"]),
                row["fixed2_wins"],
                row["analysis_n"],
                row["jain_mean"],
            )
        )
    print("\nHomogeneous baselines:")
    for row in baselines:
        print(
            "server={} cc={} pacing={} policy={} usable={}/{} gap={} jain={:.5f}".format(
                row["server"],
                row["cc"],
                row["pacing"],
                row["baseline_policy"],
                row["analysis_n"],
                row["n"],
                pct(row["share_gap_mean"]),
                row["jain_mean"],
            )
        )
    print("\nEffects on fixed2 share:")
    for row in effects:
        print(
            "server={} {} [{}] = {:+.2f} pp".format(
                row["server"], row["effect"], row["stratum"], 100 * row["estimate"]
            )
        )
    output = args.csv_out or args.results_root / "P2_fixed_ratio_effects.csv"
    write_csv(output, conditions, baselines, effects)
    print("\ncsv={}".format(output))
    if incomplete:
        print("warning=incomplete_or_inconsistent_runs ignored={}".format(len(incomplete)))


if __name__ == "__main__":
    main()

