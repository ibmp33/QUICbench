#!/usr/bin/env python3
"""Report numeric CC, pacing, and CC x pacing effects for the P2 pilot."""

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
    for path in root.glob(
        "P2-sender-mechanism-*-server/50rtt-20bw-0.5bdp/*/*/run_manifest.json"
    ):
        run_dir = path.parent
        try:
            repetition = int(run_dir.name.split("-", 1)[0])
        except ValueError:
            continue
        condition_root = path.parents[3].name
        key = (condition_root, run_dir.parent.name, repetition)
        previous = selected.get(key)
        if previous is None or path.stat().st_mtime > previous.stat().st_mtime:
            selected[key] = path
    return sorted(selected.values())


def resolve_jain(row_a, row_b, share_a, share_b):
    recorded = row_a.get("jain_index") or row_b.get("jain_index")
    if recorded:
        return float(recorded)
    share_square_sum = share_a * share_a + share_b * share_b
    return 1.0 / (2.0 * share_square_sum) if share_square_sum else 0.0


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
        share_a = float(row_a["share"])
        share_b = float(row_b["share"])
        jain = resolve_jain(row_a, row_b, share_a, share_b)
        pair = (row_a["ack_policy"], row_b["ack_policy"])
        if pair == ("neqo", "chromium"):
            neqo_share = share_a
        elif pair == ("chromium", "neqo"):
            neqo_share = share_b
        else:
            neqo_share = None
        runs.append(
            {
                "server": flow_a.get("server_stack_name")
                or flow_a.get("server_stack"),
                "protocol": flow_a.get("protocol") or manifest.get("protocol"),
                "cc": config_a.get("cc"),
                "pacing": config_a.get("pacing"),
                "pair": pair,
                "neqo_share": neqo_share,
                "share_gap": abs(share_a - share_b),
                "jain": jain,
                "valid": manifest.get("experiment_valid") is True,
                "saturated": manifest.get("saturation_validation", {}).get("valid")
                is True,
            }
        )
    return runs, incomplete


def mean(values):
    return statistics.mean(values) if values else float("nan")


def stddev(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0


def pct(value):
    return "n/a" if math.isnan(value) else "{:.2%}".format(value)


def condition_rows(runs):
    grouped = {}
    for run in runs:
        key = (run["server"], run["protocol"], run["cc"], run["pacing"])
        if run["neqo_share"] is not None:
            grouped.setdefault(key, []).append(run)
    rows = []
    for key, samples in sorted(grouped.items()):
        analysis_samples = [
            sample for sample in samples if sample["valid"] and sample["saturated"]
        ]
        shares = [sample["neqo_share"] for sample in analysis_samples]
        shares_when_a = [
            sample["neqo_share"]
            for sample in analysis_samples
            if sample["pair"] == ("neqo", "chromium")
        ]
        shares_when_b = [
            sample["neqo_share"]
            for sample in analysis_samples
            if sample["pair"] == ("chromium", "neqo")
        ]
        rows.append(
            {
                "server": key[0],
                "protocol": key[1],
                "cc": key[2],
                "pacing": key[3],
                "n": len(samples),
                "analysis_n": len(analysis_samples),
                "valid_n": sum(sample["valid"] for sample in samples),
                "saturated_n": sum(sample["saturated"] for sample in samples),
                "neqo_share_mean": mean(shares),
                "neqo_share_stddev": stddev(shares),
                "neqo_share_when_a": mean(shares_when_a),
                "neqo_share_when_b": mean(shares_when_b),
                "role_difference": abs(mean(shares_when_a) - mean(shares_when_b))
                if shares_when_a and shares_when_b
                else float("nan"),
                "neqo_wins": sum(value > 0.5 for value in shares),
                "jain_mean": mean([sample["jain"] for sample in analysis_samples]),
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
    by_server = {}
    for row in conditions:
        if math.isnan(row["neqo_share_mean"]):
            continue
        by_server.setdefault((row["server"], row["protocol"]), {})[
            (row["cc"], row["pacing"])
        ] = row["neqo_share_mean"]
    effects = []
    for (server, protocol), cells in sorted(by_server.items()):
        for cc_algo in sorted({key[0] for key in cells}):
            if (cc_algo, "enabled") in cells and (cc_algo, "disabled") in cells:
                effects.append(
                    {
                        "server": server,
                        "protocol": protocol,
                        "effect": "pacing_on_minus_off",
                        "stratum": cc_algo,
                        "estimate": cells[(cc_algo, "enabled")]
                        - cells[(cc_algo, "disabled")],
                    }
                )
        for pacing in ("enabled", "disabled"):
            if ("reno", pacing) in cells and ("cubic", pacing) in cells:
                effects.append(
                    {
                        "server": server,
                        "protocol": protocol,
                        "effect": "reno_minus_cubic",
                        "stratum": "pacing_{}".format(pacing),
                        "estimate": cells[("reno", pacing)]
                        - cells[("cubic", pacing)],
                    }
                )
        required = {
            ("cubic", "enabled"),
            ("cubic", "disabled"),
            ("reno", "enabled"),
            ("reno", "disabled"),
        }
        if required.issubset(cells):
            effects.append(
                {
                    "server": server,
                    "protocol": protocol,
                    "effect": "cc_x_pacing_interaction",
                    "stratum": "(reno_on-off)-(cubic_on-off)",
                    "estimate": (
                        cells[("reno", "enabled")]
                        - cells[("reno", "disabled")]
                    )
                    - (
                        cells[("cubic", "enabled")]
                        - cells[("cubic", "disabled")]
                    ),
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
        "neqo_share_mean",
        "neqo_share_stddev",
        "neqo_share_when_a",
        "neqo_share_when_b",
        "role_difference",
        "neqo_wins",
        "jain_mean",
        "baseline_policy",
        "share_gap_mean",
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
        raise SystemExit("No completed P2 sender mechanism runs found")
    conditions = condition_rows(runs)
    baselines = baseline_rows(runs)
    effects = effect_rows(conditions)
    print("P2 sender mechanism numeric analysis")
    for row in conditions:
        print(
            "server={} protocol={} cc={} pacing={} usable={}/{} valid={}/{} saturated={}/{} "
            "neqo_share={} std={} role_A={} role_B={} role_diff={} wins={}/{} jain={:.5f}".format(
                row["server"],
                row["protocol"],
                row["cc"],
                row["pacing"],
                row["analysis_n"],
                row["n"],
                row["valid_n"],
                row["n"],
                row["saturated_n"],
                row["n"],
                pct(row["neqo_share_mean"]),
                pct(row["neqo_share_stddev"]),
                pct(row["neqo_share_when_a"]),
                pct(row["neqo_share_when_b"]),
                pct(row["role_difference"]),
                row["neqo_wins"],
                row["analysis_n"],
                row["jain_mean"],
            )
        )
    if baselines:
        print("\nHomogeneous baselines:")
        for row in baselines:
            print(
                "server={} cc={} pacing={} policy={}/{} usable={}/{} mean_gap={} jain={:.5f}".format(
                    row["server"],
                    row["cc"],
                    row["pacing"],
                    row["baseline_policy"],
                    row["baseline_policy"],
                    row["analysis_n"],
                    row["n"],
                    pct(row["share_gap_mean"]),
                    row["jain_mean"],
                )
            )
    print("\nEffects on Neqo share (percentage-point interpretation):")
    for row in effects:
        print(
            "server={} {} [{}] = {:+.2f} pp".format(
                row["server"],
                row["effect"],
                row["stratum"],
                100 * row["estimate"],
            )
        )
    output = args.csv_out or args.results_root / "P2_sender_mechanism_effects.csv"
    write_csv(output, conditions, baselines, effects)
    print("\ncsv={}".format(output))
    if incomplete:
        print("warning=incomplete_or_inconsistent_runs ignored={}".format(len(incomplete)))
    if any(row["protocol"] == "raw" for row in conditions):
        print("warning=raw mvfst results must not be pooled with HTTP/3 results")


if __name__ == "__main__":
    main()
