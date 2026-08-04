#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path
from collections import defaultdict


EVENT_PAIR_LABELS = {
    "E1_ack2_vs_ack10": "ack2:ack10",
    "E2_ack10_vs_ack2": "ack2:ack10",
    "E3_ack10_vs_ack10": "ack10:ack10",
    "E4_ack2_vs_ack2": "ack2:ack2",
    "P1_neqo_vs_chromium": "neqo:chromium",
    "P2_chromium_vs_neqo": "neqo:chromium",
    "P3_neqo_vs_neqo": "neqo:neqo",
    "P4_chromium_vs_chromium": "chromium:chromium",
}


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("results_root", help="experiment root, e.g. results/B0-two-flow-fairness-no-jitter-chromium-server")
    parser.add_argument(
        "--output",
        "-o",
        help="output csv path; defaults to <results_root>/flattened_summary.csv",
    )
    parser.add_argument(
        "--format",
        choices=["compact", "detailed"],
        default="compact",
        help="compact: tag,net,event,pair,share_ratio; detailed: keep expanded columns",
    )
    return parser.parse_args()


def infer_tag(results_root: Path) -> str:
    name = results_root.name
    suffix = "-server"
    if name.endswith(suffix):
        prefix = name[: -len(suffix)]
        return prefix.rsplit("-", 1)[-1]
    return name


def load_trial_summary(summary_path: Path):
    with summary_path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return None
    return rows


def order_rows(event_name: str, rows):
    pair_label = EVENT_PAIR_LABELS.get(event_name, event_name)
    if pair_label == "neqo:chromium":
        order = {"neqo": 0, "chromium": 1}
        return sorted(rows, key=lambda row: order.get(str(row.get("ack_policy", "")), 99)), pair_label
    if pair_label in ("neqo:neqo", "chromium:chromium"):
        return sorted(rows, key=lambda row: row["flow_id"]), pair_label
    if pair_label == "ack2:ack10":
        order = {"2": 0, "10": 1}
        return sorted(rows, key=lambda row: order.get(str(row["ack_freq"]), 99)), pair_label
    if pair_label == "ack10:ack10":
        return sorted(rows, key=lambda row: row["flow_id"]), pair_label
    if pair_label == "ack2:ack2":
        return sorted(rows, key=lambda row: row["flow_id"]), pair_label
    return sorted(rows, key=lambda row: row["flow_id"]), pair_label


def to_float(row, key):
    return float(row[key]) if row.get(key) not in ("", None) else 0.0


def build_output_rows(results_root: Path):
    tag = infer_tag(results_root)
    output_rows = []

    for network_dir in sorted(p for p in results_root.iterdir() if p.is_dir()):
        net = network_dir.name
        for event_dir in sorted(p for p in network_dir.iterdir() if p.is_dir()):
            event_name = event_dir.name
            summary_path = event_dir / "summary.csv"
            if not summary_path.exists():
                continue

            rows = load_trial_summary(summary_path)
            if not rows:
                continue

            rows_by_run_id = defaultdict(list)
            for row in rows:
                rows_by_run_id[row.get("run_id", "")].append(row)

            for run_id in sorted(rows_by_run_id):
                run_rows = rows_by_run_id[run_id]
                ordered_rows, pair_label = order_rows(event_name, run_rows)
                first = ordered_rows[0]
                second = ordered_rows[1] if len(ordered_rows) > 1 else ordered_rows[0]
                total_tp = to_float(first, "avg_throughput_mbps") + to_float(second, "avg_throughput_mbps")

                output_rows.append(
                    {
                        "tag": tag,
                        "net": net,
                        "event": event_name,
                        "pair": pair_label,
                        "left_ack_freq": first.get("ack_freq", ""),
                        "left_ack_policy": first.get("ack_policy", ""),
                        "left_stack": first.get("stack_name", ""),
                        "left_avg_throughput_mbps": first.get("avg_throughput_mbps", ""),
                        "left_app_goodput_mbps": first.get("app_goodput_mbps", ""),
                        "left_ack_eliciting_packets_received": first.get("ack_eliciting_packets_received", ""),
                        "left_ack_frames_sent": first.get("ack_frames_sent", ""),
                        "left_realized_ack_ratio": first.get("realized_ack_ratio", ""),
                        "left_mean_ack_interval_ms": first.get("mean_ack_interval_ms", ""),
                        "left_share": first.get("share", ""),
                        "right_ack_freq": second.get("ack_freq", ""),
                        "right_ack_policy": second.get("ack_policy", ""),
                        "right_stack": second.get("stack_name", ""),
                        "right_avg_throughput_mbps": second.get("avg_throughput_mbps", ""),
                        "right_app_goodput_mbps": second.get("app_goodput_mbps", ""),
                        "right_ack_eliciting_packets_received": second.get("ack_eliciting_packets_received", ""),
                        "right_ack_frames_sent": second.get("ack_frames_sent", ""),
                        "right_realized_ack_ratio": second.get("realized_ack_ratio", ""),
                        "right_mean_ack_interval_ms": second.get("mean_ack_interval_ms", ""),
                        "right_share": second.get("share", ""),
                        "total_throughput_mbps": "{:.5f}".format(total_tp),
                        "jain_index": first.get("jain_index", ""),
                        "steady_state_start_s": first.get("steady_state_start_s", ""),
                        "steady_state_end_s": first.get("steady_state_end_s", ""),
                        "run_ids": run_id,
                    }
                )

    return output_rows


def write_csv(output_path: Path, rows, output_format: str):
    if output_format == "compact":
        headers = ["tag", "net", "event", "pair", "share_ratio"]
        compact_rows = []
        for row in rows:
            compact_rows.append(
                {
                    "tag": row["tag"],
                    "net": row["net"],
                    "event": row["event"],
                    "pair": row["pair"],
                    "share_ratio": "{}:{}".format(row["left_share"], row["right_share"]),
                }
            )
        rows_to_write = compact_rows
    else:
        headers = [
            "tag",
            "net",
            "event",
            "pair",
            "left_ack_freq",
            "left_ack_policy",
            "left_stack",
            "left_avg_throughput_mbps",
            "left_app_goodput_mbps",
            "left_ack_eliciting_packets_received",
            "left_ack_frames_sent",
            "left_realized_ack_ratio",
            "left_mean_ack_interval_ms",
            "left_share",
            "right_ack_freq",
            "right_ack_policy",
            "right_stack",
            "right_avg_throughput_mbps",
            "right_app_goodput_mbps",
            "right_ack_eliciting_packets_received",
            "right_ack_frames_sent",
            "right_realized_ack_ratio",
            "right_mean_ack_interval_ms",
            "right_share",
            "total_throughput_mbps",
            "jain_index",
            "steady_state_start_s",
            "steady_state_end_s",
            "run_ids",
        ]
        rows_to_write = rows

    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows_to_write)


def main():
    args = get_args()
    results_root = Path(args.results_root)
    output_path = Path(args.output) if args.output else results_root / "flattened_summary.csv"
    rows = build_output_rows(results_root)
    write_csv(output_path, rows, args.format)
    print(output_path)


if __name__ == "__main__":
    main()
