#!/usr/bin/env python3
"""Build the HotNets ACK-policy fairness reproducibility bundle.

Unknown fields from completed runs are written as NA. Work that has not been
performed is written as -todo-. Raw experiment artifacts are never modified or
copied; the bundle contains relative-path and SHA-256 indexes instead.
"""

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tarfile


NA = "NA"
TODO = "-todo-"
POLICY_ORDER = {"fixed2": 0, "fixed10": 1, "neqo": 2, "chromium": 3}


def args_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument("results_root", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("quicbench-export"))
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--hash-raw",
        action="store_true",
        help="hash all indexed qlog/pcap/application logs (can read several GiB)",
    )
    return parser.parse_args()


def clean_value(value):
    if value is None or value == "":
        return NA
    if isinstance(value, float) and not math.isfinite(value):
        return NA
    return value


def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: clean_value(row.get(field)) for field in fields})


def read_csv(path):
    if not path.is_file():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rel(path, root):
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def localize(path_text, results_root):
    if not path_text:
        return None
    marker = "/results/"
    if marker in path_text:
        return results_root / path_text.split(marker, 1)[1]
    path = Path(path_text)
    return path if path.is_absolute() else results_root / path


def metric_points(path):
    points = []
    for row in read_csv(path):
        try:
            points.append((int(row["elapsed_ms"]), int(row["cumulative_body_bytes"])))
        except (KeyError, TypeError, ValueError):
            pass
    return sorted(points)


def window_metric(path, start_s, end_s):
    points = metric_points(path)
    if not points:
        return None
    start_ms, end_ms = int(start_s * 1000), int(end_s * 1000)
    before_start = [point for point in points if point[0] <= start_ms]
    before_end = [point for point in points if point[0] <= end_ms]
    if not before_start or not before_end:
        return None
    start_point, end_point = before_start[-1], before_end[-1]
    byte_count = max(0, end_point[1] - start_point[1])
    active_ms = 0
    previous = points[0]
    for current in points[1:]:
        left = max(previous[0], start_ms)
        right = min(current[0], end_ms)
        if right > left and current[1] > previous[1]:
            active_ms += right - left
        previous = current
    duration_s = end_s - start_s
    return {
        "bytes": byte_count,
        "active_time_s": active_ms / 1000.0,
        "goodput_bps": byte_count * 8 / duration_s if duration_s > 0 else float("nan"),
        "sample_start_us": start_point[0] * 1000,
        "sample_end_us": end_point[0] * 1000,
    }


def jain(left, right):
    denominator = 2 * (left * left + right * right)
    return ((left + right) ** 2 / denominator) if denominator else 0.0


def run_directories(root):
    candidates = set()
    for name in ("run_manifest.json", "summary.csv"):
        for path in root.glob("P*-server/**/{}".format(name)):
            candidates.add(path.parent)
    return sorted(candidates)


def experiment_family(run_dir, root):
    top = run_dir.relative_to(root).parts[0]
    if top.startswith("P0-"):
        return "P0_policy_fairness"
    if top.startswith("P2-fixed-ratio"):
        return "P2_fixed_ratio_mechanism"
    if top.startswith("P2-sender-mechanism"):
        return "P2_sender_mechanism"
    return top


def sender_from_path(run_dir, root):
    top = run_dir.relative_to(root).parts[0]
    for sender in ("quic-go", "quiche", "xquic", "mvfst"):
        if top.endswith("{}-server".format(sender)):
            return sender
    return NA


def summary_window(rows):
    starts, ends = [], []
    for row in rows:
        try:
            starts.append(float(row["steady_state_start_s"]))
            ends.append(float(row["steady_state_end_s"]))
        except (KeyError, TypeError, ValueError):
            pass
    return (starts[0], ends[0]) if starts and ends else (None, None)


def flow_log_paths(run_dir, flow_id):
    base = run_dir / "flows" / flow_id
    return ";".join(
        str(path) for path in sorted(base.glob("**/logs/*.log")) if path.is_file()
    ) or NA


def build_runs_and_fairness(results_root, connection_lookup):
    runs, fairness, homogeneous, exclusions, contexts = [], [], [], [], {}
    for run_dir in run_directories(results_root):
        manifest_path = run_dir / "run_manifest.json"
        summary_path = run_dir / "summary.csv"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
        summary = read_csv(summary_path)
        by_flow = {row.get("flow_id"): row for row in summary}
        flows = {flow.get("flow_id"): flow for flow in manifest.get("flows", [])}
        run_id = rel(run_dir, results_root)
        sender = (
            flows.get("flow_a", {}).get("server_stack_name")
            or flows.get("flow_a", {}).get("server_stack")
            or sender_from_path(run_dir, results_root)
        )
        start_s, end_s = summary_window(summary)
        has_manifest = manifest_path.is_file()
        manifest_valid = manifest.get("experiment_valid") is True
        saturated = manifest.get("saturation_validation", {}).get("valid") is True
        exclusion_reason = "" if has_manifest else "legacy_run_missing_manifest"
        eligible = bool(has_manifest and manifest_valid and saturated)
        if not eligible:
            exclusions.append(
                {
                    "run_id": run_id,
                    "experiment_family": experiment_family(run_dir, results_root),
                    "stage": "run_selection",
                    "reason": exclusion_reason or manifest.get("invalid_reason") or "invalid_run",
                    "available_artifacts": ";".join(
                        rel(path, results_root) for path in (manifest_path, summary_path) if path.exists()
                    ),
                }
            )
        flow_a, flow_b = flows.get("flow_a", {}), flows.get("flow_b", {})
        row_a, row_b = by_flow.get("flow_a", {}), by_flow.get("flow_b", {})
        config = flow_a.get("server_config", {})
        conn_a = connection_lookup.get((run_id, "flow_a"), {})
        conn_b = connection_lookup.get((run_id, "flow_b"), {})
        pcap = run_dir / "packets.pcap"
        runs.append(
            {
                "run_id": run_id,
                "experiment_family": experiment_family(run_dir, results_root),
                "sender_implementation": sender,
                "sender_full_commit": flow_a.get("server_git_commit", NA),
                "sender_binary_sha256": flow_a.get("server_binary_sha256", NA),
                "source_dirty": NA,
                "workload": manifest.get("workload_name", NA),
                "congestion_control": config.get("cc") or row_a.get("cc_algo", NA),
                "initial_cwnd_packets": NA,
                "configured_pacing": config.get("pacing", NA),
                "effective_pacing": NA,
                "gso_enabled": config.get("gso", NA),
                "sendmmsg_enabled": NA,
                "receiver_policy_flow_a": flow_a.get("ack_policy") or row_a.get("ack_policy", NA),
                "receiver_policy_flow_b": flow_b.get("ack_policy") or row_b.get("ack_policy", NA),
                "flow_a_connection_id": conn_a.get("connection_id", NA),
                "flow_b_connection_id": conn_b.get("connection_id", NA),
                "flow_a_port": flow_a.get("local_port", NA),
                "flow_b_port": flow_b.get("local_port", NA),
                "launch_order": ";".join(manifest.get("client_start_order", [])) or NA,
                "duration_s": manifest.get("duration_s", NA),
                "measurement_start_s": start_s,
                "measurement_end_s": end_s,
                "bottleneck_mbps": 20,
                "base_rtt_ms": 50,
                "queue_definition": "0.5BDP",
                "configured_loss": 0,
                "eligible": eligible,
                "exclusion_reason": exclusion_reason,
                "qlog_path_a": conn_a.get("source_log", NA),
                "qlog_path_b": conn_b.get("source_log", NA),
                "pcap_path": rel(pcap, results_root) if pcap.is_file() else NA,
                "application_log_paths": "flow_a={};flow_b={}".format(
                    flow_log_paths(run_dir, "flow_a"), flow_log_paths(run_dir, "flow_b")
                ),
            }
        )
        contexts[run_id] = {
            "run_dir": run_dir,
            "manifest": manifest,
            "flows": flows,
            "summary": by_flow,
            "measurement_start_s": start_s,
            "measurement_end_s": end_s,
        }
        if not eligible or start_s is None or end_s is None or set(flows) != {"flow_a", "flow_b"}:
            continue
        metrics = {}
        for flow_id in ("flow_a", "flow_b"):
            path = localize(flows[flow_id].get("client_metrics_path"), results_root)
            metrics[flow_id] = window_metric(path, start_s, end_s) if path else None
        if not all(metrics.values()):
            exclusions.append(
                {"run_id": run_id, "experiment_family": experiment_family(run_dir, results_root),
                 "stage": "fairness", "reason": "missing_or_unreadable_client_metrics",
                 "available_artifacts": rel(summary_path, results_root)}
            )
            continue
        policies = {flow_id: flows[flow_id]["ack_policy"] for flow_id in ("flow_a", "flow_b")}
        if policies["flow_a"] == policies["flow_b"]:
            p_flow, q_flow = "flow_a", "flow_b"
        else:
            p_flow, q_flow = sorted(
                ("flow_a", "flow_b"), key=lambda fid: POLICY_ORDER.get(policies[fid], 99)
            )
        p_goodput, q_goodput = metrics[p_flow]["goodput_bps"], metrics[q_flow]["goodput_bps"]
        total = p_goodput + q_goodput
        p_share = p_goodput / total if total else 0
        q_share = q_goodput / total if total else 0
        fair_row = {
            "run_id": run_id, "sender_implementation": sender,
            "policy_p": policies[p_flow], "policy_q": policies[q_flow],
            "policy_p_flow_label": p_flow, "policy_q_flow_label": q_flow,
            "policy_p_bytes": metrics[p_flow]["bytes"], "policy_q_bytes": metrics[q_flow]["bytes"],
            "policy_p_active_time_s": metrics[p_flow]["active_time_s"],
            "policy_q_active_time_s": metrics[q_flow]["active_time_s"],
            "policy_p_goodput_bps": p_goodput, "policy_q_goodput_bps": q_goodput,
            "policy_p_share": p_share, "policy_q_share": q_share,
            "share_gap_p_minus_q": p_share - q_share, "jain_index": jain(p_goodput, q_goodput),
            "winner_policy": policies[p_flow] if p_goodput >= q_goodput else policies[q_flow],
            "both_flows_active": metrics[p_flow]["active_time_s"] > 0 and metrics[q_flow]["active_time_s"] > 0,
            "bottleneck_saturated": saturated, "eligible": True, "exclusion_reason": "",
            "measurement_start_s": start_s, "measurement_end_s": end_s,
            "policy_p_sample_start_us": metrics[p_flow]["sample_start_us"],
            "policy_p_sample_end_us": metrics[p_flow]["sample_end_us"],
            "policy_q_sample_start_us": metrics[q_flow]["sample_start_us"],
            "policy_q_sample_end_us": metrics[q_flow]["sample_end_us"],
        }
        fairness.append(fair_row)
        if policies["flow_a"] == policies["flow_b"]:
            homogeneous.append(
                {"run_id": run_id, "sender_implementation": sender,
                 "policy_pair": "{0}/{0}".format(policies["flow_a"]),
                 "flow_a_share": p_share, "flow_b_share": q_share,
                 "absolute_share_gap": abs(p_share - q_share),
                 "jain_index": fair_row["jain_index"],
                 "launch_order": runs[-1]["launch_order"], "eligible": True}
            )
    return runs, fairness, homogeneous, exclusions, contexts


def run_ack_extractor(results_root, work_dir):
    script = Path(__file__).with_name("analyze_ack_feedback.py")
    command = [sys.executable, str(script), str(results_root), "--pacing", "enabled", "disabled",
               "--window-start-s", "0", "--window-end-s", "20", "--output-dir", str(work_dir)]
    subprocess.run(command, check=True, stdout=subprocess.PIPE, text=True)
    return command


def mechanism_lookup(rows, results_root):
    lookup = {}
    for row in rows:
        source = Path(row["source_log"])
        run_dir = next(parent for parent in source.parents if (parent / "run_manifest.json").is_file())
        run_id = rel(run_dir, results_root)
        lookup[(run_id, row["flow_id"])] = {
            "connection_id": row["connection_id"],
            "source_log": rel(source, results_root),
        }
    return lookup


def percentile(values, fraction):
    values = sorted(values)
    if not values:
        return float("nan")
    position = (len(values) - 1) * fraction
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return values[lower]
    return values[lower] * (upper - position) + values[upper] * (position - lower)


def mean(values):
    values = [value for value in values if isinstance(value, (int, float)) and math.isfinite(value)]
    return statistics.mean(values) if values else float("nan")


def median(values):
    values = [value for value in values if isinstance(value, (int, float)) and math.isfinite(value)]
    return statistics.median(values) if values else float("nan")


def number(row, key):
    try:
        return float(row[key])
    except (KeyError, TypeError, ValueError):
        return float("nan")


def ack_exports(raw_rows, contexts, results_root):
    grouped = {}
    ack_rows = []
    for raw in raw_rows:
        source = Path(raw["source_log"])
        run_dir = next(parent for parent in source.parents if (parent / "run_manifest.json").is_file())
        run_id = rel(run_dir, results_root)
        context = contexts[run_id]
        start_s, end_s = context["measurement_start_s"], context["measurement_end_s"]
        key = (run_id, raw["connection_id"])
        grouped.setdefault(key, []).append((raw, context))
    for key, samples in grouped.items():
        samples.sort(key=lambda item: number(item[0], "time_since_start_ms"))
        previous_us = None
        for index, (raw, context) in enumerate(samples, 1):
            time_us = int(round(number(raw, "time_since_start_ms") * 1000))
            start_us = int(context["measurement_start_s"] * 1_000_000)
            end_us = int(context["measurement_end_s"] * 1_000_000)
            batch_bytes = number(raw, "newly_acked_bytes")
            if batch_bytes == 0 and number(raw, "newly_acked_packet_count") > 0:
                batch_bytes = float("nan")
            pacing_bytes = number(raw, "pacing_rate_bytes_per_s")
            ack_rows.append(
                {"run_id": key[0], "connection_id": key[1], "flow_label": raw["flow_id"],
                 "receiver_policy": raw["ack_policy"], "sender_implementation": raw["server"],
                 "recorded_network_share": number(raw, "network_share"),
                 "ack_event_index": index, "ack_receive_time_us": raw.get("ack_receive_time_us") or NA,
                 "analysis_time_since_start_us": time_us,
                 "in_measurement_window": start_us <= time_us <= end_us,
                 "ack_frame_largest_acked": raw.get("ack_frame_largest_acked") or NA,
                 "ack_range_count": raw.get("ack_range_count") or NA,
                 "newly_acked_packets": int(number(raw, "newly_acked_packet_count")),
                 "newly_acked_bytes": batch_bytes, "ack_delay_us": number(raw, "ack_delay_us"),
                 "time_since_previous_ack_us": time_us - previous_us if previous_us is not None else NA,
                 "immediate_ack": NA, "immediate_ack_reason": NA,
                 "reordered_or_gap_observed": NA, "ecn_ce_observed": NA,
                 "cwnd_before_bytes": number(raw, "cwnd_before_bytes"),
                 "cwnd_after_bytes": number(raw, "cwnd_after_bytes"),
                 "delta_cwnd_bytes": number(raw, "cwnd_delta_bytes"),
                 "bytes_in_flight_before": number(raw, "inflight_before_bytes"),
                 "bytes_in_flight_after": number(raw, "inflight_after_bytes"),
                 "delta_bytes_in_flight": number(raw, "inflight_delta_bytes"),
                 "srtt_us": number(raw, "srtt_us"), "latest_rtt_us": number(raw, "latest_rtt_us"),
                 "rttvar_us": number(raw, "rttvar_us"),
                 "pacing_rate_bps": pacing_bytes * 8 if math.isfinite(pacing_bytes) else NA,
                 "next_release_delay_us": number(raw, "next_data_send_delay_us"),
                 "packets_declared_lost": number(raw, "packets_declared_lost"),
                 "bytes_declared_lost": number(raw, "bytes_declared_lost"),
                 "application_limited_if_observable": raw.get("application_limited") or NA,
                 "source_qlog_path": rel(Path(raw["source_log"]), results_root),
                 "source_event_ids": raw.get("source_event_ids") or NA}
            )
            previous_us = time_us
    return ack_rows


def bins_and_connections(ack_rows, contexts, results_root):
    grouped = {}
    for row in ack_rows:
        grouped.setdefault((row["run_id"], row["connection_id"]), []).append(row)
    time_rows, connection_rows, validation = [], [], []
    for (run_id, connection_id), episodes in sorted(grouped.items()):
        episodes.sort(key=lambda row: row["analysis_time_since_start_us"])
        first = episodes[0]
        context = contexts[run_id]
        flow_id = first["flow_label"]
        other_flow = "flow_b" if flow_id == "flow_a" else "flow_a"
        flow = context["flows"][flow_id]
        own_metrics = localize(flow.get("client_metrics_path"), results_root)
        other_metrics = localize(context["flows"][other_flow].get("client_metrics_path"), results_root)
        duration = int(context["manifest"].get("duration_s", 20))
        for second in range(duration):
            left_us, right_us = second * 1_000_000, (second + 1) * 1_000_000
            window = [row for row in episodes if left_us <= row["analysis_time_since_start_us"] < right_us]
            own = window_metric(own_metrics, second, second + 1) if own_metrics else None
            competing = window_metric(other_metrics, second, second + 1) if other_metrics else None
            own_bps = own["goodput_bps"] if own else float("nan")
            competing_bps = competing["goodput_bps"] if competing else float("nan")
            total_bps = own_bps + competing_bps
            batches = [row["newly_acked_packets"] for row in window]
            batch_bytes = [row["newly_acked_bytes"] for row in window if isinstance(row["newly_acked_bytes"], (int, float))]
            intervals = [row["time_since_previous_ack_us"] for row in window if isinstance(row["time_since_previous_ack_us"], (int, float))]
            cwnds = [row["cwnd_before_bytes"] for row in window]
            inflights = [row["bytes_in_flight_before"] for row in window]
            time_rows.append(
                {"run_id": run_id, "connection_id": connection_id,
                 "sender_implementation": first["sender_implementation"],
                 "receiver_policy": first["receiver_policy"], "window_start_s": second,
                 "window_end_s": second + 1, "in_measurement_window":
                 context["measurement_start_s"] <= second and second + 1 <= context["measurement_end_s"],
                 "ack_frame_count": len(window), "newly_acked_packets": sum(batches),
                 "newly_acked_bytes": sum(batch_bytes) if batch_bytes else NA,
                 "mean_packets_per_ack": mean(batches), "median_packets_per_ack": median(batches),
                 "p90_packets_per_ack": percentile(batches, .9),
                 "mean_ack_interarrival_us": mean(intervals), "goodput_bps": own_bps,
                 "competing_flow_goodput_bps": competing_bps,
                 "policy_normalized_share": own_bps / total_bps if total_bps else NA,
                 "mean_cwnd_bytes": mean(cwnds), "median_cwnd_bytes": median(cwnds),
                 "mean_bytes_in_flight": mean(inflights), "mean_srtt_us": mean([row["srtt_us"] for row in window]),
                 "loss_events": sum(1 for row in window if isinstance(row["packets_declared_lost"], (int, float)) and row["packets_declared_lost"] > 0),
                 "paced_release_count": NA,
                 "mean_release_delay_us": mean([row["next_release_delay_us"] for row in window]),
                 "active": bool(own and own["bytes"] > 0),
                 "application_limited_if_observable": NA,
                 "cwnd_start_bytes": cwnds[0] if cwnds else NA,
                 "cwnd_end_bytes": cwnds[-1] if cwnds else NA,
                 "delta_cwnd_bytes": cwnds[-1] - cwnds[0] if len(cwnds) > 1 else NA,
                 "mean_newly_acked_bytes_per_ack": mean(batch_bytes)}
            )
        measurement = [row for row in episodes if row["in_measurement_window"]]
        batches = [row["newly_acked_packets"] for row in measurement]
        batch_bytes = [row["newly_acked_bytes"] for row in measurement if isinstance(row["newly_acked_bytes"], (int, float))]
        intervals = [row["time_since_previous_ack_us"] for row in measurement if isinstance(row["time_since_previous_ack_us"], (int, float))]
        cwnds = [row["cwnd_before_bytes"] for row in measurement]
        inflights = [row["bytes_in_flight_before"] for row in measurement]
        metric = window_metric(own_metrics, context["measurement_start_s"], context["measurement_end_s"])
        other_metric = window_metric(other_metrics, context["measurement_start_s"], context["measurement_end_s"])
        total = metric["goodput_bps"] + other_metric["goodput_bps"] if metric and other_metric else 0
        connection_rows.append(
            {"run_id": run_id, "connection_id": connection_id,
             "sender_implementation": first["sender_implementation"], "receiver_policy": first["receiver_policy"],
             "ack_episode_count": len(measurement), "mean_packets_per_ack": mean(batches),
             "median_packets_per_ack": median(batches), "p90_packets_per_ack": percentile(batches, .9),
             "p99_packets_per_ack": percentile(batches, .99), "mean_newly_acked_bytes": mean(batch_bytes),
             "mean_ack_interarrival_us": mean(intervals), "immediate_ack_fraction": NA,
             "reordered_ack_fraction": NA, "mean_cwnd_bytes": mean(cwnds),
             "median_cwnd_bytes": median(cwnds),
             "cwnd_start_bytes": cwnds[0] if cwnds else NA, "cwnd_end_bytes": cwnds[-1] if cwnds else NA,
             "mean_bytes_in_flight": mean(inflights), "goodput_bps": metric["goodput_bps"] if metric else NA,
             "policy_normalized_share": metric["goodput_bps"] / total if metric and total else NA,
             "recorded_network_share": first.get("recorded_network_share", NA),
             "loss_event_count": sum(1 for row in measurement if isinstance(row["packets_declared_lost"], (int, float)) and row["packets_declared_lost"] > 0),
             "observed_duration_s": (episodes[-1]["analysis_time_since_start_us"] - episodes[0]["analysis_time_since_start_us"]) / 1_000_000,
             "qlog_complete": episodes[-1]["analysis_time_since_start_us"] >= (duration - 1) * 1_000_000,
             "selection_reason": "P2F fixed2/fixed10 role reversal; repetition 1; first-only retained qlog"}
        )
        policy = first["receiver_policy"]
        nominal = 2 if policy == "fixed2" else 10 if policy == "fixed10" else None
        validation.append(
            {"run_id": run_id, "connection_id": connection_id, "configured_policy": policy,
             "expected_threshold_or_state_machine": "threshold={}".format(nominal) if nominal else TODO,
             "observed_mean_packets_per_ack": mean(batches), "observed_median_packets_per_ack": median(batches),
             "observed_p90_packets_per_ack": percentile(batches, .9),
             "max_ack_delay_observed_us": max([row["ack_delay_us"] for row in measurement] or [float("nan")]),
             "fraction_matching_nominal_threshold": mean([1 if value == nominal else 0 for value in batches]) if nominal else NA,
             "fraction_early_due_to_timer": NA, "fraction_early_due_to_reordering": NA,
             "fraction_early_due_to_handshake": NA, "validation_passed": TODO,
             "validation_notes": "Formal single-flow ACK-process validation is not present in this result tree; sender-side episodes are descriptive."}
        )
    return time_rows, connection_rows, validation


def ranks(values):
    indexed = sorted(enumerate(values), key=lambda item: item[1])
    output = [0.0] * len(values)
    cursor = 0
    while cursor < len(indexed):
        end = cursor + 1
        while end < len(indexed) and indexed[end][1] == indexed[cursor][1]:
            end += 1
        rank = ((cursor + 1) + end) / 2
        for index, _ in indexed[cursor:end]:
            output[index] = rank
        cursor = end
    return output


def correlation(left, right, method):
    pairs = [(float(x), float(y)) for x, y in zip(left, right)
             if isinstance(x, (int, float)) and isinstance(y, (int, float)) and math.isfinite(x) and math.isfinite(y)]
    if len(pairs) < 3:
        return float("nan"), len(pairs)
    x, y = list(zip(*pairs))
    if method == "spearman":
        x, y = ranks(x), ranks(y)
    mx, my = statistics.mean(x), statistics.mean(y)
    numerator = sum((a - mx) * (b - my) for a, b in zip(x, y))
    denominator = math.sqrt(sum((a - mx) ** 2 for a in x) * sum((b - my) ** 2 for b in y))
    return numerator / denominator if denominator else float("nan"), len(pairs)


def mechanism_exports(time_rows, connection_rows):
    inputs = []
    for row in time_rows:
        inputs.append(
            {"run_id": row["run_id"], "connection_id": row["connection_id"],
             "sender_implementation": row["sender_implementation"],
             "time_window": "{}-{}s".format(row["window_start_s"], row["window_end_s"]),
             "mean_packets_per_ack": row["mean_packets_per_ack"],
             "mean_newly_acked_bytes_per_ack": row["mean_newly_acked_bytes_per_ack"],
             "mean_cwnd_bytes": row["mean_cwnd_bytes"], "delta_cwnd_bytes": row["delta_cwnd_bytes"],
             "goodput_bps": row["goodput_bps"], "policy_normalized_share": row["policy_normalized_share"],
             "in_measurement_window": row["in_measurement_window"]}
        )
    by_connection = []
    for key in sorted({(row["run_id"], row["connection_id"]) for row in inputs}):
        samples = [row for row in inputs if (row["run_id"], row["connection_id"]) == key and row["in_measurement_window"]]
        for method in ("pearson", "spearman"):
            for outcome in ("mean_cwnd_bytes", "policy_normalized_share"):
                value, count = correlation([row["mean_packets_per_ack"] for row in samples], [row[outcome] for row in samples], method)
                by_connection.append(
                    {"run_id": key[0], "connection_id": key[1],
                     "sender_implementation": samples[0]["sender_implementation"] if samples else NA,
                     "x_variable": "mean_packets_per_ack", "y_variable": outcome,
                     "correlation_method": method, "correlation": value,
                     "number_of_windows_or_episodes": count, "time_bin_width": "1s", "lag": 0,
                     "detrended": False, "measurement_window": "5-15s"}
                )
    by_implementation = []
    for sender in sorted({row["sender_implementation"] for row in connection_rows}):
        samples = [row for row in connection_rows if row["sender_implementation"] == sender]
        for method in ("pearson", "spearman"):
            for outcome in ("median_cwnd_bytes", "recorded_network_share"):
                value, count = correlation([row["mean_packets_per_ack"] for row in samples], [row[outcome] for row in samples], method)
                by_implementation.append(
                    {"sender_implementation": sender, "x_variable": "mean_packets_per_ack",
                     "y_variable": outcome, "aggregation_method": "connection_level_pooled_across_pacing",
                     "correlation_method": method, "correlation": value,
                     "number_of_connections": len(samples), "number_of_rows": count,
                     "time_bin_width": "connection_summary", "lag": 0, "detrended": False,
                     "measurement_window": "5-15s"}
                )
    return inputs, by_connection, by_implementation


def raw_index(results_root, hash_raw):
    patterns = ("run_manifest.json", "summary.csv", "metrics.csv", "*.sqlog", "*.slog", "*.pcap", "*.log", "*.tp-trace")
    paths = set()
    for pattern in patterns:
        paths.update(path for path in results_root.glob("P*-server/**/{}".format(pattern)) if path.is_file())
    rows, checksum_lines = [], []
    for path in sorted(paths):
        raw_type = "qlog" if path.suffix in {".sqlog", ".slog"} else "pcap" if path.suffix == ".pcap" else "derived_or_application_log"
        should_hash = hash_raw or path.name in {"run_manifest.json", "summary.csv", "metrics.csv"}
        digest = sha256(path) if should_hash else TODO
        relative = rel(path, results_root)
        rows.append({"raw_type": raw_type, "results_relative_path": relative,
                     "sha256": digest, "size_bytes": path.stat().st_size,
                     "hash_status": "computed" if should_hash else TODO,
                     "storage": "external_RESULTS_ROOT_not_copied"})
        if should_hash:
            checksum_lines.append("{}  RESULTS_ROOT/{}".format(digest, relative))
    return rows, checksum_lines


def git_value(args, cwd):
    try:
        return subprocess.check_output(["git"] + args, cwd=cwd, text=True).strip()
    except subprocess.CalledProcessError:
        return NA


def create_readme(output, counts, hash_raw):
    text = """# QUICbench HotNets reproducibility export

This bundle addresses implementation-dependent ACK-feedback dynamics without
claiming that ACK aggregation causes a sender outcome. `NA` means a field is
unknown or unobservable in an experiment that ran. `-todo-` means the requested
experiment, validation, artifact, or calculation has not been completed.

## Regeneration

```bash
python3 scripts/export_hotnets_reproducibility.py /path/to/results --output-dir quicbench-export{hash_flag}
```

The exporter never overwrites qlog, pcap, manifest, metrics, or application
logs. Raw artifacts are not copied into the archive; `raw/files.csv` addresses
them relative to `RESULTS_ROOT`. {hash_note}

## Inventory

- run directories: {runs}
- eligible runs: {eligible}
- excluded runs: {excluded}
- ACK episodes exported: {episodes}
- mechanism connections: {connections} (8 per implementation; 16 total)
- one-second connection windows: {windows}

Excluded directories are retained rather than silently dropped. They have a
summary or partial artifacts but no manifest, so they cannot establish the
required topology/provenance invariants. This includes one early P0 run and
earlier failed/retry P2 directories; see `fairness/exclusions.csv`.

## Units and sampling

ACK and sender-state time fields are microseconds. Time-series bin boundaries
remain seconds because the requested schema names them `_s`. Throughput and
goodput are bit/s. Raw byte counts and the actual metric sample boundary times
are retained in `fairness/run_fairness.csv`. A run, not a time bin, is an
independent experiment. Correlations over bins are descriptive only and have no
p-values.

`ack_episodes.csv` contains application packet-number-space wire ACKs. Newly
acked packets exclude packets already covered by a previous ACK. quiche qlog
does not provide a trustworthy absolute wall-clock ACK time, so that field is
`NA`; relative microseconds are retained. Immediate-ACK reasons, reorder causes,
ECN evidence, and effective pacer rate are `NA` where not observable.

## Mechanism selection and earlier coefficients

The mechanism set is not cherry-picked: it contains every connection with a
retained server qlog in repetition 1 of P2F CUBIC fixed2/fixed10 and its role
reversal, for quiche and xquic with pacing on/off. This is 8 connections per
implementation. Later repetitions used `qlog-policy first-only`, so they do not
have server qlog.

The previously reported coefficients used connection-level rows pooled across
pacing, measurement seconds 5-15, no lag, no detrending:

- quiche: mean newly acked packets/ACK vs ACK-event-sampled median cwnd,
  Pearson; and the same ACK variable vs the recorded network share, Pearson.
- xquic: the same two Pearson associations.

Exact regenerated values, Spearman counterparts, row counts, and connection
counts are in `mechanism/correlations_by_implementation.csv`. Episode/time-bin
rows were not treated as independent trials for those coefficients.

## Missing work

-todo- formal single-flow ACK-process validation is not present in this copied result tree.

-todo- ACK_FREQUENCY mitigation experiments have not been exported because no matching runs exist here.

-todo- final diagnostic PDFs were not generated; the CSVs retain every run/connection needed to make them.

-todo- sender full commits, source dirty state, effective pacing telemetry,
numeric initial cwnd, and sendmmsg state were not recorded by these manifests.

-todo- a self-contained copy of the multi-GiB raw artifact tree is not embedded;
the bundle provides a relative-path index{raw_hash_suffix}.

## Interpretation boundary

The observations support implementation-dependent closed-loop ACK-feedback
dynamics. They do not establish that two implementations respond differently
to an identical timestamp-for-timestamp ACK trace; no ACK replay experiment was
performed.

The fixed2/fixed10 mechanism data are retained as a stress test rather than a
deployment claim. A transition-matched `steady2` versus `late10` control with
identical ACK-2 startup is `-todo-`; the current client binary does not implement
those two policy names.
""".format(
        hash_flag=" --hash-raw" if hash_raw else "",
        hash_note="All indexed raw files are SHA-256 hashed." if hash_raw else "Large raw files are marked `-todo-` in the hash column; rerun with `--hash-raw`.",
        raw_hash_suffix=" with SHA-256" if hash_raw else "; large-file SHA-256 remains `-todo-`",
        **counts
    )
    (output / "README.md").write_text(text)


def main():
    args = args_parse()
    output = args.output_dir.resolve()
    if output.exists():
        if not args.force:
            raise SystemExit("output exists; pass --force to replace {}".format(output))
        shutil.rmtree(output)
    for name in ("provenance", "manifests", "fairness", "ack", "sender_state", "mechanism", "scripts", "raw"):
        (output / name).mkdir(parents=True, exist_ok=True)
    work = output / ".work-ack"
    ack_command = run_ack_extractor(args.results_root, work)
    raw_ack = read_csv(work / "ack_episodes.csv")
    initial_lookup = mechanism_lookup(raw_ack, args.results_root)
    runs, fairness, homogeneous, exclusions, contexts = build_runs_and_fairness(args.results_root, initial_lookup)
    ack_rows = ack_exports(raw_ack, contexts, args.results_root)
    time_rows, connection_rows, validation = bins_and_connections(ack_rows, contexts, args.results_root)
    correlation_inputs, by_connection, by_implementation = mechanism_exports(time_rows, connection_rows)

    schemas = {
        output / "manifests/runs.csv": ["run_id","experiment_family","sender_implementation","sender_full_commit","sender_binary_sha256","source_dirty","workload","congestion_control","initial_cwnd_packets","configured_pacing","effective_pacing","gso_enabled","sendmmsg_enabled","receiver_policy_flow_a","receiver_policy_flow_b","flow_a_connection_id","flow_b_connection_id","flow_a_port","flow_b_port","launch_order","duration_s","measurement_start_s","measurement_end_s","bottleneck_mbps","base_rtt_ms","queue_definition","configured_loss","eligible","exclusion_reason","qlog_path_a","qlog_path_b","pcap_path","application_log_paths"],
        output / "fairness/run_fairness.csv": ["run_id","sender_implementation","policy_p","policy_q","policy_p_flow_label","policy_q_flow_label","policy_p_bytes","policy_q_bytes","policy_p_active_time_s","policy_q_active_time_s","policy_p_goodput_bps","policy_q_goodput_bps","policy_p_share","policy_q_share","share_gap_p_minus_q","jain_index","winner_policy","both_flows_active","bottleneck_saturated","eligible","exclusion_reason","measurement_start_s","measurement_end_s","policy_p_sample_start_us","policy_p_sample_end_us","policy_q_sample_start_us","policy_q_sample_end_us"],
        output / "fairness/homogeneous_baselines.csv": ["run_id","sender_implementation","policy_pair","flow_a_share","flow_b_share","absolute_share_gap","jain_index","launch_order","eligible"],
        output / "fairness/exclusions.csv": ["run_id","experiment_family","stage","reason","available_artifacts"],
        output / "ack/ack_episodes.csv": ["run_id","connection_id","flow_label","receiver_policy","sender_implementation","ack_event_index","ack_receive_time_us","analysis_time_since_start_us","in_measurement_window","ack_frame_largest_acked","ack_range_count","newly_acked_packets","newly_acked_bytes","ack_delay_us","time_since_previous_ack_us","immediate_ack","immediate_ack_reason","reordered_or_gap_observed","ecn_ce_observed","cwnd_before_bytes","cwnd_after_bytes","delta_cwnd_bytes","bytes_in_flight_before","bytes_in_flight_after","delta_bytes_in_flight","srtt_us","latest_rtt_us","rttvar_us","pacing_rate_bps","next_release_delay_us","packets_declared_lost","bytes_declared_lost","source_qlog_path","source_event_ids"],
        output / "ack/connection_ack_summary.csv": ["run_id","connection_id","sender_implementation","receiver_policy","ack_episode_count","mean_packets_per_ack","median_packets_per_ack","p90_packets_per_ack","p99_packets_per_ack","mean_newly_acked_bytes","mean_ack_interarrival_us","immediate_ack_fraction","reordered_ack_fraction","mean_cwnd_bytes","median_cwnd_bytes","cwnd_start_bytes","cwnd_end_bytes","mean_bytes_in_flight","goodput_bps","policy_normalized_share","recorded_network_share","loss_event_count","observed_duration_s","qlog_complete","selection_reason"],
        output / "ack/ack_validation.csv": ["run_id","connection_id","configured_policy","expected_threshold_or_state_machine","observed_mean_packets_per_ack","observed_median_packets_per_ack","observed_p90_packets_per_ack","max_ack_delay_observed_us","fraction_matching_nominal_threshold","fraction_early_due_to_timer","fraction_early_due_to_reordering","fraction_early_due_to_handshake","validation_passed","validation_notes"],
        output / "sender_state/connection_timeseries.csv": ["run_id","connection_id","sender_implementation","receiver_policy","window_start_s","window_end_s","in_measurement_window","ack_frame_count","newly_acked_packets","newly_acked_bytes","mean_packets_per_ack","median_packets_per_ack","p90_packets_per_ack","mean_ack_interarrival_us","goodput_bps","competing_flow_goodput_bps","policy_normalized_share","mean_cwnd_bytes","median_cwnd_bytes","mean_bytes_in_flight","mean_srtt_us","loss_events","paced_release_count","mean_release_delay_us","active","application_limited_if_observable"],
        output / "sender_state/connection_summary.csv": ["run_id","connection_id","sender_implementation","receiver_policy","ack_episode_count","mean_packets_per_ack","mean_cwnd_bytes","median_cwnd_bytes","mean_bytes_in_flight","goodput_bps","policy_normalized_share","recorded_network_share","cwnd_start_bytes","cwnd_end_bytes","selection_reason"],
        output / "mechanism/correlation_inputs.csv": ["run_id","connection_id","sender_implementation","time_window","mean_packets_per_ack","mean_newly_acked_bytes_per_ack","mean_cwnd_bytes","delta_cwnd_bytes","goodput_bps","policy_normalized_share","in_measurement_window"],
        output / "mechanism/correlations_by_connection.csv": ["run_id","connection_id","sender_implementation","x_variable","y_variable","correlation_method","correlation","number_of_windows_or_episodes","time_bin_width","lag","detrended","measurement_window"],
        output / "mechanism/correlations_by_implementation.csv": ["sender_implementation","x_variable","y_variable","aggregation_method","correlation_method","correlation","number_of_connections","number_of_rows","time_bin_width","lag","detrended","measurement_window"],
    }
    data = [runs, fairness, homogeneous, exclusions, ack_rows, connection_rows, validation,
            time_rows, connection_rows, correlation_inputs, by_connection, by_implementation]
    for (path, fields), rows in zip(schemas.items(), data):
        write_csv(path, fields, rows)

    raw_rows, checksums = raw_index(args.results_root, args.hash_raw)
    write_csv(output / "raw/files.csv", ["raw_type","results_relative_path","sha256","size_bytes","hash_status","storage"], raw_rows)
    (output / "provenance/inputs.sha256").write_text("\n".join(checksums) + "\n")
    repo = Path(__file__).resolve().parents[1]
    revisions = [
        {"component": "QUICbench-analysis", "revision": git_value(["rev-parse", "HEAD"], repo),
         "dirty": bool(git_value(["status", "--porcelain"], repo)), "source": str(repo)},
    ]
    for sender in sorted({row["sender_implementation"] for row in runs}):
        hashes = sorted({row["sender_binary_sha256"] for row in runs if row["sender_implementation"] == sender and row["sender_binary_sha256"] != NA})
        revisions.append({"component": sender, "revision": NA, "dirty": NA,
                          "source": "binary_sha256=" + ";".join(hashes) if hashes else NA})
    write_csv(output / "provenance/revisions.csv", ["component","revision","dirty","source"], revisions)
    command = "python3 scripts/export_hotnets_reproducibility.py RESULTS_ROOT --output-dir quicbench-export{}\n".format(" --hash-raw" if args.hash_raw else "")
    (output / "provenance/analysis-command.txt").write_text(command + "ACK extractor: " + " ".join(map(str, ack_command)) + "\n")
    (output / "provenance/environment.txt").write_text(
        "python={}\nplatform={}\nmachine={}\nresults_root={}\n".format(sys.version.replace("\n", " "), platform.platform(), platform.machine(), args.results_root.resolve())
    )
    shutil.copy2(Path(__file__), output / "scripts" / Path(__file__).name)
    shutil.copy2(Path(__file__).with_name("analyze_ack_feedback.py"), output / "scripts/analyze_ack_feedback.py")
    counts = {"runs": len(runs), "eligible": sum(str(row["eligible"]).lower() == "true" for row in runs),
              "excluded": len(exclusions), "episodes": len(ack_rows),
              "connections": len(connection_rows), "windows": len(time_rows)}
    create_readme(output, counts, args.hash_raw)
    shutil.rmtree(work)
    archive = output.with_suffix(".tar.gz")
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(output, arcname=output.name)
    archive_hash = sha256(archive)
    archive.with_suffix(archive.suffix + ".sha256").write_text("{}  {}\n".format(archive_hash, archive.name))
    print(json.dumps({"output": str(output), "archive": str(archive), "archive_sha256": archive_hash, **counts}, indent=2))


if __name__ == "__main__":
    main()
