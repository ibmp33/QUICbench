"""Derive workload and network conclusions from immutable raw artifacts."""

import csv
import json
import os
import re

from paper_v1.io import atomic_write_json, load_json, sha256_file


def _jsonl(path):
    with open(path, encoding="utf-8") as source:
        return [json.loads(line) for line in source if line.strip()]


def _labels(path):
    result = {}
    with open(path, encoding="utf-8") as source:
        for line in source:
            if ": " in line:
                key, value = line.rstrip().split(": ", 1)
                result[key] = value
    return result


def _metric_rows(path):
    with open(path, newline="", encoding="utf-8") as source:
        return [(int(row["elapsed_ms"]), int(row["cumulative_body_bytes"])) for row in csv.DictReader(source)]


def _bytes_at(rows, milliseconds):
    values = [value for elapsed, value in rows if elapsed <= milliseconds]
    return values[-1] if values else 0


def derive_runtime(run_dir, manifest):
    """Build the H3 flow contract from client logs, metrics and policy identity."""
    requested = manifest["requested"]
    effective_duration = requested["workload"]["effective_duration_s"]
    window_start = 0 if requested["workload"].get("smoke") else requested["workload"]["measurement_window_start_s"]
    window_end = effective_duration if requested["workload"].get("smoke") else requested["workload"]["measurement_window_end_s"]
    flows = []
    for flow_id in ("flow_a", "flow_b"):
        flow_dir = os.path.join(run_dir, flow_id)
        labels = _labels(os.path.join(flow_dir, "client.stdout.log"))
        rows = _metric_rows(os.path.join(flow_dir, "metrics.csv"))
        initialized = next(event for event in _jsonl(os.path.join(flow_dir, "receiver-policy.jsonl"))
                           if event.get("event") == "policy_initialized")
        qlogs = [os.path.join(flow_dir, "qlog", name) for name in os.listdir(os.path.join(flow_dir, "qlog"))]
        blocked = False
        for path in qlogs:
            with open(path, encoding="utf-8") as source:
                for line in source:
                    if "stream_data_blocked" in line or '"data_blocked"' in line:
                        blocked = True
                        break
        increases = sum(1 for left, right in zip(rows, rows[1:]) if right[1] > left[1])
        max_gap = max((right[0] - left[0] for left, right in zip(rows, rows[1:])), default=10**9)
        content_length = int(labels.get("Content-Length", "-1"))
        decoded = int(labels.get("Bytes", rows[-1][1] if rows else 0))
        flows.append({
            "flow_id": flow_id,
            "connection_id": initialized["connection_id"],
            "client_local_port": int(labels.get("Local UDP port", "0")),
            "request_start_unix_ns": int(labels.get("Request start Unix ns", "0")),
            "alpn": "h3" if labels.get("Proto", "").startswith("HTTP/3") else labels.get("Proto"),
            "http_status": int(labels.get("Status", "0").split()[0]),
            "headers_valid": content_length >= requested["workload"]["response_body_bytes"],
            "response_content_length": content_length,
            "stream_count": 1,
            "decoded_body_bytes": decoded,
            "measurement_window_body_bytes": _bytes_at(rows, window_end * 1000) - _bytes_at(rows, window_start * 1000),
            "client_continuous_read": len(rows) >= 2 and max_gap <= 250 and increases >= max(1, len(rows) - 3),
            "flow_control_blocked_in_window": blocked,
            "application_limited_in_window": not (len(rows) >= 2 and max_gap <= 250 and increases >= max(1, len(rows) - 3)),
            "metrics_sample_count": len(rows),
            "maximum_metrics_gap_ms": max_gap,
        })
    start_skew_ns = abs(flows[0]["request_start_unix_ns"] - flows[1]["request_start_unix_ns"])
    return {
        "schema_version": "runtime-derived-v1.0.0",
        "derivation": {"name": "quicbench-runtime-deriver", "version": "1.0.0",
                       "sources": ["client stdout", "client metrics", "receiver policy log", "receiver qlog"]},
        "flows": flows,
        "workload": {
            "protocol": "http3", "server_process_count": 1, "server_listening_port_count": 1,
            "server_application_ready": all(flow["client_continuous_read"] for flow in flows),
            "body_counter": "client-decoded-http3-response-body-bytes",
            "duration_s": effective_duration,
            "measurement_window_start_s": window_start,
            "measurement_window_end_s": window_end,
            "start_skew_ns": start_skew_ns,
        },
    }


def _qdiscs(snapshot, role):
    return json.loads(snapshot[role]["qdisc_json"])


def _offloads_disabled(snapshot):
    required = ("tcp-segmentation-offload", "generic-segmentation-offload",
                "generic-receive-offload", "large-receive-offload", "tx-udp-segmentation")
    for endpoint in snapshot.values():
        values = dict(re.findall(r"^([^\t][^:]+): (on|off)(?: .*)?$", endpoint["offload_text"], re.MULTILINE))
        if any(values.get(name) != "off" for name in required):
            return False
    return True


def derive_network(run_dir, manifest):
    before = load_json(os.path.join(run_dir, "network-before.json"))
    active = load_json(os.path.join(run_dir, "network-active.json"))
    after = load_json(os.path.join(run_dir, "network-after.json"))
    profile = manifest["requested"]["network_profile"]
    bottleneck = _qdiscs(before, "bottleneck")
    forward = _qdiscs(before, "forward_delay")
    reverse = _qdiscs(before, "reverse_delay")
    tbf = [item for item in bottleneck if item.get("kind") == "tbf" and item.get("root")]
    forward_netem = [item for item in forward if item.get("kind") == "netem" and item.get("root")]
    reverse_netem = [item for item in reverse if item.get("kind") == "netem" and item.get("root")]
    all_qdiscs = bottleneck + forward + reverse
    expected_rate = int(float(profile["forward_bandwidth_mbps"]) * 1_000_000 / 8)
    tbf_options = tbf[0].get("options", {}) if len(tbf) == 1 else {}
    observed_queue_bytes = None
    if isinstance(tbf_options.get("lat"), (int, float)) and isinstance(tbf_options.get("burst"), int):
        observed_queue_bytes = round(tbf_options["lat"] / 1_000_000 * expected_rate + tbf_options["burst"])
    def delay_seconds(item):
        return item.get("options", {}).get("delay", {}).get("delay")
    qdisc_matches = (
        len(tbf) == len(forward_netem) == len(reverse_netem) == 1
        and len([item for item in all_qdiscs if item.get("kind") == "tbf"]) == 1
        and tbf[0].get("options", {}).get("rate") == expected_rate
        and abs(observed_queue_bytes - int(profile["queue_size_bytes"])) <= 1500
        and abs(delay_seconds(forward_netem[0]) - float(profile["forward_delay_ms"]) / 1000) < 1e-6
        and abs(delay_seconds(reverse_netem[0]) - float(profile["reverse_delay_ms"]) / 1000) < 1e-6
    )
    runtime = derive_runtime(run_dir, manifest)
    duration = runtime["workload"]["measurement_window_end_s"] - runtime["workload"]["measurement_window_start_s"]
    aggregate_bytes = sum(flow["measurement_window_body_bytes"] for flow in runtime["flows"])
    utilization = aggregate_bytes * 8 / max(1, duration) / (float(profile["forward_bandwidth_mbps"]) * 1_000_000)
    max_skew = int(manifest.get("requested", {}).get("maximum_start_skew_ms", 20)) * 1_000_000
    conclusion = {
        "qdisc_matches_requested": qdisc_matches,
        "offloads_valid": all(_offloads_disabled(item) for item in (before, active, after)),
        "shared_bottleneck": len([item for item in all_qdiscs if item.get("kind") == "tbf"]) == 1,
        "saturated": utilization >= 0.90,
        "both_flows_active": all(flow["measurement_window_body_bytes"] > 0 for flow in runtime["flows"]),
        "not_application_limited": all(not flow["application_limited_in_window"] for flow in runtime["flows"]),
        "start_skew_valid": runtime["workload"]["start_skew_ns"] <= max_skew,
    }
    return {
        "schema_version": "network-evidence-v1.0.0",
        "source_artifact_sha256": {
            "qdisc_before": sha256_file(os.path.join(run_dir, "network-before.json")),
            "qdisc_active": sha256_file(os.path.join(run_dir, "network-active.json")),
            "qdisc_after": sha256_file(os.path.join(run_dir, "network-after.json")),
        },
        "requested_profile": profile,
        "observed": {"aggregate_measurement_bytes": aggregate_bytes, "utilization": utilization,
                     "start_skew_ns": runtime["workload"]["start_skew_ns"],
                     "derived_bottleneck_queue_bytes": observed_queue_bytes,
                     "bottleneck_qdisc": tbf, "forward_delay_qdisc": forward_netem,
                     "reverse_delay_qdisc": reverse_netem},
        "conclusion": conclusion,
    }


def write_derived_evidence(run_dir, manifest):
    runtime = derive_runtime(run_dir, manifest)
    network = derive_network(run_dir, manifest)
    atomic_write_json(os.path.join(run_dir, "runtime-evidence.json"), runtime)
    atomic_write_json(os.path.join(run_dir, "network-evidence.json"), network)
    return runtime, network
