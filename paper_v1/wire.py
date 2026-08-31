"""Independent qlog/pcap validation of receiver-generated ACK episodes."""

import json
import os
import subprocess

from paper_v1.io import atomic_write_json, sha256_file


def _jsonl(path):
    events = []
    with open(path, encoding="utf-8") as source:
        for line in source:
            line = line.strip().lstrip("\x1e")
            if line:
                events.append(json.loads(line))
    return events


def _first_file(directory):
    return next(os.path.join(directory, name) for name in sorted(os.listdir(directory))
                if os.path.isfile(os.path.join(directory, name)))


def _qlog_acks(path):
    result = []
    for event in _jsonl(path):
        if event.get("name") != "transport:packet_sent":
            continue
        data = event.get("data", {})
        if data.get("header", {}).get("packet_type") != "1RTT":
            continue
        for frame in data.get("frames", []):
            if frame.get("frame_type") != "ack":
                continue
            ranges = frame.get("acked_ranges", [])
            acknowledged = set()
            for smallest, largest in ranges:
                acknowledged.update(range(int(smallest), int(largest) + 1))
            result.append({"time_ns": round(float(event["time"]) * 1_000_000),
                           "largest": max(acknowledged), "ack_delay_ns": round(float(frame.get("ack_delay", 0)) * 1_000_000),
                           "acknowledged": acknowledged})
    previous = set()
    for index, item in enumerate(result):
        item["batch"] = len(item["acknowledged"] - previous)
        item["spacing_ns"] = 0 if index == 0 else item["time_ns"] - result[index - 1]["time_ns"]
        previous |= item["acknowledged"]
    return result


def _pcap_acks(tshark, pcap, keylog, local_port):
    command = [tshark, "-r", pcap, "-o", "tls.keylog_file:{}".format(keylog),
               "-Y", "udp.srcport=={} && quic.short && quic.ack.largest_acknowledged".format(local_port),
               "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a",
               "-e", "frame.time_epoch", "-e", "quic.ack.largest_acknowledged", "-e", "quic.ack.ack_delay"]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    result = []
    for line in completed.stdout.splitlines():
        columns = line.split("\t")
        if len(columns) != 3:
            continue
        times = [columns[0]]
        largest = columns[1].split(",")
        delays = columns[2].split(",")
        for index, value in enumerate(largest):
            result.append({"time_ns": round(float(times[0]) * 1_000_000_000), "largest": int(value),
                           "ack_delay_ns": int(delays[index]) * 8_000})
    return result, command


def _align_pcap(qlog, pcap):
    aligned = []
    cursor = 0
    for expected in qlog:
        candidates = [(index, item) for index, item in enumerate(pcap[cursor:], cursor)
                      if item["largest"] == expected["largest"]]
        if not candidates:
            return []
        index, selected = min(candidates, key=lambda pair: abs(pair[1]["ack_delay_ns"] - expected["ack_delay_ns"]))
        aligned.append(selected)
        cursor = index + 1
    for index, item in enumerate(aligned):
        item["spacing_ns"] = 0 if index == 0 else item["time_ns"] - aligned[index - 1]["time_ns"]
    return aligned


def derive_wire(run_dir, manifest, tshark="/usr/bin/tshark"):
    pcap = os.path.join(run_dir, "trace.pcap")
    flows = []
    commands = []
    source_hashes = {"pcap": sha256_file(pcap)}
    all_consistent = True
    for flow_id in ("flow_a", "flow_b"):
        flow_dir = os.path.join(run_dir, flow_id)
        policy_path = os.path.join(flow_dir, "receiver-policy.jsonl")
        qlog_path = _first_file(os.path.join(flow_dir, "qlog"))
        keylog_path = os.path.join(flow_dir, "tls.keys")
        policy_events = _jsonl(policy_path)
        initialized = next(event for event in policy_events if event.get("event") == "policy_initialized")
        episodes = [event for event in policy_events if event.get("event") == "ack_episode"]
        qlog = _qlog_acks(qlog_path)
        pcap_rows, command = _pcap_acks(tshark, pcap, keylog_path, int(next(
            flow["client_local_port"] for flow in manifest["runtime_reported"]["flows"] if flow["flow_id"] == flow_id)))
        commands.append(command)
        aligned = _align_pcap(qlog, pcap_rows)
        policy_batches = [int(event["ack_batch_size"]) for event in episodes]
        policy_spacing = [int(event.get("ack_spacing_ns", 0)) for event in episodes]
        policy_delays = [int(event["ack_delay_ns"]) for event in episodes]
        qlog_batches = [item["batch"] for item in qlog]
        qlog_spacing = [item["spacing_ns"] for item in qlog]
        qlog_delays = [item["ack_delay_ns"] for item in qlog]
        largest_match = [event["largest_acknowledged"] for event in episodes] == [item["largest"] for item in qlog]
        batch_match = policy_batches == qlog_batches
        spacing_match = len(qlog_spacing) == len(policy_spacing) and all(
            abs(a - b) <= 2_000_000 for a, b in zip(policy_spacing[1:], qlog_spacing[1:]))
        delay_match = len(qlog_delays) == len(policy_delays) and all(
            abs(a - b) <= 20_000 for a, b in zip(policy_delays, qlog_delays))
        pcap_match = len(aligned) == len(qlog) and all(
            abs(a["ack_delay_ns"] - b["ack_delay_ns"]) <= 20_000 for a, b in zip(aligned, qlog))
        transition = [event for event in policy_events if event.get("event") == "policy_transition"
                      and event.get("old_state") != "uninitialized"]
        transition_match = initialized["policy_name"] != "chrome-like-ack" or (
            len(transition) == 1 and transition[0]["observed_packet_number"] == transition[0]["reference_packet_number"] + 100)
        consistent = largest_match and batch_match and spacing_match and delay_match and pcap_match
        all_consistent = all_consistent and consistent and transition_match
        source_hashes.update({"receiver_qlog_{}".format(flow_id): sha256_file(qlog_path),
                              "receiver_policy_{}".format(flow_id): sha256_file(policy_path),
                              "keylog_{}".format(flow_id): sha256_file(keylog_path)})
        flows.append({
            "flow_id": flow_id, "policy_name": initialized["policy_name"], "ack_episode_count": len(episodes),
            "ack_batches": policy_batches, "ack_spacing_ns": policy_spacing, "ack_delay_ns": policy_delays,
            "pcap_ack_frame_count": len(aligned), "qlog_ack_frame_count": len(qlog),
            "ack_batch_observed": batch_match, "ack_spacing_observed": spacing_match,
            "ack_delay_observed": delay_match, "policy_log_matches_wire": consistent,
            "qlog_matches_pcap": pcap_match, "ack_delay_units_valid": delay_match and pcap_match,
            "transition_matches_wire": transition_match,
        })
    version = subprocess.run([tshark, "--version"], check=True, capture_output=True, text=True).stdout.splitlines()[0]
    evidence = {
        "schema_version": "wire-ack-evidence-v1.0.0",
        "extractor": {"name": "quicbench-wire-validator", "version": "1.0.0", "command": commands,
                      "tool_versions": {"tshark": version, "qlog_parser": "quicbench-1.0.0"}},
        "source_artifact_sha256": source_hashes, "flows": flows,
        "conclusion": {"qlog_policy_consistent": all_consistent, "pcap_policy_consistent": all_consistent,
                       "ack_delay_units_valid": all(flow["ack_delay_units_valid"] for flow in flows)},
    }
    atomic_write_json(os.path.join(run_dir, "wire-evidence.json"), evidence)
    return evidence
