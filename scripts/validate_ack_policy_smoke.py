#!/usr/bin/env python3
"""Cross-check receiver policy JSONL against client qlog ACK frames."""

import argparse
import csv
import json
from pathlib import Path
import statistics
import sys


def jsonl(path):
    with path.open() as source:
        for line in source:
            line = line.lstrip("\x1e").strip()
            if line:
                yield json.loads(line)


def qlog_ack_frames(path):
    frames = []
    for event in jsonl(path):
        if event.get("name") != "transport:packet_sent":
            continue
        data = event.get("data", {})
        header = data.get("header", {})
        if header.get("packet_type") != "1RTT":
            continue
        for frame in data.get("frames", []):
            if frame.get("frame_type") != "ack":
                continue
            ranges = frame.get("acked_ranges") or []
            frames.append(
                {
                    "largest": max((int(r[-1]) for r in ranges if r), default=-1),
                    "ack_delay_ms": float(frame.get("ack_delay", 0.0)),
                    "qlog_time_ms": float(event.get("time", 0.0)),
                }
            )
    return frames


def percentile(values, fraction):
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))]


def validate_flow(flow_dir):
    events_path = flow_dir / "events.jsonl"
    qlogs = list((flow_dir / "qlog").glob("*.sqlog"))
    if not events_path.exists() or len(qlogs) != 1:
        raise ValueError(f"{flow_dir}: expected events.jsonl and exactly one .sqlog")
    events = list(jsonl(events_path))
    transitions = [e for e in events if e.get("event") == "policy_transition"]
    episodes = [e for e in events if e.get("event") == "ack_episode"]
    wire = qlog_ack_frames(qlogs[0])
    policy = transitions[0]["policy_name"] if transitions else "missing"
    version = transitions[0].get("policy_version", "missing") if transitions else "missing"

    compared = min(len(episodes), len(wire))
    largest_matches = sum(
        int(episodes[i]["packet_number"]) == wire[i]["largest"]
        for i in range(compared)
    )
    delay_errors_us = [
        abs(float(episodes[i].get("ack_delay_ns", 0)) / 1000.0 - wire[i]["ack_delay_ms"] * 1000.0)
        for i in range(compared)
    ]
    transition_ok = len(transitions) == (2 if policy == "chrome-like-ack" else 1)
    boundary_ok = True
    if policy == "chrome-like-ack":
        boundary_ok = transitions[1].get("packet_number") == transitions[0].get("packet_number", 0) + 100
    passed = (
        version == "1.0.0"
        and transition_ok
        and boundary_ok
        and len(episodes) == len(wire)
        and largest_matches == compared
        and max(delay_errors_us or [0]) <= 1.0
    )
    batches = [int(e.get("ack_batch_size", 0)) for e in episodes]
    spacings_us = [float(e.get("ack_spacing_ns", 0)) / 1000.0 for e in episodes[1:]]
    delays_us = [float(e.get("ack_delay_ns", 0)) / 1000.0 for e in episodes]
    trigger_counts = {
        name: sum(e.get("trigger") == name for e in episodes)
        for name in ("threshold", "timer", "reordering", "immediate-ecn-ce", "opportunistic")
    }
    return {
        "flow_dir": str(flow_dir),
        "policy_name": policy,
        "policy_version": version,
        "transition_count": len(transitions),
        "transition_boundary_pn": transitions[-1].get("packet_number", "") if len(transitions) > 1 else "",
        "intent_ack_episodes": len(episodes),
        "qlog_wire_ack_frames": len(wire),
        "largest_acked_matches": f"{largest_matches}/{compared}",
        "max_delay_error_us": max(delay_errors_us or [0]),
        "median_ack_batch": statistics.median(batches) if batches else 0,
        "p90_ack_batch": percentile(batches, 0.90),
        "median_ack_spacing_us": statistics.median(spacings_us) if spacings_us else 0,
        "p90_ack_delay_us": percentile(delays_us, 0.90),
        "threshold_acks": trigger_counts["threshold"],
        "timer_acks": trigger_counts["timer"],
        "reordering_acks": trigger_counts["reordering"],
        "ecn_ce_acks": trigger_counts["immediate-ecn-ce"],
        "opportunistic_acks": trigger_counts["opportunistic"],
        "validation_passed": passed,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, help="smoke root containing real1..real4")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    flows = [path for pair in sorted(args.root.glob("real[1-4]")) for path in (pair / "a", pair / "b")]
    rows = [validate_flow(path) for path in flows]
    fields = list(rows[0]) if rows else []
    destination = args.output.open("w", newline="") if args.output else sys.stdout
    try:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if args.output:
            destination.close()
    if not rows or not all(row["validation_passed"] for row in rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
