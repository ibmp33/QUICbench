#!/usr/bin/env python3
"""Extract comparable sender reactions to receiver ACK feedback.

This is a read-only, first-pass mechanism analyzer for the server-side qlog
produced by quiche and the textual slog produced by xquic.  It intentionally
does not claim that the two logging formats expose identical internals.

The default scope is deliberately small: repetition 1 of the two heterogeneous
fixed2/fixed10 role assignments, CUBIC, pacing enabled.  Use CLI flags to widen
the scope after the parser has been validated on a new result set.
"""

import argparse
import bisect
import csv
from datetime import datetime
import json
import math
from pathlib import Path
import re
import statistics
from zoneinfo import ZoneInfo


EPISODE_FIELDS = [
    "server",
    "cc",
    "pacing",
    "trial_name",
    "repetition",
    "run_id",
    "flow_id",
    "ack_policy",
    "network_share",
    "app_goodput_mbps",
    "local_port",
    "connection_id",
    "time_since_start_ms",
    "ack_receive_time_us",
    "packet_number_space",
    "ack_frame_largest_acked",
    "ack_range_count",
    "ack_delay_us",
    "ack_range_packet_count",
    "newly_acked_packet_count",
    "newly_acked_bytes",
    "cwnd_before_bytes",
    "cwnd_after_bytes",
    "cwnd_delta_bytes",
    "cwnd_delta_per_newly_acked_byte",
    "inflight_before_bytes",
    "inflight_after_bytes",
    "inflight_delta_bytes",
    "srtt_us",
    "latest_rtt_us",
    "rttvar_us",
    "pacing_rate_bytes_per_s",
    "application_limited",
    "packets_declared_lost",
    "bytes_declared_lost",
    "data_packets_next_1ms",
    "data_bytes_next_1ms",
    "data_packets_next_5ms",
    "data_bytes_next_5ms",
    "data_packets_next_srtt",
    "data_bytes_next_srtt",
    "next_data_send_delay_us",
    "source_log",
    "source_event_ids",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract per-ACK sender reactions from retained P2F logs."
    )
    parser.add_argument("results_root", type=Path)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/ack-feedback-prototype"),
    )
    parser.add_argument(
        "--servers", nargs="+", choices=("quiche", "xquic"), default=["quiche", "xquic"]
    )
    parser.add_argument("--cc", nargs="+", default=["cubic"])
    parser.add_argument(
        "--pacing", nargs="+", choices=("enabled", "disabled"), default=["enabled"]
    )
    parser.add_argument(
        "--pairs",
        nargs="+",
        default=["F1_fixed2_vs_fixed10", "F2_fixed10_vs_fixed2"],
    )
    parser.add_argument("--repetition", type=int, default=1)
    parser.add_argument("--window-start-s", type=float, default=5.0)
    parser.add_argument("--window-end-s", type=float, default=15.0)
    return parser.parse_args()


def finite_number(value):
    return isinstance(value, (int, float)) and math.isfinite(value)


def number_or_blank(value):
    if isinstance(value, float) and not math.isfinite(value):
        return ""
    return value


def mean(values):
    values = [value for value in values if finite_number(value)]
    return statistics.mean(values) if values else float("nan")


def median(values):
    values = [value for value in values if finite_number(value)]
    return statistics.median(values) if values else float("nan")


def percentile(values, percentile_value):
    values = sorted(value for value in values if finite_number(value))
    if not values:
        return float("nan")
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * percentile_value
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return values[lower]
    fraction = position - lower
    return values[lower] * (1 - fraction) + values[upper] * fraction


def parse_repetition(run_dir):
    try:
        return int(run_dir.name.split("-", 1)[0])
    except ValueError:
        return None


def selected_manifests(args):
    selected = {}
    pattern = (
        "P2-fixed-ratio-mechanism-*-server/"
        "50rtt-20bw-0.5bdp/*/*/run_manifest.json"
    )
    for path in args.results_root.glob(pattern):
        run_dir = path.parent
        repetition = parse_repetition(run_dir)
        if repetition != args.repetition or run_dir.parent.name not in args.pairs:
            continue
        manifest = json.loads(path.read_text())
        flows = manifest.get("flows", [])
        if len(flows) != 2:
            continue
        flow = flows[0]
        server = flow.get("server_stack_name") or flow.get("server_stack")
        config = flow.get("server_config", {})
        cc = config.get("cc")
        pacing = config.get("pacing")
        if server not in args.servers or cc not in args.cc or pacing not in args.pacing:
            continue
        key = (server, cc, pacing, run_dir.parent.name, repetition)
        previous = selected.get(key)
        if previous is None or path.stat().st_mtime > previous.stat().st_mtime:
            selected[key] = path
    return sorted(selected.values())


def read_manifest(path):
    manifest = json.loads(path.read_text())
    flows = {flow["flow_id"]: flow for flow in manifest["flows"]}
    summary_path = path.parent / "summary.csv"
    if summary_path.is_file():
        with summary_path.open(newline="") as handle:
            summary_by_flow = {row.get("flow_id"): row for row in csv.DictReader(handle)}
        for flow_id, flow in flows.items():
            summary = summary_by_flow.get(flow_id, {})
            flow["_network_share"] = (
                float(summary["share"]) if summary.get("share") else float("nan")
            )
            flow["_app_goodput_mbps"] = (
                float(summary["app_goodput_mbps"])
                if summary.get("app_goodput_mbps")
                else float("nan")
            )
    first = flows["flow_a"]
    config = first.get("server_config", {})
    return {
        "path": path,
        "run_dir": path.parent,
        "run_id": path.parent.name,
        "trial_name": path.parent.parent.name,
        "repetition": parse_repetition(path.parent),
        "server": first.get("server_stack_name") or first.get("server_stack"),
        "cc": config.get("cc"),
        "pacing": config.get("pacing"),
        "scheduled_start_us": int(first.get("scheduled_start_unix_ns", 0) / 1000),
        "flows": flows,
    }


def iter_json_seq(path):
    with path.open("rb") as handle:
        for raw in handle:
            raw = raw.lstrip(b"\x1e").strip()
            if not raw:
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError:
                continue


def qlog_connection_ids(path):
    ids = set()
    for event in iter_json_seq(path):
        header = event.get("data", {}).get("header", {})
        for key in ("scid", "dcid"):
            if header.get(key):
                ids.add(header[key])
    return ids


def map_quiche_logs(meta):
    client_ids = {}
    for flow_id in ("flow_a", "flow_b"):
        candidates = list((meta["run_dir"] / "flows" / flow_id).glob("**/*_client.sqlog"))
        if len(candidates) != 1:
            raise ValueError("expected one client qlog for {} in {}".format(flow_id, meta["run_dir"]))
        client_ids[flow_id] = qlog_connection_ids(candidates[0])
    server_logs = list((meta["run_dir"] / "servers").glob("**/server-*.sqlog"))
    mapping = {}
    for server_log in server_logs:
        connection_id = server_log.stem.removeprefix("server-")
        matches = [flow_id for flow_id, ids in client_ids.items() if connection_id in ids]
        if len(matches) != 1:
            raise ValueError("cannot uniquely map {} to a flow".format(server_log))
        mapping[matches[0]] = (connection_id, server_log)
    if set(mapping) != {"flow_a", "flow_b"}:
        raise ValueError("did not map both quiche server connections in {}".format(meta["run_dir"]))
    return mapping


def packet_number_space(packet_type):
    return {
        "initial": "initial",
        "handshake": "handshake",
        "0RTT": "application",
        "1RTT": "application",
        "short": "application",
    }.get(packet_type, packet_type or "unknown")


def expand_ranges(ranges):
    packet_numbers = set()
    for item in ranges:
        if not item:
            continue
        low = int(item[0])
        high = int(item[-1])
        if high < low:
            low, high = high, low
        packet_numbers.update(range(low, high + 1))
    return packet_numbers


def state_value(state, key):
    value = state.get(key) if state else None
    if isinstance(value, dict):
        return value.get("total")
    return value


def delta(after, before):
    return after - before if finite_number(after) and finite_number(before) else float("nan")


def parse_quiche_log(meta, flow_id, connection_id, path):
    seen = {"initial": set(), "handshake": set(), "application": set()}
    current_state = {}
    pending = []
    episodes = []
    sends = []
    sent_sizes = {"initial": {}, "handshake": {}, "application": {}}
    for event in iter_json_seq(path):
        name = event.get("name")
        data = event.get("data", {})
        time_ms = event.get("time")
        if not finite_number(time_ms):
            continue
        if name == "quic:packet_sent":
            header = data.get("header", {})
            frames = data.get("frames", [])
            sent_pns = packet_number_space(header.get("packet_type"))
            packet_number = header.get("packet_number")
            length = int(data.get("raw", {}).get("length", 0) or 0)
            if packet_number is not None:
                sent_sizes.setdefault(sent_pns, {})[int(packet_number)] = length
            if sent_pns == "application" and any(
                frame.get("frame_type") in {"stream", "http:frame_created"}
                for frame in frames
            ):
                sends.append((float(time_ms), length))
        elif name == "quic:packet_received":
            header = data.get("header", {})
            pns = packet_number_space(header.get("packet_type"))
            for frame in data.get("frames", []):
                if frame.get("frame_type") != "ack" or pns != "application":
                    continue
                packet_numbers = expand_ranges(frame.get("acked_ranges", []))
                newly_acked = packet_numbers - seen.setdefault(pns, set())
                seen[pns].update(packet_numbers)
                episode = {
                    "event_time_ms": float(time_ms),
                    "ack_receive_time_us": float("nan"),
                    "packet_number_space": pns,
                    "ack_frame_largest_acked": max(packet_numbers) if packet_numbers else float("nan"),
                    "ack_range_count": len(frame.get("acked_ranges", [])),
                    "ack_delay_us": (
                        float(frame["ack_delay"]) * 1000
                        if finite_number(frame.get("ack_delay"))
                        else float("nan")
                    ),
                    "ack_range_packet_count": len(packet_numbers),
                    "newly_acked_packet_count": len(newly_acked),
                    "newly_acked_bytes": sum(
                        sent_sizes.get(pns, {}).get(packet_number, 0)
                        for packet_number in newly_acked
                    ),
                    "source_event_ids": "packet_received:{}".format(
                        header.get("packet_number", "NA")
                    ),
                    "before": dict(current_state),
                    "after": {},
                }
                episodes.append(episode)
                pending.append(episode)
        elif name == "quic:recovery_metrics_updated":
            current_state.update(data)
            if pending:
                for episode in pending:
                    episode["after"] = dict(current_state)
                pending.clear()
    return finish_episodes(meta, flow_id, connection_id, path, episodes, sends, "quiche")


XQUIC_PREFIX_RE = re.compile(
    r"^\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) (\d{6})\]"
)
SCID_RE = re.compile(r"\|scid:([0-9a-fA-F]+)\|")
PEER_PORT_RE = re.compile(r" p-[^| ]+-(\d+)-[0-9a-fA-F]+ ")
KEY_VALUE_RE = re.compile(r"(?:^|\|)([A-Za-z_]+):(-?\d+)(?=\||$)")
ACK_FRAME_RE = re.compile(
    r"\[frames_processed\].*\|scid:([0-9a-fA-F]+)\|xqc_parse_ack_frame\|"
    r"type:\d+\|ack_delay:(\d+)\|ack_range:\{([^}]*)\}"
)
ACK_RANGE_RE = re.compile(r"(\d+)\s*-\s*(\d+)")


def xquic_prefix_time_us(line, second_cache):
    match = XQUIC_PREFIX_RE.match(line)
    if not match:
        return None
    second_text, micros = match.groups()
    if second_text not in second_cache:
        # xquic writes wall-clock timestamps in the Linux experiment machine's
        # local timezone.  The retained runs were produced in Asia/Shanghai;
        # manifest scheduling timestamps remain Unix UTC values.
        dt = datetime.strptime(second_text, "%Y/%m/%d %H:%M:%S").replace(
            tzinfo=ZoneInfo("Asia/Shanghai")
        )
        second_cache[second_text] = int(dt.timestamp()) * 1_000_000
    return second_cache[second_text] + int(micros)


def parse_key_values(line):
    return {key: int(value) for key, value in KEY_VALUE_RE.findall(line)}


def discover_xquic_ports(path):
    mapping = {}
    with path.open("r", errors="replace") as handle:
        for line in handle:
            if " p-" not in line or "|scid:" not in line:
                continue
            scid = SCID_RE.search(line)
            port = PEER_PORT_RE.search(line)
            if scid and port:
                mapping[scid.group(1)] = int(port.group(1))
            if len(mapping) >= 2:
                return mapping
    return mapping


def parse_xquic_log(meta, path):
    port_to_flow = {flow["local_port"]: flow_id for flow_id, flow in meta["flows"].items()}
    scid_ports = discover_xquic_ports(path)
    scid_to_flow = {
        scid: port_to_flow[port]
        for scid, port in scid_ports.items()
        if port in port_to_flow
    }
    if set(scid_to_flow.values()) != {"flow_a", "flow_b"}:
        raise ValueError("did not map both xquic connections in {}".format(path))

    states = {scid: {} for scid in scid_to_flow}
    active = {scid: None for scid in scid_to_flow}
    episodes = {scid: [] for scid in scid_to_flow}
    sends = {scid: [] for scid in scid_to_flow}
    second_cache = {}
    with path.open("r", errors="replace") as handle:
        for line in handle:
            scid_match = SCID_RE.search(line)
            if not scid_match or scid_match.group(1) not in scid_to_flow:
                continue
            scid = scid_match.group(1)
            time_us = xquic_prefix_time_us(line, second_cache)
            if time_us is None:
                continue
            if "[packet_sent]" in line and "|pkt_pns:2|" in line and "frame_flag:" in line:
                frame_text = line.split("frame_flag:", 1)[1].split("|", 1)[0]
                if "STREAM" in frame_text:
                    values = parse_key_values(line)
                    send_time = values.get("now", time_us)
                    send_bytes = values.get("sent", values.get("size", 0))
                    sends[scid].append((send_time / 1000.0, send_bytes))
                continue

            ack_match = ACK_FRAME_RE.search(line)
            if ack_match:
                _, ack_delay, ranges_text = ack_match.groups()
                packet_numbers = set()
                for high_text, low_text in ACK_RANGE_RE.findall(ranges_text):
                    high = int(high_text)
                    low = int(low_text)
                    if high < low:
                        high, low = low, high
                    packet_numbers.update(range(low, high + 1))
                episode = {
                    "event_time_ms": time_us / 1000.0,
                    "ack_receive_time_us": time_us,
                    "packet_number_space": "application",
                    "ack_frame_largest_acked": max(packet_numbers) if packet_numbers else float("nan"),
                    "ack_range_count": len(ACK_RANGE_RE.findall(ranges_text)),
                    "ack_delay_us": int(ack_delay),
                    "ack_range_packet_count": len(packet_numbers),
                    "newly_acked_packet_count": 0,
                    "newly_acked_bytes": 0,
                    "source_event_ids": "xquic_ack:{}".format(time_us),
                    "before": dict(states[scid]),
                    "after": {},
                }
                active[scid] = episode
                episodes[scid].append(episode)
                continue

            if active[scid] is not None and "xqc_send_ctl_on_ack_received" in line:
                if "|conn:" in line and "|pkt_num:" in line:
                    active[scid]["newly_acked_packet_count"] += 1
                    values = parse_key_values(line)
                    active[scid]["newly_acked_bytes"] += values.get("size", 0)
                if "[rec_metrics_updated]" in line:
                    values = parse_key_values(line)
                    active[scid]["after"] = values
                    states[scid].update(values)
                    active[scid] = None
                continue

            if "[stats]" in line:
                values = parse_key_values(line)
                states[scid].update(values)

    rows = []
    for scid, flow_id in scid_to_flow.items():
        rows.extend(finish_episodes(meta, flow_id, scid, path, episodes[scid], sends[scid], "xquic"))
    return rows


def metric_values(implementation, state):
    if implementation == "quiche":
        # quiche qlog recovery RTT values are milliseconds; normalize all
        # implementations to microseconds in the exported schema.
        srtt = state_value(state, "smoothed_rtt")
        latest_rtt = state_value(state, "latest_rtt")
        rttvar = state_value(state, "rtt_variance")
        return {
            "cwnd": state_value(state, "congestion_window"),
            "inflight": state_value(state, "bytes_in_flight"),
            "srtt": srtt * 1000 if finite_number(srtt) else srtt,
            "latest_rtt": latest_rtt * 1000 if finite_number(latest_rtt) else latest_rtt,
            "rttvar": rttvar * 1000 if finite_number(rttvar) else rttvar,
            "pacing_rate": state_value(state, "pacing_rate"),
        }
    return {
        "cwnd": state_value(state, "cwnd"),
        "inflight": state_value(state, "inflight"),
        "srtt": state_value(state, "srtt"),
        "latest_rtt": state_value(state, "latest_rtt"),
        "rttvar": state_value(state, "rttvar"),
        "pacing_rate": (
            state_value(state, "pacing_rate")
            if finite_number(state_value(state, "pacing_rate"))
            and state_value(state, "pacing_rate") > 0
            else float("nan")
        ),
    }


def send_window(sends, send_times, event_time_ms, window_ms):
    start = bisect.bisect_left(send_times, event_time_ms)
    end = bisect.bisect_right(send_times, event_time_ms + window_ms)
    selected = sends[start:end]
    return len(selected), sum(size for _, size in selected)


def finish_episodes(meta, flow_id, connection_id, path, episodes, sends, implementation):
    flow = meta["flows"][flow_id]
    sends.sort()
    send_times = [item[0] for item in sends]
    if implementation == "xquic" and meta["scheduled_start_us"]:
        start_time_ms = meta["scheduled_start_us"] / 1000.0
    else:
        start_time_ms = 0.0
    rows = []
    for episode in episodes:
        relative_ms = episode["event_time_ms"] - start_time_ms
        raw_before = episode["before"]
        raw_after = episode["after"]
        before = metric_values(implementation, episode["before"])
        after = metric_values(implementation, episode["after"])
        cwnd_delta = delta(after["cwnd"], before["cwnd"])
        inflight_delta = delta(after["inflight"], before["inflight"])
        newly_acked = episode["newly_acked_packet_count"]
        srtt_us = after["srtt"] if finite_number(after["srtt"]) else before["srtt"]
        srtt_ms = srtt_us / 1000.0 if finite_number(srtt_us) and srtt_us > 0 else 5.0
        packets_1ms, bytes_1ms = send_window(sends, send_times, episode["event_time_ms"], 1.0)
        packets_5ms, bytes_5ms = send_window(sends, send_times, episode["event_time_ms"], 5.0)
        packets_srtt, bytes_srtt = send_window(sends, send_times, episode["event_time_ms"], srtt_ms)
        send_index = bisect.bisect_left(send_times, episode["event_time_ms"])
        next_delay_us = (
            (send_times[send_index] - episode["event_time_ms"]) * 1000
            if send_index < len(send_times)
            else float("nan")
        )
        rows.append(
            {
                "server": meta["server"],
                "cc": meta["cc"],
                "pacing": meta["pacing"],
                "trial_name": meta["trial_name"],
                "repetition": meta["repetition"],
                "run_id": meta["run_id"],
                "flow_id": flow_id,
                "ack_policy": flow["ack_policy"],
                "network_share": flow.get("_network_share", float("nan")),
                "app_goodput_mbps": flow.get("_app_goodput_mbps", float("nan")),
                "local_port": flow["local_port"],
                "connection_id": connection_id,
                "time_since_start_ms": relative_ms,
                "ack_receive_time_us": episode.get("ack_receive_time_us", float("nan")),
                "packet_number_space": episode["packet_number_space"],
                "ack_frame_largest_acked": episode.get("ack_frame_largest_acked", float("nan")),
                "ack_range_count": episode.get("ack_range_count", float("nan")),
                "ack_delay_us": episode["ack_delay_us"],
                "ack_range_packet_count": episode["ack_range_packet_count"],
                "newly_acked_packet_count": newly_acked,
                "newly_acked_bytes": episode.get("newly_acked_bytes", float("nan")),
                "cwnd_before_bytes": before["cwnd"],
                "cwnd_after_bytes": after["cwnd"],
                "cwnd_delta_bytes": cwnd_delta,
                "cwnd_delta_per_newly_acked_byte": (
                    cwnd_delta / newly_acked
                    if finite_number(cwnd_delta) and newly_acked > 0
                    else float("nan")
                ),
                "inflight_before_bytes": before["inflight"],
                "inflight_after_bytes": after["inflight"],
                "inflight_delta_bytes": inflight_delta,
                "srtt_us": srtt_us,
                "latest_rtt_us": (
                    after["latest_rtt"] if finite_number(after["latest_rtt"]) else before["latest_rtt"]
                ),
                "rttvar_us": after["rttvar"] if finite_number(after["rttvar"]) else before["rttvar"],
                "pacing_rate_bytes_per_s": (
                    after["pacing_rate"]
                    if finite_number(after["pacing_rate"])
                    else before["pacing_rate"]
                ),
                "application_limited": (
                    raw_after.get("applimit")
                    if "applimit" in raw_after
                    else raw_before.get("applimit", float("nan"))
                ),
                "packets_declared_lost": (
                    raw_after.get("cf_lost_packets", {}).get("delta")
                    if isinstance(raw_after.get("cf_lost_packets"), dict)
                    else max(0, delta(raw_after.get("lost"), raw_before.get("lost")))
                    if finite_number(raw_after.get("lost")) and finite_number(raw_before.get("lost"))
                    else float("nan")
                ),
                "bytes_declared_lost": (
                    raw_after.get("cf_lost_bytes", {}).get("delta")
                    if isinstance(raw_after.get("cf_lost_bytes"), dict)
                    else float("nan")
                ),
                "data_packets_next_1ms": packets_1ms,
                "data_bytes_next_1ms": bytes_1ms,
                "data_packets_next_5ms": packets_5ms,
                "data_bytes_next_5ms": bytes_5ms,
                "data_packets_next_srtt": packets_srtt,
                "data_bytes_next_srtt": bytes_srtt,
                "next_data_send_delay_us": next_delay_us,
                "source_log": str(path),
                "source_event_ids": episode.get("source_event_ids", "NA"),
            }
        )
    return rows


def write_episode_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=EPISODE_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: number_or_blank(row.get(key)) for key in EPISODE_FIELDS})


def summarize(rows, window_start_s, window_end_s):
    grouped = {}
    for row in rows:
        key = (row["server"], row["cc"], row["pacing"], row["ack_policy"])
        grouped.setdefault(key, []).append(row)
    output = []
    duration_s = window_end_s - window_start_s
    for key, samples in sorted(grouped.items()):
        values = lambda field: [sample[field] for sample in samples]
        connections = {
            (row["run_id"], row["connection_id"]): row for row in samples
        }
        output.append(
            {
                "server": key[0],
                "cc": key[1],
                "pacing": key[2],
                "ack_policy": key[3],
                "connections": len(connections),
                "network_share_mean": mean(
                    [row["network_share"] for row in connections.values()]
                ),
                "app_goodput_mbps_mean": mean(
                    [row["app_goodput_mbps"] for row in connections.values()]
                ),
                "ack_episodes": len(samples),
                "ack_episode_rate_per_connection_hz": len(samples)
                / (duration_s * len(connections)),
                "newly_acked_mean": mean(values("newly_acked_packet_count")),
                "newly_acked_median": median(values("newly_acked_packet_count")),
                "newly_acked_p90": percentile(values("newly_acked_packet_count"), 0.90),
                "cwnd_before_median_bytes": median(values("cwnd_before_bytes")),
                "inflight_before_median_bytes": median(values("inflight_before_bytes")),
                "cwnd_delta_mean_bytes": mean(values("cwnd_delta_bytes")),
                "cwnd_delta_median_bytes": median(values("cwnd_delta_bytes")),
                "cwnd_delta_per_newly_acked_mean": mean(values("cwnd_delta_per_newly_acked_byte")),
                "cwnd_changed_fraction": mean(
                    [1.0 if value != 0 else 0.0 for value in values("cwnd_delta_bytes") if finite_number(value)]
                ),
                "cwnd_increase_event_fraction": mean(
                    [1.0 if value > 0 else 0.0 for value in values("cwnd_delta_bytes") if finite_number(value)]
                ),
                "cwnd_decrease_event_fraction": mean(
                    [1.0 if value < 0 else 0.0 for value in values("cwnd_delta_bytes") if finite_number(value)]
                ),
                "next_send_delay_median_us": median(values("next_data_send_delay_us")),
                "data_packets_next_1ms_mean": mean(values("data_packets_next_1ms")),
                "data_bytes_next_1ms_mean": mean(values("data_bytes_next_1ms")),
                "data_packets_next_5ms_mean": mean(values("data_packets_next_5ms")),
                "data_bytes_next_5ms_mean": mean(values("data_bytes_next_5ms")),
                "pacing_rate_mean_bytes_per_s": mean(values("pacing_rate_bytes_per_s")),
            }
        )
    return output


def write_summary_csv(path, rows):
    fields = list(rows[0]) if rows else []
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: number_or_blank(value) for key, value in row.items()})


def connection_rows(rows, window_start_s, window_end_s):
    grouped = {}
    for row in rows:
        key = (row["run_id"], row["connection_id"])
        grouped.setdefault(key, []).append(row)
    duration_s = window_end_s - window_start_s
    output = []
    for _, samples in sorted(grouped.items()):
        first = samples[0]
        ordered_times = sorted(row["time_since_start_ms"] for row in samples)
        intervals_us = [
            (current - previous) * 1000
            for previous, current in zip(ordered_times, ordered_times[1:])
            if current >= previous
        ]
        cwnd_deltas = [
            row["cwnd_delta_bytes"]
            for row in samples
            if finite_number(row["cwnd_delta_bytes"])
        ]
        output.append(
            {
                "server": first["server"],
                "cc": first["cc"],
                "pacing": first["pacing"],
                "trial_name": first["trial_name"],
                "repetition": first["repetition"],
                "run_id": first["run_id"],
                "flow_id": first["flow_id"],
                "ack_policy": first["ack_policy"],
                "local_port": first["local_port"],
                "connection_id": first["connection_id"],
                "network_share": first["network_share"],
                "app_goodput_mbps": first["app_goodput_mbps"],
                "ack_episodes": len(samples),
                "ack_episode_rate_hz": len(samples) / duration_s,
                "effective_ack_batch_mean": mean(
                    [row["newly_acked_packet_count"] for row in samples]
                ),
                "ack_interval_median_us": median(intervals_us),
                "cwnd_median_bytes": median(
                    [row["cwnd_before_bytes"] for row in samples]
                ),
                "inflight_median_bytes": median(
                    [row["inflight_before_bytes"] for row in samples]
                ),
                "cwnd_delta_mean_bytes": mean(cwnd_deltas),
                "cwnd_changed_fraction": mean(
                    [1.0 if value != 0 else 0.0 for value in cwnd_deltas]
                ),
                "next_send_delay_median_us": median(
                    [row["next_data_send_delay_us"] for row in samples]
                ),
                "data_bytes_next_5ms_mean": mean(
                    [row["data_bytes_next_5ms"] for row in samples]
                ),
            }
        )
    return output


def average_ranks(values):
    indexed = sorted(enumerate(values), key=lambda item: item[1])
    ranks = [0.0] * len(values)
    position = 0
    while position < len(indexed):
        end = position + 1
        while end < len(indexed) and indexed[end][1] == indexed[position][1]:
            end += 1
        rank = ((position + 1) + end) / 2.0
        for original_index, _ in indexed[position:end]:
            ranks[original_index] = rank
        position = end
    return ranks


def pearson_correlation(left, right):
    pairs = [
        (float(x_value), float(y_value))
        for x_value, y_value in zip(left, right)
        if finite_number(x_value) and finite_number(y_value)
    ]
    if len(pairs) < 3:
        return float("nan"), len(pairs)
    x_values, y_values = zip(*pairs)
    x_mean = statistics.mean(x_values)
    y_mean = statistics.mean(y_values)
    numerator = sum(
        (x_value - x_mean) * (y_value - y_mean)
        for x_value, y_value in pairs
    )
    x_sum = sum((x_value - x_mean) ** 2 for x_value in x_values)
    y_sum = sum((y_value - y_mean) ** 2 for y_value in y_values)
    denominator = math.sqrt(x_sum * y_sum)
    return (numerator / denominator if denominator else float("nan")), len(pairs)


def association_rows(connections):
    groups = {}
    for row in connections:
        groups.setdefault((row["server"], row["pacing"]), []).append(row)
        groups.setdefault((row["server"], "pooled"), []).append(row)
    predictors = (
        "effective_ack_batch_mean",
        "ack_episode_rate_hz",
        "ack_interval_median_us",
    )
    outcomes = ("cwnd_median_bytes", "network_share")
    output = []
    for (server, pacing), samples in sorted(groups.items()):
        for predictor in predictors:
            for outcome in outcomes:
                x_values = [row[predictor] for row in samples]
                y_values = [row[outcome] for row in samples]
                pearson_r, sample_count = pearson_correlation(x_values, y_values)
                valid_pairs = [
                    (x_value, y_value)
                    for x_value, y_value in zip(x_values, y_values)
                    if finite_number(x_value) and finite_number(y_value)
                ]
                if len(valid_pairs) >= 3:
                    rank_x = average_ranks([pair[0] for pair in valid_pairs])
                    rank_y = average_ranks([pair[1] for pair in valid_pairs])
                    spearman_r, _ = pearson_correlation(rank_x, rank_y)
                else:
                    spearman_r = float("nan")
                output.append(
                    {
                        "server": server,
                        "pacing_stratum": pacing,
                        "predictor": predictor,
                        "outcome": outcome,
                        "n_connections": sample_count,
                        "pearson_r": pearson_r,
                        "spearman_r": spearman_r,
                        "interpretation": "descriptive_only_no_independence_or_causality_claim",
                    }
                )
    return output


def main():
    args = parse_args()
    if args.window_end_s <= args.window_start_s:
        raise SystemExit("--window-end-s must be greater than --window-start-s")
    manifests = selected_manifests(args)
    if not manifests:
        raise SystemExit("no matching retained P2F manifests found")

    all_rows = []
    audit_rows = []
    for manifest_path in manifests:
        meta = read_manifest(manifest_path)
        try:
            if meta["server"] == "quiche":
                mapping = map_quiche_logs(meta)
                rows = []
                for flow_id, (connection_id, log_path) in mapping.items():
                    rows.extend(parse_quiche_log(meta, flow_id, connection_id, log_path))
                source_count = len(mapping)
            elif meta["server"] == "xquic":
                candidates = list((meta["run_dir"] / "servers").glob("**/xquic-server.slog"))
                if len(candidates) != 1:
                    raise ValueError("expected one xquic server slog")
                rows = parse_xquic_log(meta, candidates[0])
                source_count = 1
            else:
                continue
            lower_ms = args.window_start_s * 1000
            upper_ms = args.window_end_s * 1000
            selected = [
                row
                for row in rows
                if lower_ms <= row["time_since_start_ms"] <= upper_ms
                and row["packet_number_space"] == "application"
            ]
            all_rows.extend(selected)
            audit_rows.append(
                {
                    "manifest": str(manifest_path),
                    "server": meta["server"],
                    "trial_name": meta["trial_name"],
                    "run_id": meta["run_id"],
                    "source_logs": source_count,
                    "episodes_all": len(rows),
                    "episodes_in_window": len(selected),
                    "status": "ok" if selected else "empty-window",
                    "error": "",
                }
            )
        except (OSError, ValueError) as exc:
            audit_rows.append(
                {
                    "manifest": str(manifest_path),
                    "server": meta["server"],
                    "trial_name": meta["trial_name"],
                    "run_id": meta["run_id"],
                    "source_logs": 0,
                    "episodes_all": 0,
                    "episodes_in_window": 0,
                    "status": "error",
                    "error": str(exc),
                }
            )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    episode_path = args.output_dir / "ack_episodes.csv"
    summary_path = args.output_dir / "ack_response_summary.csv"
    connection_path = args.output_dir / "connection_feedback_summary.csv"
    association_path = args.output_dir / "feedback_cwnd_association.csv"
    audit_path = args.output_dir / "extraction_audit.csv"
    write_episode_csv(episode_path, all_rows)
    summary = summarize(all_rows, args.window_start_s, args.window_end_s)
    write_summary_csv(summary_path, summary)
    connections = connection_rows(all_rows, args.window_start_s, args.window_end_s)
    associations = association_rows(connections)
    write_summary_csv(connection_path, connections)
    write_summary_csv(association_path, associations)
    with audit_path.open("w", newline="") as handle:
        fields = list(audit_rows[0]) if audit_rows else []
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(audit_rows)

    print("ACK feedback extraction")
    print("manifests={} episodes={} window={}s-{}s".format(
        len(manifests), len(all_rows), args.window_start_s, args.window_end_s
    ))
    for row in summary:
        print(
            "server={server} cc={cc} pacing={pacing} policy={ack_policy} "
            "connections={connections} share={network_share_mean:.3f} "
            "ACK/s/conn={ack_episode_rate_per_connection_hz:.1f} "
            "newly_acked={newly_acked_mean:.2f} cwnd_med={cwnd_before_median_bytes:.0f}B "
            "cwnd_delta={cwnd_delta_mean_bytes:.1f}B "
            "next_5ms={data_bytes_next_5ms_mean:.1f}B".format(**row)
        )
    print("episodes={}".format(episode_path))
    print("summary={}".format(summary_path))
    print("connections={}".format(connection_path))
    print("associations={}".format(association_path))
    print("audit={}".format(audit_path))
    if any(row["status"] != "ok" for row in audit_rows):
        raise SystemExit("one or more extractions were not successful; inspect extraction_audit.csv")


if __name__ == "__main__":
    main()
