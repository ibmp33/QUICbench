import argparse
import csv
import json
import os
import subprocess
import sys

import pandas as pd

sys.path.insert(1, os.path.join(sys.path[0], ".."))

from constants import INTERFACE_PCAP_FILENAME
from utils.files import write_to_csv


RELATIVE_TIME = "frame.time_relative"
IP_SRC = "ip.src"
IP_DST = "ip.dst"
FRAME_LEN = "frame.len"
UDP_SRCPORT = "udp.srcport"
UDP_DSTPORT = "udp.dstport"
DEFAULT_STEADY_STATE_START_S = 10.0


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exp_conf", "-e", type=str, required=True)
    parser.add_argument("--general_conf", "-g", type=str, required=True)
    parser.add_argument("--trial_name", "-n", type=str, required=True)
    parser.add_argument("--trial_dir", "-t", type=str, required=True)
    parser.add_argument("--network_profile_name", type=str, help="optional network profile name from exp_conf")
    return parser.parse_args()


def load_json(path):
    with open(path) as f:
        return json.load(f)


def get_effective_netem_conf(exp_conf, network_profile_name):
    if not network_profile_name:
        return exp_conf["netem_conf"]

    for profile in exp_conf.get("network_profiles", []):
        if profile.get("name") == network_profile_name:
            return profile["netem_conf"]
    raise SystemExit(
        "Unknown network profile '{}' in parse_pcap_min.py.".format(network_profile_name)
    )


def convert_pcap_to_csv(pcap_path, csv_path):
    cmd = "tshark -r {} -T fields ".format(pcap_path)
    for field in [RELATIVE_TIME, IP_SRC, IP_DST, FRAME_LEN, UDP_SRCPORT, UDP_DSTPORT]:
        cmd += "-e {} ".format(field)
    cmd += "-E header=y -E separator=, -E quote=d -E occurrence=f > {}".format(csv_path)
    subprocess.run(cmd, shell=True, check=True)


def read_packets_df(pcap_path):
    csv_path = pcap_path + ".csv"
    convert_pcap_to_csv(pcap_path, csv_path)
    df = pd.read_csv(csv_path, dtype=str)
    os.remove(csv_path)

    df.fillna("", inplace=True)
    df[RELATIVE_TIME] = df[RELATIVE_TIME].astype(float)
    df[FRAME_LEN] = df[FRAME_LEN].astype(float)
    return df


def parse_qlog_json_seq_line(line):
    line = line.lstrip("\x1e").strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def find_connection_started_event(qlog_dir):
    if not qlog_dir or not os.path.isdir(qlog_dir):
        return None

    for filename in sorted(os.listdir(qlog_dir)):
        qlog_path = os.path.join(qlog_dir, filename)
        if not os.path.isfile(qlog_path):
            continue
        with open(qlog_path) as qlog_file:
            for line in qlog_file:
                event = parse_qlog_json_seq_line(line)
                if event and event.get("name") == "transport:connection_started":
                    return event
    return None


def extract_ack_metrics(qlog_dir):
    if not qlog_dir or not os.path.isdir(qlog_dir):
        return None
    ack_eliciting_received = 0
    ack_frames_sent = 0
    ack_times = []
    non_ack_eliciting = {"ack", "padding", "connection_close"}
    for filename in sorted(os.listdir(qlog_dir)):
        qlog_path = os.path.join(qlog_dir, filename)
        if not os.path.isfile(qlog_path):
            continue
        with open(qlog_path) as qlog_file:
            for line in qlog_file:
                event = parse_qlog_json_seq_line(line)
                if not event:
                    continue
                data = event.get("data", {})
                if data.get("header", {}).get("packet_type") != "1RTT":
                    continue
                frames = data.get("frames", [])
                frame_types = {frame.get("frame_type") for frame in frames}
                if event.get("name") == "transport:packet_received":
                    if any(frame_type not in non_ack_eliciting for frame_type in frame_types):
                        ack_eliciting_received += 1
                elif event.get("name") == "transport:packet_sent" and "ack" in frame_types:
                    ack_frames_sent += 1
                    ack_times.append(float(event.get("time", 0)))
    if ack_frames_sent == 0 and ack_eliciting_received == 0:
        return None
    intervals = [later - earlier for earlier, later in zip(ack_times, ack_times[1:])]
    return {
        "ack_eliciting_packets_received": ack_eliciting_received,
        "ack_frames_sent": ack_frames_sent,
        "realized_ack_ratio": round(ack_eliciting_received / ack_frames_sent, 5) if ack_frames_sent else 0.0,
        "mean_ack_interval_ms": round(sum(intervals) / len(intervals), 5) if intervals else 0.0,
    }


def extract_flow_tuple(flow_metadata):
    event = find_connection_started_event(flow_metadata.get("client_qlog_path"))
    if not event:
        return None

    data = event.get("data", {})
    local = data.get("local", {})
    remote = data.get("remote", {})
    client_port = local.get("port_v4") or local.get("port_v6")
    server_port = remote.get("port_v4") or remote.get("port_v6")
    if client_port is None or server_port is None:
        return None
    return str(client_port), str(server_port)


def get_flow_packets(df, server_ip, flow_metadata):
    local_port = flow_metadata.get("local_port")
    if local_port is not None:
        client_port = str(local_port)
        server_port = str(flow_metadata["port_no"])
        outgoing = df.loc[
            (df[IP_SRC] == server_ip)
            & (df[UDP_SRCPORT] == server_port)
            & (df[UDP_DSTPORT] == client_port)
        ]
        incoming = df.loc[
            (df[IP_DST] == server_ip)
            & (df[UDP_DSTPORT] == server_port)
            & (df[UDP_SRCPORT] == client_port)
        ]
        return outgoing, incoming

    flow_tuple = extract_flow_tuple(flow_metadata)
    if flow_tuple:
        client_port, server_port = flow_tuple
        outgoing = df.loc[
            (df[IP_SRC] == server_ip)
            & (df[UDP_SRCPORT] == server_port)
            & (df[UDP_DSTPORT] == client_port)
        ]
        incoming = df.loc[
            (df[IP_DST] == server_ip)
            & (df[UDP_DSTPORT] == server_port)
            & (df[UDP_SRCPORT] == client_port)
        ]
        return outgoing, incoming

    port_no = str(flow_metadata["port_no"])
    outgoing = df.loc[(df[IP_SRC] == server_ip) & (df[UDP_SRCPORT] == port_no)]
    incoming = df.loc[(df[IP_DST] == server_ip) & (df[UDP_DSTPORT] == port_no)]
    return outgoing, incoming


def moving_average_trace(packets_df, window_size_s):
    if packets_df.empty:
        return []

    trace = []
    bucket_bytes = 0.0
    bucket_idx = 0
    max_time = float(packets_df.iloc[-1][RELATIVE_TIME])

    for _, packet in packets_df.iterrows():
        pkt_time = float(packet[RELATIVE_TIME])
        pkt_len = float(packet[FRAME_LEN])
        pkt_bucket_idx = int(pkt_time / window_size_s)

        while bucket_idx < pkt_bucket_idx:
            bucket_end = round((bucket_idx + 1) * window_size_s, 5)
            rate_mbps = round(bucket_bytes * 8 / window_size_s / 1_000_000, 5)
            trace.append([bucket_end, rate_mbps])
            bucket_idx += 1
            bucket_bytes = 0.0

        bucket_bytes += pkt_len

    bucket_end = round((bucket_idx + 1) * window_size_s, 5)
    rate_mbps = round(bucket_bytes * 8 / window_size_s / 1_000_000, 5)
    trace.append([bucket_end, rate_mbps])

    max_bucket_idx = int(max_time / window_size_s)
    while bucket_idx < max_bucket_idx:
        bucket_idx += 1
        bucket_end = round((bucket_idx + 1) * window_size_s, 5)
        trace.append([bucket_end, 0.0])

    return trace


def get_steady_state_window(exp_conf):
    window = exp_conf.get("steady_state_window_s")
    if isinstance(window, dict):
        start_s = float(window.get("start", DEFAULT_STEADY_STATE_START_S))
        end_s = float(window.get("end", exp_conf["flow_duration_s"] - DEFAULT_STEADY_STATE_START_S))
        return start_s, end_s

    start_s = DEFAULT_STEADY_STATE_START_S
    end_s = float(exp_conf["flow_duration_s"]) - DEFAULT_STEADY_STATE_START_S
    if end_s <= start_s:
        start_s = 0.0
        end_s = float(exp_conf["flow_duration_s"])
    return start_s, end_s


def filter_packets_in_window(packets_df, start_s, end_s):
    if packets_df.empty:
        return packets_df
    return packets_df.loc[
        (packets_df[RELATIVE_TIME] >= float(start_s))
        & (packets_df[RELATIVE_TIME] < float(end_s))
    ]


def rebase_packets_to_request_start(packets_df, request_start_s):
    rebased = packets_df.copy()
    if not rebased.empty:
        rebased[RELATIVE_TIME] = rebased[RELATIVE_TIME] - float(request_start_s)
    return rebased


def average_throughput_mbps(packets_df, duration_s):
    if packets_df.empty:
        return 0.0
    bytes_total = packets_df[FRAME_LEN].sum()
    return round(bytes_total * 8 / duration_s / 1_000_000, 5)


def application_goodput_mbps(metrics_path, start_s, end_s):
    if not metrics_path or not os.path.isfile(metrics_path):
        return 0.0
    metrics = pd.read_csv(metrics_path)
    if metrics.empty:
        return 0.0
    metrics["elapsed_s"] = metrics["elapsed_ms"].astype(float) / 1000.0
    before_start = metrics.loc[metrics["elapsed_s"] <= float(start_s)]
    before_end = metrics.loc[metrics["elapsed_s"] <= float(end_s)]
    if before_end.empty:
        return 0.0
    start_bytes = float(before_start.iloc[-1]["cumulative_body_bytes"]) if not before_start.empty else 0.0
    end_bytes = float(before_end.iloc[-1]["cumulative_body_bytes"])
    return round(max(0.0, end_bytes - start_bytes) * 8 / (end_s - start_s) / 1_000_000, 5)


def jain_index(values):
    if not values or sum(values) == 0:
        return 0.0
    numerator = sum(values) ** 2
    denominator = len(values) * sum(v * v for v in values)
    return round(numerator / denominator, 5)


def append_summary(summary_path, row):
    headers = [
        "trial_name",
        "run_id",
        "flow_id",
        "stack_name",
        "cc_algo",
        "ack_policy",
        "ack_freq",
        "avg_throughput_mbps",
        "app_goodput_mbps",
        "ack_eliciting_packets_received",
        "ack_frames_sent",
        "realized_ack_ratio",
        "mean_ack_interval_ms",
        "share",
        "jain_index",
        "steady_state_start_s",
        "steady_state_end_s",
    ]
    file_exists = os.path.exists(summary_path)
    with open(summary_path, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(headers)
        writer.writerow(row)


def main():
    args = get_args()
    exp_conf = load_json(args.exp_conf)
    general_conf = load_json(args.general_conf)
    trial_conf = next(trial for trial in exp_conf["trials"] if trial["name"] == args.trial_name)
    manifest_path = os.path.join(args.trial_dir, "run_manifest.json")
    manifest = load_json(manifest_path) if os.path.exists(manifest_path) else {"flows": []}
    manifest_flow_map = {flow["flow_id"]: flow for flow in manifest.get("flows", [])}

    server_ip = general_conf["server_ip"]
    flow_duration_s = exp_conf["flow_duration_s"]
    netem_conf = get_effective_netem_conf(exp_conf, args.network_profile_name)
    window_size_s = exp_conf.get("throughput_window_s") or netem_conf["RTT_ms"] / 100
    steady_start_s, steady_end_s = get_steady_state_window(exp_conf)
    steady_duration_s = steady_end_s - steady_start_s

    pcap_path = os.path.join(args.trial_dir, INTERFACE_PCAP_FILENAME)
    df = read_packets_df(pcap_path)

    results = []
    for flow in trial_conf["flows"]:
        flow_metadata = dict(flow)
        flow_metadata.update(manifest_flow_map.get(flow["flow_id"], {}))
        outgoing, incoming = get_flow_packets(df, server_ip, flow_metadata)
        request_start_s = (
            float(incoming[RELATIVE_TIME].min())
            if not incoming.empty
            else float(outgoing[RELATIVE_TIME].min())
            if not outgoing.empty
            else 0.0
        )
        outgoing_from_start = rebase_packets_to_request_start(outgoing, request_start_s)
        incoming_from_start = rebase_packets_to_request_start(incoming, request_start_s)
        trace = moving_average_trace(outgoing_from_start, window_size_s)
        steady_outgoing = filter_packets_in_window(
            outgoing_from_start, steady_start_s, steady_end_s
        )
        avg_tp = average_throughput_mbps(steady_outgoing, steady_duration_s)
        app_goodput = application_goodput_mbps(
            flow_metadata.get("client_metrics_path"),
            steady_start_s,
            steady_end_s,
        )
        ack_metrics = extract_ack_metrics(flow_metadata.get("client_qlog_path")) or {}
        results.append(
            {
                "flow": flow,
                "outgoing": outgoing_from_start,
                "steady_outgoing": steady_outgoing,
                "incoming": incoming_from_start,
                "trace": trace,
                "avg_tp": avg_tp,
                "app_goodput": app_goodput,
                "ack_metrics": ack_metrics,
            }
        )
        write_to_csv(
            os.path.join(args.trial_dir, "{}.tp-trace".format(flow["flow_id"])),
            ["time (s)", "throughput (Mbps)"],
            trace,
        )

    total_tp = sum(result["avg_tp"] for result in results)
    fairness = jain_index([result["avg_tp"] for result in results])
    run_id = os.path.basename(args.trial_dir)

    per_run_rows = []
    for result in results:
        flow = result["flow"]
        ack_metrics = result["ack_metrics"]
        share = round(result["avg_tp"] / total_tp, 5) if total_tp else 0.0
        per_run_rows.append(
            [
                flow["flow_id"],
                flow["stack_name"],
                flow["cc_algo"],
                flow.get("ack_policy", ""),
                flow.get("ack_freq", ""),
                result["avg_tp"],
                result["app_goodput"],
                ack_metrics.get("ack_eliciting_packets_received", ""),
                ack_metrics.get("ack_frames_sent", ""),
                ack_metrics.get("realized_ack_ratio", ""),
                ack_metrics.get("mean_ack_interval_ms", ""),
                share,
                steady_start_s,
                steady_end_s,
            ]
        )
        append_summary(
            os.path.join(os.path.dirname(args.trial_dir), "summary.csv"),
            [
                args.trial_name,
                run_id,
                flow["flow_id"],
                flow["stack_name"],
                flow["cc_algo"],
                flow.get("ack_policy", ""),
                flow.get("ack_freq", ""),
                result["avg_tp"],
                result["app_goodput"],
                ack_metrics.get("ack_eliciting_packets_received", ""),
                ack_metrics.get("ack_frames_sent", ""),
                ack_metrics.get("realized_ack_ratio", ""),
                ack_metrics.get("mean_ack_interval_ms", ""),
                share,
                fairness,
                steady_start_s,
                steady_end_s,
            ],
        )

    write_to_csv(
        os.path.join(args.trial_dir, "summary.csv"),
        [
            "flow_id",
            "stack_name",
            "cc_algo",
            "ack_policy",
            "ack_freq",
            "avg_throughput_mbps",
            "app_goodput_mbps",
            "ack_eliciting_packets_received",
            "ack_frames_sent",
            "realized_ack_ratio",
            "mean_ack_interval_ms",
            "share",
            "steady_state_start_s",
            "steady_state_end_s",
        ],
        per_run_rows,
    )


if __name__ == "__main__":
    main()
