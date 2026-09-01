import argparse
import csv
import json
import math
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
    raise SystemExit("Unknown network profile '{}' in parse_pcap_single_flow.py.".format(network_profile_name))


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


def average_throughput_mbps(packets_df, flow_duration_s):
    if packets_df.empty:
        return 0.0
    bytes_total = packets_df[FRAME_LEN].sum()
    return round(bytes_total * 8 / flow_duration_s / 1_000_000, 5)


def trace_stats(trace):
    if not trace:
        return 0.0, 0.0
    values = [float(point[1]) for point in trace]
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    stddev = math.sqrt(variance)
    cv = stddev / mean if mean > 0 else 0.0
    return round(stddev, 5), round(cv, 5)


def append_summary(summary_path, row):
    headers = [
        "trial_name",
        "run_id",
        "stack_name",
        "server_stack_name",
        "cc_algo",
        "ack_freq",
        "avg_throughput_mbps",
        "throughput_stddev_mbps",
        "throughput_cv",
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
    flow_metadata = dict(trial_conf["flows"][0])
    if manifest.get("flows"):
        flow_metadata.update(manifest["flows"][0])

    server_ip = general_conf["server_ip"]
    flow_duration_s = exp_conf["flow_duration_s"]
    netem_conf = get_effective_netem_conf(exp_conf, args.network_profile_name)
    window_size_s = exp_conf.get("throughput_window_s") or netem_conf["RTT_ms"] / 100

    pcap_path = os.path.join(args.trial_dir, INTERFACE_PCAP_FILENAME)
    df = read_packets_df(pcap_path)
    outgoing, incoming = get_flow_packets(df, server_ip, flow_metadata)
    trace = moving_average_trace(outgoing, window_size_s)
    avg_tp = average_throughput_mbps(outgoing, flow_duration_s)
    stddev_tp, cv_tp = trace_stats(trace)

    write_to_csv(
        os.path.join(args.trial_dir, "{}.tp-trace".format(flow_metadata["flow_id"])),
        ["time (s)", "throughput (Mbps)"],
        trace,
    )
    write_to_csv(
        os.path.join(args.trial_dir, "summary.csv"),
        [
            "flow_id",
            "stack_name",
            "server_stack_name",
            "cc_algo",
            "ack_freq",
            "avg_throughput_mbps",
            "throughput_stddev_mbps",
            "throughput_cv",
        ],
        [[
            flow_metadata["flow_id"],
            flow_metadata["stack_name"],
            flow_metadata["server_stack_name"],
            flow_metadata["cc_algo"],
            flow_metadata.get("ack_freq", ""),
            avg_tp,
            stddev_tp,
            cv_tp,
        ]],
    )
    write_to_csv(
        os.path.join(args.trial_dir, "stability.csv"),
        ["flow_id", "stack_name", "server_stack_name", "ack_freq", "throughput_stddev_mbps", "throughput_cv"],
        [[
            flow_metadata["flow_id"],
            flow_metadata["stack_name"],
            flow_metadata["server_stack_name"],
            flow_metadata.get("ack_freq", ""),
            stddev_tp,
            cv_tp,
        ]],
    )
    append_summary(
        os.path.join(os.path.dirname(args.trial_dir), "summary.csv"),
        [
            args.trial_name,
            os.path.basename(args.trial_dir),
            flow_metadata["stack_name"],
            flow_metadata["server_stack_name"],
            flow_metadata["cc_algo"],
            flow_metadata.get("ack_freq", ""),
            avg_tp,
            stddev_tp,
            cv_tp,
        ],
    )


if __name__ == "__main__":
    main()
