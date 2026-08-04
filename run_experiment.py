#!/usr/bin/env python3
"""Run one policy-client flow against a selected QUIC server adapter."""

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime

from stacks.mvfst import Mvfst
from stacks.quiche import Quiche
from stacks.quic_go import QuicGo, QuicGoPolicy
from stacks.xquic import Xquic
from workloads import generated_target, load_workload_profiles, resolve_workload


SERVER_CLASSES = {
    QuicGo.NAME: QuicGo,
    Quiche.NAME: Quiche,
    Xquic.NAME: Xquic,
    Mvfst.NAME: Mvfst,
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the unified quic-go policy client against one server adapter."
    )
    parser.add_argument("--server", required=True, choices=sorted(SERVER_CLASSES))
    parser.add_argument(
        "--ack-policy",
        required=True,
        choices=sorted(QuicGoPolicy.ACK_POLICIES),
    )
    parser.add_argument("--stacks-conf", default="./config/stacks_conf_default.json")
    parser.add_argument("--general-conf", default="./config/general_conf_default.json")
    parser.add_argument("--workloads-conf", default="./config/workloads_conf_default.json")
    parser.add_argument("--workload", choices=["smoke", "fairness"], default="smoke")
    parser.add_argument("--port", type=int, help="override the adapter's verified default port")
    parser.add_argument(
        "--duration",
        type=int,
        help="deprecated runtime override; normally use the workload profile duration_s",
    )
    parser.add_argument("--local-port", type=int)
    parser.add_argument(
        "--output",
        default="/home/ioio33/QUIC_project/results/adapter-smoke",
    )
    parser.add_argument("--qlog", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def load_json(path):
    with open(path) as config_file:
        return json.load(config_file)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_text(command):
    if isinstance(command, str):
        return command
    return shlex.join(command)


def refresh_client_command(args, run, scheduled_start):
    run["scheduled_start"] = scheduled_start
    run["client_command"] = run["client"].run_client_cmd(
        run["port"],
        args.duration,
        start_at_unix_ns=scheduled_start,
        local_port=args.local_port,
        ack_policy=args.ack_policy,
        target=run["target"],
    )
    run["client_command_text"] = command_text(run["client_command"])


def build_run(args, stacks_conf, general_conf, workload):
    server_conf = stacks_conf[args.server]
    client_conf = stacks_conf[QuicGoPolicy.NAME]
    server_ip = general_conf["server_ip"]
    common = {
        "server_ip": server_ip,
        "server_hostname": "localhost",
        "server_pw_path": "",
    }
    server = SERVER_CLASSES[args.server](**common, **server_conf)
    client = QuicGoPolicy(**common, **client_conf)
    server.set_qlog_enabled(args.qlog)
    client.set_qlog_enabled(args.qlog)

    port = str(args.port or server_conf["default_port"])
    run_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = os.path.join(args.output, args.server, args.ack_policy, run_id)
    server_root = os.path.join(run_dir, "servers", "{}-{}".format(args.server, port))
    client_root = os.path.join(run_dir, "flows", "flow_a", "client")
    server.set_run_root(server_root)
    client.set_run_root(client_root)

    target = server.get_client_target(port, workload=workload)
    scheduled_start = time.time_ns() + 1_000_000_000
    server_command = server.run_server_cmd(port, args.duration + 5)
    client_command = client.run_client_cmd(
        port,
        args.duration,
        start_at_unix_ns=scheduled_start,
        local_port=args.local_port,
        ack_policy=args.ack_policy,
        target=target,
    )
    return {
        "server": server,
        "client": client,
        "port": port,
        "target": target,
        "workload": workload,
        "scheduled_start": scheduled_start,
        "run_dir": run_dir,
        "server_command": server_command,
        "client_command": client_command,
        "server_command_text": command_text(server_command),
        "client_command_text": command_text(client_command),
    }


def validate_linux_runtime(run):
    if not sys.platform.startswith("linux"):
        raise SystemExit("Execution requires the Ubuntu experiment host; use --dry-run on macOS.")
    for label, path in [
        ("server binary", run["server"].server_path),
        ("client binary", run["client"].client_path),
    ]:
        if not os.path.isfile(path):
            raise SystemExit("{} does not exist: {}".format(label, path))


def manifest(args, run):
    timestamp = datetime.now().isoformat(timespec="seconds")
    return {
        "server_stack": args.server,
        "server_binary": run["server"].server_path,
        "server_protocol": run["target"]["protocol"],
        "server_config": {
            "cc": "cubic",
            "requested_cc": "cubic",
            "icw": "not-configured",
            "pacing": "adapter-default",
            "gso": "adapter-default",
        },
        "client_binary": run["client"].client_path,
        "protocol": run["target"]["protocol"],
        "ack_policy": args.ack_policy,
        "port": run["port"],
        "local_port": args.local_port,
        "client_target": run["target"],
        "workload_name": run["workload"]["name"],
        "requested_bytes": run["workload"]["bytes"],
        "duration_s": args.duration,
        "duration": args.duration,
        "generated_target": generated_target(run["target"]),
        "server_command": run["server_command_text"],
        "client_command": run["client_command_text"],
        "command": run["client_command_text"],
        "timestamp": timestamp,
        "scheduled_start_unix_ns": run["scheduled_start"],
        "run_results_dir": run["run_dir"],
    }


def write_manifest(path, payload):
    with open(path, "w") as output:
        json.dump(payload, output, indent=2)


def main():
    args = parse_args()
    workload_profiles = load_workload_profiles(args.workloads_conf)
    workload = resolve_workload(workload_profiles, args.workload)
    if args.duration is None:
        args.duration = workload["duration_s"]
    else:
        workload["duration_s"] = args.duration
    if args.duration <= 0:
        raise SystemExit("--duration must be > 0")
    stacks_conf = load_json(args.stacks_conf)
    general_conf = load_json(args.general_conf)
    run = build_run(args, stacks_conf, general_conf, workload)

    print("server_stack: {}".format(args.server))
    print("protocol: {}".format(run["target"]["protocol"]))
    print("ack_policy: {}".format(args.ack_policy))
    print(
        "workload: {} bytes={} duration_s={}".format(
            workload["name"], workload["bytes"], workload["duration_s"]
        )
    )
    print("server_command: {}".format(run["server_command_text"]))
    print("client_command: {}".format(run["client_command_text"]))
    if args.dry_run:
        return

    validate_linux_runtime(run)
    os.makedirs(run["run_dir"], exist_ok=True)
    payload = manifest(args, run)
    payload["server_binary_sha256"] = sha256(run["server"].server_path)
    payload["client_binary_sha256"] = sha256(run["client"].client_path)
    manifest_path = os.path.join(run["run_dir"], "run_manifest.json")
    write_manifest(manifest_path, payload)

    server_process = run["server"].run_remote_server(
        run["port"], "cubic", args.duration + 5
    )
    time.sleep(2)
    if server_process.poll() is not None:
        raise SystemExit("server exited before the client started; inspect the server stderr log")

    refresh_client_command(args, run, time.time_ns() + 1_000_000_000)
    payload["client_command"] = run["client_command_text"]
    payload["command"] = run["client_command_text"]
    payload["scheduled_start_unix_ns"] = run["scheduled_start"]
    write_manifest(manifest_path, payload)

    client_process = run["client"].run_client(
        run["port"],
        "cubic",
        args.duration,
        start_at_unix_ns=run["scheduled_start"],
        local_port=args.local_port,
        ack_policy=args.ack_policy,
        target=run["target"],
    )
    client_code = client_process.wait()
    server_code = server_process.wait()
    payload["client_exit_code"] = client_code
    payload["server_exit_code"] = server_code
    payload["end_timestamp"] = datetime.now().isoformat(timespec="seconds")
    write_manifest(manifest_path, payload)
    if client_code != 0:
        raise SystemExit(client_code)


if __name__ == "__main__":
    main()
