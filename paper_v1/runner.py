"""Single-attempt executor for the Paper-v1 two-receiver H3 workload."""

import os
import platform
import shutil
import signal
import subprocess
import tarfile
import time
import uuid

from paper_v1.io import atomic_write_json, load_json, sha256_file
from paper_v1.evidence import write_derived_evidence
from paper_v1.manifest import ManifestStore, new_manifest
from paper_v1.matrix import load_matrix, planned_runs
from paper_v1.policy import load_policy_spec
from paper_v1.topology import NamespaceTopology
from paper_v1.wire import derive_wire


def _transport_log_path(sender_name, run_dir):
    if sender_name == "xquic":
        return os.path.join(run_dir, "xquic-server.slog")
    if sender_name == "mvfst":
        return os.path.join(run_dir, "server.stderr.log")
    return None


class RunError(RuntimeError):
    pass


def _mkdir(path):
    os.makedirs(path, exist_ok=True)
    return path


def _binary_sha256(path):
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        raise RunError("missing executable: {}".format(path))
    return sha256_file(path)


def _path_for_run(matrix, run_id):
    planned = next((item for item in planned_runs(matrix) if item["run_id"] == run_id), None)
    if planned is None:
        raise RunError("run_id is not in the canonical main matrix: {}".format(run_id))
    path = next(item for item in matrix["paths"] if item["path_id"] == planned["path_id"])
    profile = next(
        item for item in matrix["network_profiles"] if item["profile_id"] == planned["network_profile_id"]
    )
    return planned, path, profile


class ManagedProcess:
    def __init__(self, kind, argv, stdout_path, stderr_path, cwd=None, env=None):
        self.kind = kind
        self.argv = list(argv)
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path
        self.cwd = cwd
        self.env = env
        self.process = None
        self.start_ns = None
        self.end_ns = None
        self.termination_reason = None
        self._stdout = None
        self._stderr = None

    def start(self):
        self._stdout = open(self.stdout_path, "wb")
        self._stderr = open(self.stderr_path, "wb")
        self.start_ns = time.monotonic_ns()
        self.process = subprocess.Popen(
            self.argv,
            stdout=self._stdout,
            stderr=self._stderr,
            cwd=self.cwd,
            env=self.env,
            start_new_session=True,
        )
        return self

    def wait(self, timeout=None):
        code = self.process.wait(timeout=timeout)
        self.end_ns = time.monotonic_ns()
        self.termination_reason = self.termination_reason or "normal"
        self._close_logs()
        return code

    def stop(self, sig=signal.SIGTERM, timeout=5, reason="graceful_stop"):
        if self.process is None:
            return
        if self.process.poll() is None:
            os.killpg(self.process.pid, sig)
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=timeout)
                reason = "forced_kill"
        self.end_ns = time.monotonic_ns()
        self.termination_reason = reason
        self._close_logs()

    def _close_logs(self):
        for handle in (self._stdout, self._stderr):
            if handle and not handle.closed:
                handle.close()

    def record(self):
        code = self.process.poll() if self.process else None
        return {
            "kind": self.kind,
            "command": self.argv,
            "pid": self.process.pid if self.process else None,
            "start_monotonic_ns": self.start_ns,
            "end_monotonic_ns": self.end_ns,
            "exit_code": code,
            "termination_reason": self.termination_reason,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "residual_process": bool(self.process and self.process.poll() is None),
        }


class PaperV1Runner:
    def __init__(self, local_config_path, matrix_path, policy_spec_path):
        self.config = load_json(local_config_path)
        self.matrix = load_matrix(matrix_path)
        self.policy_spec = load_policy_spec(policy_spec_path)
        self.local_config_path = os.path.abspath(local_config_path)
        self.processes = []

    def _ns_argv(self, namespace, argv):
        return ["ip", "netns", "exec", namespace, *argv]

    def _server_command(self, path, run_dir, port, response_bytes):
        sender = path["sender"]
        binary_key = "mvfst-h3" if sender == "mvfst" else sender
        binary = self.config["binaries"][binary_key]
        cert = self.config["tls"]["cert"]
        key = self.config["tls"]["key"]
        server_ip = self.config["network"].get("server_ip", "198.19.0.2")
        qlog_dir = _mkdir(os.path.join(run_dir, "qlog", "server"))
        root = _mkdir(os.path.join(run_dir, "server-root"))
        object_path = os.path.join(root, str(response_bytes))
        if sender == "quic-go" and not os.path.exists(object_path):
            with open(object_path, "wb") as artifact:
                artifact.truncate(response_bytes)
        env = os.environ.copy()
        cwd = run_dir
        if sender == "quic-go":
            runtime = os.path.join(run_dir, "sender-runtime-initial.jsonl")
            argv = [binary, "-addr", "{}:{}".format(server_ip, port), "-cert", cert, "-key", key,
                    "-root", root, "-qlog-dir", qlog_dir, "-paper-v1-runtime-report", runtime]
        elif sender == "quiche":
            runtime = os.path.join(run_dir, "sender-runtime-initial.jsonl")
            env["QLOGDIR"] = qlog_dir
            env["RUST_LOG"] = "info"
            argv = [binary, "--listen", "{}:{}".format(server_ip, port), "--cert", cert, "--key", key,
                    "--root", root, "--http-version", "HTTP/3", "--no-retry", "--cc-algorithm", path["cc"],
                    "--paper-v1-runtime-report", runtime]
            if path["requested_pacing"] == "off":
                argv.append("--disable-pacing")
        elif sender == "xquic":
            shutil.copy2(cert, os.path.join(run_dir, "server.crt"))
            shutil.copy2(key, os.path.join(run_dir, "server.key"))
            cc = {"cubic": "c", "reno": "r", "bbr-family": "b"}[path["cc"]]
            runtime = os.path.join(run_dir, "sender-runtime-initial.jsonl")
            argv = [binary, "-a", server_ip, "-p", str(port), "-c", cc,
                    "--paper-v1-body-bytes", str(response_bytes),
                    "--paper-v1-runtime-report", runtime,
                    "-o", os.path.join(run_dir, "xquic-server.slog")]
            if path["requested_pacing"] == "on":
                argv.append("-C")
        elif sender == "mvfst":
            runtime = os.path.join(run_dir, "sender-runtime-initial.jsonl")
            argv = [binary, "--mode=server", "--host={}".format(server_ip), "--port={}".format(port),
                    "--cert={}".format(cert), "--key={}".format(key), "--response_bytes={}".format(response_bytes),
                    "--congestion={}".format(path["cc"]),
                    "--pacing={}".format("true" if path["requested_pacing"] == "on" else "false"),
                    "--qlogger_path={}".format(qlog_dir),
                    "--paper_v1_runtime_report={}".format(runtime)]
        else:
            raise RunError("unsupported sender: {}".format(sender))
        return argv, cwd, env

    def _client_command(self, flow_id, policy, run_dir, port, duration_s, response_bytes, path, start_ns):
        binary = self.config["binaries"]["receiver"]
        server_ip = self.config["network"].get("server_ip", "198.19.0.2")
        flow_dir = _mkdir(os.path.join(run_dir, flow_id))
        qlog_dir = _mkdir(os.path.join(flow_dir, "qlog"))
        policy_hash = self.policy_spec["policies"][policy]["parameter_schema_sha256"]
        server_name = "test.xquic.com" if path["sender"] == "xquic" else self.config["tls"].get("server_name", "server")
        local_ports = self.config["network"].get("client_local_ports", [54433, 54434])
        local_port = local_ports[0 if flow_id == "flow_a" else 1]
        stream_window = int(self.config["network"].get("receiver_stream_window_bytes", 134217728))
        connection_window = int(self.config["network"].get("receiver_connection_window_bytes", 134217728))
        request_path = (
            "paper-v1/{}".format(response_bytes)
            if path["sender"] == "quiche" else str(response_bytes)
        )
        argv = [binary, "-paper-v1", "-protocol", "http3", "-ack-policy", policy,
                "-ack-policy-log", os.path.join(flow_dir, "receiver-policy.jsonl"),
                "-flow-id", flow_id, "-policy-spec-sha256", policy_hash,
                "-url", "https://{}:{}/{}".format(server_ip, port, request_path),
                "-server-name", server_name, "-insecure", "-local-port", str(local_port),
                "-initial-dcid-length", str(int(self.config["network"].get("initial_dcid_length", 16))),
                "-initial-stream-receive-window", str(stream_window),
                "-max-stream-receive-window", str(stream_window),
                "-initial-connection-receive-window", str(connection_window),
                "-max-connection-receive-window", str(connection_window),
                "-start-at-unix-ns", str(start_ns), "-start-timeout", "10s",
                "-duration", "{}s".format(duration_s), "-metrics", os.path.join(flow_dir, "metrics.csv"),
                "-o", "/dev/null", "-qlog-dir", qlog_dir,
                "-keylog", os.path.join(flow_dir, "tls.keys")]
        return argv

    @staticmethod
    def _write_snapshot(run_dir, name, value):
        path = os.path.join(run_dir, name + ".json")
        atomic_write_json(path, value)
        return path

    def run(self, run_id, attempt_id=None, smoke=False):
        NamespaceTopology.require_root()
        planned, path, profile = _path_for_run(self.matrix, run_id)
        attempt_id = attempt_id or "attempt-{}".format(uuid.uuid4().hex[:12])
        run_dir = os.path.join(self.config["dataset_root"], run_id, attempt_id)
        if os.path.exists(run_dir):
            raise FileExistsError(run_dir)
        _mkdir(run_dir)
        shutil.copy2(self.local_config_path, os.path.join(run_dir, "config-snapshot.json"))
        store = ManifestStore(os.path.join(run_dir, "run_manifest.json"))
        manifest = store.create(new_manifest(
            self.matrix["dataset_id_template"], planned["suite_id"], run_id, attempt_id, planned["repetition"]
        ))
        duration_s = 5 if smoke else self.matrix["workload"]["duration_s"]
        response_bytes = self.matrix["workload"]["response_body_bytes"]
        port = int(self.config["network"].get("server_port", 4433))
        topology = NamespaceTopology(
            profile,
            server_namespace=self.config["network"].get("server_namespace", "qb-server"),
            router_namespace=self.config["network"].get("router_namespace", "qb-router"),
            client_namespace=self.config["network"].get("client_namespace", "qb-client"),
            server_ip=self.config["network"].get("server_ip", "198.19.0.2"),
            client_ip=self.config["network"].get("client_ip", "198.19.0.6"),
        )
        requested_sender = dict(path, binary_sha256=_binary_sha256(
            self.config["binaries"]["mvfst-h3" if path["sender"] == "mvfst" else path["sender"]]
        ))
        if path["sender"] == "mvfst":
            requested_sender.update(self.config.get("mvfst_h3", {}))
        manifest["requested"] = {
            "sender": requested_sender,
            "flows": [
                dict(flow_id="flow_a", policy=planned["policy_pair"][0],
                     policy_version="1.0.0", policy_spec_sha256=self.policy_spec["policies"][planned["policy_pair"][0]]["parameter_schema_sha256"],
                     effective_parameters=self.policy_spec["policies"][planned["policy_pair"][0]]["parameters"],
                     initial_dcid_length=int(self.config["network"].get("initial_dcid_length", 16))),
                dict(flow_id="flow_b", policy=planned["policy_pair"][1],
                     policy_version="1.0.0", policy_spec_sha256=self.policy_spec["policies"][planned["policy_pair"][1]]["parameter_schema_sha256"],
                     effective_parameters=self.policy_spec["policies"][planned["policy_pair"][1]]["parameters"],
                     initial_dcid_length=int(self.config["network"].get("initial_dcid_length", 16))),
            ],
            "network_profile": profile,
            "workload": dict(
                self.matrix["workload"], smoke=bool(smoke), effective_duration_s=duration_s,
                receiver_stream_window_bytes=int(self.config["network"].get(
                    "receiver_stream_window_bytes", 134217728)),
                receiver_connection_window_bytes=int(self.config["network"].get(
                    "receiver_connection_window_bytes", 134217728)),
            ),
            "receiver_binary_sha256": _binary_sha256(self.config["binaries"]["receiver"]),
            "maximum_start_skew_ms": int(self.config["network"].get("maximum_start_skew_ms", 20)),
        }
        store.save(manifest)
        capture = server = None
        try:
            topology.setup()
            before = topology.snapshot()
            self._write_snapshot(run_dir, "network-before", before)
            store.transition("preflight_passed")
            capture = ManagedProcess(
                "capture",
                # Capture at the server endpoint. Receiver ACKs have already
                # traversed the reverse delay here, while outgoing Initials
                # are visible before TBF and remain reliably decryptable by
                # the Linux Wireshark 3.6 QUIC dissector.
                self._ns_argv(topology.server_namespace, ["tcpdump", "-i", topology.server_interface, "-U", "-s", "0", "-w", os.path.join(run_dir, "trace.pcap"), "udp", "port", str(port)]),
                os.path.join(run_dir, "capture.stdout.log"), os.path.join(run_dir, "capture.stderr.log"),
            ).start()
            self.processes.append(capture)
            server_argv, cwd, env = self._server_command(path, run_dir, port, response_bytes)
            server = ManagedProcess(
                "server", self._ns_argv(topology.server_namespace, server_argv),
                os.path.join(run_dir, "server.stdout.log"), os.path.join(run_dir, "server.stderr.log"), cwd=cwd, env=env,
            ).start()
            self.processes.append(server)
            time.sleep(0.5)
            if server.process.poll() is not None:
                raise RunError("server exited before clients: {}".format(server.process.returncode))
            start_ns = time.time_ns() + 2_000_000_000
            clients = []
            for flow_id, policy in zip(("flow_a", "flow_b"), planned["policy_pair"]):
                flow_dir = os.path.join(run_dir, flow_id)
                client = ManagedProcess(
                    "client_{}".format(flow_id),
                    self._ns_argv(topology.client_namespace, self._client_command(
                        flow_id, policy, run_dir, port, duration_s, response_bytes, path, start_ns
                    )),
                    os.path.join(flow_dir, "client.stdout.log"), os.path.join(flow_dir, "client.stderr.log"),
                ).start()
                clients.append(client)
                self.processes.append(client)
            store.transition("running")
            time.sleep(2 + min(2, max(1, duration_s // 2)))
            self._write_snapshot(run_dir, "network-active", topology.snapshot())
            for client in clients:
                if client.wait(timeout=duration_s + 15) != 0:
                    raise RunError("{} failed with {}".format(client.kind, client.process.returncode))
            # Give packet-buffered tcpdump time to flush terminal QUIC packets
            # before any process receives a stop signal. Wire validation still
            # requires complete qlog/pcap correspondence.
            time.sleep(0.5)
            server.stop()
            time.sleep(0.5)
            capture.stop(sig=signal.SIGINT, reason="graceful_stop")
            self._write_snapshot(run_dir, "network-after", topology.snapshot())
            store.transition("collecting")
            manifest = store.load()
            manifest["processes"] = [process.record() for process in self.processes]
            runtime, network = write_derived_evidence(run_dir, manifest)
            manifest["runtime_reported"] = dict(runtime, smoke=bool(smoke))
            tools = self.config.get("tools", {})
            if tools.get("tshark_container_image"):
                tshark = [tools.get("docker", "/usr/bin/docker"), "run", "--rm",
                          "-v", "{}:{}".format(run_dir, run_dir), tools["tshark_container_image"]]
            else:
                tshark = tools.get("tshark", "/usr/bin/tshark")
            wire = derive_wire(run_dir, manifest, tshark)
            manifest.setdefault("validator_conclusion", {})["network"] = network["conclusion"]
            manifest.setdefault("validator_conclusion", {})["wire"] = wire["conclusion"]
            store.save(manifest)
            self._collect_artifacts(run_dir, store)
            store.transition("validating")
            return run_dir
        except KeyboardInterrupt:
            current = store.load()["state"]
            if current not in ("completed_valid", "completed_invalid", "interrupted"):
                store.transition("interrupted", reason="operator_interrupt")
            raise
        except Exception as error:
            current = store.load()["state"]
            target = {
                "created": "failed_preflight",
                "preflight_passed": "failed_start",
                "running": "failed_runtime",
                "collecting": "failed_collection",
                "validating": "failed_validation",
            }.get(current)
            if target:
                store.transition(target, reason=str(error))
            raise
        finally:
            for process in reversed(self.processes):
                if process.process and process.process.poll() is None:
                    process.stop(reason="cleanup")
            topology.teardown()

    def _collect_artifacts(self, run_dir, store):
        manifest = store.load()
        sender_name = manifest["requested"]["sender"]["sender"]
        system_metadata = {
            "hostname": platform.node(),
            "kernel": platform.release(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "uname": list(platform.uname()),
        }
        self._write_snapshot(run_dir, "system-metadata", system_metadata)
        server_qlog_archive = os.path.join(run_dir, "server-qlogs.tar")
        server_qlog_dir = os.path.join(run_dir, "qlog", "server")
        if os.path.isdir(server_qlog_dir):
            with tarfile.open(server_qlog_archive, "w") as archive:
                archive.add(server_qlog_dir, arcname="server")

        def first_file(directory):
            if not os.path.isdir(directory):
                return None
            files = [
                os.path.join(directory, name)
                for name in sorted(os.listdir(directory))
                if os.path.isfile(os.path.join(directory, name))
                and os.path.getsize(os.path.join(directory, name)) > 0
            ]
            return files[0] if files else None

        role_paths = {
            "config_snapshot": os.path.join(run_dir, "config-snapshot.json"),
            "process_table": os.path.join(run_dir, "process-table.json"),
            "client_metrics_flow_a": os.path.join(run_dir, "flow_a", "metrics.csv"),
            "client_metrics_flow_b": os.path.join(run_dir, "flow_b", "metrics.csv"),
            "receiver_policy_flow_a": os.path.join(run_dir, "flow_a", "receiver-policy.jsonl"),
            "receiver_policy_flow_b": os.path.join(run_dir, "flow_b", "receiver-policy.jsonl"),
            "keylog_flow_a": os.path.join(run_dir, "flow_a", "tls.keys"),
            "keylog_flow_b": os.path.join(run_dir, "flow_b", "tls.keys"),
            "pcap": os.path.join(run_dir, "trace.pcap"),
            "qdisc_before": os.path.join(run_dir, "network-before.json"),
            "qdisc_active": os.path.join(run_dir, "network-active.json"),
            "qdisc_after": os.path.join(run_dir, "network-after.json"),
            "offload_before": os.path.join(run_dir, "network-before.json"),
            "offload_active": os.path.join(run_dir, "network-active.json"),
            "offload_after": os.path.join(run_dir, "network-after.json"),
            "system_metadata": os.path.join(run_dir, "system-metadata.json"),
            "server_stdout": os.path.join(run_dir, "server.stdout.log"),
            "server_stderr": os.path.join(run_dir, "server.stderr.log"),
            "client_stdout_flow_a": os.path.join(run_dir, "flow_a", "client.stdout.log"),
            "client_stderr_flow_a": os.path.join(run_dir, "flow_a", "client.stderr.log"),
            "client_stdout_flow_b": os.path.join(run_dir, "flow_b", "client.stdout.log"),
            "client_stderr_flow_b": os.path.join(run_dir, "flow_b", "client.stderr.log"),
            "capture_stderr": os.path.join(run_dir, "capture.stderr.log"),
            "receiver_qlog_flow_a": first_file(os.path.join(run_dir, "flow_a", "qlog")),
            "receiver_qlog_flow_b": first_file(os.path.join(run_dir, "flow_b", "qlog")),
            # xquic's test server writes qlog events and transport diagnostics
            # to one combined slog. Preserve the same immutable file under
            # both semantic roles; other stacks use the qlog archive.
            "sender_qlog": (
                os.path.join(run_dir, "xquic-server.slog")
                if os.path.isfile(os.path.join(run_dir, "xquic-server.slog"))
                else server_qlog_archive if os.path.getsize(server_qlog_archive) > 10240 else None
            ),
            "sender_runtime": os.path.join(run_dir, "sender-runtime.jsonl"),
            "sender_runtime_raw": os.path.join(run_dir, "sender-runtime-initial.jsonl"),
            # Only stacks whose derived identity actually parses a transport
            # log publish this semantic role. quic-go and quiche emit their
            # direct transport events to sender-runtime-initial.jsonl; an
            # empty, normal stderr must not masquerade as transport evidence.
            "sender_transport_log": _transport_log_path(sender_name, run_dir),
            "runtime_evidence": os.path.join(run_dir, "runtime-evidence.json"),
            "network_evidence": os.path.join(run_dir, "network-evidence.json"),
            "wire_evidence": os.path.join(run_dir, "wire-evidence.json"),
            "wire_pcap_flow_a": os.path.join(run_dir, "wire-port-{}.pcap".format(
                self.config["network"].get("client_local_ports", [54433, 54434])[0])),
            "wire_pcap_flow_b": os.path.join(run_dir, "wire-port-{}.pcap".format(
                self.config["network"].get("client_local_ports", [54433, 54434])[1])),
        }
        atomic_write_json(role_paths["process_table"], [process.record() for process in self.processes])
        artifacts = []
        for role, path in role_paths.items():
            if path and os.path.isfile(path):
                artifacts.append({"role": role, "path": os.path.relpath(path, run_dir), "sha256": sha256_file(path)})
        checksums_path = os.path.join(run_dir, "artifact-checksums.json")
        atomic_write_json(checksums_path, {item["role"]: item["sha256"] for item in artifacts})
        artifacts.append({
            "role": "artifact_checksums",
            "path": os.path.relpath(checksums_path, run_dir),
            "sha256": sha256_file(checksums_path),
        })
        manifest = store.load()
        manifest["artifacts"] = artifacts
        store.save(manifest)
