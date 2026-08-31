import os
import shlex
import subprocess

from stacks.stack import Stack


class QuicGo(Stack):
    NAME = "quic-go"
    CUBIC = "cubic"
    ACK_POLICY = None
    SUPPORTS_EXPERIMENT_FLAGS = False
    ACK_POLICIES = {
        "neqo-like-ack",
        "chrome-like-ack",
        "synthetic-fixed-ack-2",
        "synthetic-fixed-ack-10",
    }

    def __init__(
        self,
        server_ip,
        server_hostname,
        server_pw_path,
        server_path,
        client_path,
        server_cert_path,
        server_key_path,
        root_dir=None,
        server_root=None,
        server_addr=None,
        server_netns="quicbench-server",
        client_netns="quicbench-client",
        client_timeout="30s",
        client_url_template=None,
        workload_url_template=None,
        workload_url_templates=None,
        client_addr_template=None,
        client_server_name=None,
        protocol="http3",
        default_port=None,
        server_cc_algo="cubic",
        server_pacing="enabled",
        server_gso="implementation-default",
        workload_capabilities=None,
        client_ack_frequency_mode="disabled",
        client_min_ack_delay=None,
        paper_v1_mode=False,
        paper_v1_policy_hashes=None,
    ):
        self.server_ip = server_ip
        self.server_hostname = server_hostname
        self.server_path = server_path
        self.client_path = client_path
        self.server_cert_path = server_cert_path
        self.server_key_path = server_key_path
        self.root_dir = root_dir
        self.server_root = server_root
        self.server_addr = server_addr
        self.server_netns = server_netns
        self.client_netns = client_netns
        self.client_timeout = client_timeout
        self.client_url_template = client_url_template
        self.workload_url_template = workload_url_template
        self.workload_url_templates = workload_url_templates or {}
        self.client_addr_template = client_addr_template
        self.client_server_name = client_server_name
        self.protocol = protocol
        self.default_port = default_port
        self.server_cc_algo = server_cc_algo
        self.server_pacing = server_pacing
        self.server_gso = server_gso
        self.workload_capabilities = workload_capabilities or {}
        if client_ack_frequency_mode not in {"disabled", "mvfst-draft"}:
            raise ValueError(
                "unsupported client ACK_FREQUENCY mode {!r}".format(
                    client_ack_frequency_mode
                )
            )
        if client_ack_frequency_mode != "disabled" and not client_min_ack_delay:
            client_min_ack_delay = "1ms"
        self.client_ack_frequency_mode = client_ack_frequency_mode
        self.client_min_ack_delay = client_min_ack_delay
        self.paper_v1_mode = bool(paper_v1_mode)
        self.paper_v1_policy_hashes = paper_v1_policy_hashes or {}
        if self.paper_v1_mode and self.client_ack_frequency_mode != "disabled":
            raise ValueError("paper-v1 forbids negotiated ACK_FREQUENCY")
        self.run_root = None
        self.qlog_enabled = False

    def run_remote_server(self, port_no, cc_algo, duration_s):
        cmd = self.run_server_cmd(port_no, duration_s, cc_algo=cc_algo)
        return subprocess.Popen(cmd)

    def run_client(
        self,
        port_no,
        cc_algo,
        duration_s,
        start_at_unix_ns=None,
        local_port=None,
        ack_policy=None,
        target=None,
        flow_id=None,
    ):
        cmd = self.run_client_cmd(
            port_no,
            duration_s,
            start_at_unix_ns=start_at_unix_ns,
            local_port=local_port,
            ack_policy=ack_policy,
            target=target,
            flow_id=flow_id,
        )
        return subprocess.Popen(cmd, shell=True)

    def run_server_cmd(self, port_no, duration_s, cc_algo=None):
        requested_cc = cc_algo or self.server_cc_algo
        if requested_cc != self.server_cc_algo:
            raise ValueError(
                "quic-go server binary is fixed to {!r}; requested {!r}".format(
                    self.server_cc_algo, requested_cc
                )
            )
        root_dir = self._get_root_dir(self.server_path)
        run_dir = self._get_run_dir(port_no)
        server_addr = self._get_server_addr(port_no)

        parts = [
            "cd {}".format(shlex.quote(root_dir)),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "qlogs", "server"))),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "logs"))),
        ]

        server_cmd = [
            shlex.quote(self.server_path),
            "-addr",
            shlex.quote(server_addr),
            "-cert",
            shlex.quote(self.server_cert_path),
            "-key",
            shlex.quote(self.server_key_path),
        ]
        if self.server_root:
            server_cmd.extend(["-root", shlex.quote(self.server_root)])
        if self.qlog_enabled:
            server_cmd.extend(["-qlog-dir", shlex.quote(os.path.join(run_dir, "qlogs", "server"))])

        parts.append(
            "timeout {} {}".format(
                int(duration_s),
                " ".join(server_cmd),
            )
            + " >{} 2>{}".format(
                shlex.quote(os.path.join(run_dir, "logs", "server.stdout.log")),
                shlex.quote(os.path.join(run_dir, "logs", "server.stderr.log")),
            )
        )

        shell_cmd = " && ".join(parts)
        return [
            "sudo",
            "-n",
            "ip",
            "netns",
            "exec",
            self.server_netns,
            "bash",
            "-lc",
            shell_cmd,
        ]

    def get_server_runtime_config(self, cc_algo):
        return {
            "cc": self.server_cc_algo,
            "requested_cc": cc_algo,
            "icw": "implementation-default",
            "pacing": self.server_pacing,
            "gso": self.server_gso,
            "control_source": "binary-build",
        }

    def run_client_cmd(
        self,
        port_no,
        duration_s,
        start_at_unix_ns=None,
        local_port=None,
        ack_policy=None,
        target=None,
        flow_id=None,
    ):
        root_dir = self._get_root_dir(self.client_path)
        run_dir = self._get_run_dir(port_no)
        target = target or self.get_client_target(port_no)
        client_timeout = self._get_client_timeout(duration_s)

        parts = [
            "cd {}".format(shlex.quote(root_dir)),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "qlogs", "client"))),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "stdout"))),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "logs"))),
        ]

        client_cmd = [
            shlex.quote(self.client_path),
            "-protocol",
            shlex.quote(target["protocol"]),
        ]
        if target["protocol"] == "http3":
            client_cmd.extend(["-url", shlex.quote(target["url"]), "-insecure"])
            if target.get("server_name"):
                client_cmd.extend(["-server-name", shlex.quote(target["server_name"])])
        elif target["protocol"] == "raw":
            client_cmd.extend(["-addr", shlex.quote(target["addr"]), "-insecure"])
        else:
            raise ValueError("unsupported client protocol {!r}".format(target["protocol"]))
        if self.SUPPORTS_EXPERIMENT_FLAGS:
            effective_ack_policy = ack_policy or self.ACK_POLICY
            if effective_ack_policy not in self.ACK_POLICIES:
                raise ValueError(
                    "unsupported ACK policy {!r}; valid values: {}".format(
                        effective_ack_policy, ", ".join(sorted(self.ACK_POLICIES))
                    )
                )
            client_cmd.extend(
                [
                    "-duration",
                    shlex.quote(client_timeout),
                    "-ack-policy",
                    shlex.quote(effective_ack_policy),
                    "-metrics",
                    shlex.quote(os.path.join(run_dir, "metrics.csv")),
                    "-ack-policy-log",
                    shlex.quote(os.path.join(run_dir, "ack-policy-events.jsonl")),
                ]
            )
            if self.client_ack_frequency_mode != "disabled":
                client_cmd.extend(
                    [
                        "-ack-frequency-mode",
                        shlex.quote(self.client_ack_frequency_mode),
                        "-min-ack-delay",
                        shlex.quote(str(self.client_min_ack_delay)),
                    ]
                )
            if self.paper_v1_mode:
                if effective_ack_policy not in {"neqo-like-ack", "chrome-like-ack"}:
                    raise ValueError("paper-v1 permits only modeled ACK policies")
                if not flow_id:
                    raise ValueError("paper-v1 requires a flow ID")
                policy_hash = self.paper_v1_policy_hashes.get(effective_ack_policy)
                if not policy_hash:
                    raise ValueError(
                        "paper-v1 policy hash is missing for {!r}".format(
                            effective_ack_policy
                        )
                    )
                client_cmd.extend(
                    [
                        "-paper-v1",
                        "-flow-id",
                        shlex.quote(flow_id),
                        "-policy-spec-sha256",
                        shlex.quote(policy_hash),
                        "-ack-frequency-mode",
                        "disabled",
                    ]
                )
            if target.get("max_bytes") is not None:
                client_cmd.extend(["-max-bytes", shlex.quote(str(target["max_bytes"]))])
            if local_port is not None:
                client_cmd.extend(["-local-port", shlex.quote(str(local_port))])
            if start_at_unix_ns is not None:
                client_cmd.extend(["-start-at-unix-ns", shlex.quote(str(start_at_unix_ns))])
        else:
            client_cmd.extend(
                [
                    "-timeout",
                    shlex.quote(client_timeout),
                    "-o",
                    shlex.quote(os.path.join(run_dir, "stdout", "client.body.bin")),
                ]
            )
        if self.qlog_enabled:
            client_cmd.extend(
                [
                    "-qlog-dir",
                    shlex.quote(os.path.join(run_dir, "qlogs", "client")),
                ]
            )
        parts.append(
            "exec {}".format(" ".join(client_cmd))
            + " >{} 2>{} </dev/null".format(
                shlex.quote(os.path.join(run_dir, "logs", "client.stdout.log")),
                shlex.quote(os.path.join(run_dir, "logs", "client.stderr.log")),
            )
        )

        shell_cmd = " && ".join(parts)
        return " ".join(
            [
                "sudo",
                "-n",
                "ip",
                "netns",
                "exec",
                shlex.quote(self.client_netns),
                "bash",
                "-lc",
                shlex.quote(shell_cmd),
            ]
        )

    def _get_root_dir(self, binary_path):
        if self.root_dir:
            return self.root_dir
        return os.path.dirname(binary_path) or "."

    def _get_run_dir(self, port_no):
        base_dir = self.run_root or os.path.join("/tmp", "quicbench")
        return os.path.join(base_dir, self.NAME, str(port_no))

    def set_run_root(self, run_root):
        self.run_root = run_root

    def set_qlog_enabled(self, enabled):
        self.qlog_enabled = bool(enabled)

    def get_flow_paths(self, port_no):
        run_dir = self._get_run_dir(port_no)
        return {
            "run_dir": run_dir,
            "server_qlog_dir": os.path.join(run_dir, "qlogs", "server"),
            "client_qlog_dir": os.path.join(run_dir, "qlogs", "client"),
            "server_stdout_log": os.path.join(run_dir, "logs", "server.stdout.log"),
            "server_stderr_log": os.path.join(run_dir, "logs", "server.stderr.log"),
            "client_stdout_log": os.path.join(run_dir, "logs", "client.stdout.log"),
            "client_stderr_log": os.path.join(run_dir, "logs", "client.stderr.log"),
            "ack_policy_event_log": os.path.join(run_dir, "ack-policy-events.jsonl"),
            "client_metrics_path": os.path.join(run_dir, "metrics.csv"),
        }

    def _get_server_addr(self, port_no):
        if self.server_addr:
            return self.server_addr.format(port=port_no, server_ip=self.server_ip)
        return "0.0.0.0:{}".format(port_no)

    def _get_client_url(self, port_no, workload=None):
        template = self.client_url_template
        if workload:
            template = self.workload_url_templates.get(
                workload["name"], self.workload_url_template or template
            )
        if template:
            return template.format(
                port=port_no,
                server_ip=self.server_ip,
                bytes=workload["bytes"] if workload else "",
            )
        return "https://{}:{}/".format(self.server_ip, port_no)

    def get_client_target(self, port_no=None, workload=None):
        port_no = str(port_no or self.default_port)
        if not port_no or port_no == "None":
            raise ValueError("no port supplied for stack '{}'".format(self.NAME))
        if self.protocol == "http3":
            target = {
                "protocol": "http3",
                "url": self._get_client_url(port_no, workload=workload),
            }
            if self.client_server_name:
                target["server_name"] = self.client_server_name
            if workload:
                target["max_bytes"] = int(workload["bytes"])
            return target
        if self.protocol == "raw":
            template = self.client_addr_template or "{server_ip}:{port}"
            target = {
                "protocol": "raw",
                "addr": template.format(server_ip=self.server_ip, port=port_no),
            }
            if workload:
                target["max_bytes"] = int(workload["bytes"])
            return target
        raise ValueError("unsupported protocol {!r} for stack '{}'".format(self.protocol, self.NAME))

    def _get_client_timeout(self, duration_s):
        if self.client_timeout:
            return self.client_timeout
        return "{}s".format(int(duration_s))

    def get_client_feedback_config(self):
        config = {"ack_frequency_mode": self.client_ack_frequency_mode}
        if self.client_ack_frequency_mode != "disabled":
            config.update(
                {
                    "min_ack_delay": str(self.client_min_ack_delay),
                    "min_ack_delay_transport_parameter_id": "0xff04de1a",
                    "ack_frequency_frame_type": "0xaf",
                    "immediate_ack_frame_type": "0xac",
                }
            )
        return config

    @staticmethod
    def get_cc_algos():
        return [QuicGo.CUBIC]


class QuicGoAck5(QuicGo):
    NAME = "quic-go-ack5"
    ACK_POLICY = "fixed5"
    SUPPORTS_EXPERIMENT_FLAGS = True


class QuicGoAck2(QuicGo):
    NAME = "quic-go-ack2"
    ACK_POLICY = "fixed2"
    SUPPORTS_EXPERIMENT_FLAGS = True


class QuicGoAck10(QuicGo):
    NAME = "quic-go-ack10"
    ACK_POLICY = "fixed10"
    SUPPORTS_EXPERIMENT_FLAGS = True


class QuicGoPolicy(QuicGo):
    NAME = "quic-go-policy"
    SUPPORTS_EXPERIMENT_FLAGS = True
