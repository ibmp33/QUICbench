import os
import shlex
import subprocess

from stacks.quic_go import QuicGo


class Mvfst(QuicGo):
    NAME = "mvfst"
    CUBIC = "cubic"
    BBR = "bbr"
    RENO = "reno"

    def __init__(
        self,
        server_ack_frequency=False,
        server_ack_frequency_threshold=10,
        server_ack_frequency_reordering_threshold=3,
        server_ack_frequency_min_rtt_divisor=2,
        server_ack_frequency_startup_ack2=True,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.server_ack_frequency = bool(server_ack_frequency)
        self.server_ack_frequency_threshold = int(server_ack_frequency_threshold)
        self.server_ack_frequency_reordering_threshold = int(
            server_ack_frequency_reordering_threshold
        )
        self.server_ack_frequency_min_rtt_divisor = int(
            server_ack_frequency_min_rtt_divisor
        )
        self.server_ack_frequency_startup_ack2 = bool(
            server_ack_frequency_startup_ack2
        )
        if self.server_ack_frequency_threshold <= 1:
            raise ValueError("server ACK_FREQUENCY threshold must be greater than 1")
        if self.server_ack_frequency_reordering_threshold <= 1:
            raise ValueError(
                "server ACK_FREQUENCY reordering threshold must be greater than 1"
            )
        if self.server_ack_frequency_min_rtt_divisor <= 0:
            raise ValueError("server ACK_FREQUENCY min RTT divisor must be positive")

    def _pacing_enabled(self):
        if isinstance(self.server_pacing, bool):
            return self.server_pacing
        return str(self.server_pacing).lower() in {"1", "true", "yes", "enabled", "on"}

    def _map_cc_algo(self, cc_algo):
        return "newreno" if cc_algo == self.RENO else cc_algo

    def get_server_runtime_config(self, cc_algo):
        config = {
            "cc": cc_algo,
            "requested_cc": cc_algo,
            "icw": "implementation-default",
            "pacing": "enabled" if self._pacing_enabled() else "disabled",
            "gso": "enabled",
            "control_source": "server-command-line",
            "ack_frequency_enabled": self.server_ack_frequency,
        }
        if self.server_ack_frequency:
            config["ack_frequency_config"] = {
                "ack_eliciting_threshold": self.server_ack_frequency_threshold,
                "reordering_threshold": self.server_ack_frequency_reordering_threshold,
                "min_rtt_divisor": self.server_ack_frequency_min_rtt_divisor,
                "use_small_threshold_during_startup": self.server_ack_frequency_startup_ack2,
            }
        return config

    def run_remote_server(self, port_no, cc_algo, duration_s):
        cmd = self.run_server_cmd(port_no, duration_s, cc_algo=cc_algo)
        return subprocess.Popen(cmd)

    def run_server_cmd(self, port_no, duration_s, cc_algo=None):
        requested_cc = cc_algo or self.CUBIC
        if self.server_ack_frequency and requested_cc != self.BBR:
            raise ValueError("mvfst ACK_FREQUENCY treatment requires BBR1")
        if self.server_ack_frequency and not self._pacing_enabled():
            raise ValueError("mvfst ACK_FREQUENCY treatment requires pacing enabled")
        root_dir = self._get_root_dir(self.server_path)
        run_dir = self._get_run_dir(port_no)
        qlog_dir = os.path.join(run_dir, "qlogs", "server")
        parts = [
            "cd {}".format(shlex.quote(root_dir)),
            "mkdir -p {}".format(shlex.quote(qlog_dir)),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "logs"))),
        ]

        server_cmd = [
            shlex.quote(self.server_path),
            "--mode=server",
            "--transport=quic",
            "--host={}".format(shlex.quote(self.server_ip)),
            "--port={}".format(shlex.quote(str(port_no))),
            "--congestion={}".format(
                shlex.quote(self._map_cc_algo(requested_cc))
            ),
            "--pacing={}".format("true" if self._pacing_enabled() else "false"),
            "--gso=true",
            "--num_streams=1",
        ]
        if self.server_ack_frequency:
            server_cmd.extend(
                [
                    "--ack_frequency=true",
                    "--ack_frequency_threshold={}".format(
                        self.server_ack_frequency_threshold
                    ),
                    "--ack_frequency_reordering_threshold={}".format(
                        self.server_ack_frequency_reordering_threshold
                    ),
                    "--ack_frequency_min_rtt_divisor={}".format(
                        self.server_ack_frequency_min_rtt_divisor
                    ),
                    "--ack_frequency_startup_ack2={}".format(
                        "true" if self.server_ack_frequency_startup_ack2 else "false"
                    ),
                ]
            )
        if self.qlog_enabled:
            server_cmd.append(
                "--server_qlogger_path={}".format(shlex.quote(qlog_dir))
            )

        parts.append(
            "timeout {} {}".format(int(duration_s), " ".join(server_cmd))
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

    @staticmethod
    def get_cc_algos():
        return [Mvfst.CUBIC, Mvfst.BBR, Mvfst.RENO]


class MvfstH3(Mvfst):
    """Minimal paper-v1 HTTP/3 application over the pinned mvfst transport.

    This is an experiment adapter, not an upstream mvfst application. Runtime
    validation must consume adapter/mvfst telemetry before accepting its declared
    controller or pacing identity.
    """

    NAME = "mvfst-h3"
    ADAPTER_IDENTITY = "mvfst + paper-v1 minimal H3 adapter"
    ADAPTER_KIND = "minimal-native-h3"

    def __init__(
        self,
        transport_commit,
        h3_adapter_patch_sha256,
        runtime_telemetry_required=True,
        server_response_bytes=1073741824,
        server_threads=1,
        server_batching_mode=1,
        server_batch_size=16,
        **kwargs
    ):
        kwargs["protocol"] = "http3"
        kwargs["server_ack_frequency"] = False
        super().__init__(**kwargs)
        self.transport_commit = transport_commit
        self.h3_adapter_patch_sha256 = h3_adapter_patch_sha256
        self.runtime_telemetry_required = bool(runtime_telemetry_required)
        self.server_response_bytes = int(server_response_bytes)
        self.server_threads = int(server_threads)
        self.server_batching_mode = int(server_batching_mode)
        self.server_batch_size = int(server_batch_size)
        if self.server_response_bytes < 1073741824:
            raise ValueError("paper-v1 mvfst H3 response must be at least 1 GiB")
        if self.server_threads != 1:
            raise ValueError("paper-v1 mvfst H3 requires one server thread")

    def get_server_runtime_config(self, cc_algo):
        return {
            "requested_cc": self._map_cc_algo(cc_algo),
            "active_cc": "runtime-telemetry-required",
            "fallback": "runtime-telemetry-required",
            "icw": "runtime-telemetry-required",
            "configured_pacing": "on" if self._pacing_enabled() else "off",
            "effective_pacing": "runtime-telemetry-required",
            "pacer_initialized": "runtime-telemetry-required",
            "pacing_callback_or_tick_observed": "runtime-telemetry-required",
            "gso": "enabled" if self.server_batching_mode in (1, 3) else "disabled",
            "control_source": "mvfst-paper-v1-adapter-runtime-report",
            "h3_adapter_identity": self.ADAPTER_IDENTITY,
            "h3_adapter_kind": self.ADAPTER_KIND,
            "h3_adapter_patch_sha256": self.h3_adapter_patch_sha256,
            "transport_commit": self.transport_commit,
            "workload_protocol": "http3",
            "body_counter": "client-decoded-http3-response-body-bytes",
        }

    def run_server_cmd(self, port_no, duration_s, cc_algo=None):
        requested_cc = self._map_cc_algo(cc_algo or self.CUBIC)
        if requested_cc == self.BBR and not self._pacing_enabled():
            raise ValueError("mvfst H3 BBR requires effective pacing on")
        run_dir = self._get_run_dir(port_no)
        qlog_dir = os.path.join(run_dir, "qlogs", "server")
        telemetry_path = os.path.join(run_dir, "mvfst-h3-runtime.jsonl")
        parts = [
            "cd {}".format(shlex.quote(self._get_root_dir(self.server_path))),
            "mkdir -p {}".format(shlex.quote(qlog_dir)),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "logs"))),
        ]
        command = [
            shlex.quote(self.server_path),
            "--mode=server",
            "--host={}".format(shlex.quote(self.server_ip)),
            "--port={}".format(shlex.quote(str(port_no))),
            "--protocol=h3",
            "--httpversion=3",
            "--threads=1",
            "--cert={}".format(shlex.quote(self.server_cert_path)),
            "--key={}".format(shlex.quote(self.server_key_path)),
            "--response_bytes={}".format(self.server_response_bytes),
            "--use_insecure_default_cert=false",
            "--congestion={}".format(shlex.quote(requested_cc)),
            "--pacing={}".format("true" if self._pacing_enabled() else "false"),
            "--pacing_timer_tick_interval_us=200",
            "--qlogger_path={}".format(shlex.quote(qlog_dir)),
            "--pretty_json=false",
            "--txn_timeout=120000",
            "--early_data=false",
            "--quic_batching_mode={}".format(self.server_batching_mode),
            "--quic_batch_size={}".format(self.server_batch_size),
            "--paper_v1_runtime_report={}".format(shlex.quote(telemetry_path)),
            "--paper_v1_adapter_identity={}".format(shlex.quote(self.ADAPTER_IDENTITY)),
        ]
        parts.append(
            "timeout {} {} >{} 2>{}".format(
                int(duration_s),
                " ".join(command),
                shlex.quote(os.path.join(run_dir, "logs", "server.stdout.log")),
                shlex.quote(os.path.join(run_dir, "logs", "server.stderr.log")),
            )
        )
        return [
            "sudo",
            "-n",
            "ip",
            "netns",
            "exec",
            self.server_netns,
            "bash",
            "-lc",
            " && ".join(parts),
        ]

    def get_client_target(self, port_no=None, workload=None):
        port_no = str(port_no or self.default_port)
        response_bytes = int(workload["bytes"]) if workload else self.server_response_bytes
        return {
            "protocol": "http3",
            "url": "https://{}:{}/{}".format(self.server_ip, port_no, response_bytes),
            "max_bytes": response_bytes,
        }

    @staticmethod
    def get_cc_algos():
        return [MvfstH3.RENO, MvfstH3.CUBIC, MvfstH3.BBR]
