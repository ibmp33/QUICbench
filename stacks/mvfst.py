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
