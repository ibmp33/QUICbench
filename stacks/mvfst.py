import os
import shlex
import subprocess

from stacks.quic_go import QuicGo


class Mvfst(QuicGo):
    NAME = "mvfst"
    CUBIC = "cubic"
    BBR = "bbr"
    RENO = "newreno"

    def get_server_runtime_config(self, cc_algo):
        return {
            "cc": cc_algo,
            "requested_cc": cc_algo,
            "icw": "implementation-default",
            "pacing": "disabled",
            "gso": "enabled",
            "control_source": "server-command-line",
        }

    def run_remote_server(self, port_no, cc_algo, duration_s):
        cmd = self.run_server_cmd(port_no, duration_s, cc_algo=cc_algo)
        return subprocess.Popen(cmd)

    def run_server_cmd(self, port_no, duration_s, cc_algo=None):
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
            "--congestion={}".format(shlex.quote(cc_algo or self.CUBIC)),
            "--pacing=false",
            "--gso=true",
            "--num_streams=1",
        ]

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
