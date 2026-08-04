import os
import shlex
import subprocess

from stacks.stack import Stack


class Xquic(Stack):
    NAME = "xquic"
    CUBIC = "cubic"
    RENO = "reno"

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
        server_pacing=True,
        server_gso="implementation-default",
        workload_capabilities=None,
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
        self.server_pacing = bool(server_pacing)
        self.server_gso = server_gso
        self.workload_capabilities = workload_capabilities or {}
        self.run_root = None
        self.qlog_enabled = False

    def run_remote_server(self, port_no, cc_algo, duration_s):
        cmd = self.run_server_cmd(port_no, duration_s, cc_algo=cc_algo)
        return subprocess.Popen(cmd)

    def run_client(self, port_no, cc_algo, duration_s):
        cmd = self.run_client_cmd(port_no, duration_s, cc_algo=cc_algo)
        return subprocess.Popen(cmd, shell=True)

    def run_server_cmd(self, port_no, duration_s, cc_algo=None):
        root_dir = self._get_root_dir(self.server_path)
        run_dir = self._get_run_dir(port_no)
        server_addr = self._get_server_addr(port_no)
        cc_algo = cc_algo or self.CUBIC

        parts = [
            "cd {}".format(shlex.quote(root_dir)),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "qlogs", "server"))),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "logs"))),
        ]

        server_cmd = [
            shlex.quote(self.server_path),
            "-a",
            shlex.quote(self.server_ip),
            "-p",
            shlex.quote(str(port_no)),
            "-c",
            shlex.quote(self._map_cc_algo(cc_algo)),
            "-r",
            "index.txt",
            "-o",
            "xquic-server.slog",
        ]
        if self.server_pacing:
            server_cmd.append("-C")

        parts.append(
            "timeout {} {}".format(int(duration_s), " ".join(server_cmd))
            + " >{} 2>{} </dev/null".format(
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
            "cc": cc_algo,
            "requested_cc": cc_algo,
            "icw": "implementation-default",
            "pacing": "enabled" if self.server_pacing else "disabled",
            "gso": self.server_gso,
            "control_source": "server-command-line",
        }

    def run_client_cmd(self, port_no, duration_s, cc_algo=None):
        root_dir = self._get_root_dir(self.client_path)
        run_dir = self._get_run_dir(port_no)
        client_url = self._get_client_url(port_no)
        client_timeout = self._get_client_timeout(duration_s)
        cc_algo = cc_algo or self.CUBIC

        parts = [
            "cd {}".format(shlex.quote(root_dir)),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "qlogs", "client"))),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "stdout"))),
            "mkdir -p {}".format(shlex.quote(os.path.join(run_dir, "logs"))),
        ]

        client_cmd = [
            shlex.quote(self.client_path),
            "-a",
            shlex.quote(self.server_ip),
            "-p",
            shlex.quote(str(port_no)),
            "-U",
            shlex.quote(client_url),
            "-A",
            "h3",
            "-c",
            shlex.quote(self._map_cc_algo(cc_algo)),
            "-t",
            shlex.quote(str(self._get_client_timeout_seconds(duration_s))),
            "-D",
            shlex.quote(os.path.join(run_dir, "stdout")),
        ]
        if self.qlog_enabled:
            client_cmd.extend(
                [
                    "-C",
                    "-L",
                    shlex.quote(os.path.join(run_dir, "qlogs", "client")),
                ]
            )

        parts.append(
            "timeout {} {}".format(
                shlex.quote(client_timeout),
                " ".join(client_cmd),
            )
            + " >{} 2>{} </dev/null".format(
                shlex.quote(os.path.join(run_dir, "logs", "client.stdout.log")),
                shlex.quote(os.path.join(run_dir, "logs", "client.stderr.log")),
            )
        )
        parts.append(self._build_client_output_normalize_cmd(run_dir))

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

    def _get_client_timeout(self, duration_s):
        if self.client_timeout:
            return self.client_timeout
        return "{}s".format(int(duration_s))

    def get_client_target(self, port_no=None, workload=None):
        port_no = str(port_no or self.default_port)
        if not port_no or port_no == "None":
            raise ValueError("no port supplied for stack '{}'".format(self.NAME))
        target = {
            "protocol": self.protocol,
            "url": self._get_client_url(port_no, workload=workload),
        }
        if self.client_server_name:
            target["server_name"] = self.client_server_name
        if workload:
            target["max_bytes"] = int(workload["bytes"])
        return target

    def _get_client_timeout_seconds(self, duration_s):
        timeout_value = self._get_client_timeout(duration_s)
        if isinstance(timeout_value, int):
            return timeout_value
        if isinstance(timeout_value, str) and timeout_value.endswith("s"):
            return int(timeout_value[:-1])
        return int(timeout_value)

    def _map_cc_algo(self, cc_algo):
        mapping = {
            self.CUBIC: "c",
            self.RENO: "r",
            "bbr": "b",
            "copa": "P",
        }
        return mapping.get(cc_algo, "c")

    def _build_client_output_normalize_cmd(self, run_dir):
        output_dir = os.path.join(run_dir, "stdout")
        canonical_output = os.path.join(output_dir, "client.body.bin")
        return (
            "if [ ! -f {canonical} ]; then "
            "for candidate in {output_dir}/*; do "
            "if [ -f \"$candidate\" ] && [ \"$candidate\" != {canonical} ]; then "
            "cp \"$candidate\" {canonical}; "
            "break; "
            "fi; "
            "done; "
            "fi"
        ).format(
            canonical=shlex.quote(canonical_output),
            output_dir=shlex.quote(output_dir),
        )

    @staticmethod
    def get_cc_algos():
        return [Xquic.CUBIC, Xquic.RENO]
