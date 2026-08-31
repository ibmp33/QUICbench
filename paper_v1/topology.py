"""Isolated two-flow Paper-v1 network topology.

The server and both receivers live in dedicated network namespaces connected
by one veth pair.  The server egress qdisc is therefore the single shared data
bottleneck; the client egress qdisc delays ACKs without rate limiting them.
"""

import os
import re
import subprocess


class TopologyError(RuntimeError):
    pass


_SAFE_NAME = re.compile(r"^qb-[a-z0-9-]{1,24}$")


class NamespaceTopology:
    def __init__(
        self,
        profile,
        server_namespace="qb-server",
        client_namespace="qb-client",
        server_interface="qb-srv",
        client_interface="qb-cli",
        server_ip="198.19.0.2",
        client_ip="198.19.0.1",
        runner=None,
    ):
        for label, value in (
            ("server namespace", server_namespace),
            ("client namespace", client_namespace),
            ("server interface", server_interface),
            ("client interface", client_interface),
        ):
            if not _SAFE_NAME.fullmatch(value):
                raise TopologyError("unsafe {} name: {!r}".format(label, value))
        self.profile = dict(profile)
        self.server_namespace = server_namespace
        self.client_namespace = client_namespace
        self.server_interface = server_interface
        self.client_interface = client_interface
        self.server_ip = server_ip
        self.client_ip = client_ip
        self._run = runner or self._default_run
        self._validate_profile()

    @staticmethod
    def _default_run(argv, **kwargs):
        kwargs.setdefault("check", True)
        kwargs.setdefault("text", True)
        return subprocess.run(argv, **kwargs)

    def _validate_profile(self):
        required = (
            "forward_bandwidth_mbps",
            "forward_delay_ms",
            "reverse_delay_ms",
            "queue_size_bytes",
        )
        missing = [key for key in required if key not in self.profile]
        if missing:
            raise TopologyError("network profile missing: {}".format(", ".join(missing)))
        if self.profile.get("reverse_bottleneck") is not False:
            raise TopologyError("Paper-v1 reverse path must not be rate limited")
        for key in required:
            if float(self.profile[key]) <= 0:
                raise TopologyError("{} must be positive".format(key))
        if float(self.profile.get("random_loss_reverse_percent", 0)) != 0:
            raise TopologyError("Paper-v1 reverse random loss must be zero")

    @staticmethod
    def require_root():
        if os.geteuid() != 0:
            raise TopologyError("Paper-v1 runner must be started with sudo -E")

    def _ip(self, *args, **kwargs):
        return self._run(["ip", *args], **kwargs)

    def _ns(self, namespace, *argv, **kwargs):
        return self._run(["ip", "netns", "exec", namespace, *argv], **kwargs)

    def teardown(self):
        # Namespace deletion also removes the named veth endpoint. Targets are
        # constructor-validated fixed names; no glob or broad interface is used.
        for namespace in (self.server_namespace, self.client_namespace):
            self._run(
                ["ip", "netns", "del", namespace],
                check=False,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    def setup(self):
        self.require_root()
        self.teardown()
        self._ip("netns", "add", self.server_namespace)
        self._ip("netns", "add", self.client_namespace)
        self._ip(
            "link", "add", self.server_interface, "type", "veth", "peer", "name", self.client_interface
        )
        self._ip("link", "set", self.server_interface, "netns", self.server_namespace)
        self._ip("link", "set", self.client_interface, "netns", self.client_namespace)
        for namespace, interface, address in (
            (self.server_namespace, self.server_interface, self.server_ip),
            (self.client_namespace, self.client_interface, self.client_ip),
        ):
            self._ns(namespace, "ip", "link", "set", "lo", "up")
            self._ns(namespace, "ip", "addr", "add", address + "/30", "dev", interface)
            self._ns(namespace, "ip", "link", "set", "dev", interface, "mtu", "1500", "up")
            self._ns(
                namespace,
                "ethtool",
                "-K",
                interface,
                "gro",
                "off",
                "gso",
                "off",
                "tso",
                "off",
                "lro",
                "off",
                "tx-udp-segmentation",
                "off",
            )
        self.apply_profile()

    def apply_profile(self):
        p = self.profile
        rate = "{}mbit".format(p["forward_bandwidth_mbps"])
        queue = str(int(p["queue_size_bytes"]))
        burst = max(1500, int(float(p["forward_bandwidth_mbps"]) * 1_000_000 / 8 / 250))
        # TBF must be the root. Putting TBF below netem adds roughly one TBF
        # latency interval to the first packet after idle on Linux, turning the
        # requested 50 ms RTT into about 100 ms in the base profile.
        self._ns(
            self.server_namespace,
            "tc", "qdisc", "replace", "dev", self.server_interface,
            "root", "handle", "1:", "tbf",
            "rate", rate, "burst", str(burst), "limit", queue,
        )
        forward_netem = [
            "tc", "qdisc", "replace", "dev", self.server_interface,
            "parent", "1:1", "handle", "10:", "netem",
            "delay", "{}ms".format(p["forward_delay_ms"]),
        ]
        forward_loss = float(p.get("random_loss_forward_percent", 0))
        if forward_loss:
            forward_netem.extend(["loss", "random", "{}%".format(forward_loss)])
        forward_netem.extend(["limit", "100000"])
        self._ns(self.server_namespace, *forward_netem)
        self._ns(
            self.client_namespace,
            "tc", "qdisc", "replace", "dev", self.client_interface,
            "root", "handle", "2:", "netem",
            "delay", "{}ms".format(p["reverse_delay_ms"]), "limit", "100000",
        )

    def snapshot(self):
        result = {}
        for role, namespace, interface in (
            ("forward", self.server_namespace, self.server_interface),
            ("reverse", self.client_namespace, self.client_interface),
        ):
            qdisc = self._ns(
                namespace, "tc", "-s", "-j", "qdisc", "show", "dev", interface,
                capture_output=True,
            )
            address = self._ns(namespace, "ip", "-j", "addr", "show", "dev", interface, capture_output=True)
            route = self._ns(namespace, "ip", "-j", "route", "show", capture_output=True)
            offload = self._ns(namespace, "ethtool", "-k", interface, capture_output=True)
            result[role] = {
                "namespace": namespace,
                "interface": interface,
                "qdisc_json": qdisc.stdout,
                "address_json": address.stdout,
                "route_json": route.stdout,
                "offload_text": offload.stdout,
            }
        return result
