"""Isolated Paper-v1 topology with independently observable queues."""

import os
import re
import subprocess


class TopologyError(RuntimeError):
    pass


_SAFE_NAME = re.compile(r"^qb-[a-z0-9-]{1,24}$")


class NamespaceTopology:
    """Three namespaces separating congestion queue from propagation delay."""

    def __init__(self, profile, server_namespace="qb-server", router_namespace="qb-router",
                 client_namespace="qb-client", server_interface="qb-srv",
                 router_server_interface="qb-rs", router_client_interface="qb-rc",
                 client_interface="qb-cli", server_ip="198.19.0.2",
                 router_server_ip="198.19.0.1", router_client_ip="198.19.0.5",
                 client_ip="198.19.0.6", runner=None):
        for label, value in (
            ("server namespace", server_namespace), ("router namespace", router_namespace),
            ("client namespace", client_namespace), ("server interface", server_interface),
            ("router server interface", router_server_interface),
            ("router client interface", router_client_interface),
            ("client interface", client_interface),
        ):
            if not _SAFE_NAME.fullmatch(value):
                raise TopologyError("unsafe {} name: {!r}".format(label, value))
        self.profile = dict(profile)
        self.server_namespace = server_namespace
        self.router_namespace = router_namespace
        self.client_namespace = client_namespace
        self.server_interface = server_interface
        self.router_server_interface = router_server_interface
        self.router_client_interface = router_client_interface
        self.client_interface = client_interface
        self.server_ip = server_ip
        self.router_server_ip = router_server_ip
        self.router_client_ip = router_client_ip
        self.client_ip = client_ip
        self.capture_namespace = router_namespace
        self.capture_interface = router_server_interface
        self._run = runner or self._default_run
        self._validate_profile()

    @staticmethod
    def _default_run(argv, **kwargs):
        kwargs.setdefault("check", True)
        kwargs.setdefault("text", True)
        return subprocess.run(argv, **kwargs)

    def _validate_profile(self):
        required = ("forward_bandwidth_mbps", "forward_delay_ms", "reverse_delay_ms", "queue_size_bytes")
        missing = [key for key in required if key not in self.profile]
        if missing:
            raise TopologyError("network profile missing: {}".format(", ".join(missing)))
        if self.profile.get("reverse_bottleneck") is not False:
            raise TopologyError("Paper-v1 reverse path must not be rate limited")
        for key in required:
            if float(self.profile[key]) <= 0:
                raise TopologyError("{} must be positive".format(key))
        for key in (
            "random_loss_forward_percent",
            "random_loss_reverse_percent",
            "jitter_ms",
            "intentional_reordering_percent",
        ):
            if float(self.profile.get(key, 0)) != 0:
                raise TopologyError("Paper-v1 forbids configured {}".format(key))

    @staticmethod
    def require_root():
        if os.geteuid() != 0:
            raise TopologyError("Paper-v1 runner must be started with sudo -E")

    def _ip(self, *args, **kwargs):
        return self._run(["ip", *args], **kwargs)

    def _ns(self, namespace, *argv, **kwargs):
        return self._run(["ip", "netns", "exec", namespace, *argv], **kwargs)

    def teardown(self):
        for namespace in (self.server_namespace, self.router_namespace, self.client_namespace):
            self._run(["ip", "netns", "del", namespace], check=False, text=True,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def setup(self):
        self.require_root()
        self.teardown()
        for namespace in (self.server_namespace, self.router_namespace, self.client_namespace):
            self._ip("netns", "add", namespace)
        self._ip("link", "add", self.server_interface, "type", "veth", "peer", "name", self.router_server_interface)
        self._ip("link", "add", self.router_client_interface, "type", "veth", "peer", "name", self.client_interface)
        self._ip("link", "set", self.server_interface, "netns", self.server_namespace)
        self._ip("link", "set", self.router_server_interface, "netns", self.router_namespace)
        self._ip("link", "set", self.router_client_interface, "netns", self.router_namespace)
        self._ip("link", "set", self.client_interface, "netns", self.client_namespace)
        endpoints = (
            (self.server_namespace, self.server_interface, self.server_ip),
            (self.router_namespace, self.router_server_interface, self.router_server_ip),
            (self.router_namespace, self.router_client_interface, self.router_client_ip),
            (self.client_namespace, self.client_interface, self.client_ip),
        )
        for namespace in (self.server_namespace, self.router_namespace, self.client_namespace):
            self._ns(namespace, "ip", "link", "set", "lo", "up")
        for namespace, interface, address in endpoints:
            self._ns(namespace, "ip", "addr", "add", address + "/30", "dev", interface)
            self._ns(namespace, "ip", "link", "set", "dev", interface, "mtu", "1500", "up")
            self._ns(namespace, "ethtool", "-K", interface, "gro", "off", "gso", "off", "tso", "off",
                     "lro", "off", "tx-udp-segmentation", "off")
        self._ns(self.router_namespace, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
        self._ns(self.server_namespace, "ip", "route", "add", "default", "via", self.router_server_ip)
        self._ns(self.client_namespace, "ip", "route", "add", "default", "via", self.router_client_ip)
        self.apply_profile()
        self.warmup()

    def warmup(self):
        self._ns(self.client_namespace, "ping", "-c", "2", "-i", "0.1", "-W", "1", self.server_ip,
                 stdout=subprocess.DEVNULL)

    def apply_profile(self):
        p = self.profile
        rate = "{}mbit".format(p["forward_bandwidth_mbps"])
        queue = str(int(p["queue_size_bytes"]))
        burst = max(1500, int(float(p["forward_bandwidth_mbps"]) * 1_000_000 / 8 / 250))
        # The sole rate limiter and byte-bounded congestion queue.
        self._ns(self.server_namespace, "tc", "qdisc", "replace", "dev", self.server_interface,
                 "root", "handle", "1:", "tbf", "rate", rate, "burst", str(burst), "limit", queue)
        forward = ["tc", "qdisc", "replace", "dev", self.router_client_interface, "root", "handle", "10:",
                   "netem", "delay", "{}ms".format(p["forward_delay_ms"])]
        forward.extend(["limit", "100000"])
        self._ns(self.router_namespace, *forward)
        self._ns(self.client_namespace, "tc", "qdisc", "replace", "dev", self.client_interface, "root",
                 "handle", "20:", "netem", "delay", "{}ms".format(p["reverse_delay_ms"]), "limit", "100000")

    def snapshot(self):
        result = {}
        for role, namespace, interface in (
            ("bottleneck", self.server_namespace, self.server_interface),
            ("forward_delay", self.router_namespace, self.router_client_interface),
            ("reverse_delay", self.client_namespace, self.client_interface),
        ):
            qdisc = self._ns(namespace, "tc", "-s", "-j", "qdisc", "show", "dev", interface, capture_output=True)
            address = self._ns(namespace, "ip", "-j", "addr", "show", "dev", interface, capture_output=True)
            route = self._ns(namespace, "ip", "-j", "route", "show", capture_output=True)
            offload = self._ns(namespace, "ethtool", "-k", interface, capture_output=True)
            result[role] = {"namespace": namespace, "interface": interface, "qdisc_json": qdisc.stdout,
                            "address_json": address.stdout, "route_json": route.stdout,
                            "offload_text": offload.stdout}
        return result
