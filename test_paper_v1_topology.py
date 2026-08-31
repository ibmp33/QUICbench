import unittest
from unittest import mock

from paper_v1.topology import NamespaceTopology, TopologyError


BASE = {
    "forward_bandwidth_mbps": 20,
    "forward_delay_ms": 25,
    "reverse_delay_ms": 25,
    "reverse_bottleneck": False,
    "queue_size_bytes": 125000,
    "random_loss_forward_percent": 0,
    "random_loss_reverse_percent": 0,
}


class PaperV1TopologyTest(unittest.TestCase):
    def test_rejects_unsafe_targets_and_reverse_bottleneck(self):
        with self.assertRaises(TopologyError):
            NamespaceTopology(BASE, server_namespace="/")
        profile = dict(BASE, reverse_bottleneck=True)
        with self.assertRaises(TopologyError):
            NamespaceTopology(profile)

    @mock.patch("paper_v1.topology.os.geteuid", return_value=0)
    def test_builds_one_forward_bottleneck_and_delay_only_reverse(self, _geteuid):
        calls = []

        def record(argv, **kwargs):
            calls.append(argv)
            return mock.Mock(stdout="[]")

        topology = NamespaceTopology(BASE, runner=record)
        topology.setup()
        joined = [" ".join(command) for command in calls]
        forward_tbf = [command for command in joined if "qb-server tc qdisc" in command and " tbf " in command]
        reverse_tbf = [command for command in joined if "qb-client tc qdisc" in command and " tbf " in command]
        self.assertEqual(len(forward_tbf), 1)
        self.assertIn("rate 20mbit", forward_tbf[0])
        self.assertIn("limit 125000b", forward_tbf[0])
        self.assertEqual(reverse_tbf, [])
        self.assertTrue(any("qb-client tc qdisc" in command and "delay 25ms" in command for command in joined))

    def test_optional_loss_is_forward_only(self):
        calls = []
        profile = dict(BASE, random_loss_forward_percent=0.1)
        topology = NamespaceTopology(profile, runner=lambda argv, **kwargs: calls.append(argv) or mock.Mock(stdout="[]"))
        topology.apply_profile()
        joined = [" ".join(command) for command in calls]
        self.assertTrue(any("qb-server" in command and "loss random 0.1%" in command for command in joined))
        self.assertFalse(any("qb-client" in command and "loss random" in command for command in joined))


if __name__ == "__main__":
    unittest.main()
