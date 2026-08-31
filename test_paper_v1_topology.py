import unittest
from unittest import mock

from paper_v1.topology import NamespaceTopology, TopologyError


BASE = {
    "forward_bandwidth_mbps": 20,
    "forward_delay_ms": 25,
    "reverse_delay_ms": 25,
    "reverse_bottleneck": False,
    "queue_size_bytes": 62500,
    "random_loss_forward_percent": 0,
    "random_loss_reverse_percent": 0,
    "jitter_ms": 0,
    "intentional_reordering_percent": 0,
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
        all_tbf = [command for command in joined if " tc qdisc" in command and " tbf " in command]
        self.assertEqual(len(forward_tbf), 1)
        self.assertEqual(all_tbf, forward_tbf)
        self.assertIn("root handle 1: tbf", forward_tbf[0])
        self.assertIn("rate 20mbit", forward_tbf[0])
        self.assertIn("limit 62500", forward_tbf[0])
        self.assertTrue(any("qb-router tc qdisc" in command and "delay 25ms" in command for command in joined))
        self.assertTrue(any("qb-client tc qdisc" in command and "delay 25ms" in command for command in joined))
        self.assertTrue(any("qb-router sysctl -q -w net.ipv4.ip_forward=1" in command for command in joined))
        self.assertTrue(any("qb-client ping -c 2" in command for command in joined))

    def test_rejects_every_active_impairment(self):
        for field, value in (
            ("random_loss_forward_percent", 0.1),
            ("random_loss_reverse_percent", 0.1),
            ("jitter_ms", 1),
            ("intentional_reordering_percent", 1),
        ):
            with self.subTest(field=field):
                with self.assertRaises(TopologyError):
                    NamespaceTopology(dict(BASE, **{field: value}))


if __name__ == "__main__":
    unittest.main()
