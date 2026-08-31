import json
import os
import tempfile
import unittest

from paper_v1.wire import (
    _align_pcap,
    _emission_timing,
    _parse_pcap_ack_rows,
    _qlog_acks,
    _tool_command,
    _validation_window,
)


class PaperV1WireTest(unittest.TestCase):
    def test_emission_timing_removes_clock_origin_and_bounds_scheduler_jitter(self):
        policy = [
            {"monotonic_time_ns": 5_000_000_000},
            {"monotonic_time_ns": 5_010_000_000},
            {"monotonic_time_ns": 5_020_000_000},
        ]
        qlog = [
            {"time_ns": 5_061_000_000},
            {"time_ns": 5_071_100_000},
            {"time_ns": 5_080_900_000},
        ]
        valid, residuals, origin = _emission_timing(policy, qlog, limit_ns=1_000_000)
        self.assertTrue(valid)
        self.assertEqual(origin, 61_000_000)
        self.assertEqual(residuals, [0, 100_000, -100_000])

        qlog[-1]["time_ns"] += 2_000_000
        valid, _, _ = _emission_timing(policy, qlog, limit_ns=1_000_000)
        self.assertFalse(valid)

    def test_tool_command_supports_pinned_container_prefix(self):
        prefix = ["docker", "run", "--rm", "image@sha256:abc"]
        self.assertEqual(_tool_command(prefix, "--version"), prefix + ["--version"])

    def test_qlog_batches_and_pcap_alignment_skip_coalesced_handshake_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "client.sqlog")
            events = [
                {"time": 10.0, "name": "transport:packet_sent", "data": {
                    "header": {"packet_type": "1RTT"},
                    "frames": [{"frame_type": "ack", "ack_delay": 0.792,
                                "acked_ranges": [[0, 1]]}]}},
                {"time": 12.0, "name": "transport:packet_sent", "data": {
                    "header": {"packet_type": "1RTT"},
                    "frames": [{"frame_type": "ack", "ack_delay": 0.080,
                                "acked_ranges": [[11], [2, 10]]}]}},
            ]
            with open(path, "w", encoding="utf-8") as artifact:
                for event in events:
                    artifact.write("\x1e" + json.dumps(event) + "\n")
            qlog = _qlog_acks(path)
            self.assertEqual([item["batch"] for item in qlog], [2, 10])
            pcap = [
                {"time_ns": 1, "largest": 1, "ack_delay_ns": 0},
                {"time_ns": 2, "largest": 1, "ack_delay_ns": 792000},
                {"time_ns": 3, "largest": 11, "ack_delay_ns": 80000},
            ]
            aligned = _align_pcap(qlog, pcap)
            self.assertEqual([item["time_ns"] for item in aligned], [2, 3])

    def test_pcap_parser_handles_coalesced_ack_fields(self):
        rows = _parse_pcap_ack_rows("1.250000000\t7,6\t2,3\n")
        self.assertEqual([item["largest"] for item in rows], [7, 6])
        self.assertEqual([item["ack_delay_ns"] for item in rows], [16000, 24000])

    def test_smoke_wire_window_has_terminal_guard_but_paper_window_does_not(self):
        manifest = {"runtime_reported": {"smoke": True, "workload": {
            "measurement_window_start_s": 0, "measurement_window_end_s": 5,
        }}}
        self.assertEqual(_validation_window(manifest), (0, 4_900_000_000, 100_000_000))
        manifest["runtime_reported"].update({"smoke": False, "workload": {
            "measurement_window_start_s": 5, "measurement_window_end_s": 25,
        }})
        self.assertEqual(_validation_window(manifest), (5_000_000_000, 25_000_000_000, 0))


if __name__ == "__main__":
    unittest.main()
