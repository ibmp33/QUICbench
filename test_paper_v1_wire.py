import json
import os
import tempfile
import unittest

from paper_v1.wire import _align_pcap, _qlog_acks


class PaperV1WireTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
