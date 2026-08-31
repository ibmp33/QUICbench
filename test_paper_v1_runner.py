import json
import os
import tempfile
import unittest

from paper_v1.runner import PaperV1Runner, _path_for_run
from paper_v1.evidence import derive_sender, saturation_threshold


ROOT = os.path.dirname(os.path.abspath(__file__))
MATRIX = os.path.join(ROOT, "configs", "paper-v1", "matrix.json")
POLICY = os.path.join(ROOT, "specs", "receiver_ack_policy_v1.json")


class PaperV1RunnerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        cert = os.path.join(self.temp.name, "cert.pem")
        key = os.path.join(self.temp.name, "key.pem")
        for path in (cert, key):
            with open(path, "w", encoding="utf-8") as artifact:
                artifact.write("test\n")
        config = {
            "dataset_root": os.path.join(self.temp.name, "dataset"),
            "binaries": {
                "receiver": "/bin/true",
                "quic-go": "/bin/true",
                "quiche": "/bin/true",
                "xquic": "/bin/true",
                "mvfst-h3": "/bin/true",
            },
            "tls": {"cert": cert, "key": key, "server_name": "server"},
            "network": {"server_ip": "198.19.0.2", "client_local_ports": [54433, 54434]},
        }
        self.config_path = os.path.join(self.temp.name, "local.json")
        with open(self.config_path, "w", encoding="utf-8") as artifact:
            json.dump(config, artifact)
        self.runner = PaperV1Runner(self.config_path, MATRIX, POLICY)

    def tearDown(self):
        self.temp.cleanup()

    def test_all_sender_commands_are_h3_and_use_one_gibibyte(self):
        for path in self.runner.matrix["paths"]:
            run_dir = os.path.join(self.temp.name, path["path_id"])
            os.makedirs(run_dir)
            command, _, _ = self.runner._server_command(path, run_dir, 4433, 1073741824)
            joined = " ".join(command)
            if path["sender"] == "xquic":
                self.assertIn("--paper-v1-body-bytes 1073741824", joined)
            elif path["sender"] == "mvfst":
                self.assertIn("--response_bytes=1073741824", joined)
            else:
                self.assertIn("HTTP/3", joined) if path["sender"] == "quiche" else self.assertIn("-root", command)
            if path["sender"] == "quiche":
                self.assertIn("--paper-v1-runtime-report", command)
                self.assertFalse(os.path.exists(os.path.join(run_dir, "server-root", "1073741824")))

    def test_receiver_command_requires_keylog_and_exact_policy_identity(self):
        planned, path, _ = _path_for_run(
            self.runner.matrix,
            "xquic__cubic__pacing-off--neqo-like-ack__chrome-like-ack--r01",
        )
        command = self.runner._client_command(
            "flow_b", planned["policy_pair"][1], self.temp.name, 4433, 5, 1073741824, path, 1234
        )
        joined = " ".join(command)
        self.assertIn("-ack-policy chrome-like-ack", joined)
        self.assertIn("-keylog", command)
        self.assertIn("-initial-dcid-length 16", joined)
        self.assertIn("-initial-stream-receive-window 134217728", joined)
        self.assertIn("-max-connection-receive-window 134217728", joined)
        self.assertIn("test.xquic.com", command)
        self.assertIn("54434", command)

    def test_quiche_client_uses_bounded_paper_v1_route(self):
        planned, path, _ = _path_for_run(
            self.runner.matrix,
            "quiche__cubic__effectively-unpaced--neqo-like-ack__neqo-like-ack--r01",
        )
        command = self.runner._client_command(
            "flow_a", planned["policy_pair"][0], self.temp.name, 4433, 5,
            1073741824, path, 1234,
        )
        self.assertIn("https://198.19.0.2:4433/paper-v1/1073741824", command)

    def test_smoke_gate_does_not_change_paper_admission_threshold(self):
        self.assertEqual(saturation_threshold(True), 0.85)
        self.assertEqual(saturation_threshold(False), 0.90)

    def test_xquic_sender_identity_is_derived_from_transport_log(self):
        raw = os.path.join(self.temp.name, "sender-runtime-initial.jsonl")
        with open(raw, "w", encoding="utf-8") as artifact:
            artifact.write('{"event":"sender_initialized"}\n')
        slog = os.path.join(self.temp.name, "xquic-server.slog")
        event = (
            "|paper_v1_transport_initialized|active_cc:bbr|configured_pacing:0|"
            "effective_pacing:1|pacer_initialized:1|initial_cwnd_packets:32|\n"
        )
        with open(slog, "w", encoding="utf-8") as artifact:
            artifact.write(event + event + "|PACING timer update|delay:1000|\n")
        result = derive_sender(self.temp.name, {"requested": {"sender": {
            "sender": "xquic", "cc": "bbr-family", "binary_sha256": "a" * 64,
        }}})
        self.assertEqual(result["active_cc"], "bbr")
        self.assertFalse(result["fallback"])
        self.assertEqual(result["configured_pacing"], "off")
        self.assertEqual(result["effective_pacing"], "paced")
        self.assertTrue(result["pacing_callback_or_tick_observed"])
        self.assertEqual(result["direct_event_counts"]["transport_initialized"], 2)

    def test_quiche_sender_identity_is_derived_per_connection(self):
        raw = os.path.join(self.temp.name, "sender-runtime-initial.jsonl")
        event = {
            "schema": "sender-runtime-v1.0.0",
            "event": "transport_initialized",
            "sender": "quiche",
            "connection_id": "abc",
            "active_cc": "cubic",
            "configured_pacing": False,
            "effective_pacing": False,
            "initial_congestion_window_packets": 10,
        }
        with open(raw, "w", encoding="utf-8") as artifact:
            artifact.write(json.dumps(event) + "\n")
            event["connection_id"] = "def"
            artifact.write(json.dumps(event) + "\n")
        result = derive_sender(self.temp.name, {"requested": {"sender": {
            "sender": "quiche", "cc": "cubic", "requested_pacing": "off",
            "binary_sha256": "b" * 64,
        }}})
        self.assertEqual(result["active_cc"], "cubic")
        self.assertEqual(result["effective_pacing"], "effectively_unpaced")
        self.assertFalse(result["fallback"])
        self.assertEqual(result["direct_event_counts"]["transport_initialized"], 2)

    def test_mvfst_paced_identity_requires_two_live_pacer_events(self):
        raw = os.path.join(self.temp.name, "sender-runtime-initial.jsonl")
        with open(raw, "w", encoding="utf-8") as artifact:
            artifact.write(json.dumps({
                "event": "server_config",
                "adapter_identity": "mvfst + paper-v1 minimal H3 adapter",
            }) + "\n")
        stderr = os.path.join(self.temp.name, "server.stderr.log")
        events = []
        for connection in ("a", "b"):
            events.extend([
                ("PAPER_V1_TRANSPORT_EVENT ", {
                    "event": "transport_ready", "active_cc": "bbr",
                    "configured_pacing": True, "fallback": False,
                }),
                ("PAPER_V1_PACING_EVENT ", {
                    "event": "pacer_initialized", "looper_id": connection,
                }),
                ("PAPER_V1_PACING_EVENT ", {
                    "event": "pacing_timer_fired", "looper_id": connection,
                }),
                ("PAPER_V1_TRANSPORT_SAMPLE ", {
                    "pacing_burst_size": 10, "pacing_interval_us": 100,
                }),
            ])
        events.append(("PAPER_V1_SERVER_CONFIG ", {"icw_mss": 10}))
        with open(stderr, "w", encoding="utf-8") as artifact:
            for marker, event in events:
                artifact.write("prefix " + marker + json.dumps(event) + "\n")
        result = derive_sender(self.temp.name, {"requested": {"sender": {
            "sender": "mvfst", "cc": "bbr", "requested_pacing": "on",
            "binary_sha256": "c" * 64,
            "adapter_kind": "minimal-native-h3",
            "adapter_patch_sha256": "d" * 64,
            "transport_commit": "e" * 40,
            "patch_commit": "f" * 40,
        }}})
        self.assertEqual(result["effective_pacing"], "paced")
        self.assertTrue(result["pacer_initialized"])
        self.assertTrue(result["pacing_callback_or_tick_observed"])
        self.assertEqual(result["direct_event_counts"]["pacing_timer_fired"], 2)


if __name__ == "__main__":
    unittest.main()
