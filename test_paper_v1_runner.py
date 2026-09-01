import json
import os
import tempfile
import unittest

from paper_v1.runner import (
    PaperV1Runner,
    RunError,
    _path_for_run,
    _transport_log_path,
    validate_storage,
)
from paper_v1.smoke import SmokeSuiteError, _valid_existing_attempt, smoke_plan
from paper_v1.corpus import CorpusError, corpus_plan
from paper_v1.build_identity import _toolchain_identity, git_identity
from paper_v1.matrix import load_matrix
from paper_v1.evidence import (
    _qdisc_counter_deltas,
    derive_sender,
    measurement_window,
    saturation_threshold,
)


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

    def test_corpus_path_filter_supports_isolated_icw_sensitivity(self):
        matrix = load_matrix(MATRIX)
        runs = corpus_plan(matrix, ["quic-go__cubic__default-pacer"])
        self.assertEqual(len(runs), 40)
        self.assertEqual(
            {run["path_id"] for run in runs},
            {"quic-go__cubic__default-pacer"},
        )
        with self.assertRaises(CorpusError):
            corpus_plan(matrix, ["missing-path"])

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

    def test_storage_gate_allows_tmp_only_for_smoke(self):
        config = {"dataset_root": "/tmp", "storage": {"minimum_free_bytes": 1}}
        evidence = validate_storage(config, smoke=True)
        self.assertEqual(evidence["minimum_free_bytes"], 1)
        with self.assertRaisesRegex(RunError, "volatile storage"):
            validate_storage(config, smoke=False)

    def test_formal_storage_gate_requires_explicit_reserve(self):
        durable_root = os.path.join("/private", "tmp", os.path.basename(self.temp.name))
        with self.assertRaisesRegex(RunError, "storage.minimum_free_bytes"):
            validate_storage({"dataset_root": durable_root}, smoke=False)

    def test_qdisc_counter_deltas_are_derived_from_snapshots(self):
        def snapshot(value):
            qdisc = json.dumps([{
                "kind": "tbf", "handle": "1:", "root": True,
                "bytes": value * 100, "packets": value * 10,
                "drops": value, "overlimits": value * 2,
                "requeues": 0, "backlog": value * 3, "qlen": value,
            }])
            return {
                role: {"qdisc_json": qdisc}
                for role in ("bottleneck", "forward_delay", "reverse_delay")
            }

        deltas = _qdisc_counter_deltas(snapshot(1), snapshot(3), snapshot(6))
        bottleneck = deltas["bottleneck"]
        self.assertEqual(bottleneck["before_to_active"][0]["delta"]["drops"], 2)
        self.assertEqual(bottleneck["active_to_after"][0]["delta"]["packets"], 30)
        self.assertEqual(bottleneck["before_to_after"][0]["delta"]["bytes"], 500)
        self.assertEqual(bottleneck["before_to_after"][0]["end_backlog_bytes"], 18)

    def test_smoke_plan_covers_each_path_and_policy_pair_once(self):
        runs = smoke_plan(self.runner.matrix)
        self.assertEqual(len(runs), 44)
        self.assertEqual(len({run["run_id"] for run in runs}), 44)
        selected = smoke_plan(self.runner.matrix, ["xquic__cubic__pacing-off"])
        self.assertEqual(len(selected), 4)
        with self.assertRaisesRegex(SmokeSuiteError, "unknown path IDs"):
            smoke_plan(self.runner.matrix, ["not-a-path"])

    def test_build_identity_records_concrete_toolchain_versions(self):
        identity = _toolchain_identity()
        self.assertIn("platform", identity)
        self.assertIn("python", identity)
        self.assertIn("cc", identity)
        if identity["cc"] is not None:
            self.assertTrue(identity["cc"]["path"].startswith("/"))
            self.assertIsInstance(identity["cc"]["version"], str)

    def test_git_identity_returns_current_source_identity(self):
        identity = git_identity(ROOT)
        self.assertEqual(len(identity["commit"]), 40)
        self.assertIn("source_tree_identity", identity)
        self.assertIsInstance(identity["dirty"], bool)

    def test_smoke_resume_only_accepts_completed_valid_attempt(self):
        dataset = os.path.join(self.temp.name, "resume-dataset")
        run_id = "one-run"
        invalid = os.path.join(dataset, run_id, "attempt-invalid")
        valid = os.path.join(dataset, run_id, "attempt-valid")
        os.makedirs(invalid)
        os.makedirs(valid)
        expected = {
            "sender_path": {"sender": "xquic", "cc": "cubic"},
            "sender_binary_sha256": "sender-hash",
            "receiver_binary_sha256": "receiver-hash",
            "network_profile": {"queue_size_bytes": 62500},
            "workload": {"duration_s": 30},
            "policies": [
                {"name": "neqo-like-ack", "spec_sha256": "neqo-hash"},
                {"name": "chrome-like-ack", "spec_sha256": "chrome-hash"},
            ],
        }
        with open(os.path.join(invalid, "validation.json"), "w", encoding="utf-8") as artifact:
            json.dump({"status": "completed_invalid", "smoke_valid": False}, artifact)
        with open(os.path.join(valid, "validation.json"), "w", encoding="utf-8") as artifact:
            json.dump({"status": "completed_valid", "smoke_valid": True}, artifact)
        manifest = {
            "state": "completed_valid",
            "run_id": run_id,
            "requested": {
                "sender": {"sender": "xquic", "cc": "cubic", "binary_sha256": "sender-hash"},
                "receiver_binary_sha256": "receiver-hash",
                "network_profile": {"queue_size_bytes": 62500},
                "workload": {"duration_s": 30, "smoke": True},
                "flows": [
                    {"policy": "neqo-like-ack", "policy_spec_sha256": "neqo-hash"},
                    {"policy": "chrome-like-ack", "policy_spec_sha256": "chrome-hash"},
                ],
            },
        }
        with open(os.path.join(valid, "run_manifest.json"), "w", encoding="utf-8") as artifact:
            json.dump(manifest, artifact)
        with open(os.path.join(valid, "network-evidence.json"), "w", encoding="utf-8") as artifact:
            json.dump({"schema_version": "network-evidence-v1.1.0"}, artifact)
        self.assertEqual(_valid_existing_attempt(dataset, run_id, expected), valid)
        manifest["requested"]["network_profile"]["queue_size_bytes"] = 125000
        with open(os.path.join(valid, "run_manifest.json"), "w", encoding="utf-8") as artifact:
            json.dump(manifest, artifact)
        self.assertIsNone(_valid_existing_attempt(dataset, run_id, expected))

    def test_transport_log_role_only_exists_for_log_derived_senders(self):
        self.assertIsNone(_transport_log_path("quic-go", self.temp.name))
        self.assertIsNone(_transport_log_path("quiche", self.temp.name))
        self.assertEqual(
            _transport_log_path("xquic", self.temp.name),
            os.path.join(self.temp.name, "xquic-server.slog"),
        )
        self.assertEqual(
            _transport_log_path("mvfst", self.temp.name),
            os.path.join(self.temp.name, "server.stderr.log"),
        )

    def test_canonical_full_measurement_window_is_nested(self):
        workload = dict(self.runner.matrix["workload"], effective_duration_s=30)
        self.assertEqual(measurement_window(workload), (5, 25))
        workload.update(smoke=True, effective_duration_s=5)
        self.assertEqual(measurement_window(workload), (0, 5))

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
