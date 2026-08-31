import json
import os
import tempfile
import unittest

from paper_v1 import DATASET_SCHEMA, POLICY_SCHEMA
from paper_v1.export import ExportError, export_dataset
from paper_v1.io import atomic_write_json, load_json, sha256_file
from paper_v1.manifest import (
    ManifestStateError,
    ManifestStore,
    new_manifest,
    transition,
)
from network.set_netem import resolve_netem_parameters
from paper_v1.matrix import (
    load_matrix,
    planned_runs,
    planned_sensitivity_runs,
)
from paper_v1.policy import load_policy_spec
from paper_v1.validate import REQUIRED_ARTIFACT_ROLES, validate_run
from stacks.mvfst import MvfstH3
from stacks.xquic import Xquic


ROOT = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(ROOT, "specs", "receiver_ack_policy_v1.json")
MATRIX = os.path.join(ROOT, "configs", "paper-v1", "matrix.json")


class PaperV1Test(unittest.TestCase):
    def test_frozen_policy_hashes_verify(self):
        spec = load_policy_spec(SPEC)
        self.assertEqual(spec["policy_schema"], POLICY_SCHEMA)

    def test_matrix_is_eleven_h3_paths_and_400_main_runs(self):
        matrix = load_matrix(MATRIX)
        self.assertEqual(len(matrix["paths"]), 11)
        self.assertEqual(len(list(planned_runs(matrix))), 400)
        self.assertEqual(len(list(planned_runs(matrix, repetitions=1))), 44)
        self.assertEqual(len(list(planned_sensitivity_runs(matrix))), 120)
        self.assertNotIn("optional_appendix_loss", matrix)
        self.assertTrue(all(item["protocol"] == "http3" for item in matrix["paths"]))
        self.assertEqual(
            sum(item["sender"] == "mvfst" for item in matrix["paths"]), 4
        )

    def test_network_contract_is_explicit_and_forward_only(self):
        matrix = load_matrix(MATRIX)
        profiles = {
            item["profile_id"]: item for item in matrix["network_profiles"]
        }
        expected_queues = {
            "base_20m_50ms_q0p5_loss0": 62500,
            "rtt10_20m_q0p5_loss0": 12500,
            "rtt100_20m_q0p5_loss0": 125000,
            "queue2_20m_50ms_loss0": 250000,
        }
        for profile_id, queue_bytes in expected_queues.items():
            resolved = resolve_netem_parameters(profiles[profile_id])
            self.assertEqual(resolved["queue_size_bytes"], queue_bytes)
            self.assertFalse(resolved["reverse_bottleneck"])
            self.assertEqual(resolved["reverse_loss_percent"], 0)
            self.assertEqual(resolved["forward_loss_percent"], 0)
            self.assertEqual(profiles[profile_id]["jitter_ms"], 0)
            self.assertEqual(profiles[profile_id]["intentional_reordering_percent"], 0)

        legacy = resolve_netem_parameters(
            {"RTT_ms": 50, "bandwidth_Mbps": 20, "buffer_bdp": 0.5}
        )
        self.assertEqual(legacy["queue_size_bytes"], 62500)
        self.assertTrue(legacy["reverse_bottleneck"])

    def test_manifest_state_machine_and_atomic_write(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ManifestStore(os.path.join(temp_dir, "run_manifest.json"))
            manifest = new_manifest("dataset", "suite", "run", "attempt-1", 1)
            manifest = store.create(manifest)
            self.assertEqual(load_json(store.path)["state"], "created")
            for state in (
                "preflight_passed",
                "running",
                "collecting",
                "validating",
                "completed_valid",
            ):
                manifest = store.transition(state)
            self.assertTrue(manifest["paper_eligible"])
            with self.assertRaises(ManifestStateError):
                transition(manifest, "running")

    def test_failure_state_is_terminal_and_ineligible(self):
        manifest = transition(
            new_manifest("dataset", "suite", "run", "attempt-1", 1), "created"
        )
        manifest = transition(manifest, "failed_preflight", "binary_hash_mismatch")
        self.assertFalse(manifest["paper_eligible"])
        self.assertIn("binary_hash_mismatch", manifest["exclusion_reasons"])

    def _event(self, flow_id, policy):
        spec = load_policy_spec(SPEC)["policies"][policy]
        return {
            "schema_version": "receiver-ack-event-v1.0.0",
            "event": "policy_initialized",
            "connection_id": "cid-" + flow_id,
            "flow_id": flow_id,
            "policy_name": policy,
            "policy_version": "1.0.0",
            "policy_spec_sha256": spec["parameter_schema_sha256"],
            "effective_parameters": spec["parameters"],
            "packet_number_space": "application_data",
            "monotonic_time_ns": 0,
            "process_start_identity": "pid:1:start:1",
        }

    def _ack(self, flow_id, policy):
        return {
            "schema_version": "receiver-ack-event-v1.0.0",
            "event": "ack_episode",
            "connection_id": "cid-" + flow_id,
            "flow_id": flow_id,
            "policy_name": policy,
            "policy_version": "1.0.0",
            "policy_spec_sha256": load_policy_spec(SPEC)["policies"][policy]["parameter_schema_sha256"],
            "packet_number_space": "application_data",
            "monotonic_time_ns": 1,
            "ack_ranges": [{"smallest": 0, "largest": 1}],
            "largest_acknowledged": 1,
            "newly_acknowledged_packet_count": 2,
            "ack_batch_size": 2,
            "ack_spacing_ns": 1000,
            "ack_delay_ns": 100,
            "effective_threshold": 2,
            "timer_deadline_ns": 20000,
            "trigger_reason": "threshold",
            "policy_state": "application-delayed-ack" if policy == "neqo-like-ack" else "decimated-ack-every-10",
        }

    def _write_valid_run(self, run_dir):
        os.makedirs(run_dir)
        files = {}
        for role in REQUIRED_ARTIFACT_ROLES:
            path = os.path.join(run_dir, role + ".artifact")
            with open(path, "wb") as artifact:
                artifact.write(b"artifact\n")
            files[role] = path
        transport_log = os.path.join(run_dir, "sender_transport_log.artifact")
        with open(transport_log, "wb") as artifact:
            artifact.write(b"PAPER_V1_TRANSPORT_EVENT {}\n")
        files["sender_transport_log"] = transport_log
        flow_a_events = [
            self._event("flow_a", "neqo-like-ack"),
            self._ack("flow_a", "neqo-like-ack"),
        ]
        flow_b_events = [self._event("flow_b", "chrome-like-ack")]
        flow_b_events.append(
            {
                "schema_version": "receiver-ack-event-v1.0.0",
                "event": "policy_transition",
                "connection_id": "cid-flow_b",
                "flow_id": "flow_b",
                "policy_name": "chrome-like-ack",
                "policy_version": "1.0.0",
                "policy_spec_sha256": load_policy_spec(SPEC)["policies"]["chrome-like-ack"]["parameter_schema_sha256"],
                "packet_number_space": "application_data",
                "monotonic_time_ns": 10,
                "old_state": "initial-ack-every-2",
                "new_state": "decimated-ack-every-10",
                "reference_packet_number": 0,
                "observed_packet_number": 100,
                "transition_boundary_packet_number": 100,
                "transition_sequence_number": 1,
                "reason": "packet-number-reached-peer-first-plus-100",
            }
        )
        flow_b_events.append(self._ack("flow_b", "chrome-like-ack"))
        for role, events in (
            ("receiver_policy_flow_a", flow_a_events),
            ("receiver_policy_flow_b", flow_b_events),
        ):
            with open(files[role], "w", encoding="utf-8") as artifact:
                for event in events:
                    artifact.write(json.dumps(event) + "\n")
        sender_runtime = {
            "schema_version": "sender-runtime-v1.0.0",
            "event": "sender_final",
            "sender": "mvfst",
            "requested_cc": "bbr",
            "active_cc": "bbr",
            "fallback": False,
            "configured_pacing": "on",
            "effective_pacing": "paced",
            "pacer_initialized": True,
            "pacing_callback_or_tick_observed": True,
            "icw": 32,
            "binary_sha256": "b" * 64,
            "h3_adapter_identity": "mvfst + paper-v1 minimal H3 adapter",
            "h3_adapter_kind": "minimal-native-h3",
            "h3_adapter_patch_sha256": "a" * 64,
            "transport_commit": "80168ffa14efcb5c5dd662cec82682e78788f8b3",
            "raw_runtime_sha256": sha256_file(files["sender_runtime_raw"]),
            "transport_log_sha256": sha256_file(files["sender_transport_log"]),
        }
        with open(files["sender_runtime"], "w", encoding="utf-8") as artifact:
            artifact.write(json.dumps(sender_runtime) + "\n")
        wire_sources = {
            role: sha256_file(files[role])
            for role in (
                "pcap",
                "receiver_qlog_flow_a",
                "receiver_qlog_flow_b",
                "receiver_policy_flow_a",
                "receiver_policy_flow_b",
                "keylog_flow_a",
                "keylog_flow_b",
            )
        }
        atomic_write_json(
            files["wire_evidence"],
            {
                "schema_version": "wire-ack-evidence-v1.0.0",
                "extractor": {
                    "name": "paper-v1-wire-validator",
                    "version": "1.0.0",
                    "command": ["paper-v1-wire-validator", "--run", "attempt"],
                    "tool_versions": {"tshark": "4.x", "qlog_parser": "1.0.0"},
                },
                "source_artifact_sha256": wire_sources,
                "flows": [
                    {
                        "flow_id": "flow_a",
                        "policy_name": "neqo-like-ack",
                        "ack_episode_count": 1,
                        "ack_batches": [2],
                        "ack_spacing_ns": [1000],
                        "ack_delay_ns": [100],
                        "pcap_ack_frame_count": 1,
                        "qlog_ack_frame_count": 1,
                        "ack_batch_observed": True,
                        "ack_spacing_observed": True,
                        "ack_delay_observed": True,
                        "policy_log_matches_wire": True,
                        "qlog_matches_pcap": True,
                        "ack_delay_units_valid": True,
                    },
                    {
                        "flow_id": "flow_b",
                        "policy_name": "chrome-like-ack",
                        "ack_episode_count": 1,
                        "ack_batches": [10],
                        "ack_spacing_ns": [1000],
                        "ack_delay_ns": [100],
                        "pcap_ack_frame_count": 1,
                        "qlog_ack_frame_count": 1,
                        "ack_batch_observed": True,
                        "ack_spacing_observed": True,
                        "ack_delay_observed": True,
                        "policy_log_matches_wire": True,
                        "qlog_matches_pcap": True,
                        "ack_delay_units_valid": True,
                        "transition_matches_wire": True,
                    },
                ],
            },
        )
        derived_flows = [
            {
                "flow_id": flow_id, "connection_id": "cid-{}".format(flow_id),
                "client_local_port": 54433 if flow_id == "flow_a" else 54434,
                "alpn": "h3", "http_status": 200, "headers_valid": True,
                "response_content_length": 1073741824, "decoded_body_bytes": 1000000,
                "measurement_window_body_bytes": 800000, "flow_control_blocked_in_window": False,
                "application_limited_in_window": False, "stream_count": 1, "client_continuous_read": True,
            }
            for flow_id in ("flow_a", "flow_b")
        ]
        derived_workload = {
            "protocol": "http3", "server_process_count": 1, "server_listening_port_count": 1,
            "server_application_ready": True, "body_counter": "client-decoded-http3-response-body-bytes",
            "duration_s": 30, "measurement_window_start_s": 5, "measurement_window_end_s": 25,
        }
        derivation = {"name": "test-deriver", "version": "1.0.0", "sources": ["fixtures"]}
        atomic_write_json(files["runtime_evidence"], {
            "schema_version": "runtime-derived-v1.0.0", "derivation": derivation,
            "flows": derived_flows, "workload": derived_workload,
        })
        network_conclusion = {
            "qdisc_matches_requested": True, "offloads_valid": True, "shared_bottleneck": True,
            "saturated": True, "both_flows_active": True, "not_application_limited": True,
            "start_skew_valid": True,
        }
        atomic_write_json(files["network_evidence"], {
            "schema_version": "network-evidence-v1.0.0",
            "source_artifact_sha256": {role: sha256_file(files[role])
                                       for role in ("qdisc_before", "qdisc_active", "qdisc_after")},
            "conclusion": network_conclusion,
        })
        artifacts = [
            {
                "role": role,
                "path": os.path.basename(path),
                "sha256": sha256_file(path),
            }
            for role, path in sorted(files.items())
        ]
        manifest = new_manifest("dataset", "suite", "run", "attempt-1", 1)
        for state in ("created", "preflight_passed", "running", "collecting", "validating"):
            manifest = transition(manifest, state)
        manifest.update(
            {
                "requested": {
                    "flows": [
                        {
                            "flow_id": "flow_a",
                            "policy": "neqo-like-ack",
                            "policy_version": "1.0.0",
                            "policy_spec_sha256": load_policy_spec(SPEC)["policies"]["neqo-like-ack"]["parameter_schema_sha256"],
                            "effective_parameters": load_policy_spec(SPEC)["policies"]["neqo-like-ack"]["parameters"],
                        },
                        {
                            "flow_id": "flow_b",
                            "policy": "chrome-like-ack",
                            "policy_version": "1.0.0",
                            "policy_spec_sha256": load_policy_spec(SPEC)["policies"]["chrome-like-ack"]["parameter_schema_sha256"],
                            "effective_parameters": load_policy_spec(SPEC)["policies"]["chrome-like-ack"]["parameters"],
                        },
                    ],
                    "sender": {
                        "sender": "mvfst",
                        "cc": "bbr",
                        "required_effective_pacing": "paced",
                        "binary_sha256": "b" * 64,
                    },
                },
                "runtime_reported": {
                    "flows": derived_flows,
                    "workload": derived_workload,
                    "derivation": derivation,
                    "sender": {
                        "active_cc": "bbr",
                        "fallback": False,
                        "configured_pacing": "on",
                        "effective_pacing": "paced",
                        "pacer_initialized": True,
                        "pacing_callback_or_tick_observed": True,
                        "icw": 32,
                        "binary_sha256": "b" * 64,
                        "h3_adapter_identity": "mvfst + paper-v1 minimal H3 adapter",
                        "h3_adapter_patch_sha256": "a" * 64,
                        "transport_commit": "80168ffa14efcb5c5dd662cec82682e78788f8b3",
                        "h3_adapter_kind": "minimal-native-h3",
                    }
                },
                "validator_conclusion": {
                    "network": {
                        "qdisc_matches_requested": True,
                        "offloads_valid": True,
                        "shared_bottleneck": True,
                        "saturated": True,
                        "both_flows_active": True,
                        "not_application_limited": True,
                        "start_skew_valid": True,
                    },
                    "wire": {
                        "qlog_policy_consistent": True,
                        "pcap_policy_consistent": True,
                        "ack_delay_units_valid": True,
                    },
                },
                "processes": [
                    {
                        "kind": kind,
                        "command": [kind],
                        "pid": index + 1,
                        "start_monotonic_ns": 1,
                        "end_monotonic_ns": 2,
                        "exit_code": 0,
                        "termination_reason": "normal",
                        "stdout_path": "{}.stdout".format(kind),
                        "stderr_path": "{}.stderr".format(kind),
                    }
                    for index, kind in enumerate(
                        ("server", "client_flow_a", "client_flow_b", "capture")
                    )
                ],
                "artifacts": artifacts,
            }
        )
        atomic_write_json(os.path.join(run_dir, "run_manifest.json"), manifest)

    def test_validator_accepts_complete_run_and_rejects_ack_frequency(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = os.path.join(temp_dir, "attempt")
            self._write_valid_run(run_dir)
            result = validate_run(run_dir, SPEC)
            self.assertEqual(result["status"], "completed_valid")
            self.assertEqual(load_json(os.path.join(run_dir, "run_manifest.json"))["state"], "completed_valid")

            violation_dir = os.path.join(temp_dir, "violation")
            self._write_valid_run(violation_dir)
            policy_path = os.path.join(violation_dir, "receiver_policy_flow_a.artifact")
            with open(policy_path, "a", encoding="utf-8") as artifact:
                artifact.write(json.dumps({"event": "ack_frequency_violation"}) + "\n")
            manifest = load_json(os.path.join(violation_dir, "run_manifest.json"))
            for item in manifest["artifacts"]:
                if item["role"] == "receiver_policy_flow_a":
                    item["sha256"] = sha256_file(policy_path)
            atomic_write_json(os.path.join(violation_dir, "run_manifest.json"), manifest)
            result = validate_run(violation_dir, SPEC)
            self.assertIn("ack_frequency_observed", {item["code"] for item in result["issues"]})
            self.assertEqual(load_json(os.path.join(violation_dir, "run_manifest.json"))["state"], "completed_invalid")

    def test_validator_marks_valid_smoke_non_paper_eligible(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = os.path.join(temp_dir, "smoke")
            self._write_valid_run(run_dir)
            manifest_path = os.path.join(run_dir, "run_manifest.json")
            manifest = load_json(manifest_path)
            manifest["requested"]["workload"] = {"smoke": True, "effective_duration_s": 5}
            manifest["runtime_reported"]["smoke"] = True
            manifest["runtime_reported"]["workload"]["duration_s"] = 5
            manifest["runtime_reported"]["workload"]["measurement_window_start_s"] = 0
            manifest["runtime_reported"]["workload"]["measurement_window_end_s"] = 5
            runtime_path = os.path.join(run_dir, "runtime_evidence.artifact")
            runtime = load_json(runtime_path)
            runtime["workload"] = manifest["runtime_reported"]["workload"]
            atomic_write_json(runtime_path, runtime)
            for artifact in manifest["artifacts"]:
                if artifact["role"] == "runtime_evidence":
                    artifact["sha256"] = sha256_file(runtime_path)
            atomic_write_json(manifest_path, manifest)
            result = validate_run(run_dir, SPEC)
            self.assertEqual(result["status"], "completed_valid")
            self.assertTrue(result["smoke_valid"])
            self.assertFalse(result["paper_eligible"])

    def test_export_rejects_legacy_dataset(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            atomic_write_json(
                os.path.join(temp_dir, "dataset_manifest.json"),
                {"dataset_schema": "legacy", "attempts": []},
            )
            with self.assertRaises(ExportError):
                export_dataset(temp_dir, os.path.join(temp_dir, "export"))

    def test_paper_v1_stack_commands_use_real_h3_contracts(self):
        common = {
            "server_ip": "198.19.0.2",
            "server_hostname": "server",
            "server_pw_path": "/unused",
            "server_path": "/opt/quic/bin/server",
            "client_path": "/opt/quic/bin/client",
            "server_cert_path": "/opt/quic/cert.pem",
            "server_key_path": "/opt/quic/key.pem",
        }
        xquic = Xquic(
            **common,
            paper_v1_mode=True,
            server_response_bytes=1073741824,
            server_pacing=True,
        )
        command = " ".join(xquic.run_server_cmd(4433, 30, "bbr-family"))
        self.assertIn("-c b", command)
        self.assertIn("--paper-v1-body-bytes 1073741824", command)
        self.assertIn("--paper-v1-runtime-report", command)
        with self.assertRaises(ValueError):
            xquic.run_server_cmd(4433, 30, "unknown")

        mvfst = MvfstH3(
            **common,
            transport_commit="80168ffa14efcb5c5dd662cec82682e78788f8b3",
            h3_adapter_patch_sha256="a" * 64,
            server_pacing=True,
        )
        command = " ".join(mvfst.run_server_cmd(4433, 30, "bbr"))
        self.assertIn("--protocol=h3", command)
        self.assertIn("--paper_v1_runtime_report=", command)
        self.assertIn("--response_bytes=1073741824", command)
        self.assertIn("mvfst + paper-v1 minimal H3 adapter", command)

    def test_validator_fault_injection_process_checksum_jsonl_and_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cases = {}
            for name in ("process", "checksum", "jsonl", "fallback"):
                run_dir = os.path.join(temp_dir, name)
                self._write_valid_run(run_dir)
                cases[name] = run_dir

            manifest_path = os.path.join(cases["process"], "run_manifest.json")
            manifest = load_json(manifest_path)
            manifest["processes"][1]["exit_code"] = 7
            atomic_write_json(manifest_path, manifest)
            self.assertIn(
                "client_nonzero_exit",
                {item["code"] for item in validate_run(cases["process"], SPEC)["issues"]},
            )

            with open(os.path.join(cases["checksum"], "pcap.artifact"), "ab") as artifact:
                artifact.write(b"tampered")
            self.assertIn(
                "artifact_checksum_mismatch",
                {item["code"] for item in validate_run(cases["checksum"], SPEC)["issues"]},
            )

            policy_path = os.path.join(cases["jsonl"], "receiver_policy_flow_a.artifact")
            with open(policy_path, "a", encoding="utf-8") as artifact:
                artifact.write("{malformed\n")
            manifest_path = os.path.join(cases["jsonl"], "run_manifest.json")
            manifest = load_json(manifest_path)
            for item in manifest["artifacts"]:
                if item["role"] == "receiver_policy_flow_a":
                    item["sha256"] = sha256_file(policy_path)
            atomic_write_json(manifest_path, manifest)
            self.assertIn(
                "policy_log_invalid",
                {item["code"] for item in validate_run(cases["jsonl"], SPEC)["issues"]},
            )

            manifest_path = os.path.join(cases["fallback"], "run_manifest.json")
            manifest = load_json(manifest_path)
            manifest["runtime_reported"]["sender"]["fallback"] = True
            manifest["runtime_reported"]["sender"]["active_cc"] = "cubic"
            atomic_write_json(manifest_path, manifest)
            codes = {item["code"] for item in validate_run(cases["fallback"], SPEC)["issues"]}
            self.assertIn("controller_fallback", codes)
            self.assertIn("active_cc_mismatch", codes)

    def test_attempts_are_immutable_and_retry_gets_new_identity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            os.makedirs(os.path.join(temp_dir, "attempt-1"))
            first = ManifestStore(os.path.join(temp_dir, "attempt-1", "run_manifest.json"))
            first.create(new_manifest("dataset", "suite", "run", "attempt-1", 1))
            with self.assertRaises(FileExistsError):
                first.create(new_manifest("dataset", "suite", "run", "attempt-1", 1))
            second_manifest = new_manifest("dataset", "suite", "run", "attempt-2", 1)
            second_manifest["supersedes"] = "attempt-1"
            os.makedirs(os.path.join(temp_dir, "attempt-2"))
            second = ManifestStore(os.path.join(temp_dir, "attempt-2", "run_manifest.json"))
            created = second.create(second_manifest)
            self.assertEqual(created["attempt_id"], "attempt-2")
            self.assertEqual(created["supersedes"], "attempt-1")


if __name__ == "__main__":
    unittest.main()
