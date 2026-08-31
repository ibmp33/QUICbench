import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from ack_policies import load_ack_policy_configs
import run_B0_two_flow_fairness_no_jitter as fairness_runner
from scripts.analyze_sender_mechanism_pilot import (
    baseline_rows,
    condition_rows,
    resolve_jain,
)
from scripts.run_sender_mechanism_pilot import SUITES, condition_documents
from saturation import validate_saturation
from workloads import load_workload_profiles


ROOT = os.path.dirname(os.path.abspath(__file__))


def load_json(relative_path):
    with open(os.path.join(ROOT, relative_path)) as config_file:
        return json.load(config_file)


class ExperimentSemanticsTest(unittest.TestCase):
    def setUp(self):
        self.stacks_conf = load_json("config/stacks_conf_default.json")
        self.general_conf = load_json("config/general_conf_default.json")
        self.exp_conf = load_json("config/P0_policy_fairness.json")
        profiles = load_workload_profiles(
            os.path.join(ROOT, "config/workloads_conf_default.json")
        )
        fairness_runner.activate_workload(self.exp_conf, profiles)
        ack_policies = load_ack_policy_configs(
            os.path.join(ROOT, "config/ack_policies_default.json")
        )
        fairness_runner.activate_ack_policy_configs(self.exp_conf, ack_policies)

    def test_main_fairness_resolves_one_server_endpoint(self):
        fairness_runner.validate_experiment(self.stacks_conf, self.exp_conf)
        stacks = fairness_runner.instantiate_stacks(
            self.stacks_conf, self.general_conf
        )
        plans = fairness_runner.build_flow_plans(
            stacks, self.exp_conf, self.exp_conf["trials"][0], "/tmp/quicbench-test"
        )
        endpoints = {(plan["server_stack_name"], plan["port_no"]) for plan in plans}
        self.assertEqual(endpoints, {("quic-go", "4433")})
        self.assertEqual({plan["local_port"] for plan in plans}, {54433, 54434})
        self.assertEqual(
            {plan["generated_target"] for plan in plans},
            {"https://198.19.0.2:4433/bytes/1073741824"},
        )
        self.assertEqual(plans[0]["ack_policy_config"]["initial_threshold"], 2)
        self.assertEqual(
            plans[1]["ack_policy_config"]["switch_after_packet_number_advance"],
            100,
        )

    def test_main_fairness_rejects_different_server_port(self):
        invalid = copy.deepcopy(self.exp_conf)
        invalid["trials"][0]["flows"][1]["port_no"] = "4434"
        with self.assertRaises(SystemExit):
            fairness_runner.validate_experiment(self.stacks_conf, invalid)

    def test_saturation_requires_growth_in_every_late_segment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            metrics_path = os.path.join(temp_dir, "metrics.csv")
            with open(metrics_path, "w") as metrics_file:
                metrics_file.write("elapsed_ms,cumulative_body_bytes\n")
                for second in range(51):
                    metrics_file.write(
                        "{},{}\n".format(second * 1000, min(second, 34) * 1000)
                    )
            result = validate_saturation(metrics_path, 10, 50)
        self.assertFalse(result["valid"])
        self.assertIn("no byte growth", result["reason"])

    def test_main_matrix_contains_only_four_modeled_policy_pairs(self):
        pairs = {
            tuple(flow["ack_policy"] for flow in trial["flows"])
            for trial in self.exp_conf["trials"]
        }
        self.assertEqual(
            pairs,
            {
                ("neqo-like-ack", "chrome-like-ack"),
                ("chrome-like-ack", "neqo-like-ack"),
                ("neqo-like-ack", "neqo-like-ack"),
                ("chrome-like-ack", "chrome-like-ack"),
            },
        )

    def test_manifest_policy_identity_matches_selected_runtime_policy(self):
        for trial in self.exp_conf["trials"]:
            for flow in trial["flows"]:
                policy = flow["ack_policy"]
                definition = self.exp_conf["ack_policy_configs"][policy]
                self.assertEqual(definition["policy_name"], policy)
                self.assertEqual(definition["policy_version"], "1.0.0")
                self.assertEqual(
                    definition["state_scope"],
                    "per-connection-per-packet-number-space",
                )

    def test_pcap_retention_policy_keeps_only_first_repetition(self):
        self.assertTrue(fairness_runner.should_keep_artifact("all", 7))
        self.assertTrue(fairness_runner.should_keep_artifact("first-only", 1))
        self.assertFalse(fairness_runner.should_keep_artifact("first-only", 2))
        self.assertFalse(fairness_runner.should_keep_artifact("none", 1))

    def test_sender_analysis_calculates_jain_for_legacy_summary_schema(self):
        calculated = resolve_jain({"share": "0.6"}, {"share": "0.4"}, 0.6, 0.4)
        self.assertAlmostEqual(calculated, 1.0 / (2.0 * (0.6 ** 2 + 0.4 ** 2)))
        recorded = resolve_jain(
            {"share": "0.6", "jain_index": "0.91"},
            {"share": "0.4", "jain_index": "0.91"},
            0.6,
            0.4,
        )
        self.assertEqual(recorded, 0.91)

    def test_sender_analysis_separates_baseline_and_role_effects(self):
        common = {
            "server": "quiche",
            "protocol": "http3",
            "cc": "cubic",
            "pacing": "enabled",
            "valid": True,
            "saturated": True,
            "jain": 0.95,
            "share_gap": 0.2,
        }
        runs = [
            dict(common, pair=("neqo", "chromium"), neqo_share=0.6),
            dict(common, pair=("chromium", "neqo"), neqo_share=0.7),
            dict(common, pair=("neqo", "neqo"), neqo_share=None),
        ]
        conditions = condition_rows(runs)
        baselines = baseline_rows(runs)
        self.assertEqual(len(conditions), 1)
        self.assertAlmostEqual(conditions[0]["neqo_share_mean"], 0.65)
        self.assertAlmostEqual(conditions[0]["role_difference"], 0.1)
        self.assertEqual(len(baselines), 1)
        self.assertEqual(baselines[0]["baseline_policy"], "neqo")

    def test_quic_go_declares_effective_server_controls(self):
        stacks = fairness_runner.instantiate_stacks(
            self.stacks_conf, self.general_conf
        )
        runtime = stacks["quic-go"].get_server_runtime_config("cubic")
        self.assertEqual(runtime["cc"], "cubic")
        self.assertEqual(runtime["pacing"], "enabled")
        self.assertEqual(runtime["control_source"], "binary-build")

    def test_quiche_fairness_uses_static_object_and_explicit_controls(self):
        experiment = copy.deepcopy(self.exp_conf)
        experiment["fixed_parameters"]["server_stack_name"] = "quiche"
        fairness_runner.validate_experiment(self.stacks_conf, experiment)
        stacks = fairness_runner.instantiate_stacks(
            self.stacks_conf, self.general_conf
        )
        plans = fairness_runner.build_flow_plans(
            stacks, experiment, experiment["trials"][0], "/tmp/quicbench-test"
        )
        self.assertEqual(
            {plan["generated_target"] for plan in plans},
            {"https://198.19.0.2:4433/1GB.bin"},
        )
        command = plans[0]["server_cmd"]
        self.assertIn("--cc-algorithm cubic", command)
        self.assertNotIn("--disable-pacing", command)
        self.assertNotIn("--disable-gso", command)

    def test_xquic_fairness_is_blocked_until_continuous_h3_is_verified(self):
        experiment = copy.deepcopy(self.exp_conf)
        experiment["fixed_parameters"]["server_stack_name"] = "xquic"
        with self.assertRaises(SystemExit):
            fairness_runner.validate_experiment(self.stacks_conf, experiment)

    def test_reduced_pilot_has_five_pairs_and_short_saturated_workload(self):
        experiment = load_json("config/P1_reduced_policy_pilot.json")
        profiles = load_workload_profiles(
            os.path.join(ROOT, "config/workloads_conf_default.json")
        )
        fairness_runner.activate_workload(experiment, profiles)
        ack_policies = load_ack_policy_configs(
            os.path.join(ROOT, "config/ack_policies_default.json")
        )
        fairness_runner.activate_ack_policy_configs(experiment, ack_policies)
        fairness_runner.validate_experiment(self.stacks_conf, experiment)
        self.assertEqual(experiment["workload"]["bytes"], 67108864)
        self.assertEqual(experiment["workload"]["duration_s"], 20)
        self.assertEqual(experiment["steady_state_window_s"], {"start": 5, "end": 15})
        self.assertEqual(
            {
                tuple(flow["ack_policy"] for flow in trial["flows"])
                for trial in experiment["trials"]
            },
            {
                ("neqo-like-ack", "neqo-like-ack"),
                ("neqo-like-ack", "chrome-like-ack"),
                ("chrome-like-ack", "neqo-like-ack"),
                ("neqo-like-ack", "synthetic-fixed-ack-10"),
                ("synthetic-fixed-ack-10", "neqo-like-ack"),
            },
        )

    def test_xquic_pilot_uses_bounded_h3_body_cubic_and_pacing(self):
        experiment = load_json("config/P1_reduced_policy_pilot.json")
        experiment["fixed_parameters"]["server_stack_name"] = "xquic"
        profiles = load_workload_profiles(
            os.path.join(ROOT, "config/workloads_conf_default.json")
        )
        fairness_runner.activate_workload(experiment, profiles)
        ack_policies = load_ack_policy_configs(
            os.path.join(ROOT, "config/ack_policies_default.json")
        )
        fairness_runner.activate_ack_policy_configs(experiment, ack_policies)
        fairness_runner.validate_experiment(self.stacks_conf, experiment)
        stacks = fairness_runner.instantiate_stacks(
            self.stacks_conf, self.general_conf
        )
        plans = fairness_runner.build_flow_plans(
            stacks, experiment, experiment["trials"][0], "/tmp/quicbench-test"
        )
        command = plans[0]["server_cmd"]
        self.assertIn("-c c", command)
        self.assertIn("-C", command)
        self.assertIn("-s 67108864", command)
        self.assertEqual(plans[0]["requested_bytes"], 67108864)

    def test_xquic_qlog_uses_per_run_path(self):
        stacks = fairness_runner.instantiate_stacks(
            self.stacks_conf, self.general_conf
        )
        stacks["xquic"].set_run_root("/tmp/quicbench-qlog-test")
        stacks["xquic"].set_qlog_enabled(True)
        command = " ".join(stacks["xquic"].run_server_cmd("4433", 20, "cubic"))
        self.assertIn(
            "/tmp/quicbench-qlog-test/xquic/4433/qlogs/server/xquic-server.slog",
            command,
        )

    def test_sender_mechanism_pilot_switches_quiche_reno_and_pacing(self):
        experiment = load_json("config/P2_sender_mechanism_pilot.json")
        experiment["fixed_parameters"]["server_stack_name"] = "quiche"
        for trial in experiment["trials"]:
            for flow in trial["flows"]:
                flow["cc_algo"] = "reno"
        profiles = load_workload_profiles(
            os.path.join(ROOT, "config/workloads_conf_default.json")
        )
        fairness_runner.activate_workload(experiment, profiles)
        ack_policies = load_ack_policy_configs(
            os.path.join(ROOT, "config/ack_policies_default.json")
        )
        fairness_runner.activate_ack_policy_configs(experiment, ack_policies)
        stacks_conf = copy.deepcopy(self.stacks_conf)
        stacks_conf["quiche"]["server_pacing"] = False
        fairness_runner.validate_experiment(stacks_conf, experiment)
        stacks = fairness_runner.instantiate_stacks(stacks_conf, self.general_conf)
        fairness_runner.validate_server_cc_capabilities(stacks, experiment)
        plans = fairness_runner.build_flow_plans(
            stacks, experiment, experiment["trials"][0], "/tmp/quicbench-test"
        )
        self.assertIn("--cc-algorithm reno", plans[0]["server_cmd"])
        self.assertIn("--disable-pacing", plans[0]["server_cmd"])
        self.assertEqual(
            stacks["quiche"].get_server_runtime_config("reno")["pacing"],
            "disabled",
        )

    def test_sender_mechanism_full_has_baselines_and_role_reversal(self):
        experiment = load_json("config/P2_sender_mechanism_pilot.json")
        pairs = {
            tuple(flow["ack_policy"] for flow in trial["flows"])
            for trial in experiment["trials"]
        }
        self.assertEqual(
            pairs,
            {
                ("neqo-like-ack", "neqo-like-ack"),
                ("chrome-like-ack", "chrome-like-ack"),
                ("neqo-like-ack", "chrome-like-ack"),
                ("chrome-like-ack", "neqo-like-ack"),
            },
        )
        canary, _ = condition_documents(
            experiment,
            self.stacks_conf,
            SUITES["realistic"],
            "quiche",
            "reno",
            "off",
            True,
        )
        self.assertEqual(
            [trial["name"] for trial in canary["trials"]],
            ["M1_neqo_vs_chromium"],
        )

    def test_mvfst_maps_generic_reno_and_switches_pacing(self):
        stacks_conf = copy.deepcopy(self.stacks_conf)
        stacks_conf["mvfst"]["server_pacing"] = True
        stacks = fairness_runner.instantiate_stacks(stacks_conf, self.general_conf)
        command = " ".join(stacks["mvfst"].run_server_cmd("6666", 20, "reno"))
        self.assertIn("--congestion=newreno", command)
        self.assertIn("--pacing=true", command)
        self.assertEqual(
            stacks["mvfst"].get_server_runtime_config("reno")["pacing"],
            "enabled",
        )

    @mock.patch("run_B0_two_flow_fairness_no_jitter.subprocess.run")
    def test_server_pid_is_resolved_from_namespace_binary(self, run_mock):
        class Result:
            def __init__(self, stdout="", returncode=0):
                self.stdout = stdout
                self.returncode = returncode

        expected_binary = "/home/ioio33/QUIC_project/bin/quic-go-server"
        resolved_expected_binary = os.path.realpath(expected_binary)

        def command_result(command, **_kwargs):
            if command[:5] == ["sudo", "-n", "ip", "netns", "pids"]:
                return Result("101\n202\n")
            if command[-1] == "/proc/101/exe":
                return Result("/usr/bin/timeout\n")
            if command[-1] == "/proc/202/exe":
                return Result(resolved_expected_binary + "\n")
            return Result(returncode=1)

        run_mock.side_effect = command_result
        stack = mock.Mock(server_netns="quicbench-server")
        self.assertEqual(
            fairness_runner.discover_server_pid(stack, expected_binary), 202
        )


if __name__ == "__main__":
    unittest.main()
