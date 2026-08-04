import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from ack_policies import load_ack_policy_configs
import run_B0_two_flow_fairness_no_jitter as fairness_runner
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
        self.assertEqual(plans[0]["ack_policy_config"]["threshold"], 2)
        self.assertEqual(plans[1]["ack_policy_config"]["switch_after_packets"], 100)

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

    def test_main_matrix_contains_all_eight_policy_pairs(self):
        pairs = {
            tuple(flow["ack_policy"] for flow in trial["flows"])
            for trial in self.exp_conf["trials"]
        }
        self.assertEqual(
            pairs,
            {
                ("fixed2", "fixed2"),
                ("fixed10", "fixed10"),
                ("fixed2", "fixed10"),
                ("fixed10", "fixed2"),
                ("neqo", "chromium"),
                ("chromium", "neqo"),
                ("neqo", "neqo"),
                ("chromium", "chromium"),
            },
        )

    def test_pcap_retention_policy_keeps_only_first_repetition(self):
        self.assertTrue(fairness_runner.should_keep_artifact("all", 7))
        self.assertTrue(fairness_runner.should_keep_artifact("first-only", 1))
        self.assertFalse(fairness_runner.should_keep_artifact("first-only", 2))
        self.assertFalse(fairness_runner.should_keep_artifact("none", 1))

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
