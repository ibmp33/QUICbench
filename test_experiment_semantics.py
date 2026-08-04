import copy
import json
import os
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
