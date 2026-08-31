import json
import os
import tempfile
import unittest

from paper_v1.runner import PaperV1Runner, _path_for_run


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
        self.assertIn("test.xquic.com", command)
        self.assertIn("54434", command)


if __name__ == "__main__":
    unittest.main()
