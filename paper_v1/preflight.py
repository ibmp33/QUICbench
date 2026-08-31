"""Static, build-identity, and host prerequisites for paper-v1 execution."""

import os
import re

from paper_v1.build_identity import BuildIdentityError, verify_build_manifest
from paper_v1.io import load_json
from paper_v1.matrix import (
    MAIN_RUN_COUNT,
    SENSITIVITY_RUN_COUNT,
    SMOKE_RUN_COUNT,
    load_matrix,
    planned_runs,
    planned_sensitivity_runs,
)
from paper_v1.policy import load_policy_spec


class PreflightError(ValueError):
    pass


def _absolute_file(path, label, executable=False):
    if not isinstance(path, str) or not os.path.isabs(path):
        raise PreflightError("{} must be an absolute path".format(label))
    if not os.path.isfile(path):
        raise PreflightError("{} not found: {}".format(label, path))
    if executable and not os.access(path, os.X_OK):
        raise PreflightError("{} is not executable: {}".format(label, path))


def _absolute_dir(path, label):
    if not isinstance(path, str) or not os.path.isabs(path):
        raise PreflightError("{} must be an absolute path".format(label))
    if not os.path.isdir(path):
        raise PreflightError("{} not found: {}".format(label, path))


def run_preflight(local_config_path, matrix_path, policy_spec_path, allow_dirty=False):
    config = load_json(local_config_path)
    matrix = load_matrix(matrix_path)
    policies = load_policy_spec(policy_spec_path)
    for section in ("repositories", "binaries", "tools", "build_manifests"):
        if not isinstance(config.get(section), dict) or not config[section]:
            raise PreflightError("local config requires non-empty {}".format(section))
    if "dataset_root" not in config:
        raise PreflightError("local config requires dataset_root")
    _absolute_dir(config["dataset_root"], "dataset_root")
    storage = config.get("storage", {})
    try:
        minimum_free_bytes = int(storage["minimum_free_bytes"])
    except (KeyError, TypeError, ValueError) as error:
        raise PreflightError(
            "local config requires positive integer storage.minimum_free_bytes"
        ) from error
    if minimum_free_bytes <= 0:
        raise PreflightError("storage.minimum_free_bytes must be positive")
    dataset_root = os.path.realpath(os.path.abspath(config["dataset_root"]))
    volatile_roots = tuple(
        os.path.realpath(root) for root in ("/tmp", "/var/tmp", "/run")
    )
    if any(
        dataset_root == root or dataset_root.startswith(root + os.sep)
        for root in volatile_roots
    ):
        raise PreflightError("formal dataset_root must not use volatile storage")
    if os.statvfs(dataset_root).f_bavail * os.statvfs(dataset_root).f_frsize < minimum_free_bytes:
        raise PreflightError("dataset_root does not satisfy minimum free-space gate")
    for name, path in config["repositories"].items():
        _absolute_dir(path, "repository {}".format(name))
    for name, path in config["binaries"].items():
        _absolute_file(path, "binary {}".format(name), executable=True)
    for name, path in config["tools"].items():
        if name.endswith("_image"):
            if not isinstance(path, str) or not path:
                raise PreflightError("tool {} image identity must be non-empty".format(name))
        else:
            _absolute_file(path, "tool {}".format(name), executable=True)
    builds = {}
    for name, path in config["build_manifests"].items():
        _absolute_file(path, "build manifest {}".format(name))
        try:
            builds[name] = verify_build_manifest(path, allow_dirty=allow_dirty)
        except BuildIdentityError as error:
            raise PreflightError("{}: {}".format(name, error)) from error
    mvfst_build = builds["mvfst-h3"]
    mvfst_expected = config.get("mvfst_h3", {})
    if mvfst_build["workload_protocol"] != "http3":
        raise PreflightError("mvfst-h3 build is not HTTP/3")
    expected_adapter_identity = mvfst_expected.get(
        "adapter_identity", "mvfst + paper-v1 minimal H3 adapter"
    )
    if mvfst_build.get("application_identity") != expected_adapter_identity:
        raise PreflightError("mvfst H3 adapter identity is absent from build manifest")
    required_mvfst_identity = {
        "transport_commit": mvfst_expected.get("transport_commit"),
        "h3_adapter_kind": mvfst_expected.get("adapter_kind"),
        "h3_adapter_patch_sha256": mvfst_expected.get("adapter_patch_sha256"),
    }
    for field, expected in required_mvfst_identity.items():
        if not expected or mvfst_build.get(field) != expected:
            raise PreflightError(
                "mvfst H3 {} mismatch: expected={!r} actual={!r}".format(
                    field, expected, mvfst_build.get(field)
                )
            )
    if not re.fullmatch(r"[0-9a-f]{64}", required_mvfst_identity["h3_adapter_patch_sha256"]):
        raise PreflightError("mvfst H3 adapter patch identity is not a SHA-256")
    expected_runs = len(list(planned_runs(matrix)))
    if expected_runs != MAIN_RUN_COUNT:
        raise PreflightError("canonical matrix must plan 400 main runs")
    sensitivity_runs = len(list(planned_sensitivity_runs(matrix)))
    if sensitivity_runs != SENSITIVITY_RUN_COUNT:
        raise PreflightError("canonical matrix must plan 120 sensitivity runs")
    return {
        "status": "static_preflight_passed",
        "paper_eligible": not allow_dirty,
        "formal_corpus_unlocked": False,
        "runtime_preflights_completed": 0,
        "planned_runs": expected_runs,
        "sensitivity_runs": sensitivity_runs,
        "preflight_runs": SMOKE_RUN_COUNT,
        "paths": len(matrix["paths"]),
        "policy_schema": policies["policy_schema"],
        "builds": {name: value["binary_sha256"] for name, value in builds.items()},
    }
