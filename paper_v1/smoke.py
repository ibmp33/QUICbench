"""Minimal, resumable executor for all Paper-v1 path/policy smoke cells."""

import datetime
import os
import time

from paper_v1.io import atomic_write_json, load_json, sha256_file
from paper_v1.matrix import load_matrix, planned_runs
from paper_v1.policy import load_policy_spec
from paper_v1.runner import PaperV1Runner, handoff_sudo_artifacts
from paper_v1.validate import validate_run


class SmokeSuiteError(ValueError):
    pass


def smoke_plan(matrix, path_ids=None):
    selected = set(path_ids or [])
    known = {path["path_id"] for path in matrix["paths"]}
    unknown = selected - known
    if unknown:
        raise SmokeSuiteError("unknown path IDs: {}".format(", ".join(sorted(unknown))))
    return [
        run for run in planned_runs(matrix, repetitions=1)
        if not selected or run["path_id"] in selected
    ]


def _smoke_identity(matrix, policy_spec, planned, binary_hashes):
    path = next(item for item in matrix["paths"] if item["path_id"] == planned["path_id"])
    profile = next(
        item for item in matrix["network_profiles"]
        if item["profile_id"] == planned["network_profile_id"]
    )
    return {
        "sender_path": path,
        "sender_binary_sha256": binary_hashes[
            "mvfst-h3" if path["sender"] == "mvfst" else path["sender"]
        ],
        "receiver_binary_sha256": binary_hashes["receiver"],
        "network_profile": profile,
        "workload": matrix["workload"],
        "policies": [
            {
                "name": name,
                "spec_sha256": policy_spec["policies"][name]["parameter_schema_sha256"],
            }
            for name in planned["policy_pair"]
        ],
    }


def _valid_existing_attempt(dataset_root, run_id, expected):
    run_root = os.path.join(dataset_root, run_id)
    if not os.path.isdir(run_root):
        return None
    for attempt_id in sorted(os.listdir(run_root)):
        attempt_dir = os.path.join(run_root, attempt_id)
        validation_path = os.path.join(attempt_dir, "validation.json")
        manifest_path = os.path.join(attempt_dir, "run_manifest.json")
        network_path = os.path.join(attempt_dir, "network-evidence.json")
        if not all(os.path.isfile(path) for path in (validation_path, manifest_path, network_path)):
            continue
        try:
            result = load_json(validation_path)
            manifest = load_json(manifest_path)
            network = load_json(network_path)
        except (OSError, ValueError):
            continue
        requested = manifest.get("requested", {})
        sender = requested.get("sender", {})
        flows = requested.get("flows", [])
        workload = requested.get("workload", {})
        sender_matches = all(
            sender.get(key) == value
            for key, value in expected["sender_path"].items()
        ) and sender.get("binary_sha256") == expected["sender_binary_sha256"]
        flow_matches = len(flows) == 2 and all(
            flow.get("policy") == policy["name"]
            and flow.get("policy_spec_sha256") == policy["spec_sha256"]
            for flow, policy in zip(flows, expected["policies"])
        )
        workload_matches = workload.get("smoke") is True and all(
            workload.get(key) == value for key, value in expected["workload"].items()
        )
        if (
            result.get("status") == "completed_valid"
            and result.get("smoke_valid") is True
            and manifest.get("state") == "completed_valid"
            and requested.get("network_profile") == expected["network_profile"]
            and requested.get("receiver_binary_sha256") == expected["receiver_binary_sha256"]
            and sender_matches
            and flow_matches
            and workload_matches
            and network.get("schema_version") == "network-evidence-v1.1.0"
        ):
            return attempt_dir
    return None


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run_smoke_suite(local_config_path, matrix_path, policy_spec_path,
                    path_ids=None, resume=False, fail_fast=False, summary_path=None):
    config = load_json(local_config_path)
    matrix = load_matrix(matrix_path)
    policy_spec = load_policy_spec(policy_spec_path)
    runs = smoke_plan(matrix, path_ids=path_ids)
    binary_hashes = {
        name: sha256_file(path) for name, path in config["binaries"].items()
    }
    dataset_root = os.path.abspath(config["dataset_root"])
    if summary_path is None:
        report_dir = os.path.join(dataset_root, "_smoke_reports")
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        summary_path = os.path.join(report_dir, "paper-v1-smoke-{}.json".format(stamp))
    summary_path = os.path.abspath(summary_path)
    summary = {
        "schema_version": "paper-v1-smoke-suite-v1.0.0",
        "started_at": _utc_now(),
        "completed_at": None,
        "local_config": os.path.abspath(local_config_path),
        "matrix": os.path.abspath(matrix_path),
        "policy_spec": os.path.abspath(policy_spec_path),
        "summary_path": summary_path,
        "resume": bool(resume),
        "planned": len(runs),
        "passed": 0,
        "failed": 0,
        "skipped_valid": 0,
        "all_valid": False,
        "results": [],
    }

    def save():
        atomic_write_json(summary_path, summary)
        handoff_sudo_artifacts(summary_path)

    save()
    for index, planned in enumerate(runs, 1):
        run_id = planned["run_id"]
        expected = _smoke_identity(matrix, policy_spec, planned, binary_hashes)
        existing = (
            _valid_existing_attempt(dataset_root, run_id, expected) if resume else None
        )
        if existing:
            summary["skipped_valid"] += 1
            summary["results"].append({
                "index": index,
                "run_id": run_id,
                "path_id": planned["path_id"],
                "status": "skipped_valid",
                "run_dir": existing,
            })
            save()
            continue

        started = time.monotonic()
        run_dir = None
        try:
            runner = PaperV1Runner(local_config_path, matrix_path, policy_spec_path)
            run_dir = runner.run(run_id, smoke=True)
            result = validate_run(run_dir, policy_spec_path)
            valid = (
                result.get("status") == "completed_valid"
                and result.get("smoke_valid") is True
                and not result.get("issues")
            )
            entry = {
                "index": index,
                "run_id": run_id,
                "path_id": planned["path_id"],
                "status": "passed" if valid else "failed_validation",
                "run_dir": run_dir,
                "attempt_id": result.get("attempt_id"),
                "issues": result.get("issues", []),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            if valid:
                summary["passed"] += 1
            else:
                summary["failed"] += 1
        except KeyboardInterrupt:
            summary["completed_at"] = _utc_now()
            summary["interrupted"] = True
            save()
            raise
        except Exception as error:
            summary["failed"] += 1
            entry = {
                "index": index,
                "run_id": run_id,
                "path_id": planned["path_id"],
                "status": "failed_execution",
                "run_dir": run_dir,
                "error_type": type(error).__name__,
                "error": str(error),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        finally:
            if run_dir:
                handoff_sudo_artifacts(run_dir)
        summary["results"].append(entry)
        save()
        if summary["failed"] and fail_fast:
            break

    summary["completed_at"] = _utc_now()
    summary["all_valid"] = (
        summary["failed"] == 0
        and summary["passed"] + summary["skipped_valid"] == summary["planned"]
    )
    save()
    return summary
