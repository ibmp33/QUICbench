"""Resumable, fail-closed executor for the 400-run Paper-v1 baseline corpus."""

import datetime
import os
import time

from paper_v1.io import atomic_write_json, load_json, sha256_file
from paper_v1.matrix import load_matrix, planned_runs
from paper_v1.policy import load_policy_spec
from paper_v1.preflight import run_preflight
from paper_v1.runner import PaperV1Runner, handoff_sudo_artifacts
from paper_v1.smoke import _smoke_identity, _valid_existing_attempt, smoke_plan
from paper_v1.validate import validate_run


class CorpusError(ValueError):
    pass


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _binary_hashes(config):
    return {name: sha256_file(path) for name, path in config["binaries"].items()}


def verify_smoke_gate(matrix, policy_spec, config, smoke_dataset_root, binary_hashes):
    missing = []
    evidence = []
    for planned in smoke_plan(matrix):
        expected = _smoke_identity(matrix, policy_spec, planned, binary_hashes)
        run_dir = _valid_existing_attempt(
            smoke_dataset_root, planned["run_id"], expected, require_smoke=True
        )
        if run_dir is None:
            missing.append(planned["run_id"])
        else:
            evidence.append(run_dir)
    if missing:
        raise CorpusError(
            "current-identity smoke gate is missing {} cells: {}".format(
                len(missing), ", ".join(missing[:4])
            )
        )
    return evidence


def run_baseline_corpus(local_config_path, matrix_path, policy_spec_path,
                        smoke_dataset_root, resume=False, fail_fast=False,
                        max_consecutive_failures=3, summary_path=None,
                        check_only=False):
    if max_consecutive_failures <= 0:
        raise CorpusError("max_consecutive_failures must be positive")
    preflight = run_preflight(local_config_path, matrix_path, policy_spec_path)
    config = load_json(local_config_path)
    matrix = load_matrix(matrix_path)
    policy_spec = load_policy_spec(policy_spec_path)
    binary_hashes = _binary_hashes(config)
    smoke_evidence = verify_smoke_gate(
        matrix, policy_spec, config, os.path.abspath(smoke_dataset_root), binary_hashes
    )
    runs = list(planned_runs(matrix))
    dataset_root = os.path.abspath(config["dataset_root"])
    if check_only:
        return {
            "status": "baseline_corpus_preflight_passed",
            "all_valid": True,
            "planned": len(runs),
            "smoke_cells_verified": len(smoke_evidence),
            "dataset_root": dataset_root,
            "minimum_free_bytes": int(config["storage"]["minimum_free_bytes"]),
            "static_preflight": preflight,
        }
    if summary_path is None:
        report_dir = os.path.join(dataset_root, "_corpus_reports")
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        summary_path = os.path.join(report_dir, "paper-v1-baseline-{}.json".format(stamp))
    summary_path = os.path.abspath(summary_path)
    summary = {
        "schema_version": "paper-v1-baseline-corpus-v1.0.0",
        "started_at": _utc_now(),
        "completed_at": None,
        "summary_path": summary_path,
        "local_config": os.path.abspath(local_config_path),
        "matrix": os.path.abspath(matrix_path),
        "policy_spec": os.path.abspath(policy_spec_path),
        "smoke_dataset_root": os.path.abspath(smoke_dataset_root),
        "smoke_cells_verified": len(smoke_evidence),
        "static_preflight": preflight,
        "resume": bool(resume),
        "planned": len(runs),
        "passed": 0,
        "failed": 0,
        "skipped_valid": 0,
        "all_valid": False,
        "stopped_by_circuit_breaker": False,
        "results": [],
    }

    def save():
        atomic_write_json(summary_path, summary)
        handoff_sudo_artifacts(summary_path)

    save()
    consecutive_failures = 0
    for index, planned in enumerate(runs, 1):
        expected = _smoke_identity(matrix, policy_spec, planned, binary_hashes)
        existing = None
        if resume:
            existing = _valid_existing_attempt(
                dataset_root,
                planned["run_id"],
                expected,
                require_smoke=False,
                require_paper_eligible=True,
            )
        if existing:
            summary["skipped_valid"] += 1
            summary["results"].append({
                "index": index,
                "run_id": planned["run_id"],
                "path_id": planned["path_id"],
                "status": "skipped_valid",
                "run_dir": existing,
            })
            save()
            consecutive_failures = 0
            continue

        started = time.monotonic()
        run_dir = None
        try:
            runner = PaperV1Runner(local_config_path, matrix_path, policy_spec_path)
            run_dir = runner.run(planned["run_id"], smoke=False)
            result = validate_run(run_dir, policy_spec_path)
            valid = (
                result.get("status") == "completed_valid"
                and result.get("paper_eligible") is True
                and not result.get("issues")
            )
            entry = {
                "index": index,
                "run_id": planned["run_id"],
                "path_id": planned["path_id"],
                "status": "passed" if valid else "failed_validation",
                "run_dir": run_dir,
                "attempt_id": result.get("attempt_id"),
                "issues": result.get("issues", []),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            if valid:
                summary["passed"] += 1
                consecutive_failures = 0
            else:
                summary["failed"] += 1
                consecutive_failures += 1
        except KeyboardInterrupt:
            summary["completed_at"] = _utc_now()
            summary["interrupted"] = True
            save()
            raise
        except Exception as error:
            summary["failed"] += 1
            consecutive_failures += 1
            entry = {
                "index": index,
                "run_id": planned["run_id"],
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
        if (
            (fail_fast and consecutive_failures > 0)
            or consecutive_failures >= max_consecutive_failures
        ):
            summary["stopped_by_circuit_breaker"] = True
            break

    summary["completed_at"] = _utc_now()
    summary["all_valid"] = (
        summary["failed"] == 0
        and summary["passed"] + summary["skipped_valid"] == summary["planned"]
    )
    save()
    return summary
