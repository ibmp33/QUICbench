"""Deterministic export that accepts only explicitly indexed paper-v1 attempts."""

import csv
import os

from paper_v1 import DATASET_SCHEMA
from paper_v1.io import atomic_write_json, load_json, sha256_file


class ExportError(ValueError):
    pass


def export_dataset(dataset_dir, output_dir):
    dataset_dir = os.path.abspath(dataset_dir)
    output_dir = os.path.abspath(output_dir)
    index = load_json(os.path.join(dataset_dir, "dataset_manifest.json"))
    if index.get("dataset_schema") != DATASET_SCHEMA:
        raise ExportError("legacy or unknown dataset schema")
    attempts = index.get("attempts")
    if not isinstance(attempts, list):
        raise ExportError("dataset manifest requires an explicit attempts list")
    if len(attempts) != len(set(attempts)):
        raise ExportError("dataset manifest contains duplicate attempts")
    os.makedirs(output_dir, exist_ok=False)
    rows = []
    checksums = []
    for relative in attempts:
        if os.path.isabs(relative) or ".." in relative.split(os.sep):
            raise ExportError("attempt path must stay inside the dataset: {}".format(relative))
        run_dir = os.path.join(dataset_dir, relative)
        manifest_path = os.path.join(run_dir, "run_manifest.json")
        validation_path = os.path.join(run_dir, "validation.json")
        manifest = load_json(manifest_path)
        validation = load_json(validation_path)
        if manifest.get("dataset_schema") != DATASET_SCHEMA:
            raise ExportError("legacy manifest in explicit index: {}".format(relative))
        if validation.get("paper_eligible") != manifest.get("paper_eligible"):
            raise ExportError("manifest/validation eligibility mismatch: {}".format(relative))
        expected_state = "completed_valid" if validation.get("paper_eligible") else "completed_invalid"
        if manifest.get("state") != expected_state:
            raise ExportError("manifest is not in a completed validation state: {}".format(relative))
        rows.append(
            {
                "dataset_id": manifest["dataset_id"],
                "suite_id": manifest["suite_id"],
                "run_id": manifest["run_id"],
                "attempt_id": manifest["attempt_id"],
                "repetition": manifest["repetition"],
                "state": manifest["state"],
                "paper_eligible": validation["paper_eligible"],
                "exclusion_reasons": ";".join(
                    item["code"] for item in validation.get("issues", [])
                ),
            }
        )
        checksums.extend(
            [
                {"path": os.path.relpath(manifest_path, dataset_dir), "sha256": sha256_file(manifest_path)},
                {"path": os.path.relpath(validation_path, dataset_dir), "sha256": sha256_file(validation_path)},
            ]
        )
    table_path = os.path.join(output_dir, "runs.csv")
    with open(table_path, "w", newline="", encoding="utf-8") as artifact:
        writer = csv.DictWriter(artifact, fieldnames=list(rows[0]) if rows else ["run_id"])
        writer.writeheader()
        writer.writerows(rows)
    summary = {
        "dataset_schema": DATASET_SCHEMA,
        "dataset_id": index.get("dataset_id"),
        "planned": index.get("planned_runs"),
        "attempted": len(rows),
        "valid": sum(row["paper_eligible"] for row in rows),
        "invalid_or_failed": sum(not row["paper_eligible"] for row in rows),
        "runs_table": "runs.csv",
        "checksums": checksums,
    }
    atomic_write_json(os.path.join(output_dir, "export_manifest.json"), summary)
    return summary
