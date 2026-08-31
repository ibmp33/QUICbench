"""Atomic manifest state machine for paper-v1 attempts."""

import copy
import os
import time

from paper_v1 import DATASET_SCHEMA, POLICY_SCHEMA
from paper_v1.io import atomic_write_json, load_json


TERMINAL_STATES = {
    "completed_valid",
    "completed_invalid",
    "failed_preflight",
    "failed_start",
    "failed_runtime",
    "failed_collection",
    "failed_validation",
    "interrupted",
}

TRANSITIONS = {
    None: {"created"},
    "created": {"preflight_passed", "failed_preflight", "interrupted"},
    "preflight_passed": {"running", "failed_start", "interrupted"},
    "running": {"collecting", "failed_runtime", "interrupted"},
    "collecting": {"validating", "failed_collection", "interrupted"},
    "validating": {
        "completed_valid",
        "completed_invalid",
        "failed_validation",
        "interrupted",
    },
}


class ManifestStateError(ValueError):
    pass


def new_manifest(dataset_id, suite_id, run_id, attempt_id, repetition):
    if not all((dataset_id, suite_id, run_id, attempt_id)):
        raise ManifestStateError("dataset/suite/run/attempt identity is required")
    return {
        "dataset_schema": DATASET_SCHEMA,
        "policy_schema": POLICY_SCHEMA,
        "dataset_id": dataset_id,
        "suite_id": suite_id,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "repetition": int(repetition),
        "state": None,
        "paper_eligible": False,
        "exclusion_reasons": [],
        "supersedes": None,
        "superseded_by": None,
        "state_history": [],
        "processes": [],
        "artifacts": [],
        "requested": {},
        "runtime_reported": {},
        "validator_conclusion": {},
    }


def transition(manifest, new_state, reason=None, monotonic_ns=None):
    old_state = manifest.get("state")
    if old_state in TERMINAL_STATES:
        raise ManifestStateError("terminal manifest cannot transition")
    if new_state not in TRANSITIONS.get(old_state, set()):
        raise ManifestStateError(
            "invalid manifest transition {} -> {}".format(old_state, new_state)
        )
    updated = copy.deepcopy(manifest)
    updated["state"] = new_state
    updated["state_history"].append(
        {
            "old_state": old_state,
            "new_state": new_state,
            "monotonic_ns": monotonic_ns
            if monotonic_ns is not None
            else time.monotonic_ns(),
            "reason": reason,
        }
    )
    updated["paper_eligible"] = new_state == "completed_valid"
    if reason and new_state != "completed_valid":
        updated["exclusion_reasons"].append(reason)
    return updated


class ManifestStore:
    def __init__(self, path):
        self.path = os.path.abspath(path)

    def create(self, manifest):
        if os.path.exists(self.path):
            raise FileExistsError(self.path)
        created = transition(manifest, "created")
        atomic_write_json(self.path, created)
        return created

    def load(self):
        return load_json(self.path)

    def save(self, manifest):
        atomic_write_json(self.path, manifest)

    def transition(self, new_state, reason=None):
        updated = transition(self.load(), new_state, reason=reason)
        self.save(updated)
        return updated
