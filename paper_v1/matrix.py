"""Canonical Paper-v1 matrix loading and deterministic run planning."""

import itertools

from paper_v1 import DATASET_SCHEMA, POLICY_SCHEMA
from paper_v1.io import load_json


POLICY_PAIRS = (
    ("neqo-like-ack", "neqo-like-ack"),
    ("chrome-like-ack", "chrome-like-ack"),
    ("neqo-like-ack", "chrome-like-ack"),
    ("chrome-like-ack", "neqo-like-ack"),
)

MAIN_PATH_COUNT = 11
MAIN_RUN_COUNT = 400
SMOKE_RUN_COUNT = MAIN_PATH_COUNT * len(POLICY_PAIRS)
SENSITIVITY_RUN_COUNT = 120
OPTIONAL_LOSS_RUN_COUNT = 40


class MatrixError(ValueError):
    pass


def load_matrix(path):
    document = load_json(path)
    if document.get("dataset_schema") != DATASET_SCHEMA:
        raise MatrixError("unexpected dataset schema")
    if document.get("policy_schema") != POLICY_SCHEMA:
        raise MatrixError("unexpected policy schema")
    paths = document.get("paths")
    if not isinstance(paths, list) or len(paths) != MAIN_PATH_COUNT:
        raise MatrixError(
            "canonical paper-v1 matrix must contain {} paths".format(
                MAIN_PATH_COUNT
            )
        )
    ids = [item.get("path_id") for item in paths]
    if len(set(ids)) != len(ids):
        raise MatrixError("path IDs must be unique")
    for item in paths:
        if item.get("protocol") != "http3":
            raise MatrixError("every paper-v1 main path must use HTTP/3")
        if item.get("sender") == "mvfst" and item.get("adapter_identity") != "mvfst + paper-v1 minimal H3 adapter":
            raise MatrixError("mvfst main paths require the paper-v1 H3 adapter")
        if item["cc_family"] == "bbr" and item["requested_pacing"] != "on":
            raise MatrixError("BBR paths must request effective pacing on")
        if not isinstance(item.get("repetitions"), int) or item["repetitions"] <= 0:
            raise MatrixError("every path requires a positive repetition count")

    if tuple(tuple(pair) for pair in document.get("policy_pairs", [])) != POLICY_PAIRS:
        raise MatrixError("canonical policy-pair order is required")

    profiles = document.get("network_profiles")
    if not isinstance(profiles, list) or not profiles:
        raise MatrixError("network_profiles must be a non-empty list")
    profile_ids = [profile.get("profile_id") for profile in profiles]
    if None in profile_ids or len(profile_ids) != len(set(profile_ids)):
        raise MatrixError("network profile IDs must be present and unique")
    for profile in profiles:
        for field in (
            "forward_delay_ms",
            "reverse_delay_ms",
            "forward_bandwidth_mbps",
            "queue_size_bytes",
            "random_loss_forward_percent",
            "random_loss_reverse_percent",
            "jitter_ms",
            "intentional_reordering_percent",
        ):
            if field not in profile:
                raise MatrixError(
                    "network profile {} is missing {}".format(
                        profile.get("profile_id"), field
                    )
                )
        if profile.get("reverse_bottleneck") is not False:
            raise MatrixError("Paper-v1 reverse paths must not be bandwidth limited")

    sensitivity = document.get("network_sensitivity", {})
    anchors = sensitivity.get("anchor_path_ids", [])
    sensitivity_profiles = sensitivity.get("profile_ids", [])
    repetitions = sensitivity.get("repetitions")
    if len(anchors) != 2 or any(anchor not in ids for anchor in anchors):
        raise MatrixError("network sensitivity requires two valid anchor paths")
    if len(sensitivity_profiles) != 3 or any(
        profile not in profile_ids for profile in sensitivity_profiles
    ):
        raise MatrixError("core network sensitivity requires three valid profiles")
    if not isinstance(repetitions, int) or repetitions <= 0:
        raise MatrixError("network sensitivity repetitions must be positive")

    if len(list(planned_runs(document))) != MAIN_RUN_COUNT:
        raise MatrixError("canonical main matrix must plan 400 runs")
    if len(list(planned_sensitivity_runs(document))) != SENSITIVITY_RUN_COUNT:
        raise MatrixError("canonical sensitivity matrix must plan 120 runs")
    appendix = document.get("optional_appendix_loss", {})
    appendix_profiles = appendix.get("profile_ids", [])
    if appendix.get("anchor_path_ids") != anchors:
        raise MatrixError("optional loss appendix must use the two anchor paths")
    if len(appendix_profiles) != 1 or any(
        profile not in profile_ids for profile in appendix_profiles
    ):
        raise MatrixError("optional loss appendix requires one valid profile")
    if not isinstance(appendix.get("repetitions"), int) or appendix["repetitions"] <= 0:
        raise MatrixError("optional loss appendix repetitions must be positive")
    if len(list(planned_optional_loss_runs(document))) != OPTIONAL_LOSS_RUN_COUNT:
        raise MatrixError("optional loss appendix must plan 40 runs")
    return document


def planned_runs(matrix, repetitions=None):
    for sender_path in matrix["paths"]:
        path_repetitions = repetitions or sender_path["repetitions"]
        for policy_pair, repetition in itertools.product(
            POLICY_PAIRS, range(1, path_repetitions + 1)
        ):
            pair_id = "{}__{}".format(*policy_pair)
            yield {
                "suite_id": matrix["suite_id"],
                "experiment_class": sender_path["experiment_class"],
                "network_profile_id": matrix["base_network_profile_id"],
                "path_id": sender_path["path_id"],
                "policy_pair": list(policy_pair),
                "policy_pair_id": pair_id,
                "repetition": repetition,
                "run_id": "{}--{}--r{:02d}".format(
                    sender_path["path_id"], pair_id, repetition
                ),
            }


def planned_sensitivity_runs(matrix, repetitions=None):
    sensitivity = matrix["network_sensitivity"]
    count = repetitions or sensitivity["repetitions"]
    for path_id, profile_id, policy_pair, repetition in itertools.product(
        sensitivity["anchor_path_ids"],
        sensitivity["profile_ids"],
        POLICY_PAIRS,
        range(1, count + 1),
    ):
        pair_id = "{}__{}".format(*policy_pair)
        yield {
            "suite_id": sensitivity["suite_id"],
            "experiment_class": "network-sensitivity",
            "network_profile_id": profile_id,
            "path_id": path_id,
            "policy_pair": list(policy_pair),
            "policy_pair_id": pair_id,
            "repetition": repetition,
            "run_id": "{}--{}--{}--r{:02d}".format(
                path_id, profile_id, pair_id, repetition
            ),
        }


def planned_optional_loss_runs(matrix, repetitions=None):
    appendix = matrix["optional_appendix_loss"]
    count = repetitions or appendix["repetitions"]
    for path_id, profile_id, policy_pair, repetition in itertools.product(
        appendix["anchor_path_ids"],
        appendix["profile_ids"],
        POLICY_PAIRS,
        range(1, count + 1),
    ):
        pair_id = "{}__{}".format(*policy_pair)
        yield {
            "suite_id": appendix["suite_id"],
            "experiment_class": "optional-loss-appendix",
            "network_profile_id": profile_id,
            "path_id": path_id,
            "policy_pair": list(policy_pair),
            "policy_pair_id": pair_id,
            "repetition": repetition,
            "run_id": "{}--{}--{}--r{:02d}".format(
                path_id, profile_id, pair_id, repetition
            ),
        }
