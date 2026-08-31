"""ACK policy manifest configuration loading and validation."""

import json


REQUIRED_POLICY_FIELDS = {
    "synthetic-fixed-ack-2": {"policy_name", "policy_version", "initial_threshold", "steady_threshold", "max_ack_delay_ms", "timer_rule", "reordering_ack", "classification"},
    "synthetic-fixed-ack-10": {"policy_name", "policy_version", "initial_threshold", "steady_threshold", "max_ack_delay_ms", "timer_rule", "reordering_ack", "classification"},
    "neqo-like-ack": {"policy_name", "policy_version", "initial_threshold", "steady_threshold", "threshold_transition", "packet_number_spaces", "max_ack_delay_ms", "timer_rule", "immediate_ack_conditions", "reordering_ack", "state_scope", "reference", "reference_commit"},
    "chrome-like-ack": {
        "policy_name",
        "policy_version",
        "initial_threshold",
        "steady_threshold",
        "switch_after_packet_number_advance",
        "transition_boundary",
        "max_ack_delay_ms",
        "timer_rule",
        "immediate_ack_conditions",
        "reordering_ack",
        "packet_number_spaces",
        "state_scope",
        "reference",
        "reference_commit",
    },
}


def load_ack_policy_configs(path):
    with open(path) as config_file:
        document = json.load(config_file)
    policies = document.get("policies") if isinstance(document, dict) else None
    if not isinstance(policies, dict):
        raise ValueError("ACK policy configuration must contain a policies object")
    missing_policies = set(REQUIRED_POLICY_FIELDS).difference(policies)
    if missing_policies:
        raise ValueError(
            "ACK policy configuration is missing: {}".format(
                ", ".join(sorted(missing_policies))
            )
        )
    for policy, required_fields in REQUIRED_POLICY_FIELDS.items():
        if policies[policy].get("policy_name") != policy:
            raise ValueError("ACK policy {!r} has a mismatched policy_name".format(policy))
        missing_fields = required_fields.difference(policies[policy])
        if missing_fields:
            raise ValueError(
                "ACK policy {!r} is missing fields: {}".format(
                    policy, ", ".join(sorted(missing_fields))
                )
            )
    return {
        "schema_version": int(document.get("schema_version", 1)),
        "policies": policies,
    }
