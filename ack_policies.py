"""ACK policy manifest configuration loading and validation."""

import json


REQUIRED_POLICY_FIELDS = {
    "fixed2": {"initial_threshold", "steady_threshold", "max_ack_delay_ms", "timer_rule", "reordering_ack"},
    "fixed10": {"initial_threshold", "steady_threshold", "max_ack_delay_ms", "timer_rule", "reordering_ack"},
    "neqo": {"threshold", "max_ack_delay_ms", "timer_rule", "reordering_ack"},
    "chromium": {
        "initial_threshold",
        "steady_threshold",
        "switch_after_packets",
        "max_ack_delay_ms",
        "timer_rule",
        "reordering_ack",
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
