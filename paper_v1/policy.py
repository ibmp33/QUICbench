"""Load and verify the frozen receiver ACK policy specification."""

from paper_v1 import POLICY_SCHEMA
from paper_v1.io import canonical_json_bytes, load_json, sha256_bytes


CANONICAL_POLICIES = ("neqo-like-ack", "chrome-like-ack")


class PolicySpecError(ValueError):
    pass


def parameter_schema_hash(policy):
    identity = {
        "canonical_name": policy["canonical_name"],
        "policy_version": policy["policy_version"],
        "modeled_scope": policy["modeled_scope"],
        "packet_number_spaces": policy["packet_number_spaces"],
        "ack_eliciting_definition": policy["ack_eliciting_definition"],
        "parameters": policy["parameters"],
        "unsupported_native_behavior": policy["unsupported_native_behavior"],
    }
    return sha256_bytes(canonical_json_bytes(identity))


def load_policy_spec(path):
    document = load_json(path)
    if document.get("policy_schema") != POLICY_SCHEMA:
        raise PolicySpecError("unexpected policy schema")
    policies = document.get("policies")
    if not isinstance(policies, dict) or set(policies) != set(CANONICAL_POLICIES):
        raise PolicySpecError("paper-v1 requires exactly the two canonical policies")
    for name in CANONICAL_POLICIES:
        policy = policies[name]
        if policy.get("canonical_name") != name:
            raise PolicySpecError("policy name mismatch for {}".format(name))
        if policy.get("policy_version") != "1.0.0":
            raise PolicySpecError("policy version mismatch for {}".format(name))
        actual = parameter_schema_hash(policy)
        if policy.get("parameter_schema_sha256") != actual:
            raise PolicySpecError(
                "parameter schema hash mismatch for {}: expected {}".format(
                    name, actual
                )
            )
    return document
