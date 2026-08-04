"""Workload profile loading and target-generation helpers."""

import json


def load_workload_profiles(path):
    with open(path) as config_file:
        profiles = json.load(config_file)
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError("workload configuration must contain at least one profile")
    return profiles


def resolve_workload(profiles, name):
    if name not in profiles:
        raise ValueError(
            "unknown workload {!r}; available profiles: {}".format(
                name, ", ".join(sorted(profiles))
            )
        )
    profile = dict(profiles[name])
    try:
        requested_bytes = int(profile["bytes"])
        duration_s = int(profile["duration_s"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "workload {!r} must define integer bytes and duration_s".format(name)
        ) from exc
    if requested_bytes <= 0:
        raise ValueError("workload {!r} must set bytes > 0".format(name))
    if duration_s <= 0:
        raise ValueError("workload {!r} must set duration_s > 0".format(name))
    return {
        "name": name,
        "bytes": requested_bytes,
        "duration_s": duration_s,
    }


def generated_target(target):
    if target["protocol"] == "http3":
        return target["url"]
    if target["protocol"] == "raw":
        return target["addr"]
    raise ValueError("unsupported workload target protocol {!r}".format(target["protocol"]))
