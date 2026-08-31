"""Fail-closed validator for one paper-v1 run attempt."""

import json
import os

from paper_v1 import DATASET_SCHEMA, POLICY_SCHEMA
from paper_v1.io import atomic_write_json, load_json, sha256_file
from paper_v1.manifest import transition
from paper_v1.policy import load_policy_spec


REQUIRED_ARTIFACT_ROLES = {
    "config_snapshot",
    "process_table",
    "client_metrics_flow_a",
    "client_metrics_flow_b",
    "receiver_policy_flow_a",
    "receiver_policy_flow_b",
    "receiver_qlog_flow_a",
    "receiver_qlog_flow_b",
    "keylog_flow_a",
    "keylog_flow_b",
    "sender_qlog",
    "pcap",
    "qdisc_before",
    "qdisc_active",
    "qdisc_after",
    "offload_before",
    "offload_active",
    "offload_after",
    "system_metadata",
    "artifact_checksums",
    "server_stdout",
    "server_stderr",
    "client_stdout_flow_a",
    "client_stderr_flow_a",
    "client_stdout_flow_b",
    "client_stderr_flow_b",
    "capture_stderr",
    "sender_runtime",
    "runtime_evidence",
    "network_evidence",
    "wire_evidence",
}

EMPTY_LOG_ROLES = {
    "server_stdout", "server_stderr", "client_stdout_flow_a", "client_stderr_flow_a",
    "client_stdout_flow_b", "client_stderr_flow_b", "capture_stderr",
}


def _issue(code, detail, gate):
    return {"code": code, "detail": detail, "gate": gate}


def _read_jsonl(path):
    events = []
    with open(path, encoding="utf-8") as artifact:
        for line_number, line in enumerate(artifact, 1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(
                    "{}:{} malformed JSONL: {}".format(path, line_number, error)
                ) from error
    if not events:
        raise ValueError("empty JSONL: {}".format(path))
    return events


def _artifact_map(manifest):
    result = {}
    for artifact in manifest.get("artifacts", []):
        role = artifact.get("role")
        if role in result:
            raise ValueError("duplicate artifact role: {}".format(role))
        result[role] = artifact
    return result


def _validate_processes(manifest, issues):
    processes = manifest.get("processes", [])
    required_kinds = {"server", "client_flow_a", "client_flow_b", "capture"}
    present = {process.get("kind") for process in processes}
    for missing in sorted(required_kinds - present):
        issues.append(_issue("missing_process", missing, "process"))
    for process in processes:
        for field in (
            "command",
            "pid",
            "start_monotonic_ns",
            "end_monotonic_ns",
            "exit_code",
            "termination_reason",
            "stdout_path",
            "stderr_path",
        ):
            if field not in process:
                issues.append(
                    _issue(
                        "incomplete_process_record",
                        "{} missing {}".format(process.get("kind"), field),
                        "process",
                    )
                )
        if not isinstance(process.get("command"), list) or not process.get("command"):
            issues.append(_issue("process_argv", process.get("kind"), "process"))
        if not isinstance(process.get("pid"), int) or process.get("pid", 0) <= 0:
            issues.append(_issue("process_pid", process.get("kind"), "process"))
        if (
            isinstance(process.get("start_monotonic_ns"), int)
            and isinstance(process.get("end_monotonic_ns"), int)
            and process["end_monotonic_ns"] < process["start_monotonic_ns"]
        ):
            issues.append(_issue("process_time_order", process.get("kind"), "process"))
        if process.get("kind", "").startswith("client") and process.get("exit_code") != 0:
            issues.append(
                _issue(
                    "client_nonzero_exit",
                    "{}={}".format(process.get("kind"), process.get("exit_code")),
                    "process",
                )
            )
        if process.get("kind") == "capture" and process.get("exit_code") not in (0, -2, -15):
            issues.append(
                _issue("capture_failed", str(process.get("exit_code")), "process")
            )
        if process.get("kind") == "server" and (
            process.get("exit_code") not in (0, 124, -15)
            or process.get("termination_reason")
            not in ("normal", "duration_complete", "graceful_stop")
        ):
            issues.append(_issue("server_termination", repr(process), "process"))
        if process.get("residual_process", False):
            issues.append(_issue("residual_process", process.get("kind"), "process"))


def _validate_artifacts(manifest, run_dir, issues):
    try:
        artifacts = _artifact_map(manifest)
    except ValueError as error:
        issues.append(_issue("artifact_mapping", str(error), "artifact"))
        return {}
    for role in sorted(REQUIRED_ARTIFACT_ROLES - set(artifacts)):
        issues.append(_issue("missing_artifact", role, "artifact"))
    for role, record in artifacts.items():
        path = record.get("path")
        if not path:
            issues.append(_issue("artifact_path_missing", role, "artifact"))
            continue
        resolved = path if os.path.isabs(path) else os.path.join(run_dir, path)
        if not os.path.isfile(resolved):
            issues.append(_issue("artifact_not_found", role, "artifact"))
            continue
        if os.path.getsize(resolved) == 0 and role not in EMPTY_LOG_ROLES:
            issues.append(_issue("artifact_empty", role, "artifact"))
            continue
        expected = record.get("sha256")
        if not expected:
            issues.append(_issue("artifact_checksum_missing", role, "artifact"))
        elif sha256_file(resolved) != expected:
            issues.append(_issue("artifact_checksum_mismatch", role, "artifact"))
        record["resolved_path"] = resolved
    return artifacts


def _validate_policy_flow(flow, events, policy_spec, issues):
    requested = flow["policy"]
    expected = policy_spec["policies"][requested]
    manifest_policy_checks = {
        "policy_version": expected["policy_version"],
        "policy_spec_sha256": expected["parameter_schema_sha256"],
        "effective_parameters": expected["parameters"],
    }
    for field, expected_value in manifest_policy_checks.items():
        if flow.get(field) != expected_value:
            issues.append(
                _issue(
                    "manifest_policy_parameters",
                    "{} {} mismatch".format(flow["flow_id"], field),
                    "treatment",
                )
            )
    initialized = [event for event in events if event.get("event") == "policy_initialized"]
    if len(initialized) != 1:
        issues.append(
            _issue(
                "policy_initialization_count",
                "{} has {}".format(flow["flow_id"], len(initialized)),
                "treatment",
            )
        )
        return
    identity = initialized[0]
    checks = {
        "flow_id": flow["flow_id"],
        "policy_name": requested,
        "policy_version": "1.0.0",
        "policy_spec_sha256": expected["parameter_schema_sha256"],
        "packet_number_space": "application_data",
    }
    for field, expected_value in checks.items():
        if identity.get(field) != expected_value:
            issues.append(
                _issue(
                    "policy_identity_mismatch",
                    "{} {} expected={!r} actual={!r}".format(
                        flow["flow_id"], field, expected_value, identity.get(field)
                    ),
                    "treatment",
                )
            )
    if identity.get("effective_parameters") != expected["parameters"]:
        issues.append(_issue("policy_parameters_mismatch", flow["flow_id"], "treatment"))
    if any(
        event.get("event") in ("ack_frequency_applied", "ack_frequency_violation")
        for event in events
    ):
        issues.append(_issue("ack_frequency_observed", flow["flow_id"], "treatment"))
    transitions = [
        event
        for event in events
        if event.get("event") == "policy_transition"
        and event.get("old_state") != "uninitialized"
    ]
    if requested == "neqo-like-ack" and transitions:
        issues.append(_issue("neqo_transition_observed", flow["flow_id"], "treatment"))
    if requested == "chrome-like-ack":
        if len(transitions) != 1:
            issues.append(
                _issue(
                    "chrome_transition_count",
                    "{} has {}".format(flow["flow_id"], len(transitions)),
                    "treatment",
                )
            )
        else:
            event = transitions[0]
            reference = event.get("reference_packet_number")
            observed = event.get("observed_packet_number")
            boundary = event.get("transition_boundary_packet_number")
            if (
                event.get("packet_number_space") != "application_data"
                or reference is None
                or observed is None
                or boundary != reference + 100
                or observed < boundary
                or event.get("old_state") != "initial-ack-every-2"
                or event.get("new_state") != "decimated-ack-every-10"
            ):
                issues.append(_issue("chrome_transition_boundary", flow["flow_id"], "treatment"))
    episodes = [event for event in events if event.get("event") == "ack_episode"]
    if not episodes:
        issues.append(_issue("missing_ack_episodes", flow["flow_id"], "wire"))
    for episode_index, event in enumerate(episodes):
        for field in (
            "ack_ranges",
            "largest_acknowledged",
            "newly_acknowledged_packet_count",
            "ack_batch_size",
            "ack_delay_ns",
            "effective_threshold",
            "trigger_reason",
            "policy_state",
        ):
            if field not in event:
                issues.append(
                    _issue(
                        "ack_episode_field_missing",
                        "{} {}".format(flow["flow_id"], field),
                        "wire",
                    )
                )
        if episode_index > 0 and "ack_spacing_ns" not in event:
            issues.append(_issue("ack_episode_field_missing", "{} ack_spacing_ns".format(flow["flow_id"]), "wire"))


def _validate_sender_runtime(manifest, artifacts, issues):
    artifact = artifacts.get("sender_runtime")
    if not artifact or not artifact.get("resolved_path"):
        return
    try:
        events = _read_jsonl(artifact["resolved_path"])
    except ValueError as error:
        issues.append(_issue("sender_runtime_invalid", str(error), "sender_identity"))
        return
    finals = [item for item in events if item.get("event") == "sender_final"]
    if len(finals) != 1:
        issues.append(_issue("sender_final_count", str(len(finals)), "sender_identity"))
        return
    reported = finals[0]
    if reported.get("schema_version") != "sender-runtime-v1.0.0":
        issues.append(_issue("sender_runtime_schema", repr(reported), "sender_identity"))
    manifest_sender = manifest.get("runtime_reported", {}).get("sender", {})
    for field in (
        "active_cc",
        "fallback",
        "configured_pacing",
        "effective_pacing",
        "pacer_initialized",
        "pacing_callback_or_tick_observed",
        "icw",
        "binary_sha256",
    ):
        if reported.get(field) != manifest_sender.get(field):
            issues.append(_issue("sender_runtime_manifest_mismatch", field, "sender_identity"))
    requested_sender = manifest.get("requested", {}).get("sender", {})
    if reported.get("binary_sha256") != requested_sender.get("binary_sha256"):
        issues.append(_issue("sender_binary_identity", repr(reported), "sender_identity"))
    if requested_sender.get("sender") == "mvfst":
        for field in (
            "h3_adapter_identity",
            "h3_adapter_kind",
            "h3_adapter_patch_sha256",
            "transport_commit",
        ):
            if reported.get(field) != manifest_sender.get(field) or not reported.get(field):
                issues.append(_issue("mvfst_runtime_identity", field, "sender_identity"))


def _validate_wire_evidence(artifacts, issues):
    artifact = artifacts.get("wire_evidence")
    if not artifact or not artifact.get("resolved_path"):
        return
    try:
        evidence = load_json(artifact["resolved_path"])
    except (OSError, json.JSONDecodeError) as error:
        issues.append(_issue("wire_evidence_invalid", str(error), "wire"))
        return
    if evidence.get("schema_version") != "wire-ack-evidence-v1.0.0":
        issues.append(_issue("wire_evidence_schema", repr(evidence), "wire"))
    extractor = evidence.get("extractor", {})
    if not all(extractor.get(field) for field in ("name", "version", "command", "tool_versions")):
        issues.append(_issue("wire_extractor_identity", repr(extractor), "wire"))
    source_roles = {
        "pcap",
        "receiver_qlog_flow_a",
        "receiver_qlog_flow_b",
        "receiver_policy_flow_a",
        "receiver_policy_flow_b",
        "keylog_flow_a",
        "keylog_flow_b",
    }
    sources = evidence.get("source_artifact_sha256", {})
    for role in source_roles:
        if role not in artifacts or sources.get(role) != artifacts[role].get("sha256"):
            issues.append(_issue("wire_source_identity", role, "wire"))
    flows = evidence.get("flows", [])
    if len(flows) != 2 or {item.get("flow_id") for item in flows} != {"flow_a", "flow_b"}:
        issues.append(_issue("wire_flow_mapping", repr(flows), "wire"))
        return
    for flow in flows:
        for field in (
            "ack_episode_count",
            "ack_batch_observed",
            "ack_spacing_observed",
            "ack_delay_observed",
            "policy_log_matches_wire",
            "qlog_matches_pcap",
            "ack_delay_units_valid",
        ):
            value = flow.get(field)
            if field == "ack_episode_count":
                valid = isinstance(value, int) and value > 0
            else:
                valid = value is True
            if not valid:
                issues.append(_issue("wire_evidence_gate", "{} {}".format(flow.get("flow_id"), field), "wire"))
        episode_count = flow.get("ack_episode_count", 0)
        for field in ("ack_batches", "ack_spacing_ns", "ack_delay_ns"):
            samples = flow.get(field)
            if (
                not isinstance(samples, list)
                or len(samples) != episode_count
                or any(not isinstance(value, int) or value < 0 for value in samples)
            ):
                issues.append(_issue("wire_samples", "{} {}".format(flow.get("flow_id"), field), "wire"))
        for field in ("pcap_ack_frame_count", "qlog_ack_frame_count"):
            if not isinstance(flow.get(field), int) or flow[field] <= 0:
                issues.append(_issue("wire_frame_count", "{} {}".format(flow.get("flow_id"), field), "wire"))
        if flow.get("policy_name") == "chrome-like-ack" and flow.get("transition_matches_wire") is not True:
            issues.append(_issue("wire_transition_gate", flow.get("flow_id"), "wire"))


def _validate_network_evidence(artifacts, issues):
    artifact = artifacts.get("network_evidence")
    if not artifact or not artifact.get("resolved_path"):
        return {}
    try:
        evidence = load_json(artifact["resolved_path"])
    except (OSError, json.JSONDecodeError) as error:
        issues.append(_issue("network_evidence_invalid", str(error), "network"))
        return {}
    if evidence.get("schema_version") != "network-evidence-v1.0.0":
        issues.append(_issue("network_evidence_schema", repr(evidence), "network"))
    sources = evidence.get("source_artifact_sha256", {})
    for role in ("qdisc_before", "qdisc_active", "qdisc_after"):
        if role not in artifacts or sources.get(role) != artifacts[role].get("sha256"):
            issues.append(_issue("network_source_identity", role, "network"))
    conclusion = evidence.get("conclusion", {})
    for key in (
        "qdisc_matches_requested", "offloads_valid", "shared_bottleneck", "saturated",
        "both_flows_active", "not_application_limited", "start_skew_valid",
    ):
        if conclusion.get(key) is not True:
            issues.append(_issue("network_gate", key, "network"))
    return conclusion


def _validate_runtime_evidence(manifest, artifacts, issues):
    artifact = artifacts.get("runtime_evidence")
    if not artifact or not artifact.get("resolved_path"):
        return
    try:
        evidence = load_json(artifact["resolved_path"])
    except (OSError, json.JSONDecodeError) as error:
        issues.append(_issue("runtime_evidence_invalid", str(error), "workload"))
        return
    if evidence.get("schema_version") != "runtime-derived-v1.0.0":
        issues.append(_issue("runtime_evidence_schema", repr(evidence), "workload"))
    runtime = manifest.get("runtime_reported", {})
    for field in ("flows", "workload", "derivation"):
        if runtime.get(field) != evidence.get(field):
            issues.append(_issue("runtime_evidence_manifest_mismatch", field, "workload"))


def validate_run(run_dir, policy_spec_path):
    run_dir = os.path.abspath(run_dir)
    manifest_path = os.path.join(run_dir, "run_manifest.json")
    issues = []
    try:
        manifest = load_json(manifest_path)
    except (OSError, json.JSONDecodeError) as error:
        result = {
            "status": "failed",
            "paper_eligible": False,
            "issues": [_issue("manifest_unreadable", str(error), "artifact")],
        }
        atomic_write_json(os.path.join(run_dir, "validation.json"), result)
        return result
    if manifest.get("dataset_schema") != DATASET_SCHEMA:
        issues.append(_issue("legacy_dataset_schema", str(manifest.get("dataset_schema")), "schema"))
    if manifest.get("policy_schema") != POLICY_SCHEMA:
        issues.append(_issue("policy_schema_mismatch", str(manifest.get("policy_schema")), "schema"))
    if manifest.get("state") != "validating":
        issues.append(_issue("manifest_state", str(manifest.get("state")), "schema"))
    policy_spec = load_policy_spec(policy_spec_path)
    _validate_processes(manifest, issues)
    artifacts = _validate_artifacts(manifest, run_dir, issues)
    requested = manifest.get("requested", {})
    flows = requested.get("flows", [])
    if len(flows) != 2 or {flow.get("flow_id") for flow in flows} != {"flow_a", "flow_b"}:
        issues.append(_issue("flow_mapping", "exactly flow_a and flow_b required", "treatment"))
    else:
        for flow in flows:
            if flow.get("policy") not in policy_spec["policies"]:
                issues.append(_issue("unknown_policy", repr(flow), "treatment"))
                continue
            role = "receiver_policy_{}".format(flow["flow_id"])
            artifact = artifacts.get(role)
            if artifact and artifact.get("resolved_path"):
                try:
                    events = _read_jsonl(artifact["resolved_path"])
                    _validate_policy_flow(flow, events, policy_spec, issues)
                except ValueError as error:
                    issues.append(_issue("policy_log_invalid", str(error), "treatment"))
    _validate_sender_runtime(manifest, artifacts, issues)
    _validate_wire_evidence(artifacts, issues)
    _validate_network_evidence(artifacts, issues)
    _validate_runtime_evidence(manifest, artifacts, issues)
    runtime = manifest.get("runtime_reported", {})
    runtime_flows = runtime.get("flows", [])
    if len(runtime_flows) != 2 or {item.get("flow_id") for item in runtime_flows} != {"flow_a", "flow_b"}:
        issues.append(_issue("h3_flow_mapping", "exactly two runtime flows required", "workload"))
    else:
        connection_ids = set()
        local_ports = set()
        for flow in runtime_flows:
            connection_ids.add(flow.get("connection_id"))
            local_ports.add(flow.get("client_local_port"))
            checks = {
                "alpn": "h3",
                "http_status": 200,
                "headers_valid": True,
                "stream_count": 1,
                "client_continuous_read": True,
            }
            for field, expected in checks.items():
                if flow.get(field) != expected:
                    issues.append(
                        _issue(
                            "h3_flow_contract",
                            "{} {} expected={!r} actual={!r}".format(
                                flow.get("flow_id"), field, expected, flow.get(field)
                            ),
                            "workload",
                        )
                    )
            if flow.get("response_content_length", 0) < 1073741824:
                issues.append(_issue("h3_response_too_short", flow.get("flow_id"), "workload"))
            if flow.get("decoded_body_bytes", 0) <= 0:
                issues.append(_issue("h3_no_body_progress", flow.get("flow_id"), "workload"))
            if flow.get("measurement_window_body_bytes", 0) <= 0:
                issues.append(_issue("h3_no_window_progress", flow.get("flow_id"), "workload"))
            if flow.get("flow_control_blocked_in_window") is not False:
                issues.append(_issue("flow_control_blocked", flow.get("flow_id"), "workload"))
            if flow.get("application_limited_in_window") is not False:
                issues.append(_issue("application_limited", flow.get("flow_id"), "workload"))
        if None in connection_ids or len(connection_ids) != 2:
            issues.append(_issue("connection_isolation", repr(connection_ids), "workload"))
        if None in local_ports or len(local_ports) != 2:
            issues.append(_issue("client_local_ports", repr(local_ports), "workload"))
    workload = runtime.get("workload", {})
    workload_checks = {
        "protocol": "http3",
        "server_process_count": 1,
        "server_listening_port_count": 1,
        "server_application_ready": True,
        "body_counter": "client-decoded-http3-response-body-bytes",
        "duration_s": 30,
        "measurement_window_start_s": 5,
        "measurement_window_end_s": 25,
    }
    for field, expected in workload_checks.items():
        if workload.get(field) != expected:
            issues.append(
                _issue(
                    "h3_workload_contract",
                    "{} expected={!r} actual={!r}".format(field, expected, workload.get(field)),
                    "workload",
                )
            )
    sender = runtime.get("sender", {})
    requested_sender = requested.get("sender", {})
    active_cc_matches = sender.get("active_cc") == requested_sender.get("cc")
    if requested_sender.get("cc") == "bbr-family":
        active_cc_matches = sender.get("active_cc") in {"bbr", "bbr1", "bbr2", "bbr2modular"}
    if not active_cc_matches:
        issues.append(_issue("active_cc_mismatch", repr(sender), "sender_identity"))
    if sender.get("fallback", True):
        issues.append(_issue("controller_fallback", repr(sender), "sender_identity"))
    if sender.get("effective_pacing") != requested_sender.get("required_effective_pacing"):
        issues.append(_issue("effective_pacing_mismatch", repr(sender), "sender_identity"))
    if sender.get("pacer_initialized") is not True and requested_sender.get("required_effective_pacing") == "paced":
        issues.append(_issue("pacer_not_initialized", repr(sender), "sender_identity"))
    if sender.get("pacing_callback_or_tick_observed") is not True and requested_sender.get("required_effective_pacing") == "paced":
        issues.append(_issue("pacer_tick_not_observed", repr(sender), "sender_identity"))
    if requested_sender.get("sender") == "mvfst":
        if sender.get("h3_adapter_identity") != "mvfst + paper-v1 minimal H3 adapter":
            issues.append(_issue("mvfst_h3_identity", repr(sender), "sender_identity"))
    wire = manifest.get("validator_conclusion", {}).get("wire", {})
    for key in ("qlog_policy_consistent", "pcap_policy_consistent", "ack_delay_units_valid"):
        if wire.get(key) is not True:
            issues.append(_issue("wire_gate", key, "wire"))
    status = "completed_valid" if not issues else "completed_invalid"
    result = {
        "dataset_schema": DATASET_SCHEMA,
        "run_id": manifest.get("run_id"),
        "attempt_id": manifest.get("attempt_id"),
        "status": status,
        "paper_eligible": not issues,
        "issues": issues,
    }
    if manifest.get("state") == "validating":
        finalized = transition(manifest, status)
        finalized["paper_eligible"] = not issues
        finalized["exclusion_reasons"] = [item["code"] for item in issues]
        finalized.setdefault("validator_conclusion", {})["paper_v1"] = result
        atomic_write_json(manifest_path, finalized)
    atomic_write_json(os.path.join(run_dir, "validation.json"), result)
    return result
