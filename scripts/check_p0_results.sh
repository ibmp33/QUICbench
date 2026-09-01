#!/usr/bin/env bash
set -euo pipefail

if (($# != 1)); then
  echo "Usage: ./scripts/check_p0_results.sh RESULTS_DIRECTORY" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi

RESULTS_DIRECTORY="$1"
if [[ ! -d "$RESULTS_DIRECTORY" ]]; then
  echo "Results directory does not exist: $RESULTS_DIRECTORY" >&2
  exit 1
fi

python3 - "$RESULTS_DIRECTORY" <<'PY'
import csv
import json
import os
import statistics
import sys
from collections import defaultdict
from pathlib import Path

root = Path(sys.argv[1]).resolve()
all_manifests = list(root.rglob("run_manifest.json"))
if not all_manifests:
    raise SystemExit("No run_manifest.json files found under {}".format(root))

# Select the newest artifact for each profile/trial/repetition index. This
# avoids mixing a rerun with older artifacts that use the same 01..10 indices.
selected = {}
for manifest_path in all_manifests:
    run_dir = manifest_path.parent
    trial_dir = run_dir.parent
    profile_dir = trial_dir.parent
    repetition = run_dir.name.split("-", 1)[0]
    key = (profile_dir.name, trial_dir.name, repetition)
    previous = selected.get(key)
    if previous is None or manifest_path.stat().st_mtime > previous.stat().st_mtime:
        selected[key] = manifest_path

ordered_pairs = [
    ("fixed2", "fixed2"),
    ("fixed10", "fixed10"),
    ("fixed2", "fixed10"),
    ("fixed10", "fixed2"),
    ("neqo", "neqo"),
    ("chromium", "chromium"),
    ("neqo", "chromium"),
    ("chromium", "neqo"),
]
results = defaultdict(list)
problems = []

for manifest_path in sorted(selected.values()):
    with open(manifest_path) as manifest_file:
        manifest = json.load(manifest_file)
    flows = manifest.get("flows") or []
    label = str(manifest_path.parent)
    checks = [
        (manifest.get("server_instance_count") == 1, "server_instance_count != 1"),
        (manifest.get("workload_name") == "fairness", "workload_name != fairness"),
        (manifest.get("requested_bytes") == 1073741824, "requested_bytes != 1 GiB"),
        (manifest.get("duration_s") == 60, "duration_s != 60"),
        (manifest.get("experiment_valid") is True, "experiment_valid != true"),
        (manifest.get("saturation_validation", {}).get("measurement_window_start_s") == 10, "measurement start != 10s"),
        (manifest.get("saturation_validation", {}).get("measurement_window_end_s") == 50, "measurement end != 50s"),
        (len(flows) == 2, "flow count != 2"),
    ]
    server_pid = manifest.get("server_pid")
    if len(flows) == 2:
        checks.extend(
            [
                (server_pid is not None, "server_pid is missing"),
                (all(flow.get("server_pid") == server_pid for flow in flows), "flows do not share server_pid"),
                ({str(flow.get("port")) for flow in flows} == {"4433"}, "flows do not share server port 4433"),
                ({int(flow.get("local_port", -1)) for flow in flows} == {54433, 54434}, "local ports are not 54433/54434"),
                (all(flow.get("server_stack") == "quic-go" for flow in flows), "server stack is not quic-go"),
                (all(flow.get("ack_policy_config") for flow in flows), "ack_policy_config is missing"),
            ]
        )
    for passed, message in checks:
        if not passed:
            problems.append("{}: {}".format(label, message))

    summary_path = manifest_path.parent / "summary.csv"
    if not summary_path.is_file():
        problems.append("{}: per-run summary.csv is missing".format(label))
        continue
    with open(summary_path, newline="") as summary_file:
        rows = list(csv.DictReader(summary_file))
    if len(rows) != 2:
        problems.append("{}: per-run summary.csv does not contain two flows".format(label))
        continue

    throughputs = [float(row["avg_throughput_mbps"]) for row in rows]
    total = sum(throughputs)
    jain = (total * total / (2 * sum(value * value for value in throughputs))) if total else 0.0
    shares = [float(row["share"]) for row in rows]
    pair = tuple(row["ack_policy"] for row in rows)
    results[pair].append(
        {
            "jain": jain,
            "share_a": shares[0],
            "share_b": shares[1],
            "share_gap": abs(shares[0] - shares[1]),
            "valid": manifest.get("experiment_valid") is True,
        }
    )

missing_pairs = [pair for pair in ordered_pairs if not results.get(pair)]
for pair in missing_pairs:
    problems.append("expected policy pair is missing: {}/{}".format(*pair))

valid_count = sum(
    1
    for manifest_path in selected.values()
    if json.loads(manifest_path.read_text()).get("experiment_valid") is True
)
print("Results root: {}".format(root))
print("Selected latest runs: {}".format(len(selected)))
print("Experiment valid: {}/{}".format(valid_count, len(selected)))
print("Integrity checks: {}".format("PASS" if not problems else "FAIL"))
print()
print("Policy pairs:")

for pair in ordered_pairs:
    samples = results.get(pair, [])
    name = "{}/{}".format(*pair)
    if not samples:
        print("{}: MISSING".format(name))
        continue
    mean_share_a = statistics.mean(sample["share_a"] for sample in samples)
    mean_share_b = statistics.mean(sample["share_b"] for sample in samples)
    mean_gap = statistics.mean(sample["share_gap"] for sample in samples)
    mean_jain = statistics.mean(sample["jain"] for sample in samples)
    winner = pair[0] if mean_share_a > mean_share_b else pair[1] if mean_share_b > mean_share_a else "tie"
    print(
        "{}: runs={} valid={} mean_jain={:.5f} share_a={:.3%} share_b={:.3%} "
        "share_gap={:.3%} winner={}".format(
            name,
            len(samples),
            sum(1 for sample in samples if sample["valid"]),
            mean_jain,
            mean_share_a,
            mean_share_b,
            mean_gap,
            winner,
        )
    )

unexpected_pairs = sorted(set(results).difference(ordered_pairs))
for pair in unexpected_pairs:
    print("Unexpected pair present: {}/{}".format(*pair))

if problems:
    print()
    print("Problems:")
    for problem in problems[:50]:
        print("- " + problem)
    if len(problems) > 50:
        print("- ... {} additional problem(s)".format(len(problems) - 50))
    raise SystemExit(1)
PY
