#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
EXPECTED_CWD="$REPO_ROOT"
RUNNER="run_B0_two_flow_fairness_no_jitter.py"
EXPERIMENT_CONFIG="config/P0_policy_fairness.json"
WORKLOAD_CONFIG="config/workloads_conf_default.json"
ACK_POLICY_CONFIG="config/ack_policies_default.json"
STACKS_CONFIG="config/stacks_conf_default.json"
GENERAL_CONFIG="config/general_conf_default.json"
NETWORK_PROFILE="50rtt-20bw-0.5bdp"
RESULTS_ROOT="/home/ioio33/QUIC_project/results/P0-policy-fairness-quic-go-server"
TRIALS=1
PCAP_POLICY="first-only"

usage() {
  echo "Usage: ./run_first_quic_go_p0.sh [--trials N] [--pcap-policy all|first-only|none]" >&2
}

while (($# > 0)); do
  case "$1" in
    --trials)
      if (($# < 2)); then
        usage
        exit 2
      fi
      TRIALS="$2"
      shift 2
      ;;
    --pcap-policy)
      if (($# < 2)); then
        usage
        exit 2
      fi
      PCAP_POLICY="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ ! "$TRIALS" =~ ^[1-9][0-9]*$ ]]; then
  echo "--trials must be a positive integer." >&2
  exit 2
fi

case "$PCAP_POLICY" in
  all|first-only|none) ;;
  *)
    echo "--pcap-policy must be all, first-only, or none." >&2
    exit 2
    ;;
esac

if [[ "$(pwd -P)" != "$EXPECTED_CWD" ]]; then
  echo "Run this script from the QUICbench repository root: $EXPECTED_CWD" >&2
  exit 1
fi

if [[ ! -d .git ]] || [[ "$(git rev-parse --show-toplevel 2>/dev/null)" != "$REPO_ROOT" ]]; then
  echo "Current directory is not the expected QUICbench Git checkout." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi

for required_file in \
  "$RUNNER" \
  "$EXPERIMENT_CONFIG" \
  "$WORKLOAD_CONFIG" \
  "$ACK_POLICY_CONFIG" \
  "$STACKS_CONFIG" \
  "$GENERAL_CONFIG"; do
  if [[ ! -f "$required_file" ]]; then
    echo "Required file is missing: $required_file" >&2
    exit 1
  fi
done

python3 - "$EXPERIMENT_CONFIG" "$WORKLOAD_CONFIG" <<'PY'
import json
import sys

experiment_path, workload_path = sys.argv[1:]
with open(experiment_path) as config_file:
    experiment = json.load(config_file)
with open(workload_path) as config_file:
    workloads = json.load(config_file)

expected_pairs = {
    ("fixed2", "fixed2"),
    ("fixed10", "fixed10"),
    ("fixed2", "fixed10"),
    ("fixed10", "fixed2"),
    ("neqo", "neqo"),
    ("chromium", "chromium"),
    ("neqo", "chromium"),
    ("chromium", "neqo"),
}
actual_pairs = {
    tuple(flow["ack_policy"] for flow in trial["flows"])
    for trial in experiment["trials"]
}

checks = [
    (experiment.get("fixed_parameters", {}).get("server_stack_name") == "quic-go", "server_stack_name must be quic-go"),
    (experiment.get("topology_mode") == "shared-server-shared-port", "topology_mode must be shared-server-shared-port"),
    (experiment.get("workload_name") == "fairness", "workload_name must be fairness"),
    (actual_pairs == expected_pairs, "P0 config must contain exactly the eight expected ordered policy pairs"),
    (all({str(flow["port_no"]) for flow in trial["flows"]} == {"4433"} for trial in experiment["trials"]), "both flows must use server port 4433"),
    (all({int(flow["local_port"]) for flow in trial["flows"]} == {54433, 54434} for trial in experiment["trials"]), "flows must use local ports 54433 and 54434"),
    (workloads.get("fairness") == {"bytes": 1073741824, "duration_s": 60}, "fairness workload must be 1 GiB for 60 seconds"),
]
failures = [message for passed, message in checks if not passed]
if failures:
    raise SystemExit("P0 configuration preflight failed: " + "; ".join(failures))
PY

cat <<EOF
Experiment:
P0 policy fairness validation

Server:
quic-go

Network:
$NETWORK_PROFILE

Workload:
fairness
1GiB object
60s duration

Policies:
fixed2/fixed2
fixed10/fixed10
fixed2/fixed10
fixed10/fixed2
neqo/neqo
chromium/chromium
neqo/chromium
chromium/neqo

Repetitions per ordered pair:
$TRIALS

PCAP retention:
$PCAP_POLICY
EOF

echo
echo "Validating sudo credentials..."
sudo -v
sudo -n true

PROFILE_RESULTS="$RESULTS_ROOT/$NETWORK_PROFILE"
BEFORE_MANIFEST_COUNT=0
if [[ -d "$PROFILE_RESULTS" ]]; then
  BEFORE_MANIFEST_COUNT="$(find "$PROFILE_RESULTS" -type f -name run_manifest.json | wc -l | tr -d ' ')"
fi

python3 "$RUNNER" \
  --exp_conf "$EXPERIMENT_CONFIG" \
  --network-profile "$NETWORK_PROFILE" \
  --num-trials "$TRIALS" \
  --keep-run-artifacts \
  --pcap-policy "$PCAP_POLICY" \
  --qlog-policy none

if [[ ! -d "$PROFILE_RESULTS" ]]; then
  echo "Experiment completed, but expected results directory was not found: $PROFILE_RESULTS" >&2
  exit 1
fi

LATEST_MANIFEST="$(python3 - "$PROFILE_RESULTS" <<'PY'
import os
import sys

root = sys.argv[1]
manifests = []
for directory, _, files in os.walk(root):
    if "run_manifest.json" in files:
        path = os.path.join(directory, "run_manifest.json")
        manifests.append((os.path.getmtime(path), path))
if not manifests:
    raise SystemExit("No run_manifest.json found under " + root)
print(max(manifests)[1])
PY
)"

MANIFEST_COUNT="$(find "$PROFILE_RESULTS" -type f -name run_manifest.json | wc -l | tr -d ' ')"
NEW_MANIFEST_COUNT=$((MANIFEST_COUNT - BEFORE_MANIFEST_COUNT))
EXPECTED_NEW_MANIFESTS=$((8 * TRIALS))
if ((NEW_MANIFEST_COUNT != EXPECTED_NEW_MANIFESTS)); then
  echo "Expected $EXPECTED_NEW_MANIFESTS new manifests, found $NEW_MANIFEST_COUNT." >&2
  exit 1
fi

echo
echo "Experiment completed."
echo "Results directory: $PROFILE_RESULTS"
echo "Latest run directory: $(dirname "$LATEST_MANIFEST")"
echo "Manifests created by this invocation: $NEW_MANIFEST_COUNT"
echo "Total manifest count under profile: $MANIFEST_COUNT"
echo "Aggregate summary.csv files:"
find "$PROFILE_RESULTS" -mindepth 2 -maxdepth 2 -type f -name summary.csv -print | sort
echo
echo "Check results with:"
echo "./scripts/check_p0_results.sh $PROFILE_RESULTS"
