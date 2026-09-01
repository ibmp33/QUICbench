#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
STACKS_CONF="${STACKS_CONF:-$ROOT_DIR/config/stacks_conf_default.json}"
GENERAL_CONF="${GENERAL_CONF:-$ROOT_DIR/config/general_conf_default.json}"
EXP_CONF="${EXP_CONF:-$ROOT_DIR/config/B0_two_flow_fairness_no_jitter.json}"
RUNNER_SCRIPT="${RUNNER_SCRIPT:-$ROOT_DIR/run_B0_two_flow_fairness_no_jitter.py}"
SERVER_STACK_NAME="${SERVER_STACK_NAME:-mvfst}"
NUM_TRIALS="${NUM_TRIALS:-}"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: ./run_all_quicgo_phases.sh [options] [-- extra runner args]

Options:
  --num-trials N         Override exp_conf num_trials.
  --server-stack NAME    Override shared server stack. Default: mvfst
  --profile NAME         Run only one named network profile. Repeatable.
  --dry-run              Validate config and print commands without launching processes.
  --stacks-conf PATH     Override stacks config path.
  --general-conf PATH    Override general config path.
  --exp-conf PATH        Override experiment config path.
  --runner PATH          Override Python runner script.
  -h, --help             Show this help.

Examples:
  ./run_all_quicgo_phases.sh --num-trials 3
  ./run_all_quicgo_phases.sh --profile 50rtt-20bw-1.0bdp --num-trials 3
  ./run_all_quicgo_phases.sh --num-trials 3 -- --keep-pcap
EOF
}

cleanup_netem() {
  python3 -c '
import json
from network.clear_netem import clear_netem

with open("config/general_conf_default.json") as f:
    general_conf = json.load(f)

clear_netem(
    "localhost",
    "",
    general_conf["server_ip"],
    general_conf["interface"],
    general_conf["server_ingress_interface"],
)
' 2>/dev/null || true
}

run_phase() {
  local label="$1"
  local script_path="$2"
  local exp_conf="$3"
  shift 3

  echo "===== ${label} ====="
  cleanup_netem
  python3 "$script_path" \
    --stacks_conf "$STACKS_CONF" \
    --general_conf "$GENERAL_CONF" \
    --exp_conf "$exp_conf" \
    --server-stack-name "$SERVER_STACK_NAME" \
    "$@"
  cleanup_netem
}

cd "$ROOT_DIR"
trap cleanup_netem EXIT

default_profiles=(
  "50rtt-20bw-0.5bdp"
  "50rtt-20bw-1.0bdp"
  "50rtt-20bw-3.0bdp"
  "10rtt-20bw-0.5bdp"
  "10rtt-20bw-1.0bdp"
  "10rtt-20bw-3.0bdp"
)

profiles=()
extra_runner_args=()

while (($#)); do
  case "$1" in
    --num-trials)
      NUM_TRIALS="$2"
      shift 2
      ;;
    --server-stack)
      SERVER_STACK_NAME="$2"
      shift 2
      ;;
    --profile)
      profiles+=("$2")
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --stacks-conf)
      STACKS_CONF="$2"
      shift 2
      ;;
    --general-conf)
      GENERAL_CONF="$2"
      shift 2
      ;;
    --exp-conf)
      EXP_CONF="$2"
      shift 2
      ;;
    --runner)
      RUNNER_SCRIPT="$2"
      shift 2
      ;;
    --)
      shift
      extra_runner_args+=("$@")
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ((${#profiles[@]} == 0)); then
  profiles=("${default_profiles[@]}")
fi

runner_args=()
if [[ -n "$NUM_TRIALS" ]]; then
  runner_args+=(--num-trials "$NUM_TRIALS")
fi
if ((DRY_RUN)); then
  runner_args+=(--dry-run)
fi

for profile in "${profiles[@]}"; do
  run_phase "B0 ${profile}" \
    "$RUNNER_SCRIPT" \
    "$EXP_CONF" \
    "${runner_args[@]}" \
    --network-profile "$profile" \
    "${extra_runner_args[@]}"
done
