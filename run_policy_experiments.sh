#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNNER="$ROOT_DIR/run_B0_two_flow_fairness_no_jitter.py"
STACKS_CONF="${STACKS_CONF:-$ROOT_DIR/config/stacks_conf_default.json}"
GENERAL_CONF="${GENERAL_CONF:-$ROOT_DIR/config/general_conf_default.json}"
MODE="${1:-validate}"

common_args=(
  --stacks_conf "$STACKS_CONF"
  --general_conf "$GENERAL_CONF"
)

case "$MODE" in
  validate)
    python3 "$RUNNER" \
      "${common_args[@]}" \
      --exp_conf "$ROOT_DIR/config/P0_policy_ack_validation.json" \
      --network-profile 50rtt-20bw-0.5bdp \
      --keep-run-artifacts \
      --qlog-policy first-only
    ;;
  main)
    profiles=(
      10rtt-20bw-0.5bdp
      10rtt-20bw-1.0bdp
      50rtt-20bw-0.5bdp
      50rtt-20bw-1.0bdp
    )
    for profile in "${profiles[@]}"; do
      python3 "$RUNNER" \
        "${common_args[@]}" \
        --exp_conf "$ROOT_DIR/config/P0_policy_fairness.json" \
        --network-profile "$profile" \
        --keep-run-artifacts \
        --qlog-policy none
    done
    ;;
  dry-run)
    python3 "$RUNNER" \
      "${common_args[@]}" \
      --exp_conf "$ROOT_DIR/config/P0_policy_ack_validation.json" \
      --network-profile 50rtt-20bw-0.5bdp \
      --num-trials 1 \
      --dry-run
    ;;
  *)
    echo "Usage: $0 {validate|main|dry-run}" >&2
    exit 2
    ;;
esac
