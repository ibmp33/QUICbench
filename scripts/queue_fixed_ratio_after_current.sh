#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
RESULTS_ROOT="/home/ioio33/QUIC_project/results"
LOG_DIR="$RESULTS_ROOT/launcher-logs"
PID_FILE="$LOG_DIR/P2_fixed_ratio_mechanism.pid"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$LOG_DIR/P2_fixed_ratio_queue-$TIMESTAMP.log"

mkdir -p "$LOG_DIR"

if [[ -f "$PID_FILE" ]]; then
  existing_pid="$(tr -d '[:space:]' <"$PID_FILE")"
  if [[ "$existing_pid" =~ ^[0-9]+$ ]] && kill -0 "$existing_pid" 2>/dev/null; then
    echo "A P2F launcher or queue is already running: PID=$existing_pid" >&2
    exit 1
  fi
fi

cd "$REPO_ROOT"
sudo -v

nohup bash "$SCRIPT_DIR/run_fixed_ratio_after_current_worker.sh" "$@" \
  >"$LOG_FILE" 2>&1 &
queue_pid=$!
echo "$queue_pid" >"$PID_FILE"

echo "P2F fixed-ratio suite queued behind the current P2 suite."
echo "The queue starts only after all 8 current conditions pass."
echo "pid=$queue_pid"
echo "log=$LOG_FILE"
echo "monitor: ./scripts/check_overnight_fixed_ratio_mechanism.sh"

