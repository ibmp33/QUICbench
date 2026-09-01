#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
RESULTS_ROOT="/home/ioio33/QUIC_project/results"
LOG_DIR="$RESULTS_ROOT/launcher-logs"
PID_FILE="$LOG_DIR/P2_fixed_ratio_mechanism.pid"
CURRENT_PID_FILE="$LOG_DIR/P2_sender_mechanism.pid"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$LOG_DIR/P2_fixed_ratio_mechanism-$TIMESTAMP.log"

mkdir -p "$LOG_DIR"

pid_is_running() {
  local path="$1"
  local pid
  [[ -f "$path" ]] || return 1
  pid="$(tr -d '[:space:]' <"$path")"
  [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null
}

if pid_is_running "$CURRENT_PID_FILE"; then
  echo "The current P2 sender suite is still running; use queue_fixed_ratio_after_current.sh." >&2
  exit 1
fi
if pid_is_running "$PID_FILE"; then
  echo "A P2F fixed-ratio launcher is already running: PID=$(cat "$PID_FILE")" >&2
  exit 1
fi

cd "$REPO_ROOT"
sudo -v

command=(
  python3 scripts/run_sender_mechanism_pilot.py
  --suite fixed-ratio
  --server quiche
  --server xquic
  --cc cubic
  --pacing on
  --pacing off
  --trials 10
  --pcap-policy none
  --qlog-policy first-only
  --min-free-gb 10
)
command+=("$@")

nohup "${command[@]}" >"$LOG_FILE" 2>&1 &
launcher_pid=$!
echo "$launcher_pid" >"$PID_FILE"

echo "P2F fixed-ratio mechanism suite started."
echo "runs=160 expected_runtime=about_2_hours"
echo "pid=$launcher_pid"
echo "log=$LOG_FILE"
echo "status=$RESULTS_ROOT/P2_fixed_ratio_mechanism_status.json"
echo "monitor: ./scripts/check_overnight_fixed_ratio_mechanism.sh"

