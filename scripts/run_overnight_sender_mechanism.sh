#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
RESULTS_ROOT="/home/ioio33/QUIC_project/results"
LOG_DIR="$RESULTS_ROOT/launcher-logs"
PID_FILE="$LOG_DIR/P2_sender_mechanism.pid"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$LOG_DIR/P2_sender_mechanism-$TIMESTAMP.log"

mkdir -p "$LOG_DIR"

if [[ -f "$PID_FILE" ]]; then
  existing_pid="$(tr -d '[:space:]' <"$PID_FILE")"
  if [[ "$existing_pid" =~ ^[0-9]+$ ]] && kill -0 "$existing_pid" 2>/dev/null; then
    echo "An overnight launcher is already running: PID=$existing_pid" >&2
    exit 1
  fi
fi

cd "$REPO_ROOT"
sudo -v

command=(
  python3 scripts/run_sender_mechanism_pilot.py
  --server quiche
  --server xquic
  --cc cubic
  --cc reno
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

echo "P2 overnight sender mechanism suite started."
echo "pid=$launcher_pid"
echo "log=$LOG_FILE"
echo "status=$RESULTS_ROOT/P2_sender_mechanism_status.json"
echo "monitor: tail -f '$LOG_FILE'"
