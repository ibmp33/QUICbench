#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
RESULTS_ROOT="/home/ioio33/QUIC_project/results"
LOG_DIR="$RESULTS_ROOT/launcher-logs"
CURRENT_PID_FILE="$LOG_DIR/P2_sender_mechanism.pid"
CURRENT_STATUS="$RESULTS_ROOT/P2_sender_mechanism_status.json"

current_pid=""
if [[ -f "$CURRENT_PID_FILE" ]]; then
  current_pid="$(tr -d '[:space:]' <"$CURRENT_PID_FILE")"
fi

if [[ "$current_pid" =~ ^[0-9]+$ ]] && kill -0 "$current_pid" 2>/dev/null; then
  echo "Waiting for current P2 launcher PID=$current_pid"
  while kill -0 "$current_pid" 2>/dev/null; do
    if ! sudo -n -v; then
      echo "sudo keepalive failed while waiting; fixed-ratio suite was not started" >&2
      exit 1
    fi
    sleep 45
  done
fi

python3 - "$CURRENT_STATUS" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path) as handle:
        status = json.load(handle)
except (OSError, ValueError) as exc:
    raise SystemExit("current P2 status is unavailable: {}".format(exc))

conditions = status.get("conditions", [])
successful = {"passed", "skipped-complete"}
if status.get("failed_conditions") != 0:
    raise SystemExit("current P2 did not finish cleanly; fixed-ratio suite not started")
if len(conditions) != 8 or any(item.get("status") not in successful for item in conditions):
    raise SystemExit("current P2 has not recorded 8 successful conditions")
print("Current P2 completed successfully; starting P2F fixed-ratio suite")
PY

cd "$REPO_ROOT"
exec python3 scripts/run_sender_mechanism_pilot.py \
  --suite fixed-ratio \
  --server quiche \
  --server xquic \
  --cc cubic \
  --pacing on \
  --pacing off \
  --trials 10 \
  --pcap-policy none \
  --qlog-policy first-only \
  --min-free-gb 10 \
  "$@"

