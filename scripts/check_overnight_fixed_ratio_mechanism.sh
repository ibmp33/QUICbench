#!/usr/bin/env bash
set -euo pipefail

RESULTS_ROOT="/home/ioio33/QUIC_project/results"
LOG_DIR="$RESULTS_ROOT/launcher-logs"
PID_FILE="$LOG_DIR/P2_fixed_ratio_mechanism.pid"
STATUS_FILE="$RESULTS_ROOT/P2_fixed_ratio_mechanism_status.json"

if [[ -f "$PID_FILE" ]]; then
  launcher_pid="$(tr -d '[:space:]' <"$PID_FILE")"
  if [[ "$launcher_pid" =~ ^[0-9]+$ ]] && kill -0 "$launcher_pid" 2>/dev/null; then
    echo "launcher=RUNNING_OR_WAITING pid=$launcher_pid"
  else
    echo "launcher=NOT_RUNNING last_pid=$launcher_pid"
  fi
else
  echo "launcher=NOT_STARTED"
fi

if [[ -f "$STATUS_FILE" ]]; then
  python3 - "$STATUS_FILE" <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    status = json.load(handle)
conditions = status.get("conditions", [])
counts = {}
for condition in conditions:
    state = condition.get("status", "running")
    counts[state] = counts.get(state, 0) + 1
print("suite={}".format(status.get("suite", "unknown")))
print("planned_runs={}".format(status.get("planned_runs", "unknown")))
print("conditions_recorded={}".format(len(conditions)))
print("condition_status={}".format(",".join(
    "{}:{}".format(key, counts[key]) for key in sorted(counts)
)))
print("failed_conditions={}".format(status.get("failed_conditions", "running")))
PY
else
  echo "status_file=NOT_CREATED_QUEUE_MAY_BE_WAITING"
fi

latest_log="$(find "$LOG_DIR" -maxdepth 1 -type f \
  \( -name 'P2_fixed_ratio_queue-*.log' -o -name 'P2_fixed_ratio_mechanism-*.log' \) \
  -print 2>/dev/null | sort | tail -n 1 || true)"
if [[ -n "$latest_log" ]]; then
  echo "latest_log=$latest_log"
  echo "----- last 20 log lines -----"
  tail -n 20 "$latest_log"
fi

