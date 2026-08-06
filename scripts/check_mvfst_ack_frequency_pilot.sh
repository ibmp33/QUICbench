#!/usr/bin/env bash
set -euo pipefail

RESULTS_ROOT="${1:-/home/ioio33/QUIC_project/results}"
STATUS_FILE="$RESULTS_ROOT/P4_mvfst_ack_frequency_status.json"

if [[ -f "$STATUS_FILE" ]]; then
  jq '{mode,planned_runs,status,failed_jobs,jobs:[.jobs[]|{treatment,status,returncode}]}' "$STATUS_FILE"
else
  echo "status_file=NOT_FOUND path=$STATUS_FILE"
fi

echo "manifests=$(find "$RESULTS_ROOT" -path '*P4-mvfst-ack-frequency*' -name run_manifest.json 2>/dev/null | wc -l | tr -d ' ')"
echo "valid=$(find "$RESULTS_ROOT" -path '*P4-mvfst-ack-frequency*' -name run_manifest.json -exec jq -r 'select(.experiment_valid == true) | 1' {} \; 2>/dev/null | wc -l | tr -d ' ')"

find "$RESULTS_ROOT" -path '*P4-mvfst-ack-frequency*' -name run_manifest.json -exec jq -r '
  [.fixed_parameters.ack_frequency_treatment // "unknown",
   .flows[0].server_config.ack_frequency_enabled,
   .flows[0].client_feedback_config.ack_frequency_mode,
   .experiment_valid] | @tsv' {} \; 2>/dev/null | sort | uniq -c
