#!/usr/bin/env bash
set -euo pipefail

RESULTS_ROOT="/home/ioio33/QUIC_project/results"
STATUS_FILE="${1:-$RESULTS_ROOT/P3_bbr_mvfst_extension_status.json}"

if [[ ! -f "$STATUS_FILE" ]]; then
  echo "status=NOT_FOUND path=$STATUS_FILE"
  exit 1
fi

jq '{
  status,
  mode,
  matrix,
  planned_runs,
  failed_jobs,
  started_at,
  ended_at,
  jobs: [.jobs[] | {
    suite,
    server,
    protocol,
    cc_algos,
    status,
    returncode
  }]
}' "$STATUS_FILE"

echo "completed_manifests=$(find "$RESULTS_ROOT" -path '*P2*-bbr-pacing-*-*-server/*/*/*/run_manifest.json' 2>/dev/null | wc -l)"
echo "mvfst_manifests=$(find "$RESULTS_ROOT" -path '*-mvfst-server/*/*/*/run_manifest.json' 2>/dev/null | wc -l)"
