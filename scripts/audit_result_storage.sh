#!/usr/bin/env bash
set -euo pipefail

RESULTS_ROOT="${1:-/home/ioio33/QUIC_project/results}"

if [[ ! -d "$RESULTS_ROOT" ]]; then
  echo "Results directory does not exist: $RESULTS_ROOT" >&2
  exit 1
fi

echo "Result storage audit"
echo "root=$RESULTS_ROOT"
echo
du -sh "$RESULTS_ROOT"
df -h "$RESULTS_ROOT"
echo

python3 - "$RESULTS_ROOT" <<'PY'
import os
import statistics
import sys

root = sys.argv[1]
sizes = {"pcap": [], "qlog": [], "other": []}
counts = {"manifest": 0, "summary": 0}

for directory, _, files in os.walk(root):
    for name in files:
        path = os.path.join(directory, name)
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if name == "run_manifest.json":
            counts["manifest"] += 1
        if name == "summary.csv":
            counts["summary"] += 1
        if name.endswith(".pcap"):
            sizes["pcap"].append(size)
        elif "qlogs" in path.split(os.sep) or name.endswith((".qlog", ".sqlog")):
            sizes["qlog"].append(size)
        else:
            sizes["other"].append(size)

def mib(value):
    return value / (1024 * 1024)

print(f"manifests={counts['manifest']}")
print(f"summaries={counts['summary']}")
for category in ("pcap", "qlog", "other"):
    values = sizes[category]
    total = sum(values)
    mean = statistics.mean(values) if values else 0
    print(
        f"{category}_files={len(values)} "
        f"{category}_total_mib={mib(total):.2f} "
        f"{category}_mean_mib={mib(mean):.2f}"
    )

pcaps = sizes["pcap"]
if pcaps:
    mean = statistics.mean(pcaps)
    print()
    print(f"projected_80_pcaps_gib={mean * 80 / (1024 ** 3):.2f}")
    print(f"projected_first_only_8_pcaps_gib={mean * 8 / (1024 ** 3):.2f}")
    print(f"estimated_saving_gib={mean * 72 / (1024 ** 3):.2f}")
PY

echo
echo "Largest files:"
find "$RESULTS_ROOT" -type f -printf '%s %p\n' | sort -nr | sed -n '1,20p'
