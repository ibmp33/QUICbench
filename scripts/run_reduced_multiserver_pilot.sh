#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
RUNNER="$REPO_ROOT/run_B0_two_flow_fairness_no_jitter.py"
CONFIG="$REPO_ROOT/config/P1_reduced_policy_pilot.json"
NETWORK_PROFILE="50rtt-20bw-0.5bdp"
BIN_DIR="/home/ioio33/QUIC_project/bin"
TRIALS=3
PCAP_POLICY="first-only"
DRY_RUN=0
SERVERS=()

usage() {
  cat <<'EOF'
Usage: ./scripts/run_reduced_multiserver_pilot.sh [options]

Defaults to quiche and xquic. Together with the existing quic-go P0 data, this
keeps the quick comparison on HTTP/3. mvfst remains an explicit raw-QUIC option.

Options:
  --server NAME       Server to run; repeat for multiple servers.
                      Supported: quic-go, quiche, xquic, mvfst.
  --trials N          Repetitions per ordered pair (default: 3).
  --pcap-policy MODE  all, first-only, or none (default: first-only).
  --dry-run           Validate and print commands without launching.
  -h, --help          Show this help.

Matrix (five ordered pairs):
  neqo/neqo
  neqo/chromium
  chromium/neqo
  neqo/fixed10
  fixed10/neqo
EOF
}

while (($# > 0)); do
  case "$1" in
    --server)
      (($# >= 2)) || { usage >&2; exit 2; }
      SERVERS+=("$2")
      shift 2
      ;;
    --trials)
      (($# >= 2)) || { usage >&2; exit 2; }
      TRIALS="$2"
      shift 2
      ;;
    --pcap-policy)
      (($# >= 2)) || { usage >&2; exit 2; }
      PCAP_POLICY="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ((${#SERVERS[@]} == 0)); then
  SERVERS=(quiche xquic)
fi

[[ "$TRIALS" =~ ^[1-9][0-9]*$ ]] || { echo "--trials must be positive." >&2; exit 2; }
case "$PCAP_POLICY" in
  all|first-only|none) ;;
  *) echo "--pcap-policy must be all, first-only, or none." >&2; exit 2 ;;
esac

for server in "${SERVERS[@]}"; do
  case "$server" in
    quic-go|quiche|xquic|mvfst) ;;
    *) echo "Unsupported server: $server" >&2; exit 2 ;;
  esac
done

for required in "$RUNNER" "$CONFIG"; do
  [[ -f "$required" ]] || { echo "Missing required file: $required" >&2; exit 1; }
done
command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 1; }

echo "Reduced multi-server ACK-policy pilot"
echo "servers=${SERVERS[*]}"
echo "trials_per_pair=$TRIALS"
echo "ordered_pairs=5"
echo "runs_per_server=$((5 * TRIALS))"
echo "total_runs=$((5 * TRIALS * ${#SERVERS[@]}))"
echo "workload=64MiB/20s measurement=5-15s"
echo "network=$NETWORK_PROFILE"
echo "pcap_policy=$PCAP_POLICY"
echo "note=mvfst uses raw QUIC and is exploratory, not directly H3-equivalent"

if ((DRY_RUN == 0)); then
  sudo -v
  if printf '%s\n' "${SERVERS[@]}" | grep -qx quiche; then
    quiche_object="$BIN_DIR/64MB.bin"
    if [[ ! -e "$quiche_object" ]]; then
      echo "Creating sparse quiche pilot object: $quiche_object"
      truncate -s 64M "$quiche_object"
    fi
    object_bytes="$(stat -c %s "$quiche_object")"
    if ((object_bytes < 67108864)); then
      echo "quiche pilot object is too small: $quiche_object ($object_bytes bytes)" >&2
      exit 1
    fi
  fi
fi

for server in "${SERVERS[@]}"; do
  echo
  echo "===== server=$server ====="
  command=(
    python3 "$RUNNER"
    --exp_conf "$CONFIG"
    --server-stack-name "$server"
    --network-profile "$NETWORK_PROFILE"
    --num-trials "$TRIALS"
    --keep-run-artifacts
    --pcap-policy "$PCAP_POLICY"
    --qlog-policy none
  )
  if ((DRY_RUN)); then
    command+=(--dry-run)
  fi
  "${command[@]}"
done

echo
echo "Pilot complete. Result roots:"
for server in "${SERVERS[@]}"; do
  echo "/home/ioio33/QUIC_project/results/P1-reduced-policy-pilot-${server}-server"
done
