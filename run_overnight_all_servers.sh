#!/bin/zsh
set -u

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_SCRIPT="$ROOT_DIR/run_all_quicgo_phases.sh"
FLATTEN_SCRIPT="$ROOT_DIR/scripts/flatten_two_flow_summary.py"

NUM_TRIALS="${NUM_TRIALS:-10}"
DRY_RUN=0
KEEP_RUN_ARTIFACTS=0
KEEP_PCAP=0
RETRY_ON_FAILURE=1

server_stacks=(
  "mvfst"
  "quiche"
  "xquic"
  "quic-go"
)
server_selection_explicit=0

profiles=()
extra_runner_args=()

timestamp="$(date +%Y-%m-%d_%H-%M-%S)"
log_root="$ROOT_DIR/logs/overnight-$timestamp"
mkdir -p "$log_root"
master_log="$log_root/master.log"
summary_tsv="$log_root/status.tsv"

usage() {
  cat <<'EOF'
Usage: ./run_overnight_all_servers.sh [options] [-- extra runner args]

Options:
  --num-trials N           Number of runs per trial. Default: 10
  --server NAME            Run only one server stack. Repeatable.
  --profile NAME           Run only one network profile. Repeatable.
  --retry N                Retry a failed server stack up to N extra times. Default: 1
  --dry-run                Only print commands.
  --keep-run-artifacts     Preserve per-run directories.
  --keep-pcap              Preserve packets.pcap.
  -h, --help               Show this help.

Examples:
  bash run_overnight_all_servers.sh
  bash run_overnight_all_servers.sh --num-trials 10 --profile 10rtt-20bw-0.5bdp
  nohup bash run_overnight_all_servers.sh > logs/night.out 2>&1 &
EOF
}

log() {
  local message="$1"
  printf '[%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$message" | tee -a "$master_log"
}

cleanup_netem() {
  python3 -c '
import json
from network.clear_netem import clear_netem

with open("config/general_conf_default.json") as f:
    general_conf = json.load(f)

clear_netem(
    "localhost",
    "",
    general_conf["server_ip"],
    general_conf["interface"],
    general_conf["server_ingress_interface"],
)
' 2>/dev/null || true
}

build_results_dir() {
  local stack="$1"
  printf '%s/results/B0-two-flow-fairness-no-jitter-%s-server' "$ROOT_DIR" "$stack"
}

flatten_results_if_present() {
  local stack="$1"
  local results_dir
  results_dir="$(build_results_dir "$stack")"
  if [[ -d "$results_dir" ]]; then
    python3 "$FLATTEN_SCRIPT" "$results_dir" >>"$master_log" 2>&1 || true
  fi
}

run_one_stack() {
  local stack="$1"
  local attempt="$2"
  local stack_log="$log_root/${stack}.attempt${attempt}.log"

  local cmd=(
    bash "$RUN_SCRIPT"
    --server-stack "$stack"
    --num-trials "$NUM_TRIALS"
  )

  local profile
  for profile in "${profiles[@]}"; do
    cmd+=(--profile "$profile")
  done

  if ((DRY_RUN)); then
    cmd+=(--dry-run)
  fi

  cmd+=(--)

  if ((KEEP_RUN_ARTIFACTS)); then
    cmd+=(--keep-run-artifacts)
  fi
  if ((KEEP_PCAP)); then
    cmd+=(--keep-pcap)
  fi

  if ((${#extra_runner_args[@]} > 0)); then
    cmd+=("${extra_runner_args[@]}")
  fi

  log "Starting stack=$stack attempt=$attempt log=$stack_log"
  printf '%s\t%s\t%s\t%s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$stack" "$attempt" "START" >>"$summary_tsv"

  cleanup_netem
  (
    printf 'COMMAND:'
    printf ' %q' "${cmd[@]}"
    printf '\n'
    "${cmd[@]}"
  ) >"$stack_log" 2>&1
  local status=$?
  cleanup_netem

  if [[ $status -eq 0 ]]; then
    log "Completed stack=$stack attempt=$attempt"
    printf '%s\t%s\t%s\t%s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$stack" "$attempt" "OK" >>"$summary_tsv"
    flatten_results_if_present "$stack"
    return 0
  fi

  log "Failed stack=$stack attempt=$attempt exit=$status"
  printf '%s\t%s\t%s\tFAIL(%s)\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$stack" "$attempt" "$status" >>"$summary_tsv"
  return "$status"
}

while (($#)); do
  case "$1" in
    --num-trials)
      NUM_TRIALS="$2"
      shift 2
      ;;
    --server)
      if ((server_selection_explicit == 0)); then
        server_stacks=()
        server_selection_explicit=1
      fi
      server_stacks+=("$2")
      shift 2
      ;;
    --profile)
      profiles+=("$2")
      shift 2
      ;;
    --retry)
      RETRY_ON_FAILURE="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --keep-run-artifacts)
      KEEP_RUN_ARTIFACTS=1
      shift
      ;;
    --keep-pcap)
      KEEP_PCAP=1
      shift
      ;;
    --)
      shift
      extra_runner_args+=("$@")
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -x "$RUN_SCRIPT" && ! -f "$RUN_SCRIPT" ]]; then
  echo "Missing runner script: $RUN_SCRIPT" >&2
  exit 1
fi

if [[ "$NUM_TRIALS" -le 0 ]]; then
  echo "--num-trials must be > 0" >&2
  exit 1
fi

if [[ "$RETRY_ON_FAILURE" -lt 0 ]]; then
  echo "--retry must be >= 0" >&2
  exit 1
fi

cd "$ROOT_DIR"
trap cleanup_netem EXIT INT TERM

printf 'timestamp\tstack\tattempt\tstatus\n' >"$summary_tsv"
log "Overnight run start log_root=$log_root num_trials=$NUM_TRIALS"

for stack in "${server_stacks[@]}"; do
  attempt=1
  while true; do
    if run_one_stack "$stack" "$attempt"; then
      break
    fi
    if ((attempt > RETRY_ON_FAILURE)); then
      log "Giving up on stack=$stack after $attempt attempt(s)"
      break
    fi
    attempt=$((attempt + 1))
    log "Retrying stack=$stack next_attempt=$attempt"
    sleep 5
  done
done

log "Overnight run complete status_file=$summary_tsv"
