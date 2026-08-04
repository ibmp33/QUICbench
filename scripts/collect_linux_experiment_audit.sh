#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
RESULTS_ROOT="/home/ioio33/QUIC_project/results/P0-policy-fairness-quic-go-server/50rtt-20bw-0.5bdp"
BIN_DIR="/home/ioio33/QUIC_project/bin"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTPUT="$REPO_ROOT/logs/audits/linux-experiment-audit-$TIMESTAMP.txt"

usage() {
  cat <<'EOF'
Usage: ./scripts/collect_linux_experiment_audit.sh [options]

Read-only audit safe to run while a QUICbench experiment is active.

Options:
  --results-root PATH  Results profile to inspect.
  --output PATH        Report file to create.
  -h, --help           Show this help.

The script never changes qdiscs, interfaces, offloads, namespaces, sysctls,
CPU settings, experiment processes, or result artifacts.
EOF
}

while (($# > 0)); do
  case "$1" in
    --results-root)
      if (($# < 2)); then
        usage >&2
        exit 2
      fi
      RESULTS_ROOT="$2"
      shift 2
      ;;
    --output)
      if (($# < 2)); then
        usage >&2
        exit 2
      fi
      OUTPUT="$2"
      shift 2
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

mkdir -p "$(dirname "$OUTPUT")"
: >"$OUTPUT"
exec > >(tee -a "$OUTPUT") 2>&1

section() {
  echo
  echo "===== $1 ====="
}

run_cmd() {
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
  local status=$?
  if ((status != 0)); then
    echo "[audit] command exited with status $status"
  fi
  return 0
}

run_shell() {
  local command="$1"
  printf '$ %s\n' "$command"
  bash -o pipefail -c "$command"
  local status=$?
  if ((status != 0)); then
    echo "[audit] command exited with status $status"
  fi
  return 0
}

command_available() {
  command -v "$1" >/dev/null 2>&1
}

run_if_available() {
  local command_name="$1"
  shift
  if command_available "$command_name"; then
    run_cmd "$command_name" "$@"
  else
    echo "[audit] command not found: $command_name"
  fi
}

run_help_probe() {
  local label="$1"
  shift
  echo
  echo "--- $label ---"
  printf '$ timeout 5s'
  printf ' %q' "$@"
  printf '\n'
  timeout 5s "$@"
  local status=$?
  case "$status" in
    0)
      ;;
    124)
      echo "[audit] help probe timed out after 5 seconds"
      ;;
    *)
      echo "[audit] help probe exited with status $status (often normal for -h)"
      ;;
  esac
  return 0
}

section "AUDIT METADATA"
echo "report_path=$OUTPUT"
echo "repo_root=$REPO_ROOT"
echo "results_root=$RESULTS_ROOT"
echo "binary_root=$BIN_DIR"
echo "audit_started=$(date -Is)"
echo "audit_mode=read-only"

section "TIME AND OPERATING SYSTEM"
run_cmd date -Is
run_if_available timedatectl
run_cmd uname -a
if [[ -r /etc/os-release ]]; then
  run_cmd sed -n '1,80p' /etc/os-release
fi

section "CPU AND MEMORY"
run_if_available lscpu
run_if_available uptime
run_if_available free -h
run_shell "for path in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [ -r \"\$path\" ] && printf '%s=' \"\$path\" && cat \"\$path\"; done | sort -u"
if [[ -r /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
  run_cmd cat /sys/devices/system/cpu/intel_pstate/no_turbo
fi

section "KERNEL NETWORK PARAMETERS"
if command_available sysctl; then
  for key in \
    net.core.rmem_max \
    net.core.rmem_default \
    net.core.wmem_max \
    net.core.wmem_default \
    net.core.netdev_max_backlog \
    net.ipv4.udp_rmem_min \
    net.ipv4.udp_wmem_min \
    net.ipv4.tcp_congestion_control \
    net.ipv4.tcp_available_congestion_control; do
    run_cmd sysctl "$key"
  done
else
  echo "[audit] command not found: sysctl"
fi

section "SUDO AVAILABILITY"
SUDO_AVAILABLE=0
if command_available sudo && sudo -n true >/dev/null 2>&1; then
  SUDO_AVAILABLE=1
  echo "sudo_noninteractive=yes"
else
  echo "sudo_noninteractive=no"
  echo "[audit] privileged read-only checks will be skipped"
fi

section "NETWORK NAMESPACES AND ADDRESSES"
run_if_available ip -br link
run_if_available ip -br addr
run_if_available ip route show
if ((SUDO_AVAILABLE)); then
  run_cmd sudo -n ip netns list
  run_cmd sudo -n ip netns exec quicbench-server ip -br addr
  run_cmd sudo -n ip netns exec quicbench-server ip route show
  run_cmd sudo -n ip netns exec quicbench-client ip -br addr
  run_cmd sudo -n ip netns exec quicbench-client ip route show
fi

section "ACTIVE TRAFFIC CONTROL STATE"
if command_available tc; then
  if ((SUDO_AVAILABLE)); then
    run_cmd sudo -n tc -s qdisc show dev veth-host
    run_cmd sudo -n tc -s qdisc show dev ifb0
    run_cmd sudo -n tc filter show dev veth-host parent ffff:
  else
    run_cmd tc -s qdisc show dev veth-host
    run_cmd tc -s qdisc show dev ifb0
  fi
else
  echo "[audit] command not found: tc"
fi

section "OFFLOAD STATE"
if command_available ethtool; then
  run_shell "ethtool -k veth-host 2>&1 | grep -E 'generic-receive|generic-segmentation|tcp-segmentation|large-receive|udp-segmentation|rx-udp-gro-forwarding'"
  run_shell "ethtool -k ifb0 2>&1 | grep -E 'generic-receive|generic-segmentation|tcp-segmentation|large-receive|udp-segmentation|rx-udp-gro-forwarding'"
  if ((SUDO_AVAILABLE)); then
    run_shell "sudo -n ip netns exec quicbench-server ethtool -k veth-server 2>&1 | grep -E 'generic-receive|generic-segmentation|tcp-segmentation|large-receive|udp-segmentation|rx-udp-gro-forwarding'"
    run_shell "sudo -n ip netns exec quicbench-client ethtool -k veth-client 2>&1 | grep -E 'generic-receive|generic-segmentation|tcp-segmentation|large-receive|udp-segmentation|rx-udp-gro-forwarding'"
  fi
else
  echo "[audit] command not found: ethtool"
fi

section "QUIC BINARY PROVENANCE"
if command_available sha256sum; then
  for binary in \
    quic-go-policy-client \
    quic-go-server \
    quiche-server \
    test_server \
    tperf; do
    path="$BIN_DIR/$binary"
    if [[ -f "$path" ]]; then
      run_cmd sha256sum "$path"
      run_cmd stat -c '%n size=%s mode=%A owner=%U:%G mtime=%y' "$path"
    else
      echo "[audit] missing binary: $path"
    fi
  done
else
  echo "[audit] command not found: sha256sum"
fi

section "SERVER CC, PACING, AND GSO CAPABILITIES"
if command_available timeout; then
  [[ -x "$BIN_DIR/quic-go-server" ]] && run_help_probe "quic-go-server -h" "$BIN_DIR/quic-go-server" -h
  [[ -x "$BIN_DIR/quiche-server" ]] && run_help_probe "quiche-server --help" "$BIN_DIR/quiche-server" --help
  [[ -x "$BIN_DIR/test_server" ]] && run_help_probe "xquic test_server -h" "$BIN_DIR/test_server" -h
  [[ -x "$BIN_DIR/tperf" ]] && run_help_probe "mvfst tperf --help" "$BIN_DIR/tperf" --help
else
  echo "[audit] command not found: timeout"
fi

section "QUICBENCH SOURCE PROVENANCE"
if [[ -d "$REPO_ROOT/.git" ]]; then
  run_cmd git -C "$REPO_ROOT" status --short --branch
  run_cmd git -C "$REPO_ROOT" rev-parse HEAD
  run_cmd git -C "$REPO_ROOT" log -1 --format=fuller
else
  echo "[audit] not a Git checkout: $REPO_ROOT"
fi
for config in \
  config/general_conf_default.json \
  config/workloads_conf_default.json \
  config/ack_policies_default.json \
  config/P0_policy_fairness.json; do
  path="$REPO_ROOT/$config"
  if [[ -f "$path" ]]; then
    echo
    echo "--- $config ---"
    if command_available python3; then
      run_cmd python3 -m json.tool "$path"
    else
      run_cmd sed -n '1,320p' "$path"
    fi
  fi
done

section "ACTIVE EXPERIMENT PROCESSES"
run_shell "ps -eo pid,ppid,etimes,pcpu,pmem,stat,args | grep -E 'run_first_quic_go_p0|run_B0_two_flow|quic-go-policy-client|quic-go-server|tcpdump' | grep -v grep"

section "RESULT PROGRESS AND STORAGE"
if [[ -d "$RESULTS_ROOT" ]]; then
  manifest_count="$(find "$RESULTS_ROOT" -type f -name run_manifest.json | wc -l | tr -d ' ')"
  completed_count="$(find "$RESULTS_ROOT" -type f -path '*/[0-9][0-9]-*/summary.csv' | wc -l | tr -d ' ')"
  pcap_count="$(find "$RESULTS_ROOT" -type f -name packets.pcap | wc -l | tr -d ' ')"
  pcap_bytes="$(find "$RESULTS_ROOT" -type f -name packets.pcap -printf '%s\n' | awk '{total += $1} END {printf "%.0f", total + 0}')"
  echo "manifest_count=$manifest_count"
  echo "completed_run_count=$completed_count"
  echo "expected_p0_run_count=80"
  echo "pcap_count=$pcap_count"
  echo "pcap_bytes=$pcap_bytes"
  run_cmd du -sh "$RESULTS_ROOT"
  run_cmd df -h "$RESULTS_ROOT"
  echo
  echo "Latest run directories:"
  run_cmd bash -o pipefail -c 'find "$1" -type f -name run_manifest.json -printf "%T@ %h\n" | sort -n | tail -n 12' _ "$RESULTS_ROOT"
  echo
  echo "Largest retained artifacts:"
  run_cmd bash -o pipefail -c 'find "$1" -type f -printf "%s %p\n" | sort -nr | head -n 20' _ "$RESULTS_ROOT"
else
  echo "[audit] results directory does not exist: $RESULTS_ROOT"
  run_cmd df -h /home/ioio33/QUIC_project/results
fi

section "AUDIT COMPLETION"
echo "audit_finished=$(date -Is)"
echo "No experiment, network, kernel, CPU, or result state was modified."
echo "Send this report back to Codex:"
echo "$OUTPUT"
