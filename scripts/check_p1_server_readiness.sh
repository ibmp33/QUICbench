#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="/home/ioio33/QUIC_project/bin"
FAIRNESS_BYTES=1073741824
QUICHE_OBJECT="$BIN_DIR/1GB.bin"

usage() {
  cat <<'EOF'
Usage: ./scripts/check_p1_server_readiness.sh [--bin-dir PATH]

Read-only Linux preflight for the planned CUBIC + pacing implementation pilot.
It does not start servers, alter network state, or create workload files.
EOF
}

while (($# > 0)); do
  case "$1" in
    --bin-dir)
      (($# >= 2)) || { usage >&2; exit 2; }
      BIN_DIR="$2"
      QUICHE_OBJECT="$BIN_DIR/1GB.bin"
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

check_binary() {
  local name="$1"
  local path="$2"
  if [[ -x "$path" ]]; then
    printf '%-10s PASS     executable=%s sha256=%s\n' \
      "$name" "$path" "$(sha256sum "$path" | awk '{print $1}')"
  else
    printf '%-10s BLOCKED  missing executable=%s\n' "$name" "$path"
    return 1
  fi
}

probe_help() {
  local path="$1"
  shift
  timeout 5s "$path" "$@" 2>&1 || true
}

echo "P1 server readiness (read-only)"
echo "bin_dir=$BIN_DIR"
echo "target_cc=cubic"
echo "target_pacing=enabled"
echo "fairness_bytes=$FAIRNESS_BYTES"
echo

blocked=0
check_binary quic-go "$BIN_DIR/quic-go-server" || blocked=1
check_binary quiche "$BIN_DIR/quiche-server" || blocked=1
check_binary xquic "$BIN_DIR/test_server" || blocked=1
check_binary client "$BIN_DIR/quic-go-policy-client" || blocked=1

echo
if [[ -x "$BIN_DIR/quiche-server" ]]; then
  quiche_help="$(probe_help "$BIN_DIR/quiche-server" --help)"
  for option in --cc-algorithm --disable-pacing --disable-gso; do
    if grep -q -- "$option" <<<"$quiche_help"; then
      echo "quiche    PASS     option=$option"
    else
      echo "quiche    BLOCKED  missing_option=$option"
      blocked=1
    fi
  done
fi

if [[ -f "$QUICHE_OBJECT" ]]; then
  object_bytes="$(stat -c %s "$QUICHE_OBJECT")"
  if ((object_bytes >= FAIRNESS_BYTES)); then
    echo "quiche    PASS     fairness_object=$QUICHE_OBJECT bytes=$object_bytes"
  else
    echo "quiche    BLOCKED  fairness_object_too_small=$QUICHE_OBJECT bytes=$object_bytes required=$FAIRNESS_BYTES"
    blocked=1
  fi
else
  echo "quiche    BLOCKED  missing_fairness_object=$QUICHE_OBJECT"
  echo "                    create explicitly with: truncate -s 1G '$QUICHE_OBJECT'"
  blocked=1
fi

if [[ -x "$BIN_DIR/test_server" ]]; then
  xquic_help="$(probe_help "$BIN_DIR/test_server" -h)"
  for option in '-c' '-C'; do
    if grep -q -- "$option" <<<"$xquic_help"; then
      echo "xquic     PASS     option=$option"
    else
      echo "xquic     BLOCKED  missing_option=$option"
      blocked=1
    fi
  done
fi
echo "xquic     BLOCKED  continuous_h3_workload=not-verified (100 MiB source cap; -L is raw-stream only)"
blocked=1

echo
if ((blocked)); then
  echo "P1_READY=no"
  echo "Do not launch the three-server formal matrix yet. quic-go P0 remains valid."
  exit 1
fi

echo "P1_READY=yes"
