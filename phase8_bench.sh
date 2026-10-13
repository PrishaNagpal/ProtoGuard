#!/bin/bash
# Phase 8: time one echo each run, with and without the supervisor.
# Round-robin has been removed from supervisor.c entirely, so this
# measures plain trap cost (fork + seccomp notify round-trips).
set -euo pipefail
cd "$(dirname "$0")"
make agent supervisor >/dev/null

N=${1:-40}
PORT=18080

wait_listen() {
  local f=$1
  local i
  for i in $(seq 1 200); do
    if grep -q "listening on" "$f" 2>/dev/null; then
      return 0
    fi
    sleep 0.01
  done
  return 1
}

run_mode() {
  local label=$1
  local cmd=$2
  local i
  local start end
  local out=/tmp/phase8_$label.out

  start=$(date +%s%N)
  for i in $(seq 1 "$N"); do
    : > "$out"
    $cmd > "$out" 2>&1 &
    local spid=$!
    wait_listen "$out"
    printf 'hello\n' | nc -q 0 -w 1 127.0.0.1 "$PORT" >/dev/null
    wait "$spid"
  done
  end=$(date +%s%N)
  python3 - "$start" "$end" "$N" "$label" <<'PY'
import sys
start, end, n, label = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
total_ms = (end - start) / 1e6
avg = total_ms / n
print(f"{label:20s}  N={n}  total={total_ms:.1f} ms  avg={avg:.2f} ms/run")
PY
}

echo "Phase 8 bench: $N start+echo+exit cycles (port $PORT)"
run_mode "no_supervisor" "./agent"
run_mode "supervisor" "./supervisor ./agent"
echo
echo "Overhead is extra ms per run (fork + seccomp traps + CONTINUE)."
echo "Not a microbenchmark of one syscall; good enough for the lab table."
