#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v strace >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y strace
fi

make clean
make

echo "===== running attack (no client needed) ====="
./attack || true

echo "===== tracing attack ====="
strace -f -o attack.strace ./attack || true
echo "----- listen / connect / socket lines in attack.strace -----"
grep -E 'socket\(|bind\(|listen\(|connect\(' attack.strace || true

echo "===== tracing agent (auto client after 0.4s) ====="
rm -f agent.strace
strace -f -o agent.strace ./agent &
agent_pid=$!
sleep 0.4
printf 'hello from phase1\n' | nc -q 1 127.0.0.1 18080 || true
wait "$agent_pid" || true
echo "----- key syscalls in agent.strace -----"
grep -E 'socket\(|bind\(|listen\(|accept\(|read\(|write\(|close\(' agent.strace || true

echo "===== Phase 1 binaries and traces are ready ====="
ls -l agent attack agent.strace attack.strace
