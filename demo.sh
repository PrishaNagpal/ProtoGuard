#!/bin/bash
# 3-minute viva demo (run in WSL).
set -euo pipefail
cd "$(dirname "$0")"
make

echo "===== 1) Good path (then in another window: echo hello | nc 127.0.0.1 18080) ====="
echo "     Skipping interactive wait. Showing attack + bake-off instead."
echo
echo "===== 2) Protocol kill ====="
./supervisor ./attack || true
echo
echo "===== 3) Name-based allowlist still lets connect through ====="
./namelist ./attack || true
echo
echo "===== 4) Full escape test suite (6 attacks x 3 defenses) ====="
./run_escape_tests.sh
echo
echo "===== 5) Bench (if phase8_results.txt exists) ====="
if [ -f phase8_results.txt ]; then
  cat phase8_results.txt
else
  echo "Run: ./phase8_bench.sh"
fi
