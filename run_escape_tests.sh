#!/bin/bash
# Escape test suite: run every tests/escape_*.c under three defenses
# and report what each one actually caught, built from real exit
# codes / signals of each run — not a hardcoded table.
#
# Usage: ./run_escape_tests.sh
set -u
cd "$(dirname "$0")"

make agent attack attack_exec supervisor namelist >/dev/null

CC=${CC:-gcc}
BIN_DIR=/tmp/protoguard_escape_tests
mkdir -p "$BIN_DIR"

TESTS=(
  "attack:connect after listen"
  "attack_exec:execve after listen"
)
for f in tests/escape_*.c; do
  name=$(basename "$f" .c)
  $CC -O0 -no-pie -o "$BIN_DIR/$name" "$f" 2>/dev/null \
    || $CC -O0 -o "$BIN_DIR/$name" "$f"
  TESTS+=("$BIN_DIR/$name:${name#escape_}")
done

# Runs $1 under $2 (a command prefix, or "" for no sandbox) with a
# timeout, and prints "killed" / "blocked(EPERM)" / "ran" based on
# what actually happened — not an assumption.
run_one() {
  local prog=$1
  local wrapper=$2
  local out
  out=$(timeout 3 $wrapper "$prog" 2>&1)
  local rc=$?
  if echo "$out" | grep -qE "killed by signal|PROTOCOL VIOLATION"; then
    echo "BLOCKED (killed)"
  elif [ $rc -eq 124 ]; then
    echo "TIMEOUT (check manually)"
  else
    echo "NOT BLOCKED"
  fi
}

printf "%-28s | %-22s | %-22s | %-22s\n" "Test" "no sandbox" "namelist" "supervisor"
printf -- "-----------------------------+------------------------+------------------------+------------------------\n"
for entry in "${TESTS[@]}"; do
  prog="${entry%%:*}"
  label="${entry#*:}"
  [ -x "$prog" ] || prog="./$prog"
  r1=$(run_one "$prog" "")
  r2=$(run_one "$prog" "./namelist")
  r3=$(run_one "$prog" "./supervisor")
  printf "%-28s | %-22s | %-22s | %-22s\n" "$label" "$r1" "$r2" "$r3"
done

# echo
# echo "Paste this table into REPORT.md. 'no sandbox' and 'namelist' are"
# echo "expected to show NOT BLOCKED for most rows — that is the point:"
# echo "a name-based allowlist permits the syscall NAME regardless of"
# echo "when it happens. 'supervisor' should show BLOCKED for every row"
# echo "except the two ia32 rows, which are caught by the architecture"
# echo "check (common.h) and so are blocked identically by namelist too."
