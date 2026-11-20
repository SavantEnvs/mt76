#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer tests for the mt76-test dump path and the driver RX/MCU paths (tools/main.c mt76_dump_cb ->
# tools/fields.c printers). Upstream ships no test suite; each case feeds a fixed NL80211_ATTR_TESTDATA
# reply to mt76_test_dump_selftest (built by build.sh with normal flags) and diffs its printed
# key=value dump against golden text in mayhem/expected/. A no-op program prints nothing and fails.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

runner="$SRC/mt76_test_dump_selftest"
if [ ! -x "$runner" ]; then
  echo "missing $runner — mayhem/build.sh must build it" >&2
  emit_ctrf "mt76-test-golden" 0 1
  exit 1
fi

passed=0 failed=0
for exp in "$SRC"/mayhem/expected/*.txt; do
  name="$(basename "$exp" .txt)"
  in="$SRC/mayhem/mt76-test-dump/testsuite/$name.bin"
  if out="$("$runner" "$in" 2>/dev/null)" && diff -u "$exp" <(printf '%s\n' "$out"); then
    echo "PASS $name"; passed=$((passed + 1))
  else
    echo "FAIL $name"; failed=$((failed + 1))
  fi
done

# Driver known-answer tests: the shim targets' selftest builds (normal flags, see build.sh step 6)
# run one RX descriptor / frame / MCU response each and print the driver's verdict, the frame left
# in the skb and the RX status it filled in; mayhem/expected/kshim/<target>--<seed>.txt is golden.
for exp in "$SRC"/mayhem/expected/kshim/*.txt; do
  name="$(basename "$exp" .txt)"
  target="${name%%--*}" seed="${name#*--}"
  bin="$SRC/$(printf '%s' "$target" | tr - _)_selftest"
  in="$SRC/mayhem/$target/testsuite/$seed.bin"
  if [ ! -x "$bin" ]; then
    echo "FAIL $name (missing $bin)"; failed=$((failed + 1)); continue
  fi
  if out="$("$bin" "$in" 2>/dev/null)" && diff -u "$exp" <(printf '%s\n' "$out"); then
    echo "PASS $name"; passed=$((passed + 1))
  else
    echo "FAIL $name"; failed=$((failed + 1))
  fi
done

emit_ctrf "mt76-test-golden" "$passed" "$failed"
