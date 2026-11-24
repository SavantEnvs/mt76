#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# libnl-tiny is prebuilt (static, uninstrumented) in the image by mayhem/Dockerfile.
LIBNL="$(ls -d /opt/toolchains/deps/libnl-tiny-*/ | head -n1)"
LIBNL="${LIBNL%/}"
[ -f "$LIBNL/lib/libnl-tiny.a" ] || { echo "libnl-tiny missing under /opt/toolchains/deps" >&2; exit 1; }

# The project code under test: tools/ (mt76-test), built from the unmodified upstream sources.
# main.c is #included by the harness (its main() renamed) so its static dump callback is reachable.
TOOL_SRCS=("$SRC/tools/fields.c" "$SRC/tools/eeprom.c" "$SRC/tools/fwlog.c")
INCS=(-I"$SRC/tools" -I"$LIBNL/include" -D_GNU_SOURCE --std=gnu99)
HARNESS="$SRC/mayhem/harnesses/fuzz_mt76_test_dump.c"

# 1) Leak detection off for every ASan binary (SPEC §6.2 item 15).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o /tmp/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o

# 2) Fuzzer + standalone reproducer; harness AND tools/ sources carry the sanitizers.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${INCS[@]}" \
    "$HARNESS" "${TOOL_SRCS[@]}" /tmp/lsan_off.o "$LIBNL/lib/libnl-tiny.a" -lstdc++ \
    -o "$SRC/fuzz_mt76_test_dump"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "${INCS[@]}" \
    "$HARNESS" "${TOOL_SRCS[@]}" /tmp/standalone_main.o /tmp/lsan_off.o "$LIBNL/lib/libnl-tiny.a" -lstdc++ \
    -o "$SRC/fuzz_mt76_test_dump-standalone"

# 3) Functional oracle: the same dump path with NORMAL flags (upstream uses -Os), driven by the
#    run-once main; mayhem/test.sh diffs its output against golden text.
$CC -Os $COVERAGE_FLAGS "${INCS[@]}" \
    "$HARNESS" "${TOOL_SRCS[@]}" "$STANDALONE_FUZZ_MAIN" "$LIBNL/lib/libnl-tiny.a" \
    -o "$SRC/mt76_test_dump_selftest"

# 4) mt76x02-rx: the Wi-Fi driver's own RX path (mt76x02_mac_process_rx), the UNMODIFIED driver
#    sources compiled against the userspace kernel/mac80211 shim in mayhem/kshim/ (see kshim.h for
#    what is real and what is a stand-in). The driver sources and the shim carry the sanitizers.
KSHIM_INCS=(-D__KERNEL__ -I"$SRC/mayhem/kshim/include" -I"$SRC/mayhem/kshim" -I"$SRC" -std=gnu11
            -Wno-gnu-variable-sized-type-not-at-end -Wno-unused-value -Wno-return-type)
MT76X02_SRCS=("$SRC/mt76x02_mac.c" "$SRC/mt76x02_txrx.c" "$SRC/mt76x02_util.c"
              "$SRC/mayhem/kshim/kstubs.c" "$SRC/mayhem/kshim/mt76x02_stubs.c")
RX_HARNESS="$SRC/mayhem/harnesses/fuzz_mt76x02_rx.c"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${KSHIM_INCS[@]}" \
    "$RX_HARNESS" "${MT76X02_SRCS[@]}" /tmp/lsan_off.o -lstdc++ \
    -o "$SRC/fuzz_mt76x02_rx"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "${KSHIM_INCS[@]}" \
    "$RX_HARNESS" "${MT76X02_SRCS[@]}" /tmp/standalone_main.o /tmp/lsan_off.o -lstdc++ \
    -o "$SRC/fuzz_mt76x02_rx-standalone"

# 5) mt7615-rx / mt7615-mcu-response: the MT7615/MT7663 RX dispatcher and MCU response parser,
#    with the mt76 core RX path (mac80211.c, agg-rx.c reorder buffer, tx.c status, mcu.c) built
#    from the unmodified sources against the same shim.
MT7615_SRCS=("$SRC/mt7615/mac.c" "$SRC/mt7615/mcu.c" "$SRC/mcu.c" "$SRC/util.c" "$SRC/mac80211.c"
             "$SRC/agg-rx.c" "$SRC/tx.c" "$SRC/scan.c" "$SRC/mayhem/kshim/kstubs.c" "$SRC/mayhem/kshim/mt7615_stubs.c")
for h in mt7615_rx mt7615_mcu_response; do
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${KSHIM_INCS[@]}" \
        "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7615_SRCS[@]}" /tmp/lsan_off.o -lstdc++ \
        -o "$SRC/fuzz_$h"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${KSHIM_INCS[@]}" \
        "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7615_SRCS[@]}" /tmp/standalone_main.o /tmp/lsan_off.o -lstdc++ \
        -o "$SRC/fuzz_$h-standalone"
done

# 5b) mt7996-rx / mt7996-mcu-event: the MT7996 (Wi-Fi 7) RX dispatcher (mt7996/mac.c
#     mt7996_queue_rx_skb) and MCU event path (mt7996/mcu.c mt7996_mcu_rx_event and the unsolicited
#     UNI/legacy event handlers) with the mt76 core RX/MCU code, against the shim's HE/EHT
#     definitions (mayhem/kshim/kshim_80211ax.h).
MT7996_SRCS=("$SRC/mt7996/mac.c" "$SRC/mt7996/mcu.c" "$SRC/mt76_connac3_mac.c" "$SRC/mcu.c" "$SRC/util.c" "$SRC/mac80211.c"
             "$SRC/agg-rx.c" "$SRC/tx.c" "$SRC/scan.c" "$SRC/mayhem/kshim/kstubs.c" "$SRC/mayhem/kshim/mt7996_stubs.c")
for h in mt7996_rx mt7996_mcu_event; do
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${KSHIM_INCS[@]}" \
        "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7996_SRCS[@]}" /tmp/lsan_off.o -lstdc++ \
        -o "$SRC/fuzz_$h"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${KSHIM_INCS[@]}" \
        "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7996_SRCS[@]}" /tmp/standalone_main.o /tmp/lsan_off.o -lstdc++ \
        -o "$SRC/fuzz_$h-standalone"
done

# 5c) mt7915-rx / mt7915-mcu-event: the same two paths for MT7915/MT7916 (Wi-Fi 6, connac2):
#     mt7915/mac.c mt7915_queue_rx_skb with the connac2 RX helpers (mt76_connac_mac.c), and
#     mt7915/mcu.c mt7915_mcu_rx_event.
MT7915_SRCS=("$SRC/mt7915/mac.c" "$SRC/mt7915/mcu.c" "$SRC/mt76_connac_mac.c" "$SRC/mcu.c" "$SRC/util.c"
             "$SRC/mac80211.c" "$SRC/agg-rx.c" "$SRC/tx.c" "$SRC/scan.c" "$SRC/mayhem/kshim/kstubs.c" "$SRC/mayhem/kshim/mt7915_stubs.c")
for h in mt7915_rx mt7915_mcu_event; do
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${KSHIM_INCS[@]}" \
        "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7915_SRCS[@]}" /tmp/lsan_off.o -lstdc++ \
        -o "$SRC/fuzz_$h"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${KSHIM_INCS[@]}" \
        "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7915_SRCS[@]}" /tmp/standalone_main.o /tmp/lsan_off.o -lstdc++ \
        -o "$SRC/fuzz_$h-standalone"
done

# 5d) mt7921-rx / mt7921-mcu-event: the same two paths for MT7921/MT7922 (Wi-Fi 6E, mt792x):
#     mt7921/mac.c mt7921_queue_rx_skb (with mt792x_mac.c and the connac2 RX helpers) and
#     mt7921/mcu.c mt7921_mcu_rx_event.
MT7921_SRCS=("$SRC/mt7921/mac.c" "$SRC/mt7921/mcu.c" "$SRC/mt792x_mac.c" "$SRC/mt76_connac_mac.c" "$SRC/mcu.c"
             "$SRC/util.c" "$SRC/mac80211.c" "$SRC/agg-rx.c" "$SRC/tx.c" "$SRC/scan.c" "$SRC/mayhem/kshim/kstubs.c"
             "$SRC/mayhem/kshim/mt7921_stubs.c")
for h in mt7921_rx mt7921_mcu_event; do
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${KSHIM_INCS[@]}" \
        "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7921_SRCS[@]}" /tmp/lsan_off.o -lstdc++ \
        -o "$SRC/fuzz_$h"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${KSHIM_INCS[@]}" \
        "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7921_SRCS[@]}" /tmp/standalone_main.o /tmp/lsan_off.o -lstdc++ \
        -o "$SRC/fuzz_$h-standalone"
done

# 5e) mt7925-rx / mt7925-mcu-event: the same two paths for MT7925 (Wi-Fi 7, mt792x with the connac3
#     RX descriptor): mt7925/mac.c mt7925_queue_rx_skb (with mt792x_mac.c, the connac2 helpers, the
#     connac3 radiotap decoders and the P2P RX filter in mt7925/p2p.c) and mt7925/mcu.c
#     mt7925_mcu_rx_event with the UNI event handlers.
MT7925_SRCS=("$SRC/mt7925/mac.c" "$SRC/mt7925/mcu.c" "$SRC/mt7925/p2p.c" "$SRC/mt792x_mac.c" "$SRC/mt76_connac_mac.c"
             "$SRC/mt76_connac3_mac.c" "$SRC/mcu.c" "$SRC/util.c" "$SRC/mac80211.c" "$SRC/agg-rx.c" "$SRC/tx.c" "$SRC/scan.c"
             "$SRC/mayhem/kshim/kstubs.c" "$SRC/mayhem/kshim/mt7925_stubs.c")
for h in mt7925_rx mt7925_mcu_event; do
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${KSHIM_INCS[@]}" \
        "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7925_SRCS[@]}" /tmp/lsan_off.o -lstdc++ \
        -o "$SRC/fuzz_$h"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${KSHIM_INCS[@]}" \
        "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7925_SRCS[@]}" /tmp/standalone_main.o /tmp/lsan_off.o -lstdc++ \
        -o "$SRC/fuzz_$h-standalone"
done

# 5f) mt76-connac2-fw-load: the connac2 firmware loader in mt76_connac_mcu.c (mt76_connac2_load_patch
#     and mt76_connac2_load_ram, as mt792x_load_firmware calls them for MT7921) on an MT7921 device
#     whose MCU accepts every download command.
FWLOAD_SRCS=("$SRC/mt76_connac_mcu.c" "$SRC/mcu.c" "$SRC/util.c" "$SRC/mayhem/kshim/kstubs.c"
             "$SRC/mayhem/kshim/mt76_connac2_fw_load_stubs.c")
FWLOAD_HARNESS="$SRC/mayhem/harnesses/fuzz_mt76_connac2_fw_load.c"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${KSHIM_INCS[@]}" \
    "$FWLOAD_HARNESS" "${FWLOAD_SRCS[@]}" /tmp/lsan_off.o -lstdc++ -o "$SRC/fuzz_mt76_connac2_fw_load"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "${KSHIM_INCS[@]}" \
    "$FWLOAD_HARNESS" "${FWLOAD_SRCS[@]}" /tmp/standalone_main.o /tmp/lsan_off.o -lstdc++ \
    -o "$SRC/fuzz_mt76_connac2_fw_load-standalone"

# 6) Known-answer builds of the shim targets for mayhem/test.sh: the same harness + driver sources
#    with normal optimisation and no sanitizers, run once per input by the standalone main, with
#    mayhem/kshim/selftest_report.c printing what the driver produced.
$CC -O2 $COVERAGE_FLAGS "${KSHIM_INCS[@]}" "$RX_HARNESS" "${MT76X02_SRCS[@]}" \
    "$SRC/mayhem/kshim/selftest_report.c" "$STANDALONE_FUZZ_MAIN" -o "$SRC/mt76x02_rx_selftest"
for h in mt7615_rx mt7615_mcu_response; do
    $CC -O2 $COVERAGE_FLAGS "${KSHIM_INCS[@]}" "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7615_SRCS[@]}" \
        "$SRC/mayhem/kshim/selftest_report.c" "$STANDALONE_FUZZ_MAIN" -o "$SRC/${h}_selftest"
done
for h in mt7996_rx mt7996_mcu_event; do
    $CC -O2 $COVERAGE_FLAGS "${KSHIM_INCS[@]}" "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7996_SRCS[@]}" \
        "$SRC/mayhem/kshim/selftest_report.c" "$STANDALONE_FUZZ_MAIN" -o "$SRC/${h}_selftest"
done
for h in mt7915_rx mt7915_mcu_event; do
    $CC -O2 $COVERAGE_FLAGS "${KSHIM_INCS[@]}" "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7915_SRCS[@]}" \
        "$SRC/mayhem/kshim/selftest_report.c" "$STANDALONE_FUZZ_MAIN" -o "$SRC/${h}_selftest"
done
for h in mt7921_rx mt7921_mcu_event; do
    $CC -O2 $COVERAGE_FLAGS "${KSHIM_INCS[@]}" "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7921_SRCS[@]}" \
        "$SRC/mayhem/kshim/selftest_report.c" "$STANDALONE_FUZZ_MAIN" -o "$SRC/${h}_selftest"
done
for h in mt7925_rx mt7925_mcu_event; do
    $CC -O2 $COVERAGE_FLAGS "${KSHIM_INCS[@]}" "$SRC/mayhem/harnesses/fuzz_$h.c" "${MT7925_SRCS[@]}" \
        "$SRC/mayhem/kshim/selftest_report.c" "$STANDALONE_FUZZ_MAIN" -o "$SRC/${h}_selftest"
done
$CC -O2 $COVERAGE_FLAGS "${KSHIM_INCS[@]}" "$FWLOAD_HARNESS" "${FWLOAD_SRCS[@]}" \
    "$SRC/mayhem/kshim/selftest_report.c" "$STANDALONE_FUZZ_MAIN" -o "$SRC/mt76_connac2_fw_load_selftest"
