#!/usr/bin/env bash
# In-container AFLNet campaign runner (one instance per container).
#
# Created: 2026-09-06
# Purpose: headless entrypoint for Dockerfile.campaign -- calibrates the AFLNet
#          settle delay, then fuzzes for FUZZ_SECONDS into the bind-mounted
#          /workdir/output while sampling LLVM source coverage live every
#          SNAPSHOT_INTERVAL seconds -- the same mechanism, tool and cadence EP2
#          uses, so the two curves are directly comparable.
# Retention: PERMANENT (benchmark pipeline step)
#
# Live coverage works because the DUT is built with -fprofile-continuous and run
# with LLVM_PROFILE_FILE=...%c...: the counters are mmap'd into the .profraw, so
# each forked child's coverage lands there even though AFL kills it and it never
# runs atexit. profraw_snapshotter.py --continuous then samples that one live
# file on the interval (and must NOT prune it -- unlinking a live mapping loses
# every later update).
#
# Env: FUZZ_SECONDS, FUZZ_PORT, DELAY_US, CALIBRATE=1|0, SEEDS_DIR, INSTANCE,
#      SNAPSHOT_INTERVAL
set -uo pipefail

OUT=/workdir/output
SEEDS_DIR="${SEEDS_DIR:-/opt/fuzzer/seeds}"
DUT=/opt/fuzzer/chip-all-clusters-app-fuzz
KVS=/tmp/chip_kvs
INSTANCE="${INSTANCE:-instance-01}"
PROFRAW_DIR="${OUT}/profraw"
mkdir -p "${OUT}" "${PROFRAW_DIR}"

log() { echo "[aflnet-ct $(date -u +%H:%M:%S)] $*"; }

run_afl() {  # $1=delay_us  $2=timeout_s  $3=outdir
  rm -rf "$3" "${KVS}"; mkdir -p "$3"
  timeout -s INT "$2" "${AFLNET}/afl-fuzz" \
      -d -i "${SEEDS_DIR}" -o "$3" \
      -N "udp://127.0.0.1/${FUZZ_PORT}" \
      -P MATTER -E -K -D "$1" -m none -t 4000+ \
      -- "${DUT}" --secured-device-port "${FUZZ_PORT}" --KVS "${KVS}"
}

# --- settle-delay calibration -------------------------------------------------
# AFLNet polls only ~1ms for the response after sending, so the forked child must
# already be in epoll_wait. The delay that achieves this is load-dependent: 20ms
# is right on an idle host and fails outright ("No server states have been
# detected") on a loaded one. Probe upward and keep the first value that works,
# rather than hardcoding a number that silently kills the run.
DELAY="${DELAY_US}"
if [[ "${CALIBRATE:-1}" == "1" ]]; then
  CAL_SEEDS=/tmp/cal-seeds; rm -rf "${CAL_SEEDS}"; mkdir -p "${CAL_SEEDS}"
  find "${SEEDS_DIR}" -name '*.raw' | head -5 | xargs -I{} cp {} "${CAL_SEEDS}/"
  # Calibration runs real inputs through the DUT, so send their counters to a
  # throwaway profile -- otherwise the campaign's t=0 coverage already includes
  # up to four calibration passes.
  export LLVM_PROFILE_FILE=/tmp/cal_%c.profraw
  for d in "${DELAY_US}" 50000 100000 200000; do
    log "calibrating settle delay: -D ${d}us"
    SEEDS_DIR="${CAL_SEEDS}" run_afl "${d}" 75 /tmp/cal-out > /tmp/cal.log 2>&1 || true
    if grep -aq "PROGRAM ABORT" /tmp/cal.log; then
      log "  calibration cannot run: $(grep -a 'PROGRAM ABORT' /tmp/cal.log | head -1 | sed 's/\x1b\[[0-9;]*m//g')"
      break
    fi
    if grep -aq "No server states have been detected" /tmp/cal.log; then
      log "  -D ${d}us REJECTED (no server states)"
    else
      DELAY="${d}"; log "  -D ${d}us OK -> using it"; break
    fi
  done
  rm -rf /tmp/cal-out "${CAL_SEEDS}" /tmp/cal_*.profraw
fi
echo "delay_us=${DELAY}"   >> "${OUT}/run.env"
echo "fuzz_port=${FUZZ_PORT}" >> "${OUT}/run.env"
echo "instance=${INSTANCE}"   >> "${OUT}/run.env"
echo "seeds=$(find "${SEEDS_DIR}" -name '*.raw' | wc -l)" >> "${OUT}/run.env"
echo "started=$(date -Iseconds)" >> "${OUT}/run.env"

# --- campaign -----------------------------------------------------------------
# One live, mmap'd profraw for the whole campaign (%c = continuous mode).
export LLVM_PROFILE_FILE="${PROFRAW_DIR}/afl_%c.profraw"
echo "MATTER_FUZZ_COVERAGE_BINARY=/opt/fuzzer/chip-all-clusters-app-fuzz" > "${OUT}/coverage-run.env"

# Sample it on the interval with EP2's own snapshotter. --out-dir is the
# instance root so snapshots land in <instance>/snapshots/, which is exactly
# where aggregate_coverage_over_time.py looks.
rm -f "${OUT}/fuzzer.done"
python3 /opt/fuzzer/profraw_snapshotter.py \
    --profile-dir "${PROFRAW_DIR}" --out-dir "${OUT}" \
    --interval "${SNAPSHOT_INTERVAL}" --continuous \
    --done-file "${OUT}/fuzzer.done" > "${OUT}/snapshotter.log" 2>&1 &
SNAP_PID=$!

log "fuzzing ${FUZZ_SECONDS}s with -D ${DELAY}us, seeds=$(find "${SEEDS_DIR}" -name '*.raw' | wc -l), snapshot every ${SNAPSHOT_INTERVAL}s"
run_afl "${DELAY}" "${FUZZ_SECONDS}" "${OUT}/afl-out" > "${OUT}/instance.log" 2>&1
rc=$?
touch "${OUT}/fuzzer.done"
wait "${SNAP_PID}" 2>/dev/null || true
echo "ended=$(date -Iseconds)" >> "${OUT}/run.env"
echo "afl_exit=${rc}" >> "${OUT}/run.env"

fail() { log "FATAL: $2"; echo "status=$1" >> "${OUT}/run.env"; exit 3; }

# Classify the outcome from evidence, not from the absence of one error string.
# An empty queue means AFL never fuzzed, however it exited.
if grep -aq "PROGRAM ABORT" "${OUT}/instance.log"; then
  fail program-abort "afl-fuzz aborted: $(grep -a "PROGRAM ABORT" "${OUT}/instance.log" | head -1 | tr -d '\033' | sed 's/\[[0-9;]*m//g')"
fi
if grep -aq "No server states have been detected" "${OUT}/instance.log"; then
  fail no-server-states "AFLNet never saw a server response even after calibration (raise DELAY_US)"
fi
q=$(ls "${OUT}/afl-out/replayable-queue" 2>/dev/null | wc -l)
[[ "${q}" -gt 0 ]] || fail empty-queue "afl-out/replayable-queue is empty -- nothing was fuzzed"
echo "queue_entries=${q}" >> "${OUT}/run.env"

# A 0-byte profraw means continuous mode never armed (wrong build, or %c missing)
# -- the campaign would otherwise finish with no coverage at all.
prof_bytes=$(stat -c%s "${PROFRAW_DIR}"/afl_*.profraw 2>/dev/null | head -1)
[[ "${prof_bytes:-0}" -gt 0 ]] || fail no-profraw \
  "profraw is missing/empty -- DUT not built with matter_fuzz_continuous_coverage=true?"
snaps=$(ls "${OUT}/snapshots"/snapshot-*s.profdata 2>/dev/null | wc -l)
echo "profraw_bytes=${prof_bytes}" >> "${OUT}/run.env"
echo "snapshots=${snaps}" >> "${OUT}/run.env"
log "done rc=${rc}; queue=${q} entries"
echo "status=ok" >> "${OUT}/run.env"
touch "${OUT}/.done"
