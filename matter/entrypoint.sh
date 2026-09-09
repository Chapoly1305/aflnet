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
# Env: FUZZ_SECONDS, FUZZ_PORT, DELAY_US, POLL_MS, TRANSPORT, AFL_ALGO_FLAGS,
#      CALIBRATE=1|0, SEEDS_DIR, INSTANCE, SNAPSHOT_INTERVAL
set -uo pipefail

OUT=/workdir/output
SEEDS_DIR="${SEEDS_DIR:-/opt/fuzzer/seeds}"
DUT=/opt/fuzzer/aflnet-chip-all-clusters-app-fuzz
KVS=/tmp/chip_kvs
INSTANCE="${INSTANCE:-instance-01}"
# ProFuzzBench hands AFLNet a protocol dictionary for most of its subjects
# (-x ftp.dict / http.dict / rtsp.dict); ours is generated from our own corpus
# and every token is verified to occur in the seeds, so it injects nothing the
# seeds do not already carry. Without it AFLNet has to rediscover fixed
# constants -- cluster ids, command ids, TLV control octets -- by chance.
DICT_ARG=""
if [[ -n "${DICT:-}" && -f "${DICT}" ]]; then
  DICT_ARG="-x ${DICT}"
fi
PROFRAW_DIR="${OUT}/profraw"
mkdir -p "${OUT}" "${PROFRAW_DIR}"

log() { echo "[aflnet-ct $(date -u +%H:%M:%S)] $*"; }

# Transport. tcp uses Matter's 4-byte little-endian length framing, which the
# spec mandates for stream transports (Matter 1.5 Core Spec 4.5 / 4.5.1), and
# matches AFLNet's dominant mode -- 6 of its 7 upstream tutorials are -N tcp://.
if [ "${TRANSPORT}" = "tcp" ]; then
  PROTO=MATTERTCP; NETSPEC="tcp://127.0.0.1/${FUZZ_PORT}"
else
  PROTO=MATTER;    NETSPEC="udp://127.0.0.1/${FUZZ_PORT}"
fi

# NOTE: -d lives in AFL_ALGO_FLAGS, not here. afl-fuzz hard-FATALs on a repeated
# flag ("Multiple -d options not supported"), so nothing below may duplicate a
# flag that AFL_ALGO_FLAGS already carries (-d -q -s -E -K -R).
# AFL is stopped with `timeout -s INT`, and on SIGINT it does not always take the
# DUT down with it. A surviving DUT keeps the operational port bound, so the next
# run's DUT fails to bind, VerifyOrDie fires, and AFL reports the confusing
# "Fork server crashed with signal 6" -- before any input, which sends you
# looking at the seeds instead of at the port. This bit us between the settle
# calibration and the real campaign. UDP masked it (SO_REUSEADDR); TCP does not.
#
# The pattern is anchored with ^: afl-fuzz's own command line ends in
# "-- <DUT> --secured-device-port ...", so an unanchored `pkill -f` would kill
# the fuzzer as well as any stray DUT.
reap_dut() {
  # Kill a stale afl-fuzz FIRST. `timeout -s INT` only sets AFL's stop_soon flag
  # and AFL checks it between execs, so with -t 3000 it can outlive the timeout
  # by a long way. A surviving afl-fuzz respawns its own forkserver, which
  # re-binds the port -- so killing only the DUT lets AFL immediately put another
  # one back. This is what made the settle calibration poison the real run.
  pkill -f "^${AFLNET}/afl-fuzz" 2>/dev/null || true
  for _ in $(seq 1 50); do
    pgrep -f "^${AFLNET}/afl-fuzz" >/dev/null 2>&1 || break
    sleep 0.2
  done
  pkill -9 -f "^${AFLNET}/afl-fuzz" 2>/dev/null || true
  pkill -f "^${DUT}" 2>/dev/null || true
  for _ in $(seq 1 50); do
    pgrep -f "^${DUT}" >/dev/null 2>&1 || break
    sleep 0.2
  done
  pkill -9 -f "^${DUT}" 2>/dev/null || true
  # Wait for the kernel to release the listener before the next bind. Read
  # /proc/net/tcp directly -- the runtime image has no iproute2/ss, and adding a
  # package just for a liveness check is not worth the image surface.
  local hexport
  hexport=$(printf '%04X' "${FUZZ_PORT}")
  for _ in $(seq 1 50); do
    grep -qiE "^ *[0-9]+: [0-9A-F]+:${hexport} " /proc/net/tcp /proc/net/tcp6 2>/dev/null || break
    sleep 0.2
  done
}

run_afl() {  # $1=delay_us  $2=timeout_s  $3=outdir  $4=poll_ms
  reap_dut
  rm -rf "$3" "${KVS}"; mkdir -p "$3"
  timeout -s INT -k 10 "$2" "${AFLNET}/afl-fuzz" \
      -i "${SEEDS_DIR}" -o "$3" \
      -N "${NETSPEC}" -P "${PROTO}" \
      -D "$1" -W "$4" \
      ${AFL_ALGO_FLAGS} ${DICT_ARG} \
      -m none -t "${TEST_TIMEOUT_MS}+" \
      -- "${DUT}" --secured-device-port "${FUZZ_PORT}" --KVS "${KVS}"
}

# --- settle-delay calibration -------------------------------------------------
# AFLNet polls only ~1ms for the response after sending, so the forked child must
# already be in epoll_wait. The delay that achieves this is load-dependent: 20ms
# is right on an idle host and fails outright ("No server states have been
# detected") on a loaded one. Probe upward and keep the first value that works,
# rather than hardcoding a number that silently kills the run.
DELAY="${DELAY_US}"; POLL="${POLL_MS}"
if [[ "${CALIBRATE:-1}" == "1" ]]; then
  CAL_SEEDS=/tmp/cal-seeds; rm -rf "${CAL_SEEDS}"; mkdir -p "${CAL_SEEDS}"
  find "${SEEDS_DIR}" -name '*.raw' | head -5 | xargs -I{} cp {} "${CAL_SEEDS}/"
  # Calibration runs real inputs through the DUT, so send their counters to a
  # throwaway profile -- otherwise the campaign's t=0 coverage already includes
  # up to four calibration passes.
  export LLVM_PROFILE_FILE=/tmp/cal_%c.profraw
  # -W (response poll) is the binding knob, not -D: AFLNet defaults it to 1 ms,
  # which is too tight to catch the reply, and a too-large -D was only ever
  # compensating for that. TCP needs a larger minimum than UDP because the
  # forked child must accept() before it can read. Upstream raises -W the same
  # way for its one datagram target (tutorials/tinydtls uses -W 30). Escalate
  # the pair rather than -D alone.
  for dw in "${DELAY_US}:${POLL_MS}" "${DELAY_US}:50" "20000:50" "50000:100"; do
    d="${dw%%:*}"; w="${dw##*:}"
    log "calibrating: -D ${d}us -W ${w}ms"
    SEEDS_DIR="${CAL_SEEDS}" run_afl "${d}" 75 /tmp/cal-out "${w}" > /tmp/cal.log 2>&1 || true
    if grep -aq "PROGRAM ABORT" /tmp/cal.log; then
      log "  calibration cannot run: $(grep -a 'PROGRAM ABORT' /tmp/cal.log | head -1 | sed 's/\x1b\[[0-9;]*m//g')"
      break
    fi
    if grep -aq "No server states have been detected" /tmp/cal.log; then
      log "  -D ${d}us -W ${w}ms REJECTED (no server states)"
    else
      DELAY="${d}"; POLL="${w}"; log "  -D ${d}us -W ${w}ms OK -> using it"; break
    fi
  done
  rm -rf /tmp/cal-out "${CAL_SEEDS}" /tmp/cal_*.profraw
fi
echo "delay_us=${DELAY}"   >> "${OUT}/run.env"
echo "poll_ms=${POLL}"     >> "${OUT}/run.env"
echo "transport=${TRANSPORT}" >> "${OUT}/run.env"
echo "protocol=${PROTO}"   >> "${OUT}/run.env"
echo "afl_algo_flags=${AFL_ALGO_FLAGS}" >> "${OUT}/run.env"
echo "dict=${DICT:-none}" >> "${OUT}/run.env"
echo "dict_tokens=$(grep -c '=' "${DICT}" 2>/dev/null || echo 0)" >> "${OUT}/run.env"
echo "test_timeout_ms=${TEST_TIMEOUT_MS}" >> "${OUT}/run.env"
echo "fuzz_port=${FUZZ_PORT}" >> "${OUT}/run.env"
echo "instance=${INSTANCE}"   >> "${OUT}/run.env"
echo "seeds=$(find "${SEEDS_DIR}" -name '*.raw' | wc -l)" >> "${OUT}/run.env"
echo "started=$(date -Iseconds)" >> "${OUT}/run.env"

# --- campaign -----------------------------------------------------------------
# The fuzz DUT carries NO coverage-measurement instrumentation. That is the
# ProFuzzBench / AFLNet reference design: the target is compiled a second time
# for coverage, and the curve is produced afterwards by replaying the saved
# queue against that second binary in seed-mtime order (phase2_parallel.py).
# See ai_docs/benchmark-fuzzers.md, "Coverage measurement".
#
# Do NOT reintroduce LLVM_PROFILE_FILE / profraw_snapshotter.py here: profiling
# the fuzz binary costs throughput that the compared in-process fuzzer does not
# pay, and it makes each system's coverage come from its own binary, so the
# llvm-cov denominators stop being comparable.
echo "MATTER_FUZZ_COVERAGE_BINARY=/opt/fuzzer/aflnet-chip-all-clusters-app-cov" > "${OUT}/coverage-run.env"

log "fuzzing ${FUZZ_SECONDS}s ${TRANSPORT}/-P ${PROTO} -D ${DELAY}us -W ${POLL}ms, seeds=$(find "${SEEDS_DIR}" -name '*.raw' | wc -l), snapshot every ${SNAPSHOT_INTERVAL}s"
run_afl "${DELAY}" "${FUZZ_SECONDS}" "${OUT}/afl-out" "${POLL}" > "${OUT}/instance.log" 2>&1
rc=$?
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
# afl_exit must be checked. 124 is our own `timeout` ending the window, which is
# the normal path; 0 is a clean AFL exit. Anything else means AFL itself died --
# 134 (SIGABRT) is what a 3,165-seed corpus produced at the end of the dry run --
# and reporting that as ok let a dead 24h campaign look healthy for 90 minutes.
if [[ "${rc}" != "124" && "${rc}" != "0" ]]; then
  fail "afl-exit-${rc}" "afl-fuzz itself exited ${rc} (not the timeout); campaign did not run to completion"
fi
q=$(ls "${OUT}/afl-out/replayable-queue" 2>/dev/null | wc -l)
[[ "${q}" -gt 0 ]] || fail empty-queue "afl-out/replayable-queue is empty -- nothing was fuzzed"
echo "queue_entries=${q}" >> "${OUT}/run.env"

# Coverage is derived later by replaying afl-out/replayable-queue against the
# profgen DUT, so the queue -- not a profraw -- is the artifact this instance
# must hand over. It MUST survive the pull; a pull that drops replayable-queue
# destroys the coverage-over-time data.
qbytes=$(du -sb "${OUT}/afl-out/replayable-queue" 2>/dev/null | cut -f1)
[[ "${qbytes:-0}" -gt 0 ]] || fail empty-replayable-queue \
  "replayable-queue has no bytes -- nothing to replay for coverage"
echo "replayable_queue_bytes=${qbytes}" >> "${OUT}/run.env"
log "done rc=${rc}; queue=${q} entries"
echo "status=ok" >> "${OUT}/run.env"
touch "${OUT}/.done"
