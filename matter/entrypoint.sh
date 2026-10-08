#!/usr/bin/env bash
# In-container AFLNet campaign runner (one instance per container).
#
# Created: 2026-09-06
# Purpose: headless entrypoint for Dockerfile.campaign -- fuzzes for
#          FUZZ_SECONDS into the bind-mounted /workdir/output. It does NOT
#          measure coverage: the fuzz DUT carries no profiling instrumentation,
#          and the curve is produced afterwards by replaying afl-out/
#          replayable-queue against the separate profgen DUT
#          (phase2_parallel.py), which is the ProFuzzBench / AFLNet reference
#          design. See run_docker_campaign.sh header.
# Retention: PERMANENT (benchmark pipeline step)
#
# Consequence: afl-out/replayable-queue IS this instance's coverage artifact.
# It must survive the pull -- a pull that drops it destroys the whole
# coverage-over-time series, which cannot be reconstructed afterwards.
#
# Env: FUZZ_SECONDS, FUZZ_PORT, DELAY_US, POLL_MS, TRANSPORT, AFL_ALGO_FLAGS,
#      CALIBRATE=1|0, SEEDS_DIR, INSTANCE, SNAPSHOT_INTERVAL,
#      STORAGE_MODE=file|memory
set -euo pipefail

# Storage is an explicit experimental factor. The cross-fuzzer primary uses
# file; memory is a separately reported ablation. In file mode, leave the env
# variable unset rather than setting it to 0: 0 would additionally force the
# auxiliary chip_*.ini files to disk, while the other launchers leave that
# platform-config default unchanged.
STORAGE_MODE="${STORAGE_MODE:-file}"
case "${STORAGE_MODE}" in
  file)
    unset MATTER_FUZZ_INMEMORY_STORAGE
    STORAGE_DELEGATE=linux-file-backed
    PLATFORM_CONFIG_STORAGE=memory-default
    ;;
  memory)
    export MATTER_FUZZ_INMEMORY_STORAGE=1
    STORAGE_DELEGATE=test-in-memory
    PLATFORM_CONFIG_STORAGE=memory-explicit
    ;;
  *)
    echo "ERROR: STORAGE_MODE must be file or memory; got ${STORAGE_MODE}" >&2
    exit 2
    ;;
esac

OUT=/workdir/output
SEEDS_DIR="${SEEDS_DIR:-/opt/fuzzer/seeds}"
DICT="${DICT:-/opt/fuzzer/matter.dict}"
INPUT_MANIFEST="${INPUT_MANIFEST:-/opt/fuzzer/input-manifest.json}"
INPUT_PROJECTION="${INPUT_PROJECTION:-/opt/fuzzer/input-projection.json}"
INPUT_FIDELITY="${INPUT_FIDELITY:-/opt/fuzzer/input-fidelity.json}"
DUT=/opt/fuzzer/aflnet-chip-all-clusters-app-fuzz
KVS="${OUT}/dut-state/kvs"
INSTANCE="${INSTANCE:-instance-01}"
# ProFuzzBench hands AFLNet a protocol dictionary for most of its subjects
# (-x ftp.dict / http.dict / rtsp.dict); ours is generated from our own corpus
# and every token is verified to occur in the seeds, so it injects nothing the
# seeds do not already carry. Without it AFLNet has to rediscover fixed
# constants -- cluster ids, command ids, TLV control octets -- by chance.
DICT_ARGS=()
if [[ -n "${DICT:-}" && -f "${DICT}" ]]; then
  DICT_ARGS=(-x "${DICT}")
fi
AFL_ALGO_ARGS=()
read -r -a AFL_ALGO_ARGS <<< "${AFL_ALGO_FLAGS:-}"
PROFRAW_DIR="${OUT}/profraw"
mkdir -p "${OUT}" "${PROFRAW_DIR}" "$(dirname "${KVS}")"

[[ "${FUZZ_SECONDS}" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: FUZZ_SECONDS must be positive" >&2; exit 2; }
python3 /opt/fuzzer/validate_input_bundle.py verify --seeds "${SEEDS_DIR}" \
  --dictionary "${DICT}" --projection "${INPUT_PROJECTION}" \
  --fidelity "${INPUT_FIDELITY}" --manifest "${INPUT_MANIFEST}" || exit 2

log() { echo "[aflnet-ct $(date -u +%H:%M:%S)] $*"; }

# Transport. tcp uses Matter's 4-byte little-endian length framing, which the
# spec mandates for stream transports (Matter 1.5 Core Spec 4.5 / 4.5.1), and
# matches AFLNet's dominant mode -- 6 of its 7 upstream tutorials are -N tcp://.
if [ "${TRANSPORT}" != "udp" ]; then
  echo "ERROR: this Matter integration supports UDP only; got ${TRANSPORT}" >&2
  exit 2
fi
PROTO=MATTER; NETSPEC="udp://127.0.0.1/${FUZZ_PORT}"

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
  rm -rf "$3"; rm -f "${KVS}"; mkdir -p "$3"
  timeout -s INT -k 10 "$2" "${AFLNET}/afl-fuzz" \
      -i "${SEEDS_DIR}" -o "$3" \
      -N "${NETSPEC}" -P "${PROTO}" \
      -D "$1" -W "$4" \
      "${AFL_ALGO_ARGS[@]}" "${DICT_ARGS[@]}" \
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
  mapfile -d '' -t calibration_seeds < <(
    find "${SEEDS_DIR}" -maxdepth 1 -type f -name '*.raw' -print0 | LC_ALL=C sort -z
  )
  for seed in "${calibration_seeds[@]:0:5}"; do
    cp -- "${seed}" "${CAL_SEEDS}/"
  done
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
      log "  calibration cannot run: $(grep -am1 'PROGRAM ABORT' /tmp/cal.log | sed 's/\x1b\[[0-9;]*m//g')"
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
dict_tokens=$(grep -c '=' "${DICT}" 2>/dev/null || true)
{
  echo "delay_us=${DELAY}"
  echo "poll_ms=${POLL}"
  echo "transport=${TRANSPORT}"
  echo "protocol=${PROTO}"
  echo "afl_algo_flags=${AFL_ALGO_FLAGS:-}"
  echo "dict=${DICT:-none}"
  echo "dict_tokens=${dict_tokens:-0}"
  echo "storage_mode=${STORAGE_MODE}"
  echo "storage_delegate=${STORAGE_DELEGATE}"
  echo "storage_path=${KVS}"
  echo "storage_filesystem=$(stat -f -c %T "$(dirname "${KVS}")")"
  echo "platform_config_storage=${PLATFORM_CONFIG_STORAGE}"
  echo "testcase_state_reset=fork-snapshot"
  echo "coverage_kind=saved_queue_replay"
  echo "test_timeout_ms=${TEST_TIMEOUT_MS}"
  echo "fuzz_port=${FUZZ_PORT}"
  echo "instance=${INSTANCE}"
  echo "seeds=$(find "${SEEDS_DIR}" -name '*.raw' | wc -l)"
  echo "started=$(date -Iseconds)"
} >> "${OUT}/run.env"

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
set +e
run_afl "${DELAY}" "${FUZZ_SECONDS}" "${OUT}/afl-out" "${POLL}" > "${OUT}/instance.log" 2>&1
rc=$?
set -e
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
if [[ "${STORAGE_MODE}" == file ]]; then
  [[ -s "${KVS}" ]] || fail missing-file-kvs \
    "file-backed DUT KVS is missing or empty: ${KVS}"
fi
if [[ -f "${KVS}" ]]; then
  {
    echo "kvs_present=1"
    echo "kvs_bytes=$(stat -c %s "${KVS}")"
    echo "kvs_sha256=$(sha256sum "${KVS}" | cut -d' ' -f1)"
  } >> "${OUT}/run.env"
else
  {
    echo "kvs_present=0"
    echo "kvs_bytes=0"
    echo "kvs_sha256=none"
  } >> "${OUT}/run.env"
fi
queue_dir="${OUT}/afl-out/replayable-queue"
[[ -d "${queue_dir}" ]] || fail missing-replayable-queue \
  "afl-out/replayable-queue is missing -- nothing was fuzzed"
q=$(find "${queue_dir}" -mindepth 1 -maxdepth 1 -type f -printf '.\n' | wc -l)
[[ "${q}" -gt 0 ]] || fail empty-queue "afl-out/replayable-queue is empty -- nothing was fuzzed"
echo "queue_entries=${q}" >> "${OUT}/run.env"

# A fixed wall-clock run is not valid for this corpus if the deadline arrives
# during AFL's initial dry run. Preserve and compare the exact source inventory,
# rather than accepting any non-empty prefix of the corpus as a completed run.
expected_initial="${OUT}/initial-seeds.expected.txt"
observed_initial="${OUT}/initial-seeds.observed.txt"
find "${SEEDS_DIR}" -maxdepth 1 -type f -name '*.raw' -printf '%f\n' | \
  LC_ALL=C sort > "${expected_initial}"
find "${queue_dir}" -maxdepth 1 -type f -name '*,orig:*' -printf '%f\n' | \
  sed 's/^.*,orig://' | LC_ALL=C sort > "${observed_initial}"
expected_initial_count=$(wc -l < "${expected_initial}")
observed_initial_count=$(wc -l < "${observed_initial}")
echo "initial_queue_entries=${observed_initial_count}" >> "${OUT}/run.env"
if ! cmp -s "${expected_initial}" "${observed_initial}"; then
  missing_initial=$(comm -23 "${expected_initial}" "${observed_initial}" | wc -l)
  unexpected_initial=$(comm -13 "${expected_initial}" "${observed_initial}" | wc -l)
  fail incomplete-initial-corpus \
    "initial calibration covered ${observed_initial_count}/${expected_initial_count} seeds (missing=${missing_initial}, unexpected=${unexpected_initial})"
fi

# Coverage is derived later by replaying afl-out/replayable-queue against the
# profgen DUT, so the queue -- not a profraw -- is the artifact this instance
# must hand over. It MUST survive the pull; a pull that drops replayable-queue
# destroys the coverage-over-time data.
# Sum real file bytes, not `du -sb`: on ext4 a directory inode does not shrink
# when its entries are removed, so `du` on an EMPTIED replayable-queue still
# reports tens of KB and this gate would pass on nothing.
qbytes=$(find "${queue_dir}" -type f -printf '%s\n' \
         | awk '{s+=$1} END{print s+0}')
[[ "${qbytes:-0}" -gt 0 ]] || fail empty-replayable-queue \
  "replayable-queue has no bytes -- nothing to replay for coverage"
echo "replayable_queue_bytes=${qbytes}" >> "${OUT}/run.env"

# A populated initial queue proves calibration only. Require fuzzer_stats to
# span the requested budget (within five seconds for final stats flushing).
stats="${OUT}/afl-out/fuzzer_stats"
[[ -s "${stats}" ]] || fail missing-fuzzer-stats "fuzzer_stats is missing"
stat_value() { awk -F: -v key="$1" '$1 ~ "^" key " *$" {gsub(/ /, "", $2); print $2; exit}' "${stats}"; }
stats_start="$(stat_value start_time)"
stats_end="$(stat_value last_update)"
stats_execs="$(stat_value execs_done)"
[[ "${stats_start}" =~ ^[0-9]+$ && "${stats_end}" =~ ^[0-9]+$ && "${stats_execs}" =~ ^[0-9]+$ ]] || \
  fail invalid-fuzzer-stats "fuzzer_stats lacks numeric start_time/last_update/execs_done"
observed_seconds=$((stats_end - stats_start))
minimum_seconds=$((FUZZ_SECONDS > 10 ? FUZZ_SECONDS - 5 : 1))
(( observed_seconds >= minimum_seconds )) || fail incomplete-budget \
  "fuzzer ran ${observed_seconds}s, below required ${minimum_seconds}s of ${FUZZ_SECONDS}s"
(( stats_execs > 0 )) || fail no-executions "fuzzer_stats records zero executions"
echo "observed_fuzz_seconds=${observed_seconds}" >> "${OUT}/run.env"
echo "execs_done=${stats_execs}" >> "${OUT}/run.env"
# AFL creates its output tree mode 0700 owned by root (the container's uid).
# Both the pull and the replay-based scoring run unprivileged, and a
# "Permission denied" on replayable-queue is indistinguishable from an empty
# queue from the outside -- which is exactly how a 24h campaign's queue once
# looked lost when it was in fact intact. Since replayable-queue IS the coverage
# artifact, make the whole tree readable before handing it over.
chmod -R a+rX "${OUT}" 2>/dev/null || true

log "done rc=${rc}; queue=${q} entries"
echo "status=ok" >> "${OUT}/run.env"
touch "${OUT}/.done"
