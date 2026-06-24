#!/usr/bin/env bash
#
# AFLNet coverage-evaluation campaign: N independent instances + coverage-over-time.
#
# Paper-grade evaluation harness that mirrors the EclipseFuzz
# run_coverage_eval_campaign.sh methodology (Klees et al., CCS'18):
#   - N INDEPENDENT AFLNet instances (default 20), each with its own port,
#     out-dir, KVS, and RNG seed — these are N independent trials, NOT one
#     AFL -M/-S parallel campaign.
#   - Per-instance coverage-over-time: every --interval seconds, replay the
#     current replayable-queue/ through a LLVM-coverage DUT, merge the resulting
#     .profraw files into a snapshot-<elapsed>s.profdata.
#   - Post-run aggregation via aggregate_coverage_over_time.py: median/IQR curve
#     across all instances → coverage_over_time.csv + .png.
#
# Two DUT binaries required (both built relative to REPO_ROOT):
#   out/afl-dut-cov/chip-all-clusters-app       AFL fuzz DUT (trace-pc-guard)
#   out/afl-dut-llvmcov/chip-all-clusters-app   coverage replay DUT (profgen)
#
# Usage:
#   run_coverage_eval_campaign.sh [--instances N] [--max-total-time SEC]
#                                 [--interval SEC] [--base-port N]
#                                 [--seeds KIND] [--seed-limit N]
#                                 [--fuzz-dut PATH] [--cov-dut PATH]
#                                 [--out-dir DIR] [--no-aggregate]
#
# Examples:
#   ./run_coverage_eval_campaign.sh                           # 20 instances, 8 h
#   ./run_coverage_eval_campaign.sh --instances 5 --max-total-time 3600  # smoke
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)"
AFLNET_DIR="${REPO_ROOT}/examples/fuzzers/aflnet"
MATTER_DIR="${AFLNET_DIR}/matter"
RUNNER="${MATTER_DIR}/run_campaign.sh"
REPLAYER="${MATTER_DIR}/replay_queue_for_coverage.py"
AGGREGATOR="${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/aggregate_coverage_over_time.py"
DASHBOARD="${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/generate_coverage_dashboard.py"

INSTANCES=20
MAX_TOTAL_TIME=28800
INTERVAL=1800
BASE_PORT=5560
SEEDS_KIND="both"
SEED_LIMIT=0
FUZZ_DUT="${REPO_ROOT}/out/afl-dut-cov/chip-all-clusters-app"
COV_DUT="${REPO_ROOT}/out/afl-dut-llvmcov/chip-all-clusters-app"
OUT_DIR="${REPO_ROOT}/out/aflnet-eval-$(date +%Y%m%d-%H%M%S)"
DO_AGGREGATE=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --instances)       INSTANCES="$2";       shift 2 ;;
    --max-total-time)  MAX_TOTAL_TIME="$2";  shift 2 ;;
    --interval)        INTERVAL="$2";        shift 2 ;;
    --base-port)       BASE_PORT="$2";       shift 2 ;;
    --seeds)           SEEDS_KIND="$2";      shift 2 ;;
    --seed-limit)      SEED_LIMIT="$2";      shift 2 ;;
    --fuzz-dut)        FUZZ_DUT="$2";        shift 2 ;;
    --cov-dut)         COV_DUT="$2";         shift 2 ;;
    --out-dir)         OUT_DIR="$2";         shift 2 ;;
    --no-aggregate)    DO_AGGREGATE=0;       shift ;;
    -h|--help) sed -n '2,34p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "[afl-eval] unknown arg: $1" >&2; exit 1 ;;
  esac
done

# Validate required binaries.
[[ -x "${FUZZ_DUT}" ]] || { echo "[afl-eval] fuzz DUT not found: ${FUZZ_DUT}" >&2; exit 1; }
[[ -x "${COV_DUT}"  ]] || { echo "[afl-eval] coverage DUT not found: ${COV_DUT}" >&2; exit 1; }
[[ -x "${RUNNER}"   ]] || { echo "[afl-eval] run_campaign.sh not found: ${RUNNER}" >&2; exit 1; }

# Ensure llvm-profdata is available (needed by sampler).
if ! command -v llvm-profdata >/dev/null 2>&1; then
  CIPD_BIN="${REPO_ROOT}/.environment/cipd/packages/pigweed/bin"
  [[ -x "${CIPD_BIN}/llvm-profdata" ]] && export PATH="${CIPD_BIN}:${PATH}"
fi
command -v llvm-profdata >/dev/null 2>&1 || {
  echo "[afl-eval] llvm-profdata not found; cannot take coverage snapshots" >&2; exit 1
}

# Resolve seed corpus.
CONVERTER="${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/export_corpus_to_aflnet_seeds.py"
LIMIT_ARG=()
[[ "${SEED_LIMIT}" -gt 0 ]] && LIMIT_ARG=(--limit "${SEED_LIMIT}")
case "${SEEDS_KIND}" in
  gen)
    SEED_DIR="${MATTER_DIR}/seeds"
    if [[ ! -d "${SEED_DIR}" || -z "$(ls -A "${SEED_DIR}" 2>/dev/null)" ]]; then
      echo "[afl-eval] generating hand-rolled seeds..."
      ( cd "${MATTER_DIR}" && python3 gen_matter_seeds.py -o seeds )
    fi ;;
  fsm|plain|both)
    SEED_DIR="${REPO_ROOT}/out/aflnet-seeds-${SEEDS_KIND}"
    echo "[afl-eval] rebuilding ${SEEDS_KIND} seeds -> ${SEED_DIR}"
    rm -rf "${SEED_DIR}"
    if ! python3 "${CONVERTER}" --corpus "${SEEDS_KIND}" --out "${SEED_DIR}" "${LIMIT_ARG[@]}"; then
      echo "[afl-eval] FATAL: seed conversion failed; aborting campaign" >&2
      exit 1
    fi
    [[ -d "${SEED_DIR}" && -n "$(ls -A "${SEED_DIR}" 2>/dev/null)" ]] || {
      echo "[afl-eval] FATAL: seed dir ${SEED_DIR} empty after conversion" >&2; exit 1; } ;;
  *) echo "[afl-eval] unknown --seeds '${SEEDS_KIND}' (gen|fsm|plain|both)" >&2; exit 1 ;;
esac

NUM_CORES="$(nproc 2>/dev/null || echo '?')"
mkdir -p "${OUT_DIR}"

echo "[afl-eval] instances=${INSTANCES} max_total_time=${MAX_TOTAL_TIME}s interval=${INTERVAL}s"
echo "[afl-eval] base_port=${BASE_PORT} seeds=${SEEDS_KIND}($(ls "${SEED_DIR}" | wc -l)) cores=${NUM_CORES}"
echo "[afl-eval] fuzz_dut=${FUZZ_DUT}"
echo "[afl-eval] cov_dut=${COV_DUT}"
echo "[afl-eval] out_dir=${OUT_DIR}"
if [[ $(( INSTANCES )) -gt $(( ${NUM_CORES:-0} )) ]] 2>/dev/null; then
  echo "[afl-eval] WARNING: ${INSTANCES} instances > ${NUM_CORES} cores; CPU contention expected" >&2
fi

{
  echo "started=$(date -Iseconds)"
  echo "instances=${INSTANCES}"
  echo "max_total_time=${MAX_TOTAL_TIME}"
  echo "snapshot_interval=${INTERVAL}"
  echo "base_port=${BASE_PORT}"
  echo "seeds_kind=${SEEDS_KIND}"
  echo "fuzz_dut=${FUZZ_DUT}"
  echo "coverage_binary=${COV_DUT}"
  echo "cores=${NUM_CORES}"
} > "${OUT_DIR}/eval-meta.txt"

# ---------------------------------------------------------------------------
# per-instance coverage sampler
#
# Each call to snapshot_once():
#   1. Copies current replayable-queue/ to a temp dir (avoids AFL write races).
#   2. Starts the coverage DUT on a dedicated port with LLVM_PROFILE_FILE set.
#   3. Replays all queue files via replay_queue_for_coverage.py.
#   4. SIGTERMs the DUT — graceful shutdown flushes the profraw.
#   5. llvm-profdata merge → snapshot-Xs.profdata.
#
# COV_PORT is BASE_PORT + 200 + instance_index, well clear of the fuzz DUT
# ports (BASE_PORT + 0..INSTANCES-1). Since each instance's sampler runs
# serially (one snapshot at a time), there is no concurrent coverage DUT
# contention within one instance.
# ---------------------------------------------------------------------------
sample_instance() {
  local inst_dir="$1" start_epoch="$2" stagger="$3" cov_port="$4"
  local snap_dir="${inst_dir}/snapshots"
  local profraw_dir="${inst_dir}/profraw"
  local timeline="${inst_dir}/timeline.csv"
  mkdir -p "${snap_dir}" "${profraw_dir}"
  echo "elapsed_s,snapshot,profraw_count" > "${timeline}"

  # Cumulative baseline: snapshot N = merge(baseline + new profraws).
  # After each snapshot, profraws are deleted and the baseline is updated
  # so peak storage is bounded (~1-2 GB per instance between snapshots).
  local baseline="${inst_dir}/baseline.profdata"

  snapshot_once() {
    local now elapsed
    now="$(date +%s)"; elapsed=$(( now - start_epoch ))

    [[ -d "${profraw_dir}" ]] || return 0

    local profraws=()
    while IFS= read -r f; do profraws+=("$f"); done \
      < <(find "${profraw_dir}" -name "dump-*.profraw" -type f 2>/dev/null | sort)
    [[ "${#profraws[@]}" -eq 0 && ! -f "${baseline}" ]] && return 0

    local merge_args=()
    [[ -f "${baseline}" ]] && merge_args+=("${baseline}")
    merge_args+=("${profraws[@]}")

    local out="${snap_dir}/snapshot-${elapsed}s.profdata"
    if llvm-profdata merge --failure-mode=warn "${merge_args[@]}" -o "${out}" 2>/dev/null \
       && [[ -s "${out}" ]]; then
      # Update baseline and remove consumed profraws.
      cp "${out}" "${baseline}"
      rm -f "${profraws[@]}" 2>/dev/null
      echo "${elapsed},${out},${#profraws[@]}" >> "${timeline}"
    fi
  }

  sleep "${stagger}"
  while [[ ! -f "${inst_dir}/.done" ]]; do
    snapshot_once
    local slept=0
    while [[ "${slept}" -lt "${INTERVAL}" && ! -f "${inst_dir}/.done" ]]; do
      sleep 5; slept=$(( slept + 5 ))
    done
  done
  snapshot_once  # final snapshot at end-of-campaign
}

# ---------------------------------------------------------------------------
# Launch instances + samplers
# ---------------------------------------------------------------------------
CAMPAIGN_PIDS=()
SAMPLER_PIDS=()
STAGGER_STEP=$(( INTERVAL / INSTANCES ))
[[ "${STAGGER_STEP}" -lt 1 ]] && STAGGER_STEP=1

for i in $(seq 1 "${INSTANCES}"); do
  idx="$(printf '%02d' "${i}")"
  inst_dir="${OUT_DIR}/instance-${idx}"
  afl_out="${inst_dir}/afl-out"
  rm -rf "${inst_dir}"
  mkdir -p "${inst_dir}" "${afl_out}"

  fuzz_port=$(( BASE_PORT + i - 1 ))
  cov_port=$(( BASE_PORT + 200 + i - 1 ))
  start_epoch="$(date +%s)"
  inst_seed=$(( (start_epoch + i * 7919) % 1000000 ))

  # ── Per-instance profraw directory ────────────────────────────────
  # The SIGTERM handler (AppMain.cpp, MATTER_FUZZ_AFL_INSTRUMENT) dumps
  # LLVM source-coverage profraw files here.  One file per ~30 s window
  # (time-bucketed O_EXCL).  The sampler merges them for snapshots.
  # ──────────────────────────────────────────────────────────────────
  inst_profraw_dir="${inst_dir}/profraw"
  mkdir -p "${inst_profraw_dir}"

  # ── Per-instance isolated storage ────────────────────────────────
  # Every instance gets its own MATTER_FUZZ_STORAGE_DIR so factory,
  # config, and counters INI files are never shared across instances.
  # PosixConfig (src/platform/Linux/PosixConfig.cpp) resolves the env
  # vars at runtime — no rebuild needed.
  # ──────────────────────────────────────────────────────────────────
  inst_storage_dir="$(mktemp -d)"
  [[ -d "${inst_storage_dir}" ]] || {
    echo "[afl-eval] FATAL: mktemp -d failed for instance-${idx}" >&2
    exit 1
  }
  inst_kvs="${inst_storage_dir}/chip_kvs"

  # Write coverage-run.env so aggregate_coverage_over_time.py finds the binary.
  echo "MATTER_FUZZ_COVERAGE_BINARY=${COV_DUT}" > "${inst_dir}/coverage-run.env"

  # Copy seeds to a private per-instance directory so hardlinks in afl-fuzz's
  # queue don't share inodes across instances (avoids "Short read" races when
  # the dry-run calibration touches queue files concurrently).
  inst_seeds="${inst_dir}/seeds"
  cp -r "${SEED_DIR}" "${inst_seeds}"

  # Stagger instance starts: 3 s apart so DUT forkservers don't all compete for
  # CPU at the same moment during dry_run calibration.  Instance 1 starts
  # immediately; each subsequent one waits 3 s more.
  [[ "${i}" -gt 1 ]] && sleep 3

  # AFL host-environment bypasses.
  # AFL_SKIP_CRASHES: skip seeds that crash the DUT during dry_run instead of
  # aborting — some FSM/plain seeds may trigger real bugs on first replay, which
  # is a finding, not a reason to abort the calibration phase.
  (
    env AFL_SKIP_CPUFREQ=1 \
        AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
        AFL_NO_AFFINITY=1 \
        AFL_SKIP_CRASHES=1 \
        AFL_SKIP_CORE_PATTERN=1 \
        AFLNET="${AFLNET_DIR}" \
        DUT="${FUZZ_DUT}" \
        PORT="${fuzz_port}" \
        DELAY=20000 \
        SEEDS="${inst_seeds}" \
        KVS="${inst_kvs}" \
        MATTER_FUZZ_STORAGE_DIR="${inst_storage_dir}" \
        MATTER_FUZZ_KVS_PATH="${inst_kvs}" \
        MATTER_FUZZ_INMEMORY_STORAGE=1 \
        LLVM_PROFILE_FILE="${inst_profraw_dir}/dump-%p.profraw" \
        AFL_PROFRAW_DIR="${inst_profraw_dir}" \
      "${RUNNER}" "${afl_out}" \
      > "${inst_dir}/instance.log" 2>&1 || true
    touch "${inst_dir}/.done"
  ) &
  CAMPAIGN_PIDS+=("$!")

  stagger=$(( (i - 1) * STAGGER_STEP ))
  sample_instance "${inst_dir}" "${start_epoch}" "${stagger}" "${cov_port}" &
  SAMPLER_PIDS+=("$!")

  echo "[afl-eval] launched instance-${idx} port=${fuzz_port} cov_port=${cov_port} seed=${inst_seed}"
done

echo "[afl-eval] all ${INSTANCES} instances running; waiting (~${MAX_TOTAL_TIME}s)..."

# Enforce max-total-time: kill all campaigns after the deadline.
(
  sleep "${MAX_TOTAL_TIME}"
  echo "[afl-eval] max-total-time reached; stopping all campaigns..."
  for pid in "${CAMPAIGN_PIDS[@]}"; do
    kill "${pid}" 2>/dev/null || true
  done
) &
TIMER_PID=$!

for pid in "${CAMPAIGN_PIDS[@]}"; do wait "${pid}" 2>/dev/null || true; done
kill "${TIMER_PID}" 2>/dev/null || true

echo "[afl-eval] all campaigns finished; waiting for final coverage snapshots..."
for pid in "${SAMPLER_PIDS[@]}"; do wait "${pid}" 2>/dev/null || true; done

echo "ended=$(date -Iseconds)" >> "${OUT_DIR}/eval-meta.txt"
echo "[afl-eval] all instances complete."

if [[ "${DO_AGGREGATE}" -eq 1 ]]; then
  echo "[afl-eval] aggregating coverage over time (SDK scope)..."
  if python3 "${AGGREGATOR}" \
       --eval-dir "${OUT_DIR}" \
       --binary "${COV_DUT}" \
       --scope sdk; then
    python3 "${DASHBOARD}" --eval-dir "${OUT_DIR}" \
      || echo "[afl-eval] dashboard generation failed; rerun: python3 ${DASHBOARD} --eval-dir ${OUT_DIR}" >&2
  else
    echo "[afl-eval] aggregation failed; rerun manually:" >&2
    echo "  python3 ${AGGREGATOR} --eval-dir ${OUT_DIR} --binary ${COV_DUT}" >&2
  fi
fi

echo ""
echo "[afl-eval] done. out=${OUT_DIR}"
echo "[afl-eval]   per-instance curves: instance-*/coverage_timeline.sdk.csv"
echo "[afl-eval]   aggregated curve:    ${OUT_DIR}/coverage_over_time.csv"
echo "[afl-eval]   plot:                ${OUT_DIR}/coverage_over_time.png"
