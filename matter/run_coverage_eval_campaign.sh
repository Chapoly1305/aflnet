#!/usr/bin/env bash
#
# AFLNet coverage-evaluation campaign: N independent instances + coverage-over-time.
#
# ProFuzzBench methodology: two-phase design.
#   Phase 1: N INDEPENDENT AFLNet instances fuzz the DUT, collecting seeds in
#            replayable-queue/.  No coverage measurement during fuzzing.
#   Phase 2: After fuzzing, each instance's queue is replayed seed-by-seed
#            through a separate coverage DUT (profgen-only).  The DUT is
#            restarted every SKIPCOUNT seeds for clean initial state.  Profraws
#            are merged into cumulative snapshot-<elapsed>s.profdata files.
#   Post-run aggregation via aggregate_coverage_over_time.py: median/IQR curve
#   across all instances → coverage_over_time.csv + .png.
#
# Two DUT binaries required (built relative to REPO_ROOT):
#   out/afl-dut-cov/chip-all-clusters-app         fuzz DUT (trace-pc-guard + ASAN)
#   out/afl-dut-replay-cov/chip-all-clusters-app   coverage DUT (profgen only)
#
# Usage:
#   run_coverage_eval_campaign.sh [--instances N] [--max-total-time SEC]
#                                 [--skipcount N] [--base-port N]
#                                 [--seeds KIND] [--seed-limit N]
#                                 [--fuzz-dut PATH] [--cov-dut PATH]
#                                 [--out-dir DIR] [--no-aggregate]
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)"
AFLNET_DIR="${REPO_ROOT}/examples/fuzzers/aflnet"
MATTER_DIR="${AFLNET_DIR}/matter"
RUNNER="${MATTER_DIR}/run_campaign.sh"
AGGREGATOR="${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/aggregate_coverage_over_time.py"
DASHBOARD="${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/generate_coverage_dashboard.py"

INSTANCES=20
MAX_TOTAL_TIME=28800
SKIPCOUNT=5
BASE_PORT=5560
SEEDS_KIND="both"
SEED_LIMIT=0
FUZZ_DUT="${REPO_ROOT}/out/afl-dut-cov/chip-all-clusters-app"
COV_DUT="${REPO_ROOT}/out/afl-dut-replay-cov/chip-all-clusters-app"
OUT_DIR="${REPO_ROOT}/out/aflnet-eval-$(date +%Y%m%d-%H%M%S)"
DO_AGGREGATE=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --instances)       INSTANCES="$2";       shift 2 ;;
    --max-total-time)  MAX_TOTAL_TIME="$2";  shift 2 ;;
    --skipcount)       SKIPCOUNT="$2";       shift 2 ;;
    --base-port)       BASE_PORT="$2";       shift 2 ;;
    --seeds)           SEEDS_KIND="$2";      shift 2 ;;
    --seed-limit)      SEED_LIMIT="$2";      shift 2 ;;
    --fuzz-dut)        FUZZ_DUT="$2";        shift 2 ;;
    --cov-dut)         COV_DUT="$2";         shift 2 ;;
    --out-dir)         OUT_DIR="$2";         shift 2 ;;
    --no-aggregate)    DO_AGGREGATE=0;       shift ;;
    *) echo "[afl-eval] unknown arg: $1" >&2; exit 1 ;;
  esac
done

[[ -x "${FUZZ_DUT}" ]] || { echo "[afl-eval] fuzz DUT not found: ${FUZZ_DUT}" >&2; exit 1; }
[[ -x "${COV_DUT}"  ]] || { echo "[afl-eval] cov DUT not found: ${COV_DUT}" >&2; exit 1; }
[[ -x "${RUNNER}"   ]] || { echo "[afl-eval] run_campaign.sh not found: ${RUNNER}" >&2; exit 1; }

if ! command -v llvm-profdata >/dev/null 2>&1; then
  CIPD_BIN="${REPO_ROOT}/.environment/cipd/packages/pigweed/bin"
  [[ -x "${CIPD_BIN}/llvm-profdata" ]] && export PATH="${CIPD_BIN}:${PATH}"
fi
command -v llvm-profdata >/dev/null 2>&1 || {
  echo "[afl-eval] llvm-profdata not found" >&2; exit 1; }

# Resolve seed corpus.
CONVERTER="${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/export_corpus_to_aflnet_seeds.py"
LIMIT_ARG=()
[[ "${SEED_LIMIT}" -gt 0 ]] && LIMIT_ARG=(--limit "${SEED_LIMIT}")
case "${SEEDS_KIND}" in
  gen)
    SEED_DIR="${MATTER_DIR}/seeds"
    [[ -d "${SEED_DIR}" && -n "$(ls -A "${SEED_DIR}" 2>/dev/null)" ]] || {
      echo "[afl-eval] generating seeds..."; ( cd "${MATTER_DIR}" && python3 gen_matter_seeds.py -o seeds ); } ;;
  fsm|plain|both)
    SEED_DIR="${REPO_ROOT}/out/aflnet-seeds-${SEEDS_KIND}"
    rm -rf "${SEED_DIR}"
    python3 "${CONVERTER}" --corpus "${SEEDS_KIND}" --out "${SEED_DIR}" "${LIMIT_ARG[@]}" || {
      echo "[afl-eval] FATAL: seed conversion failed" >&2; exit 1; }
    [[ -d "${SEED_DIR}" && -n "$(ls -A "${SEED_DIR}" 2>/dev/null)" ]] || {
      echo "[afl-eval] FATAL: seed dir empty" >&2; exit 1; } ;;
  *) echo "[afl-eval] unknown --seeds" >&2; exit 1 ;;
esac

NUM_CORES="$(nproc 2>/dev/null || echo '?')"
mkdir -p "${OUT_DIR}"

echo "[afl-eval] instances=${INSTANCES} max_time=${MAX_TOTAL_TIME}s skipcount=${SKIPCOUNT}"
echo "[afl-eval] seeds=${SEEDS_KIND}($(ls "${SEED_DIR}" | wc -l)) cores=${NUM_CORES}"
echo "[afl-eval] fuzz_dut=${FUZZ_DUT}"
echo "[afl-eval] cov_dut=${COV_DUT}"
echo "[afl-eval] out_dir=${OUT_DIR}"

{
  echo "started=$(date -Iseconds)"; echo "instances=${INSTANCES}"
  echo "max_total_time=${MAX_TOTAL_TIME}"; echo "skipcount=${SKIPCOUNT}"
  echo "base_port=${BASE_PORT}"; echo "seeds_kind=${SEEDS_KIND}"
  echo "fuzz_dut=${FUZZ_DUT}"; echo "coverage_binary=${COV_DUT}"
  echo "cores=${NUM_CORES}"
} > "${OUT_DIR}/eval-meta.txt"

# =========================================================================
# Phase 1: Fuzzing
# =========================================================================
CAMPAIGN_PIDS=()

for i in $(seq 1 "${INSTANCES}"); do
  idx="$(printf '%02d' "${i}")"
  inst_dir="${OUT_DIR}/instance-${idx}"
  afl_out="${inst_dir}/afl-out"
  rm -rf "${inst_dir}"; mkdir -p "${inst_dir}" "${afl_out}"

  fuzz_port=$(( BASE_PORT + i - 1 ))
  inst_storage_dir="$(mktemp -d)"
  [[ -d "${inst_storage_dir}" ]] || { echo "[afl-eval] FATAL: mktemp failed" >&2; exit 1; }
  inst_kvs="${inst_storage_dir}/chip_kvs"
  echo "MATTER_FUZZ_COVERAGE_BINARY=${COV_DUT}" > "${inst_dir}/coverage-run.env"
  inst_seeds="${inst_dir}/seeds"; cp -r "${SEED_DIR}" "${inst_seeds}"

  [[ "${i}" -gt 1 ]] && sleep 3

  (
    env AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_AFFINITY=1 \
        AFL_SKIP_CRASHES=1 AFL_SKIP_CORE_PATTERN=1 \
        AFLNET="${AFLNET_DIR}" DUT="${FUZZ_DUT}" PORT="${fuzz_port}" DELAY=20000 \
        SEEDS="${inst_seeds}" KVS="${inst_kvs}" \
        MATTER_FUZZ_STORAGE_DIR="${inst_storage_dir}" MATTER_FUZZ_KVS_PATH="${inst_kvs}" \
        MATTER_FUZZ_INMEMORY_STORAGE=1 \
      "${RUNNER}" "${afl_out}" > "${inst_dir}/instance.log" 2>&1 || true
    touch "${inst_dir}/.done"
  ) &
  CAMPAIGN_PIDS+=("$!")
  echo "[afl-eval] instance-${idx} port=${fuzz_port}"
done

echo "[afl-eval] all ${INSTANCES} instances fuzzing (~${MAX_TOTAL_TIME}s)..."

(
  sleep "${MAX_TOTAL_TIME}"
  echo "[afl-eval] time's up; stopping..."
  for pid in "${CAMPAIGN_PIDS[@]}"; do kill "${pid}" 2>/dev/null || true; done
) &
TIMER_PID=$!
for pid in "${CAMPAIGN_PIDS[@]}"; do wait "${pid}" 2>/dev/null || true; done
kill "${TIMER_PID}" 2>/dev/null || true

echo "ended_fuzzing=$(date -Iseconds)" >> "${OUT_DIR}/eval-meta.txt"
echo "[afl-eval] fuzzing complete."

# =========================================================================
# Phase 2: Post-fuzzing coverage replay (ProFuzzBench method)
# Delegated to phase2_parallel.py: replays each instance's replayable-queue
# through the profgen cov DUT (parallel workers) into cumulative
# snapshot-<elapsed>s.profdata files (elapsed = seed_mtime - fuzzer_stats
# start_time). Single source of Phase-2 logic, shared with manual re-runs.
# =========================================================================
echo "[afl-eval] starting coverage replay via phase2_parallel.py..."
PHASE2_PY="${MATTER_DIR}/phase2_parallel.py"
if [[ -f "${PHASE2_PY}" ]]; then
  python3 "${PHASE2_PY}" --eval-dir "${OUT_DIR}" --cov-dut "${COV_DUT}" \
    || echo "[afl-eval] phase2_parallel.py failed (re-run: python3 ${PHASE2_PY} --eval-dir ${OUT_DIR})" >&2
else
  echo "[afl-eval] phase2_parallel.py not found at ${PHASE2_PY}; skipping replay" >&2
fi

echo "ended=$(date -Iseconds)" >> "${OUT_DIR}/eval-meta.txt"
echo "[afl-eval] coverage replay complete."

if [[ "${DO_AGGREGATE}" -eq 1 ]]; then
  echo "[afl-eval] aggregating (SDK scope)..."
  if python3 "${AGGREGATOR}" --eval-dir "${OUT_DIR}" --binary "${COV_DUT}" --scope sdk; then
    python3 "${DASHBOARD}" --eval-dir "${OUT_DIR}" \
      || echo "[afl-eval] dashboard failed; rerun: python3 ${DASHBOARD} --eval-dir ${OUT_DIR}"
  else
    echo "[afl-eval] aggregation failed; rerun: python3 ${AGGREGATOR} --eval-dir ${OUT_DIR} --binary ${COV_DUT}"
  fi
fi

echo "[afl-eval] done. out=${OUT_DIR}"
