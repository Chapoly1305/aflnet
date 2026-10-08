#!/usr/bin/env bash
# Launch N independent AFLNet instances, one Docker container each, headless.
#
# Created: 2026-09-06
# Purpose: run the AFLNet baseline at high concurrency for the cross-fuzzer
#          benchmark, then produce a coverage-over-time curve on the SAME
#          30-minute cadence and via the SAME aggregator as EP2.
# Retention: PERMANENT (benchmark pipeline step)
#
# Why one container per instance, and --network none:
#   A single Matter DUT binds ~24 UDP sockets -- the operational port plus 11x
#   mDNS :5353 and ~11 ephemeral. Distinct --secured-device-port values (the
#   bare-metal --base-port scheme) separate only the first of those; every
#   instance still shares one mDNS multicast space, which quietly couples
#   "independent" replicas. A private netns per container separates all of them,
#   so every instance can reuse the same port and the replicas are genuinely
#   independent. --network none keeps only lo: no veth, no iptables rules, no
#   docker0 address pool pressure at 32+ containers. Nothing is published to the
#   host, so there is no host-side port to collide with.
#
# Coverage is collected by QUEUE REPLAY (default, COV_MODE=replay) -- the
#   ProFuzzBench / AFLNet reference design. The target is compiled twice: the
#   fuzz DUT carries AFL instrumentation and NO profiling, and a second profgen
#   DUT is never fuzzed, only replayed against. After fuzzing,
#   phase2_parallel.py replays each instance's replayable-queue in seed-mtime
#   order, cumulatively merging llvm-profdata into snapshot-<elapsed>s.profdata
#   once per --interval. ProFuzzBench: "It runs again the inputs using the
#   target software compiled with gcov ... generates time series ... based on
#   the timestamps at which the inputs were generated." TSE'25 (the AFLNet
#   authors' own re-evaluation) measures branch coverage this way.
#
#   Why not live profiling of the fuzz DUT: it needs -fprofile-continuous
#   (AFL kills every forked child, so a plain profgen build writes nothing),
#   which costs per-counter indirection plus mmap writeback that the compared
#   in-process fuzzer does not pay, and it makes each system's coverage come
#   from its own binary -- so the llvm-cov denominators stop being comparable
#   ("edge counts between different binaries do not translate").
#
#   Caveat, and it MUST be applied symmetrically: replay only covers inputs AFL
#   kept in its queue, while a live profile also counts executions the fuzzer
#   discarded. So EclipseFuzz has to be scored by corpus replay against the SAME
#   profgen binary too; scoring one system live and the other by replay would
#   hand the live one credit for discarded executions.
#
#   --live is REJECTED by this image: the sampler is not installed and the fuzz
#   DUT carries no profiling. Restoring it needs both put back, plus the
#   comparability cost above. --phase2 is kept as an alias of --replay.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AFLNET_DIR="$(dirname "${SCRIPT_DIR}")"
REPO_ROOT="$(cd "${AFLNET_DIR}/../../.." && pwd)"
AGGREGATOR="${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/aggregate_coverage_over_time.py"

IMAGE="aflnet-matter-campaign:local"
INSTANCES=10
FUZZ_SECONDS=86400
TRANSPORT=udp
DELAY_US=10000
POLL_MS=100
CALIBRATE=0
INTERVAL=1800
SCOPE=clusters
COV_MODE=replay
# ProFuzzBench runs each repetition in its own container with --cpus=1
# (profuzzbench_exec_common.sh). Pinning matters with concurrent replicas:
# without it the instances contend and neither throughput nor comparison is
# reproducible.
CPUS="1"
OUT_DIR="${REPO_ROOT}/out/aflnet-docker-campaign-$(date +%Y%m%d-%H%M%S)"
REPLAY_WORKERS=16
STORAGE_MODE="${AFLNET_STORAGE_MODE:-file}"
SEEDS_DIR=""
DICT_PATH=""
MANIFEST_PATH=""
PROJECTION_PATH=""
FIDELITY_PATH=""

usage() { cat <<'U'
Usage: run_docker_campaign.sh [--instances 10] [--fuzz-seconds 86400]
         [--image TAG] [--out-dir DIR] [--transport udp]
         [--seeds DIR --dict FILE --manifest FILE --projection FILE --fidelity FILE]
         [--delay-us 10000] [--poll-ms 100] [--calibrate]
         [--storage-mode file|memory]
         [--interval 1800] [--scope clusters] [--cpus N.N]
         [--replay] [--replay-workers 16] [--no-coverage]
U
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --instances)      INSTANCES="${2:?}";     shift 2 ;;
    --fuzz-seconds)   FUZZ_SECONDS="${2:?}";  shift 2 ;;
    --image)          IMAGE="${2:?}";         shift 2 ;;
    --out-dir)        OUT_DIR="${2:?}";       shift 2 ;;
    --seeds)          SEEDS_DIR="${2:?}";     shift 2 ;;
    --dict)           DICT_PATH="${2:?}";     shift 2 ;;
    --manifest)       MANIFEST_PATH="${2:?}"; shift 2 ;;
    --projection)     PROJECTION_PATH="${2:?}"; shift 2 ;;
    --fidelity)       FIDELITY_PATH="${2:?}"; shift 2 ;;
    --delay-us)       DELAY_US="${2:?}";      shift 2 ;;
    --poll-ms)        POLL_MS="${2:?}";       shift 2 ;;
    --transport)      TRANSPORT="${2:?}";     shift 2 ;;
    --calibrate)      CALIBRATE=1;            shift ;;
    --storage-mode)   STORAGE_MODE="${2:?}";  shift 2 ;;
    --interval)       INTERVAL="${2:?}";      shift 2 ;;
    --scope)          SCOPE="${2:?}";         shift 2 ;;
    --cpus)           CPUS="${2:?}";          shift 2 ;;
    --replay-workers|--phase2-workers) REPLAY_WORKERS="${2:?}"; shift 2 ;;
    --replay)         COV_MODE=replay;        shift ;;
    --phase2)         COV_MODE=replay;        shift ;;   # legacy alias
    --live)           # Reject at parse time, not after a full fuzzing budget.
                      # This image carries no sampler (profraw_snapshotter.py is
                      # not installed) and the fuzz DUT is built WITHOUT
                      # use_coverage -- build_campaign_image.sh refuses one that
                      # has it. Restoring live sampling means rebuilding that DUT
                      # with use_coverage=true matter_fuzz_continuous_coverage=true,
                      # putting the sampler back, and accepting the comparability
                      # cost in this script's header.
                      echo "ERROR: --live is not supported by this image: the fuzz DUT" >&2
                      echo "       carries no profiling and no profraw sampler is installed." >&2
                      echo "       Use the default queue replay (--replay)." >&2
                      exit 2 ;;
    --no-coverage)    COV_MODE=none;          shift ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null || { echo "ERROR: docker required" >&2; exit 1; }
docker image inspect "${IMAGE}" >/dev/null 2>&1 || {
  echo "ERROR: image ${IMAGE} not found -- run build_campaign_image.sh" >&2; exit 1; }
[[ "${TRANSPORT}" == udp ]] || { echo "ERROR: Matter AFLNet campaign supports UDP only" >&2; exit 2; }
[[ "${SCOPE}" == clusters ]] || { echo "ERROR: the sole coverage scope is clusters (literal src/app/clusters/)" >&2; exit 2; }
[[ "${STORAGE_MODE}" == file || "${STORAGE_MODE}" == memory ]] || {
  echo "ERROR: --storage-mode must be file or memory" >&2; exit 2; }
for value in "${INSTANCES}" "${FUZZ_SECONDS}" "${DELAY_US}" "${POLL_MS}" "${INTERVAL}" "${REPLAY_WORKERS}"; do
  [[ "${value}" =~ ^[0-9]+$ ]] || { echo "ERROR: numeric arguments must be nonnegative integers" >&2; exit 2; }
done
(( INSTANCES > 0 && FUZZ_SECONDS > 0 && REPLAY_WORKERS > 0 )) || {
  echo "ERROR: instances, fuzz-seconds and replay-workers must be positive" >&2; exit 2; }
override_count=0
[[ -n "${SEEDS_DIR}" ]] && override_count=$((override_count + 1))
[[ -n "${DICT_PATH}" ]] && override_count=$((override_count + 1))
[[ -n "${MANIFEST_PATH}" ]] && override_count=$((override_count + 1))
[[ -n "${PROJECTION_PATH}" ]] && override_count=$((override_count + 1))
[[ -n "${FIDELITY_PATH}" ]] && override_count=$((override_count + 1))
[[ "${override_count}" -eq 0 || "${override_count}" -eq 5 ]] || {
  echo "ERROR: --seeds, --dict, --manifest, --projection and --fidelity must be supplied together" >&2; exit 2; }
# Docker bind mounts require an absolute host source.  The documented launchers
# commonly pass a repository-relative --out-dir, so canonicalize it before any
# directories are created or mount arguments are assembled.
OUT_DIR="$(realpath -m -- "${OUT_DIR}")"
[[ -d "${OUT_DIR}" ]] && { echo "ERROR: out dir exists: ${OUT_DIR}" >&2; exit 1; }
if [[ "${override_count}" -eq 5 ]]; then
  [[ -d "${SEEDS_DIR}" ]] || { echo "ERROR: seed dir missing: ${SEEDS_DIR}" >&2; exit 1; }
  [[ -f "${DICT_PATH}" ]] || { echo "ERROR: dictionary missing: ${DICT_PATH}" >&2; exit 1; }
  [[ -f "${MANIFEST_PATH}" ]] || { echo "ERROR: manifest missing: ${MANIFEST_PATH}" >&2; exit 1; }
  [[ -f "${PROJECTION_PATH}" ]] || { echo "ERROR: projection missing: ${PROJECTION_PATH}" >&2; exit 1; }
  [[ -f "${FIDELITY_PATH}" ]] || { echo "ERROR: fidelity missing: ${FIDELITY_PATH}" >&2; exit 1; }
fi

IMAGE_ID="$(docker image inspect "${IMAGE}" --format '{{.Id}}')"
mkdir -p "${OUT_DIR}/inputs" "${OUT_DIR}/provenance/llvm"
INPUT_SEEDS="${OUT_DIR}/inputs/seeds"
mkdir -p "${INPUT_SEEDS}"
NAMES=()
EXTRACT_CONTAINER=""
cleanup_current_run() {
  if [[ -n "${EXTRACT_CONTAINER}" ]]; then
    docker rm -f "${EXTRACT_CONTAINER}" >/dev/null 2>&1 || true
  fi
  for name in "${NAMES[@]}"; do docker rm -f "${name}" >/dev/null 2>&1 || true; done
}
trap cleanup_current_run EXIT INT TERM

EXTRACT_CONTAINER="$(docker create "${IMAGE_ID}")"
docker cp "${EXTRACT_CONTAINER}:/opt/fuzzer/aflnet-chip-all-clusters-app-fuzz" \
  "${OUT_DIR}/provenance/aflnet-chip-all-clusters-app-fuzz"
docker cp "${EXTRACT_CONTAINER}:/opt/fuzzer/aflnet-chip-all-clusters-app-cov" \
  "${OUT_DIR}/provenance/aflnet-chip-all-clusters-app-cov"
docker cp "${EXTRACT_CONTAINER}:/opt/fuzzer/cov-build-args.gn" \
  "${OUT_DIR}/provenance/cov-build-args.gn"
docker cp "${EXTRACT_CONTAINER}:/opt/fuzzer/aflnet-profgen.list" \
  "${OUT_DIR}/provenance/aflnet-profgen.list"
docker cp "${EXTRACT_CONTAINER}:/opt/fuzzer/target.zap" "${OUT_DIR}/provenance/target.zap"
docker cp "${EXTRACT_CONTAINER}:/opt/fuzzer/target.matter" "${OUT_DIR}/provenance/target.matter"
docker cp "${EXTRACT_CONTAINER}:/opt/llvm/llvm-profdata" "${OUT_DIR}/provenance/llvm/llvm-profdata"
docker cp "${EXTRACT_CONTAINER}:/opt/llvm/llvm-cov" "${OUT_DIR}/provenance/llvm/llvm-cov"
if [[ "${override_count}" -eq 0 ]]; then
  docker cp "${EXTRACT_CONTAINER}:/opt/fuzzer/seeds/." "${INPUT_SEEDS}/"
  docker cp "${EXTRACT_CONTAINER}:/opt/fuzzer/matter.dict" "${OUT_DIR}/inputs/matter.dict"
  docker cp "${EXTRACT_CONTAINER}:/opt/fuzzer/input-manifest.json" "${OUT_DIR}/inputs/manifest.json"
  docker cp "${EXTRACT_CONTAINER}:/opt/fuzzer/input-projection.json" "${OUT_DIR}/inputs/projection.json"
  docker cp "${EXTRACT_CONTAINER}:/opt/fuzzer/input-fidelity.json" "${OUT_DIR}/inputs/fidelity.json"
  SEED_SOURCE="image:${IMAGE_ID}"
else
  find "${SEEDS_DIR}" -maxdepth 1 -type f -name '*.raw' -exec cp --preserve=mode,timestamps {} "${INPUT_SEEDS}/" \;
  cp --preserve=mode,timestamps "${DICT_PATH}" "${OUT_DIR}/inputs/matter.dict"
  cp --preserve=mode,timestamps "${MANIFEST_PATH}" "${OUT_DIR}/inputs/manifest.json"
  cp --preserve=mode,timestamps "${PROJECTION_PATH}" "${OUT_DIR}/inputs/projection.json"
  cp --preserve=mode,timestamps "${FIDELITY_PATH}" "${OUT_DIR}/inputs/fidelity.json"
  SEED_SOURCE="host:${SEEDS_DIR}"
fi
docker rm "${EXTRACT_CONTAINER}" >/dev/null
EXTRACT_CONTAINER=""

python3 "${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/aflnet_input_bundle.py" verify \
  --seeds "${INPUT_SEEDS}" --dictionary "${OUT_DIR}/inputs/matter.dict" \
  --projection "${OUT_DIR}/inputs/projection.json" \
  --fidelity "${OUT_DIR}/inputs/fidelity.json" \
  --manifest "${OUT_DIR}/inputs/manifest.json"
SEED_COUNT="$(find "${INPUT_SEEDS}" -maxdepth 1 -type f -name '*.raw' | wc -l)"
[[ "${SEED_COUNT}" -gt 0 ]] || { echo "ERROR: no raw AFLNet seeds in input bundle" >&2; exit 1; }
FIRST_SEED="$(find "${INPUT_SEEDS}" -maxdepth 1 -type f -name '*.raw' -print -quit)"
DECLARED_LEN="$(od -An -tu4 -N4 "${FIRST_SEED}" | tr -d ' ')"
ACTUAL_LEN="$(stat -c%s "${FIRST_SEED}")"
if (( DECLARED_LEN + 4 == ACTUAL_LEN )); then
  echo "ERROR: UDP campaign requires bare datagrams; input bundle is TCP framed" >&2
  exit 1
fi
(
  cd "${INPUT_SEEDS}"
  find . -maxdepth 1 -type f -name '*.raw' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "${OUT_DIR}/inputs/seeds.sha256"

# A reused image must be bound to the exact mounted input bundle.  Otherwise a
# selected image can silently run full inputs (or the reverse) while retaining
# misleading image provenance labels.
SEED_SET_SHA="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["seed_set_sha256"])' \
  "${OUT_DIR}/inputs/manifest.json")"
DICT_SHA="$(sha256sum "${OUT_DIR}/inputs/matter.dict" | awk '{print $1}')"
MANIFEST_SHA="$(sha256sum "${OUT_DIR}/inputs/manifest.json" | awk '{print $1}')"
PROJECTION_SHA="$(sha256sum "${OUT_DIR}/inputs/projection.json" | awk '{print $1}')"
FIDELITY_SHA="$(sha256sum "${OUT_DIR}/inputs/fidelity.json" | awk '{print $1}')"
check_image_label() {
  local key="$1" expected="$2" actual
  actual="$(docker image inspect "${IMAGE_ID}" --format "{{index .Config.Labels \"${key}\"}}")"
  [[ -n "${actual}" && "${actual}" == "${expected}" ]] || {
    echo "ERROR: image label ${key}=${actual:-<missing>} does not match input ${expected}" >&2
    exit 1
  }
}
check_image_label aflnet.seed_count "${SEED_COUNT}"
check_image_label aflnet.seed_set_sha256 "${SEED_SET_SHA}"
check_image_label aflnet.dict_sha256 "${DICT_SHA}"
check_image_label aflnet.input_manifest_sha256 "${MANIFEST_SHA}"
check_image_label aflnet.input_projection_sha256 "${PROJECTION_SHA}"
check_image_label aflnet.input_fidelity_sha256 "${FIDELITY_SHA}"
check_image_label aflnet.storage_profiles file,memory
check_image_label aflnet.default_storage_mode file
check_image_label aflnet.storage_selection runtime
check_image_label aflnet.testcase_state_reset fork-snapshot
chmod -R a-w "${OUT_DIR}/inputs"

COV_ARGS_SHA="$(sha256sum "${OUT_DIR}/provenance/cov-build-args.gn" | awk '{print $1}')"
PROFGEN_LIST_SHA="$(sha256sum "${OUT_DIR}/provenance/aflnet-profgen.list" | awk '{print $1}')"
FUZZ_SHA="$(sha256sum "${OUT_DIR}/provenance/aflnet-chip-all-clusters-app-fuzz" | awk '{print $1}')"
COV_SHA="$(sha256sum "${OUT_DIR}/provenance/aflnet-chip-all-clusters-app-cov" | awk '{print $1}')"
TARGET_ZAP_SHA="$(sha256sum "${OUT_DIR}/provenance/target.zap" | awk '{print $1}')"
TARGET_MATTER_SHA="$(sha256sum "${OUT_DIR}/provenance/target.matter" | awk '{print $1}')"
check_image_label aflnet.fuzz_dut_sha256 "${FUZZ_SHA}"
check_image_label aflnet.cov_dut_sha256 "${COV_SHA}"
check_image_label aflnet.cov_args_sha256 "${COV_ARGS_SHA}"
check_image_label aflnet.profgen_list_sha256 "${PROFGEN_LIST_SHA}"
check_image_label aflnet.target_zap_sha256 "${TARGET_ZAP_SHA}"
check_image_label aflnet.target_matter_sha256 "${TARGET_MATTER_SHA}"
check_image_label aflnet.coverage_aggregator_sha256 \
  "$(sha256sum "${AGGREGATOR}" | awk '{print $1}')"

RUN_ID="$(basename "${OUT_DIR}")"
COV_DUT_IN_IMAGE=/opt/fuzzer/aflnet-chip-all-clusters-app-cov
# llvm-cov must read the profile with the SAME binary that produced it, and the
# only binary that produces one is the profgen replay DUT.
HOST_SCORING_DUT="${OUT_DIR}/provenance/aflnet-chip-all-clusters-app-cov"

{
  echo "started=$(date -Iseconds)"
  echo "image=${IMAGE}"
  echo "image_id=${IMAGE_ID}"
  echo "instances=${INSTANCES}"
  echo "fuzz_seconds=${FUZZ_SECONDS}"
  echo "cpu_quota=${CPUS}"
  echo "transport=${TRANSPORT}"
  echo "delay_us=${DELAY_US}"
  echo "poll_ms=${POLL_MS}"
  echo "calibrate=${CALIBRATE}"
  echo "fuzzing_clock=afl-process-wall-clock"
  echo "initial_seed_calibration_in_budget=1"
  echo "settle_parameter_probe_in_budget=0"
  echo "replica_model=independent"
  echo "rng_source=afl-dev-urandom"
  echo "rng_seed_control=unavailable"
  echo "snapshot_interval=${INTERVAL}"
  echo "replay_workers=${REPLAY_WORKERS}"
  echo "coverage_scope=${SCOPE}"
  echo "execution_mode=docker-netns-per-instance"
  echo "coverage_mode=${COV_MODE}"
  echo "storage_profile=${STORAGE_MODE}"
  echo "seed_source=${SEED_SOURCE}"
  echo "seed_count=${SEED_COUNT}"
  echo "network=none"
  echo "host=$(hostname)"
  echo "host_cpus=$(nproc)"
  echo "input_manifest_sha256=${MANIFEST_SHA}"
  echo "input_projection_sha256=${PROJECTION_SHA}"
  echo "input_fidelity_sha256=${FIDELITY_SHA}"
  echo "dictionary_sha256=${DICT_SHA}"
  echo "fuzz_binary_sha256=${FUZZ_SHA}"
  echo "scoring_binary_sha256=${COV_SHA}"
  echo "cov_build_args_sha256=${COV_ARGS_SHA}"
  echo "profgen_list_sha256=${PROFGEN_LIST_SHA}"
  echo "campaign_runner_sha256=$(sha256sum "${BASH_SOURCE[0]}" | awk '{print $1}')"
  echo "coverage_aggregator_sha256=$(sha256sum "${AGGREGATOR}" | awk '{print $1}')"
  echo "coverage_kind=saved_queue_replay"
  docker image inspect "${IMAGE_ID}" --format '{{range $k,$v := .Config.Labels}}{{$k}}={{$v}}
{{end}}' | sed '/^$/d'
} > "${OUT_DIR}/eval-meta.txt"
# The aggregator and the replay step resolve the coverage binary from this key.
echo "coverage_binary=${COV_DUT_IN_IMAGE}" >> "${OUT_DIR}/eval-meta.txt"

echo "[afl-docker] ${INSTANCES} instances x ${FUZZ_SECONDS}s -> ${OUT_DIR}"

for i in $(seq 1 "${INSTANCES}"); do
  idx="$(printf '%02d' "${i}")"
  inst="${OUT_DIR}/instance-${idx}"
  mkdir -p "${inst}"
  name="afl-${RUN_ID}-${idx}"
  cpu_arg=(); [[ -n "${CPUS}" ]] && cpu_arg=(--cpus "${CPUS}")
  docker run -d --init --name "${name}" \
    --network none \
    --user "$(id -u):$(id -g)" \
    "${cpu_arg[@]}" \
    -e FUZZ_SECONDS="${FUZZ_SECONDS}" -e DELAY_US="${DELAY_US}" \
    -e CALIBRATE="${CALIBRATE}" -e INSTANCE="instance-${idx}" \
    -e TRANSPORT="${TRANSPORT}" -e POLL_MS="${POLL_MS}" \
    -e STORAGE_MODE="${STORAGE_MODE}" \
    -e SNAPSHOT_INTERVAL="${INTERVAL}" \
    -e SEEDS_DIR=/workdir/seeds \
    -e DICT=/workdir/matter.dict -e INPUT_MANIFEST=/workdir/manifest.json \
    -e INPUT_PROJECTION=/workdir/projection.json -e INPUT_FIDELITY=/workdir/fidelity.json \
    -v "${INPUT_SEEDS}:/workdir/seeds:ro" \
    -v "${OUT_DIR}/inputs/matter.dict:/workdir/matter.dict:ro" \
    -v "${OUT_DIR}/inputs/manifest.json:/workdir/manifest.json:ro" \
    -v "${OUT_DIR}/inputs/projection.json:/workdir/projection.json:ro" \
    -v "${OUT_DIR}/inputs/fidelity.json:/workdir/fidelity.json:ro" \
    -v "${inst}:/workdir/output" \
    "${IMAGE_ID}" >/dev/null
  NAMES+=("${name}")
done
echo "[afl-docker] launched: ${#NAMES[@]} containers (docker ps --filter name=afl-${RUN_ID})"

# Wait for every container and preserve its exit status before removing it.
container_failures=0
for n in "${NAMES[@]}"; do
  rc="$(docker wait "${n}" 2>/dev/null || echo docker-wait-failed)"
  idx="${n##*-}"
  echo "container_exit=${rc}" >> "${OUT_DIR}/instance-${idx}/run.env"
  [[ "${rc}" == 0 ]] || container_failures=$((container_failures + 1))
  docker rm "${n}" >/dev/null 2>&1 || true
done
NAMES=()
echo "ended_fuzzing=$(date -Iseconds)" >> "${OUT_DIR}/eval-meta.txt"

ok=0; bad=0
for i in $(seq 1 "${INSTANCES}"); do
  idx="$(printf '%02d' "${i}")"
  if grep -q '^status=ok' "${OUT_DIR}/instance-${idx}/run.env" 2>/dev/null; then ok=$((ok+1)); else bad=$((bad+1)); fi
done
echo "[afl-docker] fuzzing done: ${ok} ok, ${bad} failed"
if (( bad > 0 || container_failures > 0 || ok != INSTANCES )); then
  echo "ERROR: ${bad} instance status failures, ${container_failures} container failures" >&2
  exit 1
fi

if [[ "${COV_MODE}" == "none" ]]; then
  echo "ended=$(date -Iseconds)" >> "${OUT_DIR}/eval-meta.txt"
  touch "${OUT_DIR}/.done"
  echo "[afl-docker] coverage skipped"; exit 0
fi

# Build the curve by replaying each instance's queue through the profgen DUT.
echo "[afl-docker] queue replay (interval=${INTERVAL}s)..."
  docker run --rm --init --network none \
    --user "$(id -u):$(id -g)" \
    --entrypoint python3 \
    -e PATH="/opt/llvm:/usr/bin:/bin" \
    -v "${OUT_DIR}:/campaign" \
    "${IMAGE_ID}" /opt/fuzzer/phase2_parallel.py \
      --eval-dir /campaign --cov-dut "${COV_DUT_IN_IMAGE}" \
      --interval "${INTERVAL}" --workers "${REPLAY_WORKERS}" \
    || { echo "ERROR: queue replay failed; retained per-seed diagnostics remain in ${OUT_DIR}" >&2; exit 1; }
for tl in "${OUT_DIR}"/instance-*/timeline.csv; do
  [[ -f "${tl}" ]] && sed -i "s#/campaign#${OUT_DIR}#g" "${tl}"
done

echo "[afl-docker] aggregating (scope=${SCOPE})..."
export PATH="${OUT_DIR}/provenance/llvm:${PATH}"
export DEBUGINFOD_URLS=""
if [[ -x "${HOST_SCORING_DUT}" ]]; then
  python3 "${AGGREGATOR}" --eval-dir "${OUT_DIR}" --binary "${HOST_SCORING_DUT}" --scope "${SCOPE}" \
    || { echo "ERROR: aggregation failed (scope=${SCOPE})" >&2; exit 1; }
else
  echo "ERROR: retained image coverage DUT missing (${HOST_SCORING_DUT})" >&2
  exit 1
fi

echo "ended=$(date -Iseconds)" >> "${OUT_DIR}/eval-meta.txt"
touch "${OUT_DIR}/.done"
echo "[afl-docker] done -> ${OUT_DIR}"
