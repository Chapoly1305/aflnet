#!/usr/bin/env bash
# Build the AFLNet Matter campaign runtime image.
#
# Created: 2026-09-06
# Purpose: stage only runtime artifacts (afl-fuzz, both DUTs, frozen seeds,
#          Phase-2 replay) into a small build context and record their hashes as
#          image labels, so a campaign is tied to exact binaries + seed corpus.
#          Mirrors examples/fuzzers/eclipsefuzz/hpc/build_docker_image.sh.
# Retention: PERMANENT (benchmark pipeline step)
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AFLNET_DIR="$(dirname "${SCRIPT_DIR}")"
# Default assumes aflnet/ sits at <repo>/examples/fuzzers/aflnet. That is wrong
# when this script runs from a git worktree of the submodule, where the path
# above resolves outside the EclipseFuzz tree and aflnet.repo_commit degrades
# to "unknown". Override with --repo-root in that case.
REPO_ROOT="$(cd "${AFLNET_DIR}/../../.." 2>/dev/null && pwd || echo "")"

IMAGE_TAG="aflnet-matter-campaign:local"
FUZZ_DUT="${REPO_ROOT}/out/aflnet-dut-fuzz/chip-all-clusters-app"
COV_DUT="${REPO_ROOT}/out/aflnet-dut-cov/chip-all-clusters-app"
SEED_DIR="${REPO_ROOT}/corpus/derived-afl"     # step3.1 output (UDP, timed acks)
DICT="${REPO_ROOT}/corpus/derived-afl.dict"   # built from those same seeds
MANIFEST="${REPO_ROOT}/corpus/derived-afl.manifest.json"
PROJECTION="${REPO_ROOT}/corpus/derived-afl.projection.json"
FIDELITY="${REPO_ROOT}/corpus/derived-afl.fidelity.json"
# The image must carry the SAME llvm-profdata/llvm-cov that built the cov DUT.
# Ubuntu's llvm-20 packages merged the profdata while the host aggregator read
# it with pigweed's LLVM 21, which produced "N functions have mismatched data".
LLVM_BIN="${REPO_ROOT}/.environment/cipd/packages/pigweed/bin"
PROFGEN_LIST="${SCRIPT_DIR}/aflnet-profgen.list"
NO_CACHE=0
ARCHIVE_IMAGE=1
BATCH_ID="${ECLIPSEFUZZ_BATCH_ID:-batch4}"
ARCHIVE_DIR=""
FUZZ_DUT_SET=0
COV_DUT_SET=0
SEEDS_SET=0
DICT_SET=0
MANIFEST_SET=0
PROJECTION_SET=0
FIDELITY_SET=0
LLVM_SET=0

usage() { cat <<'U'
Usage: build_campaign_image.sh [--tag TAG] [--fuzz-dut PATH] [--cov-dut PATH]
                               [--seeds DIR] [--dict PATH] [--manifest PATH]
                               [--projection PATH] [--fidelity PATH]
                               [--repo-root DIR] [--llvm-bin DIR]
                               [--no-cache] [--batch-id ID] [--archive-dir DIR] [--no-archive]
U
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)      IMAGE_TAG="${2:?}"; shift 2 ;;
    --fuzz-dut) FUZZ_DUT="${2:?}"; FUZZ_DUT_SET=1; shift 2 ;;
    --cov-dut)  COV_DUT="${2:?}"; COV_DUT_SET=1; shift 2 ;;
    --seeds)    SEED_DIR="${2:?}"; SEEDS_SET=1; shift 2 ;;
    --dict)     DICT="${2:?}"; DICT_SET=1; shift 2 ;;
    --manifest) MANIFEST="${2:?}"; MANIFEST_SET=1; shift 2 ;;
    --projection) PROJECTION="${2:?}"; PROJECTION_SET=1; shift 2 ;;
    --fidelity) FIDELITY="${2:?}"; FIDELITY_SET=1; shift 2 ;;
    --repo-root) REPO_ROOT="${2:?}"; shift 2 ;;
    --llvm-bin) LLVM_BIN="${2:?}"; LLVM_SET=1; shift 2 ;;
    --no-cache) NO_CACHE=1; shift ;;
    --batch-id) BATCH_ID="${2:?}"; shift 2 ;;
    --archive-dir) ARCHIVE_DIR="${2:?}"; shift 2 ;;
    --no-archive) ARCHIVE_IMAGE=0; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "${FUZZ_DUT_SET}" -eq 1 ]] || FUZZ_DUT="${REPO_ROOT}/out/aflnet-dut-fuzz/chip-all-clusters-app"
[[ "${COV_DUT_SET}" -eq 1 ]] || COV_DUT="${REPO_ROOT}/out/aflnet-dut-cov/chip-all-clusters-app"
[[ "${SEEDS_SET}" -eq 1 ]] || SEED_DIR="${REPO_ROOT}/corpus/derived-afl"
[[ "${DICT_SET}" -eq 1 ]] || DICT="${REPO_ROOT}/corpus/derived-afl.dict"
[[ "${MANIFEST_SET}" -eq 1 ]] || MANIFEST="${REPO_ROOT}/corpus/derived-afl.manifest.json"
[[ "${PROJECTION_SET}" -eq 1 ]] || PROJECTION="${REPO_ROOT}/corpus/derived-afl.projection.json"
[[ "${FIDELITY_SET}" -eq 1 ]] || FIDELITY="${REPO_ROOT}/corpus/derived-afl.fidelity.json"
[[ "${LLVM_SET}" -eq 1 ]] || LLVM_BIN="${REPO_ROOT}/.environment/cipd/packages/pigweed/bin"

command -v docker >/dev/null || { echo "ERROR: docker required" >&2; exit 1; }
[[ -x "${FUZZ_DUT}" ]] || { echo "ERROR: fuzz DUT missing: ${FUZZ_DUT}" >&2; exit 1; }
[[ -x "${COV_DUT}"  ]] || { echo "ERROR: cov DUT missing: ${COV_DUT}" >&2; exit 1; }
[[ -x "${AFLNET_DIR}/afl-fuzz" ]] || { echo "ERROR: afl-fuzz not built: run make -C ${AFLNET_DIR}" >&2; exit 1; }
[[ -f "${DICT}" ]] || { echo "ERROR: dictionary missing: ${DICT}" >&2; exit 1; }
[[ -f "${MANIFEST}" ]] || { echo "ERROR: input manifest missing: ${MANIFEST}" >&2; exit 1; }
[[ -f "${PROJECTION}" ]] || { echo "ERROR: projection evidence missing: ${PROJECTION}" >&2; exit 1; }
[[ -f "${FIDELITY}" ]] || { echo "ERROR: fidelity evidence missing: ${FIDELITY}" >&2; exit 1; }
[[ -f "${PROFGEN_LIST}" ]] || { echo "ERROR: profgen list missing: ${PROFGEN_LIST}" >&2; exit 1; }
python3 "${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/aflnet_input_bundle.py" verify \
  --seeds "${SEED_DIR}" --dictionary "${DICT}" --projection "${PROJECTION}" \
  --fidelity "${FIDELITY}" --manifest "${MANIFEST}"
n_seeds=$(find "${SEED_DIR}" -maxdepth 1 -name '*.raw' 2>/dev/null | wc -l)
[[ "${n_seeds}" -gt 0 ]] || { echo "ERROR: no .raw seeds under ${SEED_DIR}" >&2; exit 1; }
# Seeds must carry the framing the campaign transport expects. A TCP seed starts
# with its own 4-byte little-endian length; a UDP seed starts with the Matter
# message header, whose first byte is the message flags (0x00 for our exporter).
# Mixing them is silent: AFLNet would send unframed bytes down a stream socket
# and every run would look like an unresponsive server.
# -print -quit, not `| head -1`: head exits after one line, find dies of SIGPIPE,
# and under `set -o pipefail` that fails the assignment and `set -e` kills the
# script silently. Same trap as the nm|grep -q preflight above.
first_seed=$(find "${SEED_DIR}" -maxdepth 1 -name '*.raw' -print -quit)
declared=$(od -An -tu4 -N4 "${first_seed}" 2>/dev/null | tr -d ' ')
actual=$(stat -c%s "${first_seed}")
if [[ -n "${declared}" ]] && (( declared + 4 == actual )); then
  SEED_TRANSPORT=tcp
else
  SEED_TRANSPORT=udp
fi

# The fuzz DUT must actually be AFL-instrumented; a plain build links and runs
# but yields an all-zero bitmap, which only shows up hours into a campaign.
# NOTE: read each tool's output into a variable first. Piping into `grep -q`
# under `set -o pipefail` reports failure even on a match, because grep exits
# early and the producer dies of SIGPIPE.
fuzz_syms="$(nm -C "${FUZZ_DUT}" 2>/dev/null || true)"
for sym in __afl_area_ptr __afl_manual_init __sanitizer_cov_trace_pc_guard; do
  grep -qw -- "${sym}" <<<"${fuzz_syms}" || {
    echo "ERROR: ${FUZZ_DUT} lacks ${sym} -- rebuild with \
matter_fuzz_dut_transport=true matter_fuzz_afl_instrument=true" >&2; exit 1; }
done
# And it must NOT carry coverage-measurement instrumentation. Coverage comes
# from replaying the queue against COV_DUT (the ProFuzzBench design), so
# profiling the fuzz DUT only costs throughput the compared in-process fuzzer
# does not pay, and makes the two systems' llvm-cov denominators diverge.
# __llvm_profile_counter_bias is the tell for -fprofile-continuous;
# __llvm_profile_write_file for use_coverage=true.
for sym in __llvm_profile_counter_bias __llvm_profile_write_file; do
  grep -qw -- "${sym}" <<<"${fuzz_syms}" && {
    echo "ERROR: ${FUZZ_DUT} carries ${sym} -- the fuzz DUT must be built WITHOUT \
use_coverage / matter_fuzz_continuous_coverage. Coverage is measured by replaying \
the queue against the cov DUT; see run_docker_campaign.sh header." >&2; exit 1; }
done
fuzz_strings="$(strings -a "${FUZZ_DUT}" 2>/dev/null | grep -c 'SIG_AFL_DEFER_FORKSRV' || true)"
[[ "${fuzz_strings}" -gt 0 ]] || {
  echo "ERROR: ${FUZZ_DUT} has no deferred-forkserver marker" >&2; exit 1; }
cov_syms="$(nm -C "${COV_DUT}" 2>/dev/null || true)"
grep -qw -- __llvm_profile_write_file <<<"${cov_syms}" || {
  echo "ERROR: ${COV_DUT} is not a profgen build" >&2; exit 1; }
# The cov DUT must be built with -funique-internal-linkage-names. Without it,
# internal-linkage PGO names are "<file basename>:<mangled>" and the SDK's 20
# same-named CodegenIntegration.cpp anonymous-namespace delegates collide, so
# llvm-cov silently drops those records ("N functions have mismatched data").
#
# Checked against the build dir's args.gn, NOT the binary: the .__uniq.<hash>
# suffix the flag appends lives only in the PGO names, which sit zlib-compressed
# in __llvm_prf_names -- nm, strings and readelf all find nothing (verified).
cov_args="$(dirname "${COV_DUT}")/args.gn"
if [[ -f "${cov_args}" ]]; then
  grep -q 'unique-internal-linkage-names' "${cov_args}" || {
    echo "ERROR: ${COV_DUT} was built without -funique-internal-linkage-names \
(checked ${cov_args}). Rebuild with \
target_cflags=[\"-funique-internal-linkage-names\"] -- see matter/README.md." >&2; exit 1; }
  grep -q 'profile-list=.*aflnet-profgen.list' "${cov_args}" || {
    echo "ERROR: ${COV_DUT} retains known dead coverage mappings (checked \
${cov_args}). Rebuild with step3.5 --aflnet-only; llvm-cov would otherwise \
report three profile/object mismatches before cluster-scope aggregation." >&2; exit 1; }
else
  echo "ERROR: no args.gn beside ${COV_DUT}; cannot verify the coverage \
instrumentation or retain its build provenance" >&2
  exit 1
fi
for t in llvm-profdata llvm-cov; do
  [[ -x "${LLVM_BIN}/${t}" ]] || { echo "ERROR: ${LLVM_BIN}/${t} missing -- pass --llvm-bin \
(or --repo-root) pointing at the toolchain that built the cov DUT" >&2; exit 1; }
done
LLVM_VER="$("${LLVM_BIN}/llvm-profdata" --version | head -1 | sed 's/^ *//')"

sha() { sha256sum "$1" | cut -d' ' -f1; }
target_value() {
  local file="$1" key="$2"
  awk -F= -v key="${key}" '$1 == key {print substr($0, length(key) + 2); exit}' "${file}"
}
FUZZ_TARGET_ENV="$(dirname "${FUZZ_DUT}")/target-zap.env"
COV_TARGET_ENV="$(dirname "${COV_DUT}")/target-zap.env"
[[ -f "${FUZZ_TARGET_ENV}" && -f "${COV_TARGET_ENV}" ]] || {
  echo "ERROR: fuzz/cov DUT target-zap.env missing; rebuild with step3.5" >&2; exit 1; }
TARGET_ZAP_SHA="$(target_value "${FUZZ_TARGET_ENV}" target_zap_sha256)"
TARGET_MATTER_SHA="$(target_value "${FUZZ_TARGET_ENV}" target_matter_sha256)"
[[ -n "${TARGET_ZAP_SHA}" && -n "${TARGET_MATTER_SHA}" && \
   "${TARGET_ZAP_SHA}" == "$(target_value "${COV_TARGET_ENV}" target_zap_sha256)" && \
   "${TARGET_MATTER_SHA}" == "$(target_value "${COV_TARGET_ENV}" target_matter_sha256)" ]] || {
  echo "ERROR: fuzz and coverage DUTs use different target ZAP/Matter inputs" >&2; exit 1; }
for directory in "$(dirname "${FUZZ_DUT}")" "$(dirname "${COV_DUT}")"; do
  [[ "$(sha "${directory}/target.zap")" == "${TARGET_ZAP_SHA}" && \
     "$(sha "${directory}/target.matter")" == "${TARGET_MATTER_SHA}" ]] || {
    echo "ERROR: target snapshot/hash mismatch under ${directory}" >&2; exit 1; }
done

STAGE="$(mktemp -d /tmp/aflnet-campaign-img-XXXXXX)"
trap 'rm -rf -- "${STAGE}"' EXIT

mkdir -p "${STAGE}/aflnet" "${STAGE}/seeds" "${STAGE}/llvm"
cp "${LLVM_BIN}/llvm-profdata" "${LLVM_BIN}/llvm-cov" "${STAGE}/llvm/"
for f in afl-fuzz afl-showmap afl-tmin aflnet-replay afl-replay; do
  [[ -f "${AFLNET_DIR}/${f}" ]] && cp "${AFLNET_DIR}/${f}" "${STAGE}/aflnet/"
done
cp "${FUZZ_DUT}" "${STAGE}/aflnet-chip-all-clusters-app-fuzz"
cp "${COV_DUT}"  "${STAGE}/aflnet-chip-all-clusters-app-cov"
cp "${cov_args}" "${STAGE}/cov-build-args.gn"
cp "${PROFGEN_LIST}" "${STAGE}/aflnet-profgen.list"
cp "$(dirname "${COV_DUT}")/target.zap" "${STAGE}/target.zap"
cp "$(dirname "${COV_DUT}")/target.matter" "${STAGE}/target.matter"
find "${SEED_DIR}" -maxdepth 1 -name '*.raw' -exec cp {} "${STAGE}/seeds/" \;
cp "${SCRIPT_DIR}/entrypoint.sh" "${SCRIPT_DIR}/phase2_parallel.py" \
   "${SCRIPT_DIR}/replay_worker.py" "${SCRIPT_DIR}/replay_snapshots.py" "${STAGE}/"
cp "${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/aggregate_coverage_over_time.py" \
   "${STAGE}/aggregate_coverage_over_time.py"
cp "${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/aflnet_input_bundle.py" \
   "${STAGE}/validate_input_bundle.py"
cp "${DICT}" "${STAGE}/matter.dict"
cp "${MANIFEST}" "${STAGE}/input-manifest.json"
cp "${PROJECTION}" "${STAGE}/input-projection.json"
cp "${FIDELITY}" "${STAGE}/input-fidelity.json"
cp "${SCRIPT_DIR}/Dockerfile.campaign" "${STAGE}/Dockerfile"

SEED_SHA="$(cd "${STAGE}/seeds" && sha256sum -- ./*.raw | sed 's#  \./#  #' | sort -k2 | sha256sum | cut -d' ' -f1)"

echo "[build] staging: fuzz_dut=$(sha "${STAGE}/aflnet-chip-all-clusters-app-fuzz" | cut -c1-12) "\
     "cov_dut=$(sha "${STAGE}/aflnet-chip-all-clusters-app-cov" | cut -c1-12) seeds=${n_seeds}/${SEED_SHA:0:12}"

BUILD_ARGS=(--tag "${IMAGE_TAG}"
  --label "aflnet.fuzz_dut_sha256=$(sha "${STAGE}/aflnet-chip-all-clusters-app-fuzz")"
  --label "aflnet.cov_dut_sha256=$(sha "${STAGE}/aflnet-chip-all-clusters-app-cov")"
  --label "aflnet.cov_args_sha256=$(sha "${STAGE}/cov-build-args.gn")"
  --label "aflnet.profgen_list_sha256=$(sha "${STAGE}/aflnet-profgen.list")"
  --label "aflnet.afl_fuzz_sha256=$(sha "${STAGE}/aflnet/afl-fuzz")"
  --label "aflnet.seed_count=${n_seeds}"
  --label "aflnet.seed_set_sha256=${SEED_SHA}"
  --label "aflnet.seed_transport=${SEED_TRANSPORT}"
  --label "aflnet.input_manifest_sha256=$(sha "${STAGE}/input-manifest.json")"
  --label "aflnet.input_projection_sha256=$(sha "${STAGE}/input-projection.json")"
  --label "aflnet.input_fidelity_sha256=$(sha "${STAGE}/input-fidelity.json")"
  --label "aflnet.dict_sha256=$(sha "${STAGE}/matter.dict")"
  --label "aflnet.dict_tokens=$(grep -c '=' "${DICT}")"
  --label "aflnet.profdata_sha256=$(sha "${STAGE}/llvm/llvm-profdata")"
  --label "aflnet.llvm_cov_sha256=$(sha "${STAGE}/llvm/llvm-cov")"
  --label "aflnet.entrypoint_sha256=$(sha "${STAGE}/entrypoint.sh")"
  --label "aflnet.phase2_sha256=$(sha "${STAGE}/phase2_parallel.py")"
  --label "aflnet.replay_worker_sha256=$(sha "${STAGE}/replay_worker.py")"
  --label "aflnet.replay_snapshots_sha256=$(sha "${STAGE}/replay_snapshots.py")"
  --label "aflnet.coverage_aggregator_sha256=$(sha "${STAGE}/aggregate_coverage_over_time.py")"
  --label "aflnet.input_validator_sha256=$(sha "${STAGE}/validate_input_bundle.py")"
  --label "aflnet.coverage_kind=saved_queue_replay"
  --label "aflnet.raw_profile_retention=content_addressed"
  --label "aflnet.snapshot_merge_inputs=profraw"
  --label "aflnet.storage_profiles=file,memory"
  --label "aflnet.default_storage_mode=file"
  --label "aflnet.storage_selection=runtime"
  --label "aflnet.file_storage_delegate=linux-file-backed"
  --label "aflnet.memory_storage_delegate=test-in-memory"
  --label "aflnet.testcase_state_reset=fork-snapshot"
  --label "aflnet.target_zap_sha256=${TARGET_ZAP_SHA}"
  --label "aflnet.target_matter_sha256=${TARGET_MATTER_SHA}"
  --label "aflnet.llvm_version=${LLVM_VER}"
  --label "aflnet.repo_commit=$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  # The AFLNet commit is the provenance that matters for the baseline: which
  # upstream AFLNet, plus our -P MATTER parser on top.
  --label "aflnet.aflnet_commit=$(git -C "${AFLNET_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"
  --label "aflnet.aflnet_upstream_base=$(git -C "${AFLNET_DIR}" rev-parse --short 62d63a5 2>/dev/null || echo unknown)")
[[ "${NO_CACHE}" -eq 1 ]] && BUILD_ARGS+=(--no-cache)

docker build "${BUILD_ARGS[@]}" "${STAGE}"
if [[ "${ARCHIVE_IMAGE}" -eq 1 ]]; then
  archive_args=(--image "${IMAGE_TAG}" --batch-id "${BATCH_ID}")
  [[ -z "${ARCHIVE_DIR}" ]] || archive_args+=(--archive-dir "${ARCHIVE_DIR}")
  "${REPO_ROOT}/examples/fuzzers/eclipsefuzz/hpc/archive_docker_image.sh" "${archive_args[@]}"
fi
echo "[build] built ${IMAGE_TAG}"
docker image inspect "${IMAGE_TAG}" --format '{{range $k,$v := .Config.Labels}}  {{$k}}={{$v}}
{{end}}'
