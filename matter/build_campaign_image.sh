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
REPO_ROOT="$(cd "${AFLNET_DIR}/../../.." && pwd)"

IMAGE_TAG="aflnet-matter-campaign:local"
FUZZ_DUT="${REPO_ROOT}/out/aflnet-dut-fuzz/chip-all-clusters-app"
COV_DUT="${REPO_ROOT}/out/aflnet-dut-cov/chip-all-clusters-app"
SEED_DIR="${REPO_ROOT}/out/aflnet-seeds-tcp-20260908"
NO_CACHE=0

usage() { cat <<'U'
Usage: build_campaign_image.sh [--tag TAG] [--fuzz-dut PATH] [--cov-dut PATH]
                               [--seeds DIR] [--no-cache]
U
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)      IMAGE_TAG="${2:?}"; shift 2 ;;
    --fuzz-dut) FUZZ_DUT="${2:?}";  shift 2 ;;
    --cov-dut)  COV_DUT="${2:?}";   shift 2 ;;
    --seeds)    SEED_DIR="${2:?}";  shift 2 ;;
    --no-cache) NO_CACHE=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null || { echo "ERROR: docker required" >&2; exit 1; }
[[ -x "${FUZZ_DUT}" ]] || { echo "ERROR: fuzz DUT missing: ${FUZZ_DUT}" >&2; exit 1; }
[[ -x "${COV_DUT}"  ]] || { echo "ERROR: cov DUT missing: ${COV_DUT}" >&2; exit 1; }
[[ -x "${AFLNET_DIR}/afl-fuzz" ]] || { echo "ERROR: afl-fuzz not built: run make -C ${AFLNET_DIR}" >&2; exit 1; }
n_seeds=$(find "${SEED_DIR}" -maxdepth 1 -name '*.raw' 2>/dev/null | wc -l)
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
[[ "${n_seeds}" -gt 0 ]] || { echo "ERROR: no .raw seeds under ${SEED_DIR}" >&2; exit 1; }

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

STAGE="$(mktemp -d /tmp/aflnet-campaign-img-XXXXXX)"
trap 'rm -rf -- "${STAGE}"' EXIT

mkdir -p "${STAGE}/aflnet" "${STAGE}/seeds"
for f in afl-fuzz afl-showmap afl-tmin aflnet-replay afl-replay; do
  [[ -f "${AFLNET_DIR}/${f}" ]] && cp "${AFLNET_DIR}/${f}" "${STAGE}/aflnet/"
done
cp "${FUZZ_DUT}" "${STAGE}/aflnet-chip-all-clusters-app-fuzz"
cp "${COV_DUT}"  "${STAGE}/aflnet-chip-all-clusters-app-cov"
find "${SEED_DIR}" -maxdepth 1 -name '*.raw' -exec cp {} "${STAGE}/seeds/" \;
cp "${SCRIPT_DIR}/entrypoint.sh" "${SCRIPT_DIR}/phase2_parallel.py" "${STAGE}/"
[[ -f "${SCRIPT_DIR}/matter.dict" ]] || { echo "ERROR: matter.dict missing -- run generate_matter_aflnet_dict.py" >&2; exit 1; }
cp "${SCRIPT_DIR}/matter.dict" "${STAGE}/"
cp "${SCRIPT_DIR}/Dockerfile.campaign" "${STAGE}/Dockerfile"

sha() { sha256sum "$1" | cut -d' ' -f1; }
SEED_SHA="$(cd "${STAGE}/seeds" && sha256sum *.raw | sort -k2 | sha256sum | cut -d' ' -f1)"

echo "[build] staging: fuzz_dut=$(sha "${STAGE}/aflnet-chip-all-clusters-app-fuzz" | cut -c1-12) "\
     "cov_dut=$(sha "${STAGE}/aflnet-chip-all-clusters-app-cov" | cut -c1-12) seeds=${n_seeds}/${SEED_SHA:0:12}"

BUILD_ARGS=(--tag "${IMAGE_TAG}"
  --label "aflnet.fuzz_dut_sha256=$(sha "${STAGE}/aflnet-chip-all-clusters-app-fuzz")"
  --label "aflnet.cov_dut_sha256=$(sha "${STAGE}/aflnet-chip-all-clusters-app-cov")"
  --label "aflnet.afl_fuzz_sha256=$(sha "${STAGE}/aflnet/afl-fuzz")"
  --label "aflnet.seed_count=${n_seeds}"
  --label "aflnet.seed_set_sha256=${SEED_SHA}"
  --label "aflnet.seed_transport=${SEED_TRANSPORT}"
  --label "aflnet.dict_tokens=$(grep -c '=' "${SCRIPT_DIR}/matter.dict")"
  --label "aflnet.repo_commit=$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
  # The AFLNet commit is the provenance that matters for the baseline: which
  # upstream AFLNet, plus our -P MATTER parser on top.
  --label "aflnet.aflnet_commit=$(git -C "${AFLNET_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"
  --label "aflnet.aflnet_upstream_base=$(git -C "${AFLNET_DIR}" rev-parse --short 62d63a5 2>/dev/null || echo unknown)")
[[ "${NO_CACHE}" -eq 1 ]] && BUILD_ARGS+=(--no-cache)

docker build "${BUILD_ARGS[@]}" "${STAGE}"
echo "[build] built ${IMAGE_TAG}"
docker image inspect "${IMAGE_TAG}" --format '{{range $k,$v := .Config.Labels}}  {{$k}}={{$v}}
{{end}}'
