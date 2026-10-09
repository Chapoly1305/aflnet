#!/usr/bin/env bash
# Build a fuzz-only AFLNet Matter image. Python is used on the build host to
# validate the input bundle; no Python or coverage tooling enters the image.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AFLNET_DIR="$(dirname "${SCRIPT_DIR}")"
REPO_ROOT="$(cd "${AFLNET_DIR}/../../.." && pwd)"

IMAGE_TAG=aflnet-matter-campaign:local
CORPUS_VARIANT=""
FUZZ_DUT="${REPO_ROOT}/out/aflnet-dut-fuzz/chip-all-clusters-app"
SEED_DIR="${REPO_ROOT}/corpus/derived-afl"
DICT="${REPO_ROOT}/corpus/derived-afl.dict"
MANIFEST="${REPO_ROOT}/corpus/derived-afl.manifest.json"
PROJECTION="${REPO_ROOT}/corpus/derived-afl.projection.json"
FIDELITY="${REPO_ROOT}/corpus/derived-afl.fidelity.json"
NO_CACHE=0
ARCHIVE_IMAGE=1
BATCH_ID="${ECLIPSEFUZZ_BATCH_ID:-batch4}"
ARCHIVE_DIR=""
FUZZ_DUT_SET=0
SEEDS_SET=0
DICT_SET=0
MANIFEST_SET=0
PROJECTION_SET=0
FIDELITY_SET=0

usage() {
  echo "Usage: build_campaign_image.sh [--tag TAG] [--corpus-variant selected10|full]"
  echo "       [--fuzz-dut PATH] [--seeds DIR] [--dict FILE]"
  echo "       [--manifest FILE] [--projection FILE] [--fidelity FILE]"
  echo "       [--repo-root DIR] [--no-cache] [--no-archive]"
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) IMAGE_TAG="${2:?}"; shift 2 ;;
    --corpus-variant) CORPUS_VARIANT="${2:?}"; shift 2 ;;
    --fuzz-dut) FUZZ_DUT="${2:?}"; FUZZ_DUT_SET=1; shift 2 ;;
    --seeds) SEED_DIR="${2:?}"; SEEDS_SET=1; shift 2 ;;
    --dict) DICT="${2:?}"; DICT_SET=1; shift 2 ;;
    --manifest) MANIFEST="${2:?}"; MANIFEST_SET=1; shift 2 ;;
    --projection) PROJECTION="${2:?}"; PROJECTION_SET=1; shift 2 ;;
    --fidelity) FIDELITY="${2:?}"; FIDELITY_SET=1; shift 2 ;;
    --repo-root) REPO_ROOT="${2:?}"; shift 2 ;;
    --no-cache) NO_CACHE=1; shift ;;
    --batch-id) BATCH_ID="${2:?}"; shift 2 ;;
    --archive-dir) ARCHIVE_DIR="${2:?}"; shift 2 ;;
    --no-archive) ARCHIVE_IMAGE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "${FUZZ_DUT_SET}" == 1 ]] || FUZZ_DUT="${REPO_ROOT}/out/aflnet-dut-fuzz/chip-all-clusters-app"
[[ "${SEEDS_SET}" == 1 ]] || SEED_DIR="${REPO_ROOT}/corpus/derived-afl"
[[ "${DICT_SET}" == 1 ]] || DICT="${REPO_ROOT}/corpus/derived-afl.dict"
[[ "${MANIFEST_SET}" == 1 ]] || MANIFEST="${REPO_ROOT}/corpus/derived-afl.manifest.json"
[[ "${PROJECTION_SET}" == 1 ]] || PROJECTION="${REPO_ROOT}/corpus/derived-afl.projection.json"
[[ "${FIDELITY_SET}" == 1 ]] || FIDELITY="${REPO_ROOT}/corpus/derived-afl.fidelity.json"

command -v docker >/dev/null || { echo "ERROR: docker required" >&2; exit 1; }
[[ -x "${FUZZ_DUT}" ]] || { echo "ERROR: fuzz DUT missing: ${FUZZ_DUT}" >&2; exit 1; }
[[ -x "${AFLNET_DIR}/afl-fuzz" ]] || { echo "ERROR: afl-fuzz missing" >&2; exit 1; }
for path in "${DICT}" "${MANIFEST}" "${PROJECTION}" "${FIDELITY}"; do
  [[ -f "${path}" ]] || { echo "ERROR: input artifact missing: ${path}" >&2; exit 1; }
done
python3 "${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/aflnet_input_bundle.py" verify \
  --seeds "${SEED_DIR}" --dictionary "${DICT}" --projection "${PROJECTION}" \
  --fidelity "${FIDELITY}" --manifest "${MANIFEST}"

seed_count="$(find "${SEED_DIR}" -maxdepth 1 -type f -name '*.raw' -printf '.\n' | wc -l)"
if [[ -z "${CORPUS_VARIANT}" ]]; then
  [[ "${seed_count}" == 10 ]] && CORPUS_VARIANT=selected10 || CORPUS_VARIANT=full
fi
case "${CORPUS_VARIANT}" in
  selected10) [[ "${seed_count}" == 10 ]] || { echo "ERROR: selected10 requires 10 seeds" >&2; exit 1; } ;;
  full) (( seed_count > 10 )) || { echo "ERROR: full requires more than 10 seeds" >&2; exit 1; } ;;
  *) echo "ERROR: invalid corpus variant: ${CORPUS_VARIANT}" >&2; exit 2 ;;
esac

fuzz_symbols="$(nm -C "${FUZZ_DUT}" 2>/dev/null || true)"
for symbol in __afl_area_ptr __afl_manual_init __sanitizer_cov_trace_pc_guard; do
  grep -qw -- "${symbol}" <<<"${fuzz_symbols}" || {
    echo "ERROR: fuzz DUT lacks ${symbol}" >&2
    exit 1
  }
done
for symbol in __llvm_profile_counter_bias __llvm_profile_write_file; do
  if grep -qw -- "${symbol}" <<<"${fuzz_symbols}"; then
    echo "ERROR: fuzz DUT contains coverage instrumentation: ${symbol}" >&2
    exit 1
  fi
done

sha() { sha256sum "$1" | awk '{print $1}'; }
stage="$(mktemp -d /tmp/aflnet-fuzz-image-XXXXXX)"
trap 'rm -rf -- "${stage}"' EXIT
mkdir -p "${stage}/seeds"
cp "${AFLNET_DIR}/afl-fuzz" "${stage}/afl-fuzz"
cp "${FUZZ_DUT}" "${stage}/aflnet-chip-all-clusters-app-fuzz"
find "${SEED_DIR}" -maxdepth 1 -type f -name '*.raw' -exec cp {} "${stage}/seeds/" \;
cp "${DICT}" "${stage}/matter.dict"
cp "${SCRIPT_DIR}/entrypoint.sh" "${SCRIPT_DIR}/snapshot.sh" "${stage}/"
cp "${SCRIPT_DIR}/Dockerfile.campaign" "${stage}/Dockerfile"
chmod +x "${stage}/entrypoint.sh" "${stage}/snapshot.sh"

(
  cd "${stage}"
  sha256sum afl-fuzz | sed 's#  afl-fuzz$#  ../aflnet/afl-fuzz#' > runtime.sha256
  sha256sum aflnet-chip-all-clusters-app-fuzz matter.dict \
    entrypoint.sh snapshot.sh >> runtime.sha256
  find seeds -maxdepth 1 -type f -name '*.raw' -print0 | LC_ALL=C sort -z | \
    xargs -0 sha256sum >> runtime.sha256
)
seed_set_sha256="$(cd "${stage}/seeds" && sha256sum -- ./*.raw | sed 's#  \./#  #' | LC_ALL=C sort -k2 | sha256sum | awk '{print $1}')"
manifest_sha256="$(sha "${MANIFEST}")"

build_args=(
  --tag "${IMAGE_TAG}"
  --label "aflnet.image_role=fuzz-only"
  --label "aflnet.corpus_variant=${CORPUS_VARIANT}"
  --label "aflnet.seed_count=${seed_count}"
  --label "aflnet.seed_set_sha256=${seed_set_sha256}"
  --label "aflnet.input_manifest_sha256=${manifest_sha256}"
  --label "aflnet.dict_sha256=$(sha "${DICT}")"
  --label "aflnet.afl_fuzz_sha256=$(sha "${AFLNET_DIR}/afl-fuzz")"
  --label "aflnet.fuzz_dut_sha256=$(sha "${FUZZ_DUT}")"
  --label "aflnet.entrypoint_sha256=$(sha "${SCRIPT_DIR}/entrypoint.sh")"
  --label "aflnet.snapshot_sha256=$(sha "${SCRIPT_DIR}/snapshot.sh")"
  --label "aflnet.storage_mode=file"
  --label "aflnet.postprocessing=external"
  --label "aflnet.aflnet_commit=$(git -C "${AFLNET_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"
  --label "aflnet.repo_commit=$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
)
[[ "${NO_CACHE}" == 1 ]] && build_args+=(--no-cache)
docker build "${build_args[@]}" "${stage}"

if [[ "${ARCHIVE_IMAGE}" == 1 ]]; then
  archive_args=(--image "${IMAGE_TAG}" --batch-id "${BATCH_ID}")
  [[ -z "${ARCHIVE_DIR}" ]] || archive_args+=(--archive-dir "${ARCHIVE_DIR}")
  "${REPO_ROOT}/examples/fuzzers/eclipsefuzz/hpc/archive_docker_image.sh" "${archive_args[@]}"
fi
echo "[build] built fuzz-only image ${IMAGE_TAG}: ${CORPUS_VARIANT}, ${seed_count} seeds"
