#!/usr/bin/env bash
# Convert one frozen AFLNet fuzz-only Docker archive into a validated Hopper
# SIF. The archive is copied and expanded on node-local storage; only the final
# SIF and its compact evidence are published to /scratch.
#
# Required sbatch exports:
#   AF_DOCKER_ARCHIVE, AF_DOCKER_ARCHIVE_SHA256, AF_IMAGE_ROOT, AF_SIF_NAME
#   AF_CORPUS_VARIANT=selected10|full, AF_SEED_COUNT
#SBATCH --job-name=aflnet-sif-build
#SBATCH --partition=normal
#SBATCH --constraint=amd
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=16G
#SBATCH --time=00:20:00

set -euo pipefail

readonly APPTAINER="${AF_APPTAINER:-/opt/sw/other/apps/apptainer/1.4.1/bin/apptainer}"
readonly DOCKER_ARCHIVE="${AF_DOCKER_ARCHIVE:?export AF_DOCKER_ARCHIVE}"
readonly DOCKER_ARCHIVE_SHA256="${AF_DOCKER_ARCHIVE_SHA256:?export AF_DOCKER_ARCHIVE_SHA256}"
readonly IMAGE_ROOT="${AF_IMAGE_ROOT:?export AF_IMAGE_ROOT}"
readonly SIF_NAME="${AF_SIF_NAME:?export AF_SIF_NAME}"
readonly CORPUS_VARIANT="${AF_CORPUS_VARIANT:?export AF_CORPUS_VARIANT}"
readonly SEED_COUNT="${AF_SEED_COUNT:?export AF_SEED_COUNT}"

die() { echo "ERROR: $*" >&2; exit 1; }

[[ -n "${SLURM_JOB_ID:-}" ]] || die "submit with sbatch"
[[ -x "${APPTAINER}" ]] || die "Apptainer missing: ${APPTAINER}"
[[ -f "${DOCKER_ARCHIVE}" ]] || die "Docker archive missing: ${DOCKER_ARCHIVE}"
[[ "${DOCKER_ARCHIVE_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "invalid archive SHA-256"
[[ "${IMAGE_ROOT}" =~ ^/scratch/jchen73/eclipsefuzz/aflnet/images/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || \
  die "AF_IMAGE_ROOT must be one named child of the AFLNet image root"
[[ "${SIF_NAME}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.sif$ ]] || die "invalid SIF name"
[[ "${CORPUS_VARIANT}" == selected10 || "${CORPUS_VARIANT}" == full ]] || \
  die "invalid corpus variant"
[[ "${SEED_COUNT}" =~ ^[1-9][0-9]*$ ]] || die "invalid seed count"
if [[ "${CORPUS_VARIANT}" == selected10 ]]; then
  [[ "${SEED_COUNT}" == 10 ]] || die "selected10 must contain ten seeds"
else
  (( SEED_COUNT > 10 )) || die "full must contain more than ten seeds"
fi

mkdir -p "${IMAGE_ROOT}"
[[ ! -e "${IMAGE_ROOT}/${SIF_NAME}" && ! -e "${IMAGE_ROOT}/IMAGE.env" ]] || \
  die "refusing to overwrite AFLNet image root: ${IMAGE_ROOT}"
printf '%s  %s\n' "${DOCKER_ARCHIVE_SHA256}" "${DOCKER_ARCHIVE}" | sha256sum -c -

local_parent="${AF_NODE_LOCAL_ROOT:-/run/user/$(id -u)}"
[[ -d "${local_parent}" && -w "${local_parent}" ]] || \
  die "AFLNet node-local root is not writable: ${local_parent}"
[[ "${local_parent}" != /tmp && "${local_parent}" != /tmp/* ]] || \
  die "refusing to use /tmp for the AFLNet SIF build root"
local_root="$(mktemp -d "${local_parent}/aflnet-sif-build-${SLURM_JOB_ID}.XXXXXX")"
cleanup() {
  chmod -R u+w "${local_root}" 2>/dev/null || true
  rm -rf -- "${local_root}"
}
trap cleanup EXIT INT TERM
[[ "$(stat -f -c %T "${local_root}")" != nfs ]] || die "AFLNet SIF build root is NFS"
mkdir -p "${local_root}/tmp" "${local_root}/cache"
export APPTAINER_TMPDIR="${local_root}/tmp"
export APPTAINER_CACHEDIR="${local_root}/cache"
local_archive="${local_root}/docker-image.tar"
local_sif="${local_root}/${SIF_NAME}"
local_sandbox="${local_root}/rootfs"

case "${DOCKER_ARCHIVE}" in
  *.tgz|*.tar.gz)
    gzip -t "${DOCKER_ARCHIVE}"
    gzip -dc "${DOCKER_ARCHIVE}" > "${local_archive}"
    ;;
  *) cp "${DOCKER_ARCHIVE}" "${local_archive}" ;;
esac

"${APPTAINER}" build "${local_sif}" "docker-archive:${local_archive}"
"${APPTAINER}" inspect --json "${local_sif}" > "${local_root}/${SIF_NAME}.inspect.json"
"${APPTAINER}" inspect --runscript "${local_sif}" > "${local_root}/${SIF_NAME}.runscript"
"${APPTAINER}" build --sandbox "${local_sandbox}" "${local_sif}"

for path in \
  "${local_sandbox}/opt/aflnet/afl-fuzz" \
  "${local_sandbox}/opt/fuzzer/aflnet-chip-all-clusters-app-fuzz" \
  "${local_sandbox}/opt/fuzzer/entrypoint.sh" \
  "${local_sandbox}/opt/fuzzer/snapshot.sh" \
  "${local_sandbox}/opt/fuzzer/runtime.sha256"; do
  [[ -s "${path}" ]] || die "image artifact missing: ${path#"${local_sandbox}"}"
done
[[ ! -e "${local_sandbox}/opt/fuzzer/phase2_parallel.py" ]] || die "image contains post-processing Python"
[[ ! -e "${local_sandbox}/opt/fuzzer/aflnet-chip-all-clusters-app-cov" ]] || die "image contains coverage DUT"
"${APPTAINER}" exec --contain --cleanenv "${local_sandbox}" /bin/bash -c \
  'cd /opt/fuzzer && sha256sum -c runtime.sha256' > "${local_root}/runtime-check.log"

actual_seed_count="$(find "${local_sandbox}/opt/fuzzer/seeds" -maxdepth 1 -type f -name '*.raw' -printf '.\n' | wc -l)"
[[ "${actual_seed_count}" == "${SEED_COUNT}" ]] || \
  die "seed count mismatch: expected ${SEED_COUNT}, got ${actual_seed_count}"

python3 - "${local_root}/${SIF_NAME}.inspect.json" "${CORPUS_VARIANT}" "${SEED_COUNT}" \
  > "${local_root}/image-labels.env" <<'PY'
import json
import re
import sys

path, variant, seed_count = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    labels = json.load(handle)["data"]["attributes"]["labels"]
expected = {
    "aflnet.image_role": "fuzz-only",
    "aflnet.corpus_variant": variant,
    "aflnet.seed_count": seed_count,
    "aflnet.storage_mode": "file",
    "aflnet.postprocessing": "external",
    "aflnet.protected_operation_policy": "reject-list.v1",
}
for key, value in expected.items():
    if labels.get(key) != value:
        raise SystemExit(f"image label mismatch: {key}={labels.get(key)!r}, expected {value!r}")
print(f"protected_operation_policy={expected['aflnet.protected_operation_policy']}")
for key in (
    "aflnet.seed_set_sha256", "aflnet.input_manifest_sha256",
    "aflnet.dict_sha256", "aflnet.afl_fuzz_sha256", "aflnet.fuzz_dut_sha256",
    "aflnet.entrypoint_sha256", "aflnet.snapshot_sha256",
    "aflnet.protected_operation_policy_sha256",
):
    value = labels.get(key, "")
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SystemExit(f"missing or invalid image label: {key}")
    print(f"{key.split('.', 1)[1]}={value}")
PY

sif_sha256="$(sha256sum "${local_sif}" | awk '{print $1}')"
cp "${local_sif}" "${IMAGE_ROOT}/${SIF_NAME}.tmp-${SLURM_JOB_ID}"
mv "${IMAGE_ROOT}/${SIF_NAME}.tmp-${SLURM_JOB_ID}" "${IMAGE_ROOT}/${SIF_NAME}"
cp "${local_root}/${SIF_NAME}.inspect.json" "${IMAGE_ROOT}/${SIF_NAME}.inspect.json"
cp "${local_root}/${SIF_NAME}.runscript" "${IMAGE_ROOT}/${SIF_NAME}.runscript"
cp "${local_root}/runtime-check.log" "${IMAGE_ROOT}/runtime-check.log"
cp "${local_root}/image-labels.env" "${IMAGE_ROOT}/image-labels.env"
printf '%s  %s\n' "${sif_sha256}" "${SIF_NAME}" > "${IMAGE_ROOT}/${SIF_NAME}.sha256"
{
  printf 'status=validated\nprepared_at=%s\n' "$(date -Iseconds)"
  printf 'image_root=%s\nsif_name=%s\nsif_sha256=%s\n' \
    "${IMAGE_ROOT}" "${SIF_NAME}" "${sif_sha256}"
  printf 'docker_archive=%s\ndocker_archive_sha256=%s\n' \
    "${DOCKER_ARCHIVE}" "${DOCKER_ARCHIVE_SHA256}"
  printf 'corpus_variant=%s\nseed_count=%s\n' "${CORPUS_VARIANT}" "${SEED_COUNT}"
  cat "${local_root}/image-labels.env"
  printf 'apptainer_version=%s\nbuild_job_id=%s\nbuild_node=%s\n' \
    "$("${APPTAINER}" version)" "${SLURM_JOB_ID}" "$(hostname)"
  printf 'runtime_staging=docker_archive_to_node_local_sif\n'
} > "${IMAGE_ROOT}/IMAGE.env"
chmod a-w "${IMAGE_ROOT}/IMAGE.env" "${IMAGE_ROOT}/${SIF_NAME}.sha256"

echo "AFLNET_BUILD_OK job=${SLURM_JOB_ID} variant=${CORPUS_VARIANT} image=${IMAGE_ROOT}/${SIF_NAME} sha256=${sif_sha256}"
