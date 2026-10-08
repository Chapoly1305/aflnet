#!/usr/bin/env bash
# Convert one frozen selected10 AFLNet Docker archive into a verified Hopper SIF.
#
# Required sbatch exports:
#   AF_DOCKER_ARCHIVE, AF_DOCKER_ARCHIVE_SHA256, AF_IMAGE_ROOT, AF_SIF_NAME
#
# This job writes IMAGE.env with status=awaiting_smoke. Only seal_ready.sh may
# create READY.env after the exact SIF passes both storage-profile smokes.
#SBATCH --job-name=aflnet-sif-build
#SBATCH --partition=normal
#SBATCH --constraint=amd
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=16G
#SBATCH --time=00:15:00

set -euo pipefail

readonly APPTAINER="${AF_APPTAINER:-/opt/sw/other/apps/apptainer/1.4.1/bin/apptainer}"
readonly DOCKER_ARCHIVE="${AF_DOCKER_ARCHIVE:?export AF_DOCKER_ARCHIVE}"
readonly DOCKER_ARCHIVE_SHA256="${AF_DOCKER_ARCHIVE_SHA256:?export AF_DOCKER_ARCHIVE_SHA256}"
readonly IMAGE_ROOT="${AF_IMAGE_ROOT:?export AF_IMAGE_ROOT}"
readonly SIF_NAME="${AF_SIF_NAME:?export AF_SIF_NAME}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

sha() {
  sha256sum "$1" | awk '{print $1}'
}

[[ -n "${SLURM_JOB_ID:-}" ]] || die "submit with sbatch"
[[ -x "${APPTAINER}" ]] || die "Apptainer missing: ${APPTAINER}"
[[ -f "${DOCKER_ARCHIVE}" ]] || die "Docker archive missing: ${DOCKER_ARCHIVE}"
[[ "${DOCKER_ARCHIVE_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "invalid archive SHA-256"
[[ "${IMAGE_ROOT}" =~ ^/scratch/jchen73/eclipsefuzz/aflnet/images/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || \
  die "AF_IMAGE_ROOT must be one named child of /scratch/jchen73/eclipsefuzz/aflnet/images"
[[ "${SIF_NAME}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.sif$ ]] || die "invalid SIF name"

mkdir -p "${IMAGE_ROOT}"
[[ ! -e "${IMAGE_ROOT}/${SIF_NAME}" ]] || die "SIF already exists: ${IMAGE_ROOT}/${SIF_NAME}"
[[ ! -e "${IMAGE_ROOT}/IMAGE.env" ]] || die "IMAGE.env already exists: ${IMAGE_ROOT}/IMAGE.env"
printf '%s  %s\n' "${DOCKER_ARCHIVE_SHA256}" "${DOCKER_ARCHIVE}" | sha256sum -c -

local_parent="${SLURM_TMPDIR:-/tmp}"
local_root="$(mktemp -d "${local_parent}/aflnet-sif-build-${SLURM_JOB_ID}.XXXXXX")"
cleanup() {
  if [[ -d "${local_root}" ]]; then
    chmod -R u+w "${local_root}" 2>/dev/null || true
    rm -rf -- "${local_root}"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
sif_sha256="$(sha "${local_sif}")"

# Hopper compute nodes lack squashfuse. Validate through the same one-time
# node-local sandbox expansion used by smoke and production jobs.
"${APPTAINER}" build --sandbox "${local_sandbox}" "${local_sif}"
root="${local_sandbox}/opt/fuzzer"
for path in \
  "${local_sandbox}/opt/aflnet/afl-fuzz" \
  "${root}/aflnet-chip-all-clusters-app-fuzz" \
  "${root}/aflnet-chip-all-clusters-app-cov" \
  "${root}/entrypoint.sh" \
  "${root}/phase2_parallel.py" \
  "${root}/replay_worker.py" \
  "${root}/replay_snapshots.py" \
  "${root}/aggregate_coverage_over_time.py" \
  "${root}/validate_input_bundle.py" \
  "${local_sandbox}/opt/llvm/llvm-profdata" \
  "${local_sandbox}/opt/llvm/llvm-cov"; do
  [[ -s "${path}" ]] || die "required image artifact missing: ${path#"${local_sandbox}"}"
done

"${APPTAINER}" exec --contain --cleanenv "${local_sandbox}" \
  python3 /opt/fuzzer/validate_input_bundle.py verify \
    --seeds /opt/fuzzer/seeds \
    --dictionary /opt/fuzzer/matter.dict \
    --projection /opt/fuzzer/input-projection.json \
    --fidelity /opt/fuzzer/input-fidelity.json \
    --manifest /opt/fuzzer/input-manifest.json \
  > "${local_root}/input-bundle-check.log"

seed_count="$(find "${root}/seeds" -maxdepth 1 -type f -name '*.raw' -printf '.\n' | wc -l)"
[[ "${seed_count}" == 10 ]] || die "selected10 image must contain exactly 10 raw seeds; found ${seed_count}"
seed_set_sha256="$({
  cd "${root}/seeds"
  sha256sum -- ./*.raw | sed 's#  \./#  #' | LC_ALL=C sort -k2 | sha256sum | awk '{print $1}'
})"

content_file="${local_root}/image-content.sha256"
{
  sha256sum \
    "${local_sandbox}/opt/aflnet/afl-fuzz" \
    "${root}/aflnet-chip-all-clusters-app-fuzz" \
    "${root}/aflnet-chip-all-clusters-app-cov" \
    "${root}/entrypoint.sh" \
    "${root}/phase2_parallel.py" \
    "${root}/replay_worker.py" \
    "${root}/replay_snapshots.py" \
    "${root}/aggregate_coverage_over_time.py" \
    "${root}/validate_input_bundle.py" \
    "${root}/matter.dict" \
    "${root}/input-manifest.json" \
    "${root}/input-projection.json" \
    "${root}/input-fidelity.json" \
    "${root}/cov-build-args.gn" \
    "${root}/aflnet-profgen.list" \
    "${root}/target.zap" \
    "${root}/target.matter" \
    "${local_sandbox}/opt/llvm/llvm-profdata" \
    "${local_sandbox}/opt/llvm/llvm-cov"
} | sed "s#${local_sandbox}##" > "${content_file}"

content_hash() {
  local wanted="$1"
  awk -v wanted="${wanted}" '$2 == wanted {print $1; found=1; exit} END {if (!found) exit 1}' "${content_file}"
}

afl_fuzz_sha256="$(content_hash /opt/aflnet/afl-fuzz)"
fuzz_dut_sha256="$(content_hash /opt/fuzzer/aflnet-chip-all-clusters-app-fuzz)"
cov_dut_sha256="$(content_hash /opt/fuzzer/aflnet-chip-all-clusters-app-cov)"
entrypoint_sha256="$(content_hash /opt/fuzzer/entrypoint.sh)"
phase2_sha256="$(content_hash /opt/fuzzer/phase2_parallel.py)"
replay_worker_sha256="$(content_hash /opt/fuzzer/replay_worker.py)"
replay_snapshots_sha256="$(content_hash /opt/fuzzer/replay_snapshots.py)"
aggregator_sha256="$(content_hash /opt/fuzzer/aggregate_coverage_over_time.py)"
validator_sha256="$(content_hash /opt/fuzzer/validate_input_bundle.py)"
dict_sha256="$(content_hash /opt/fuzzer/matter.dict)"
manifest_sha256="$(content_hash /opt/fuzzer/input-manifest.json)"
projection_sha256="$(content_hash /opt/fuzzer/input-projection.json)"
fidelity_sha256="$(content_hash /opt/fuzzer/input-fidelity.json)"
cov_args_sha256="$(content_hash /opt/fuzzer/cov-build-args.gn)"
profgen_list_sha256="$(content_hash /opt/fuzzer/aflnet-profgen.list)"
target_zap_sha256="$(content_hash /opt/fuzzer/target.zap)"
target_matter_sha256="$(content_hash /opt/fuzzer/target.matter)"
profdata_sha256="$(content_hash /opt/llvm/llvm-profdata)"
llvm_cov_sha256="$(content_hash /opt/llvm/llvm-cov)"

expected_labels="${local_root}/expected-labels.tsv"
cat > "${expected_labels}" <<EOF
aflnet.afl_fuzz_sha256	${afl_fuzz_sha256}
aflnet.fuzz_dut_sha256	${fuzz_dut_sha256}
aflnet.cov_dut_sha256	${cov_dut_sha256}
aflnet.entrypoint_sha256	${entrypoint_sha256}
aflnet.phase2_sha256	${phase2_sha256}
aflnet.replay_worker_sha256	${replay_worker_sha256}
aflnet.replay_snapshots_sha256	${replay_snapshots_sha256}
aflnet.coverage_aggregator_sha256	${aggregator_sha256}
aflnet.input_validator_sha256	${validator_sha256}
aflnet.seed_count	${seed_count}
aflnet.seed_set_sha256	${seed_set_sha256}
aflnet.seed_transport	udp
aflnet.dict_sha256	${dict_sha256}
aflnet.input_manifest_sha256	${manifest_sha256}
aflnet.input_projection_sha256	${projection_sha256}
aflnet.input_fidelity_sha256	${fidelity_sha256}
aflnet.cov_args_sha256	${cov_args_sha256}
aflnet.profgen_list_sha256	${profgen_list_sha256}
aflnet.target_zap_sha256	${target_zap_sha256}
aflnet.target_matter_sha256	${target_matter_sha256}
aflnet.profdata_sha256	${profdata_sha256}
aflnet.llvm_cov_sha256	${llvm_cov_sha256}
aflnet.coverage_kind	saved_queue_replay
aflnet.storage_profiles	file,memory
aflnet.default_storage_mode	file
aflnet.storage_selection	runtime
aflnet.file_storage_delegate	linux-file-backed
aflnet.memory_storage_delegate	test-in-memory
aflnet.testcase_state_reset	fork-snapshot
EOF

python3 - "${local_root}/${SIF_NAME}.inspect.json" "${expected_labels}" <<'PY'
import json
import sys

inspect_path, expected_path = sys.argv[1:]
with open(inspect_path, encoding="utf-8") as stream:
    labels = json.load(stream)["data"]["attributes"]["labels"]
with open(expected_path, encoding="utf-8") as stream:
    for raw in stream:
        key, expected = raw.rstrip("\n").split("\t", 1)
        actual = labels.get(key)
        if actual != expected:
            raise SystemExit(f"image label mismatch: {key}={actual!r}, expected {expected!r}")
print("AFLNET_IMAGE_LABELS_OK")
PY

cp "${local_sif}" "${IMAGE_ROOT}/${SIF_NAME}.tmp-${SLURM_JOB_ID}"
mv "${IMAGE_ROOT}/${SIF_NAME}.tmp-${SLURM_JOB_ID}" "${IMAGE_ROOT}/${SIF_NAME}"
cp "${local_root}/${SIF_NAME}.inspect.json" "${IMAGE_ROOT}/${SIF_NAME}.inspect.json"
cp "${local_root}/${SIF_NAME}.runscript" "${IMAGE_ROOT}/${SIF_NAME}.runscript"
cp "${content_file}" "${IMAGE_ROOT}/image-content.sha256"
cp "${local_root}/input-bundle-check.log" "${IMAGE_ROOT}/input-bundle-check.log"
printf '%s  %s\n' "${sif_sha256}" "${SIF_NAME}" > "${IMAGE_ROOT}/${SIF_NAME}.sha256"

image_env_tmp="${IMAGE_ROOT}/IMAGE.env.tmp-${SLURM_JOB_ID}"
{
  printf 'status=awaiting_smoke\nprepared_at=%s\n' "$(date -Iseconds)"
  printf 'fuzzer=aflnet\ncorpus_variant=selected10\nstorage_profiles=file,memory\n'
  printf 'image_root=%s\nsif_name=%s\nsif_sha256=%s\n' \
    "${IMAGE_ROOT}" "${SIF_NAME}" "${sif_sha256}"
  printf 'docker_archive=%s\ndocker_archive_sha256=%s\n' \
    "${DOCKER_ARCHIVE}" "${DOCKER_ARCHIVE_SHA256}"
  printf 'seed_count=%s\nseed_set_sha256=%s\n' "${seed_count}" "${seed_set_sha256}"
  printf 'afl_fuzz_sha256=%s\nfuzz_dut_sha256=%s\ncov_dut_sha256=%s\n' \
    "${afl_fuzz_sha256}" "${fuzz_dut_sha256}" "${cov_dut_sha256}"
  printf 'entrypoint_sha256=%s\nphase2_sha256=%s\nreplay_worker_sha256=%s\n' \
    "${entrypoint_sha256}" "${phase2_sha256}" "${replay_worker_sha256}"
  printf 'replay_snapshots_sha256=%s\ncoverage_aggregator_sha256=%s\ninput_validator_sha256=%s\n' \
    "${replay_snapshots_sha256}" "${aggregator_sha256}" "${validator_sha256}"
  printf 'dictionary_sha256=%s\ninput_manifest_sha256=%s\ninput_projection_sha256=%s\ninput_fidelity_sha256=%s\n' \
    "${dict_sha256}" "${manifest_sha256}" "${projection_sha256}" "${fidelity_sha256}"
  printf 'cov_build_args_sha256=%s\nprofgen_list_sha256=%s\n' \
    "${cov_args_sha256}" "${profgen_list_sha256}"
  printf 'target_zap_sha256=%s\ntarget_matter_sha256=%s\n' \
    "${target_zap_sha256}" "${target_matter_sha256}"
  printf 'llvm_profdata_sha256=%s\nllvm_cov_sha256=%s\n' \
    "${profdata_sha256}" "${llvm_cov_sha256}"
  printf 'apptainer_version=%s\nbuild_job_id=%s\nbuild_node=%s\n' \
    "$("${APPTAINER}" version)" "${SLURM_JOB_ID}" "$(hostname)"
  printf 'runtime_staging=sif_to_node_local_sandbox_once_per_job\n'
} > "${image_env_tmp}"
mv "${image_env_tmp}" "${IMAGE_ROOT}/IMAGE.env"

echo "BUILD_OK job=${SLURM_JOB_ID} image=${IMAGE_ROOT}/${SIF_NAME} sha256=${sif_sha256} seeds=${seed_count}"
echo "NEXT=submit smoke.sbatch with AF_IMAGE_ENV=${IMAGE_ROOT}/IMAGE.env"
