#!/usr/bin/env bash
#SBATCH --job-name=aflnet
#SBATCH --partition=normal
#SBATCH --constraint=amd
#SBATCH --nodes=1
#SBATCH --ntasks=10
#SBATCH --cpus-per-task=1
#SBATCH --mem-per-cpu=8G
#SBATCH --time=3-03:00:00

# Usage:
#   sbatch --export=NONE run_campaign.sbatch IMAGE.sif CAMPAIGN_DIR
#
# One job, one image, AF_REPLICAS independent AFLNet instances. The image
# performs only fuzzing and periodic lightweight snapshots. Coverage is
# post-processed later.
set -euo pipefail

readonly APPTAINER="${AF_APPTAINER:-/opt/sw/other/apps/apptainer/1.4.1/bin/apptainer}"
readonly FUZZ_SECONDS="${AF_FUZZ_SECONDS:-86400}"
readonly SNAPSHOT_INTERVAL="${AF_SNAPSHOT_INTERVAL:-1800}"
readonly REPLICAS="${AF_REPLICAS:-10}"

die() { echo "ERROR: $*" >&2; exit 1; }

image_value() {
  local key="$1"
  local count
  count="$(awk -F= -v key="${key}" '$1 == key { count++ } END { print count + 0 }' "${IMAGE_ENV}")"
  [[ "${count}" == 1 ]] || die "IMAGE.env must contain exactly one ${key}= entry"
  awk -F= -v key="${key}" '$1 == key { print substr($0, length(key) + 2) }' "${IMAGE_ENV}"
}

if [[ "${1:-}" == --instance ]]; then
  [[ $# == 5 ]] || die "--instance requires REPLICA ROOTFS ACTIVE_ROOT TMP_ROOT"
  replica="$2"
  rootfs="$3"
  active_root="$4"
  tmp_root="$5"
  printf -v name 'instance-%02d' "${replica}"
  output="${active_root}/${name}"
  instance_tmp="${tmp_root}/${name}"
  mkdir -p "${output}" "${instance_tmp}"
  [[ ! -e "${output}/run.env" ]] || die "refusing to overwrite ${output}"
  exec "${APPTAINER}" exec --containall --cleanenv --net --network none \
    --bind "${output}:/workdir/output" \
    --bind "${instance_tmp}:/tmp" \
    --pwd /opt/fuzzer \
    --env HOME=/tmp \
    --env TMPDIR=/tmp \
    --env INSTANCE="${name}" \
    --env FUZZ_SECONDS="${FUZZ_SECONDS}" \
    --env SNAPSHOT_INTERVAL="${SNAPSHOT_INTERVAL}" \
    --env CALIBRATION_GUARD_SECONDS="${AF_CALIBRATION_GUARD_SECONDS:-172800}" \
    "${rootfs}" /opt/fuzzer/entrypoint.sh
fi

[[ $# == 2 ]] || die "usage: sbatch --export=NONE $0 IMAGE.sif CAMPAIGN_DIR"
SIF="$(realpath -e -- "$1")"
CAMPAIGN="$(realpath -m -- "$2")"
IMAGE_ENV="$(realpath -e -- "${AF_IMAGE_ENV:-$(dirname "${SIF}")/IMAGE.env}")"
readonly SIF CAMPAIGN IMAGE_ENV
[[ "${SIF}" == *.sif ]] || die "image must be a .sif"
[[ "${CAMPAIGN}" == /scratch/* ]] || die "campaign must be under /scratch"
[[ ! -e "${CAMPAIGN}" ]] || die "campaign already exists: ${CAMPAIGN}"
[[ "${FUZZ_SECONDS}" =~ ^[1-9][0-9]*$ ]] || die "invalid AF_FUZZ_SECONDS"
[[ "${SNAPSHOT_INTERVAL}" =~ ^[1-9][0-9]*$ ]] || die "invalid AF_SNAPSHOT_INTERVAL"
if [[ ! "${REPLICAS}" =~ ^[1-9][0-9]*$ ]] || (( REPLICAS > 10 )); then
  die "AF_REPLICAS must be in 1..10"
fi
[[ "${SLURM_NTASKS:-}" == "${REPLICAS}" ]] || \
  die "Slurm task count ${SLURM_NTASKS:-unset} does not match AF_REPLICAS=${REPLICAS}"
[[ -x "${APPTAINER}" ]] || die "Apptainer missing: ${APPTAINER}"

[[ "$(image_value status)" == validated ]] || die "AFLNet image is not validated"
image_root="$(realpath -e -- "$(image_value image_root)")"
[[ "${image_root}" == "$(dirname "${SIF}")" ]] || \
  die "IMAGE.env image_root does not own ${SIF}"
[[ "$(image_value sif_name)" == "$(basename "${SIF}")" ]] || \
  die "IMAGE.env sif_name does not match ${SIF}"
expected_sif_sha256="$(image_value sif_sha256)"
[[ "${expected_sif_sha256}" =~ ^[0-9a-f]{64}$ ]] || die "invalid IMAGE.env sif_sha256"
corpus_variant="$(image_value corpus_variant)"
seed_count="$(image_value seed_count)"
protected_operation_policy="$(image_value protected_operation_policy)"
protected_operation_policy_sha256="$(image_value protected_operation_policy_sha256)"
[[ "${corpus_variant}" == selected10 || "${corpus_variant}" == full ]] || \
  die "invalid IMAGE.env corpus_variant"
[[ "${seed_count}" =~ ^[1-9][0-9]*$ ]] || die "invalid IMAGE.env seed_count"
if [[ "${corpus_variant}" == selected10 ]]; then
  [[ "${seed_count}" == 10 ]] || die "selected10 IMAGE.env must record ten seeds"
else
  (( seed_count > 10 )) || die "full IMAGE.env must record more than ten seeds"
fi
[[ "${protected_operation_policy}" == reject-list.v1 ]] || \
  die "invalid protected-operation policy in IMAGE.env"
[[ "${protected_operation_policy_sha256}" =~ ^[0-9a-f]{64}$ ]] || \
  die "invalid protected-operation policy hash in IMAGE.env"
sif_sha256="$(sha256sum "${SIF}" | awk '{print $1}')"
[[ "${sif_sha256}" == "${expected_sif_sha256}" ]] || \
  die "SIF SHA-256 does not match IMAGE.env"

# Prevent variables inherited from an interactive allocation from making the
# single srun invalid. Slurm always propagates SLURM_* even with --export=NONE.
unset SLURM_MEM_PER_NODE SLURM_MEM_PER_GPU

local_parent="${SLURM_TMPDIR:-/tmp}"
local_root="$(mktemp -d "${local_parent}/aflnet-${SLURM_JOB_ID}.XXXXXX")"
rootfs="${local_root}/rootfs"
active_root="${local_root}/active"
cleanup() {
  chmod -R u+w "${local_root}" 2>/dev/null || true
  rm -rf -- "${local_root}"
}
trap cleanup EXIT INT TERM

publish_instance() {
  local source="$1" destination="$2"
  local partial="${destination}.partial-${SLURM_JOB_ID}"
  local critical=(publication.env)
  [[ "${source}" == /tmp/* || \
     ( -n "${SLURM_TMPDIR:-}" && "${source}" == "${SLURM_TMPDIR}"/* ) ]] || \
    die "AFLNet active output is not job-local: ${source}"
  [[ "${destination}" == /scratch/* ]] || die "invalid AFLNet publication path: ${destination}"
  [[ ! -e "${destination}" && ! -e "${partial}" ]] || \
    die "refusing to overwrite AFLNet publication: ${destination}"
  {
    printf 'schema=aflnet-node-local-publication.v1\n'
    printf 'active_filesystem=%s\nactive_bytes=%s\nactive_files=%s\n' \
      "$(stat -f -c %T "${source}")" \
      "$(du -sb "${source}" | awk '{print $1}')" \
      "$(find "${source}" -type f -printf '.\n' | wc -l)"
  } > "${source}/publication.env"
  [[ -f "${source}/run.env" ]] && critical+=(run.env)
  [[ -f "${source}/instance.log" ]] && critical+=(instance.log)
  [[ -f "${source}/afl-out/fuzzer_stats" ]] && critical+=(afl-out/fuzzer_stats)
  (
    cd "${source}"
    sha256sum "${critical[@]}" > publication-critical.sha256
  )
  mkdir "${partial}"
  cp -a "${source}/." "${partial}/"
  (cd "${partial}" && sha256sum -c publication-critical.sha256)
  mv "${partial}" "${destination}"
}

mkdir -p "${CAMPAIGN}/manifest" "${active_root}"
[[ "$(stat -f -c %T "${local_root}")" != nfs ]] || die "AFLNet local root is NFS"
cp "${BASH_SOURCE[0]}" "${CAMPAIGN}/manifest/run_campaign.sbatch"
cp "${IMAGE_ENV}" "${CAMPAIGN}/manifest/IMAGE.env"
printf '%s  %s\n' "${sif_sha256}" "${SIF}" > "${CAMPAIGN}/manifest/image.sha256"
scontrol show job -dd "${SLURM_JOB_ID}" > "${CAMPAIGN}/manifest/slurm-job.txt"
{
  printf 'started=%s\njob_id=%s\nnode=%s\n' "$(date -Iseconds)" "${SLURM_JOB_ID}" "$(hostname)"
  printf 'image=%s\ninstances=%s\ncpus_per_instance=1\n' "${SIF}" "${REPLICAS}"
  printf 'image_env=%s\ncorpus_variant=%s\nseed_count=%s\n' \
    "${IMAGE_ENV}" "${corpus_variant}" "${seed_count}"
  printf 'protected_operation_policy=%s\nprotected_operation_policy_sha256=%s\n' \
    "${protected_operation_policy}" "${protected_operation_policy_sha256}"
  printf 'fuzz_seconds=%s\nsnapshot_interval=%s\npostprocessing=external\n' \
    "${FUZZ_SECONDS}" "${SNAPSHOT_INTERVAL}"
  printf 'active_storage=node-local\nnode_local_root=%s\nnode_local_filesystem=%s\n' \
    "${local_root}" "$(stat -f -c %T "${local_root}")"
  df -Pk "${local_root}" | tail -1 | \
    awk '{printf "node_local_kib_total=%s\nnode_local_kib_available=%s\n", $2, $4}'
} > "${CAMPAIGN}/manifest/campaign.env"

# Hopper compute nodes cannot mount the SIF directly; expand it once to the
# job-local filesystem and share that read-only tree across the tasks.
local_sif="${local_root}/image.sif"
cp "${SIF}" "${local_sif}"
printf '%s  %s\n' "${sif_sha256}" "${local_sif}" | sha256sum -c -
"${APPTAINER}" build --sandbox "${rootfs}" "${local_sif}"
for path in \
  "${rootfs}/opt/aflnet/afl-fuzz" \
  "${rootfs}/opt/fuzzer/aflnet-chip-all-clusters-app-fuzz" \
  "${rootfs}/opt/fuzzer/entrypoint.sh" \
  "${rootfs}/opt/fuzzer/snapshot.sh" \
  "${rootfs}/opt/fuzzer/runtime.sha256"; do
  [[ -s "${path}" ]] || die "image artifact missing: ${path#"${rootfs}"}"
done
[[ ! -e "${rootfs}/opt/fuzzer/phase2_parallel.py" ]] || die "image contains post-processing Python"
[[ ! -e "${rootfs}/opt/fuzzer/aflnet-chip-all-clusters-app-cov" ]] || die "image contains coverage DUT"

# Exactly AF_REPLICAS tasks and one CPU per task. Each task receives its replica number
# from SLURM_PROCID and creates one private network/PID namespace.
set +e
# shellcheck disable=SC2016
srun -N1 -n"${REPLICAS}" -c1 --cpu-bind=cores --kill-on-bad-exit=1 \
  /bin/bash -c 'exec "$1" --instance "$((SLURM_PROCID + 1))" "$2" "$3" "$4"' \
  _ "${BASH_SOURCE[0]}" "${rootfs}" "${active_root}" "${local_root}/tmp"
srun_rc=$?
set -e

complete="$(find "${active_root}" -mindepth 2 -maxdepth 2 -name .done -printf '.\n' | wc -l)"
published=0
for replica in $(seq 1 "${REPLICAS}"); do
  printf -v name 'instance-%02d' "${replica}"
  if [[ -d "${active_root}/${name}" ]]; then
    publish_instance "${active_root}/${name}" "${CAMPAIGN}/${name}"
    published=$((published + 1))
  fi
done
if (( srun_rc != 0 )) || [[ "${complete}" != "${REPLICAS}" ]]; then
  printf 'ended=%s\ncomplete_instances=%s\npublished_instances=%s\nsrun_rc=%s\nstatus=failed\n' \
    "$(date -Iseconds)" "${complete}" "${published}" "${srun_rc}" >> \
    "${CAMPAIGN}/manifest/campaign.env"
  touch "${CAMPAIGN}/campaign.failed"
  die "AFLNet failed: srun_rc=${srun_rc}, complete=${complete}/${REPLICAS}, published=${published}"
fi
printf 'ended=%s\ncomplete_instances=%s\nstatus=ok\n' \
  "$(date -Iseconds)" "${complete}" >> "${CAMPAIGN}/manifest/campaign.env"
touch "${CAMPAIGN}/campaign.done"
