#!/usr/bin/env bash
#SBATCH --job-name=aflnet
#SBATCH --partition=normal
#SBATCH --constraint=amd
#SBATCH --nodes=1
#SBATCH --ntasks=10
#SBATCH --cpus-per-task=1
#SBATCH --mem-per-cpu=8G
#SBATCH --time=1-06:00:00
#SBATCH --signal=B:USR1@600

# Usage:
#   sbatch --export=NONE run_campaign.sbatch IMAGE.sif CAMPAIGN_DIR
#
# One job, one image, AF_REPLICAS independent AFLNet instances. The image
# performs only fuzzing and periodic lightweight snapshots. Coverage is
# post-processed later.
# The 30-hour allocation covers calibration (guarded at four hours), 24 hours
# of active fuzzing, and final checksum verification. Data is live on scratch.
set -euo pipefail

readonly APPTAINER="${AF_APPTAINER:-/opt/sw/other/apps/apptainer/1.4.1/bin/apptainer}"
readonly FUZZ_SECONDS="${AF_FUZZ_SECONDS:-86400}"
readonly SNAPSHOT_INTERVAL="${AF_SNAPSHOT_INTERVAL:-1800}"
readonly REPLICAS="${AF_REPLICAS:-10}"
readonly CALIBRATION_GUARD_SECONDS="${AF_CALIBRATION_GUARD_SECONDS:-14400}"

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
    --env CALIBRATION_GUARD_SECONDS="${CALIBRATION_GUARD_SECONDS}" \
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
[[ "${CALIBRATION_GUARD_SECONDS}" =~ ^[1-9][0-9]*$ ]] || die "invalid calibration guard"
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

local_parent="${AF_NODE_LOCAL_ROOT:-/run/user/$(id -u)}"
[[ -d "${local_parent}" && -w "${local_parent}" ]] || \
  die "AFLNet node-local root is not writable: ${local_parent}"
[[ "${local_parent}" != /tmp && "${local_parent}" != /tmp/* ]] || \
  die "refusing to use /tmp for the AFLNet runtime root"
local_root="$(mktemp -d "${local_parent}/aflnet-${SLURM_JOB_ID}.XXXXXX")"
rootfs="${local_root}/rootfs"
active_root="${CAMPAIGN}"
# RETENTION_FUNCTIONS_BEGIN
# All experimental data already lives on scratch. Sealing validates complete
# replicas; cleanup only removes the image sandbox and temporary runtime files.
verify_publication() {
  local destination="$1" expected observed queue_count actual
  [[ -f "${destination}/.done" && -s "${destination}/publication-files.sha256" ]] || return 1
  [[ -s "${destination}/run.env" && -d "${destination}/afl-out/replayable-queue" ]] || return 1
  (cd "${destination}" && sha256sum -c publication-files.sha256 >/dev/null) || return 1
  [[ "$(awk -F= '$1 == "status" {v=$2} END {print v}' "${destination}/run.env")" == ok ]] || return 1
  expected="$(awk -F= '$1 == "requested_fuzz_seconds" {v=$2} END {print v}' "${destination}/run.env")"
  observed="$(awk -F= '$1 == "observed_fuzz_seconds" {v=$2} END {print v}' "${destination}/run.env")"
  [[ "${expected}" == "${FUZZ_SECONDS}" && "${observed}" =~ ^[0-9]+$ ]] || return 1
  (( observed >= FUZZ_SECONDS - 5 && observed <= FUZZ_SECONDS + 5 )) || return 1
  queue_count="$(awk -F= '$1 == "queue_entries" {v=$2} END {print v}' "${destination}/run.env")"
  actual="$(find "${destination}/afl-out/replayable-queue" -maxdepth 1 -type f -printf '.\n' | wc -l)"
  [[ "${queue_count}" =~ ^[1-9][0-9]*$ && "${actual}" == "${queue_count}" ]] || return 1
}

seal_instance() {
  local source="$1"
  local critical=(publication.env)
  [[ "${source}" == "${CAMPAIGN}"/instance-* && -d "${source}" ]] || return 1
  {
    printf 'schema=aflnet-scratch-publication.v2\nactive_storage=scratch\n'
    printf 'active_filesystem=%s\nactive_bytes=%s\nactive_files=%s\n' \
      "$(stat -f -c %T "${source}")" \
      "$(du -sb "${source}" | awk '{print $1}')" \
      "$(find "${source}" -type f -printf '.\n' | wc -l)"
  } > "${source}/publication.env" || return 1
  [[ -f "${source}/run.env" ]] && critical+=(run.env)
  [[ -f "${source}/instance.log" ]] && critical+=(instance.log)
  [[ -f "${source}/afl-out/fuzzer_stats" ]] && critical+=(afl-out/fuzzer_stats)
  (
    cd "${source}" &&
    sha256sum "${critical[@]}" > publication-critical.sha256
  ) || return 1
  # Seal every input and artifact, not just four metadata files. Hash only
  # after srun has stopped all writers; preserve queue discovery timestamps.
  # The output file is explicitly excluded from the inventory.
  # shellcheck disable=SC2094
  (
    cd "${source}" &&
      find . -type f ! -name publication-files.sha256 ! -name publication-files.sha256.tmp \
        ! -name publication-critical.sha256 -print0 | \
      sort -z | xargs -0 -r sha256sum > publication-files.sha256.tmp &&
      mv publication-files.sha256.tmp publication-files.sha256
  ) || return 1
  verify_publication "${source}"
}

finish_campaign() {
  local srun_rc="$1" complete=0 published=0 replica name
  for replica in $(seq 1 "${REPLICAS}"); do
    printf -v name 'instance-%02d' "${replica}"
    [[ ! -f "${CAMPAIGN}/${name}/.done" ]] || complete=$((complete + 1))
    if seal_instance "${CAMPAIGN}/${name}"; then
      published=$((published + 1))
    fi
  done
  if (( srun_rc != 0 || complete != REPLICAS || published != REPLICAS )); then
    printf 'ended=%s\ncomplete_instances=%s\npublished_instances=%s\nsrun_rc=%s\nstatus=failed\n' \
      "$(date -Iseconds)" "${complete}" "${published}" "${srun_rc}" >> "${CAMPAIGN}/manifest/campaign.env"
    return 1
  fi
  printf 'ended=%s\ncomplete_instances=%s\npublished_instances=%s\nstatus=ok\n' \
    "$(date -Iseconds)" "${complete}" "${published}" >> "${CAMPAIGN}/manifest/campaign.env" || return 1
  touch "${CAMPAIGN}/campaign.done" || return 1
  PUBLISHED_OK=1
  echo "AFLNET_PHASE complete verified_publications=${published} active_budget=${FUZZ_SECONDS}s"
}

campaign_exit() {
  local rc="$1"
  trap - EXIT
  trap '' INT TERM USR1
  set +e
  if [[ -n "${STEP_PID:-}" ]]; then
    kill -TERM "${STEP_PID}" 2>/dev/null
    wait "${STEP_PID}" 2>/dev/null
  fi
  if [[ "${PUBLISHED_OK:-0}" != 1 || "${rc}" != 0 ]]; then
    mkdir -p "${CAMPAIGN}/manifest"
    printf 'status=failed\nexit_code=%s\ndata_storage=scratch\ndata_retained=%s\n' \
      "${rc}" "${CAMPAIGN}" > "${CAMPAIGN}/manifest/retention.env"
    printf 'ended=%s\nexit_code=%s\nstatus=failed\n' "$(date -Iseconds)" "${rc}" \
      >> "${CAMPAIGN}/manifest/campaign.env"
    rm -f -- "${CAMPAIGN}/campaign.done"
    touch "${CAMPAIGN}/campaign.failed"
    echo "AFLNET_DATA_RETAINED scratch=${CAMPAIGN}" >&2
    (( rc != 0 )) || rc=1
  fi
  # Defense in depth: never clean a runtime directory containing the data root.
  if [[ -d "${local_root}" && "${CAMPAIGN}" != "${local_root}" && \
        "${CAMPAIGN}" != "${local_root}"/* ]]; then
    chmod -R u+w "${local_root}" 2>/dev/null
    rm -rf -- "${local_root}"
  fi
  exit "${rc}"
}
# RETENTION_FUNCTIONS_END

PUBLISHED_OK=0
STEP_PID=""
trap 'campaign_exit "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM USR1

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
  printf 'budget_clock=post-calibration-active\ncalibration_guard_seconds=%s\n' "${CALIBRATION_GUARD_SECONDS}"
  printf 'active_storage=scratch\nactive_root=%s\nactive_filesystem=%s\nruntime_local_root=%s\n' \
    "${active_root}" "$(stat -f -c %T "${active_root}")" "${local_root}"
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
echo "AFLNET_PHASE fuzzing_and_calibration active_budget=${FUZZ_SECONDS}s calibration_guard=${CALIBRATION_GUARD_SECONDS}s data=${CAMPAIGN}"
set +e
# shellcheck disable=SC2016
srun -N1 -n"${REPLICAS}" -c1 --cpu-bind=cores --kill-on-bad-exit=1 \
  /bin/bash -c 'exec "$1" --instance "$((SLURM_PROCID + 1))" "$2" "$3" "$4"' \
  _ "${BASH_SOURCE[0]}" "${rootfs}" "${active_root}" "${local_root}/tmp" &
STEP_PID=$!
wait "${STEP_PID}"
srun_rc=$?
STEP_PID=""
set -e
echo "AFLNET_PHASE verification fuzzing_stopped=1 data_already_on_scratch=${CAMPAIGN}"
finish_campaign "${srun_rc}" || die "AFLNet campaign failed; inputs retained at ${CAMPAIGN}"
