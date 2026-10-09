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
# One job, one image, ten independent AFLNet instances. The image performs only
# fuzzing and periodic lightweight snapshots. Coverage is post-processed later.
set -euo pipefail

readonly APPTAINER="${AF_APPTAINER:-/opt/sw/other/apps/apptainer/1.4.1/bin/apptainer}"
readonly FUZZ_SECONDS="${AF_FUZZ_SECONDS:-86400}"
readonly SNAPSHOT_INTERVAL="${AF_SNAPSHOT_INTERVAL:-1800}"
readonly REPLICAS=10

die() { echo "ERROR: $*" >&2; exit 1; }

if [[ "${1:-}" == --instance ]]; then
  [[ $# == 5 ]] || die "--instance requires REPLICA ROOTFS CAMPAIGN TMP_ROOT"
  replica="$2"
  rootfs="$3"
  campaign="$4"
  tmp_root="$5"
  printf -v name 'instance-%02d' "${replica}"
  output="${campaign}/${name}"
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
    "${rootfs}"
fi

[[ $# == 2 ]] || die "usage: sbatch --export=NONE $0 IMAGE.sif CAMPAIGN_DIR"
SIF="$(realpath -e -- "$1")"
CAMPAIGN="$(realpath -m -- "$2")"
readonly SIF CAMPAIGN
[[ "${SIF}" == *.sif ]] || die "image must be a .sif"
[[ "${CAMPAIGN}" == /scratch/* ]] || die "campaign must be under /scratch"
[[ ! -e "${CAMPAIGN}" ]] || die "campaign already exists: ${CAMPAIGN}"
[[ "${FUZZ_SECONDS}" =~ ^[1-9][0-9]*$ ]] || die "invalid AF_FUZZ_SECONDS"
[[ "${SNAPSHOT_INTERVAL}" =~ ^[1-9][0-9]*$ ]] || die "invalid AF_SNAPSHOT_INTERVAL"
[[ -x "${APPTAINER}" ]] || die "Apptainer missing: ${APPTAINER}"

# Prevent variables inherited from an interactive allocation from making the
# single srun invalid. Slurm always propagates SLURM_* even with --export=NONE.
unset SLURM_MEM_PER_NODE SLURM_MEM_PER_GPU

local_parent="${SLURM_TMPDIR:-/tmp}"
local_root="$(mktemp -d "${local_parent}/aflnet-${SLURM_JOB_ID}.XXXXXX")"
rootfs="${local_root}/rootfs"
cleanup() {
  chmod -R u+w "${local_root}" 2>/dev/null || true
  rm -rf -- "${local_root}"
}
trap cleanup EXIT INT TERM

mkdir -p "${CAMPAIGN}/manifest"
cp "${BASH_SOURCE[0]}" "${CAMPAIGN}/manifest/run_campaign.sbatch"
sha256sum "${SIF}" > "${CAMPAIGN}/manifest/image.sha256"
scontrol show job -dd "${SLURM_JOB_ID}" > "${CAMPAIGN}/manifest/slurm-job.txt"
{
  printf 'started=%s\njob_id=%s\nnode=%s\n' "$(date -Iseconds)" "${SLURM_JOB_ID}" "$(hostname)"
  printf 'image=%s\ninstances=%s\ncpus_per_instance=1\n' "${SIF}" "${REPLICAS}"
  printf 'fuzz_seconds=%s\nsnapshot_interval=%s\npostprocessing=external\n' \
    "${FUZZ_SECONDS}" "${SNAPSHOT_INTERVAL}"
} > "${CAMPAIGN}/manifest/campaign.env"

# Hopper compute nodes cannot mount the SIF directly; expand it once to the
# job-local filesystem and share that read-only tree across the ten tasks.
"${APPTAINER}" build --sandbox "${rootfs}" "${SIF}"
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

# Exactly ten tasks and one CPU per task. Each task receives its replica number
# from SLURM_PROCID and creates one private network/PID namespace.
# shellcheck disable=SC2016
srun -N1 -n"${REPLICAS}" -c1 --cpu-bind=cores --kill-on-bad-exit=1 \
  /bin/bash -c 'exec "$1" --instance "$((SLURM_PROCID + 1))" "$2" "$3" "$4"' \
  _ "${BASH_SOURCE[0]}" "${rootfs}" "${CAMPAIGN}" "${local_root}/tmp"

complete="$(find "${CAMPAIGN}" -mindepth 2 -maxdepth 2 -name .done -printf '.\n' | wc -l)"
[[ "${complete}" == "${REPLICAS}" ]] || die "only ${complete}/${REPLICAS} instances completed"
printf 'ended=%s\ncomplete_instances=%s\nstatus=ok\n' \
  "$(date -Iseconds)" "${complete}" >> "${CAMPAIGN}/manifest/campaign.env"
touch "${CAMPAIGN}/campaign.done"
