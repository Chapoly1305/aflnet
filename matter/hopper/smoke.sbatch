#!/usr/bin/env bash
# Smoke the exact selected10 AFLNet SIF and both frozen production runners.
#
# Required sbatch exports:
#   AF_IMAGE_ENV, AF_SMOKE_ROOT, AF_MATRIX_RUNNER, AF_REPLAY_RUNNER
#SBATCH --job-name=aflnet-appt-smoke
#SBATCH --partition=normal
#SBATCH --constraint=amd
#SBATCH --nodes=1
#SBATCH --ntasks=2
#SBATCH --cpus-per-task=1
#SBATCH --mem-per-cpu=8G
#SBATCH --time=00:15:00

set -euo pipefail

readonly APPTAINER="${AF_APPTAINER:-/opt/sw/other/apps/apptainer/1.4.1/bin/apptainer}"
readonly IMAGE_ENV="${AF_IMAGE_ENV:?export AF_IMAGE_ENV}"
readonly SMOKE_ROOT="${AF_SMOKE_ROOT:?export AF_SMOKE_ROOT}"
readonly SOURCE_MATRIX_RUNNER="${AF_MATRIX_RUNNER:?export AF_MATRIX_RUNNER}"
readonly SOURCE_REPLAY_RUNNER="${AF_REPLAY_RUNNER:?export AF_REPLAY_RUNNER}"
readonly EXPECTED_CPU_MODEL="AMD EPYC 7543 32-Core Processor"
readonly SMOKE_SECONDS=180
readonly SNAPSHOT_INTERVAL=60
readonly EXPECTED_SEEDS=10

die() {
  echo "ERROR: $*" >&2
  exit 1
}

env_value() {
  local key="$1" file="$2"
  awk -F= -v wanted="${key}" '
    $1 == wanted {
      sub(/^[^=]*=/, "")
      print
      found = 1
      exit
    }
    END { if (!found) exit 1 }
  ' "${file}"
}

[[ -n "${SLURM_JOB_ID:-}" ]] || die "submit with sbatch"
[[ -f "${IMAGE_ENV}" ]] || die "IMAGE.env missing: ${IMAGE_ENV}"
[[ -x "${SOURCE_MATRIX_RUNNER}" ]] || die "matrix runner missing: ${SOURCE_MATRIX_RUNNER}"
[[ -x "${SOURCE_REPLAY_RUNNER}" ]] || die "replay runner missing: ${SOURCE_REPLAY_RUNNER}"
[[ "${SMOKE_ROOT}" =~ ^/scratch/jchen73/eclipsefuzz/aflnet/smoke/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || \
  die "AF_SMOKE_ROOT must be one named child of /scratch/jchen73/eclipsefuzz/aflnet/smoke"
[[ ! -e "${SMOKE_ROOT}" ]] || die "refusing to reuse smoke root: ${SMOKE_ROOT}"

image_status="$(env_value status "${IMAGE_ENV}")"
image_root="$(env_value image_root "${IMAGE_ENV}")"
sif_name="$(env_value sif_name "${IMAGE_ENV}")"
sif_sha256="$(env_value sif_sha256 "${IMAGE_ENV}")"
seed_count="$(env_value seed_count "${IMAGE_ENV}")"
image_apptainer_version="$(env_value apptainer_version "${IMAGE_ENV}")"
sif_source="${image_root}/${sif_name}"
[[ "${image_status}" == awaiting_smoke ]] || die "IMAGE.env status is ${image_status}"
[[ "${seed_count}" == "${EXPECTED_SEEDS}" ]] || die "smoke requires selected10 image"
[[ "${image_root}" =~ ^/scratch/jchen73/eclipsefuzz/aflnet/images/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || \
  die "IMAGE.env contains an invalid image root"
[[ "$(realpath -e "${IMAGE_ENV}")" == "$(realpath -e "${image_root}")/IMAGE.env" ]] || \
  die "IMAGE.env must be the build contract in its image root"
[[ -f "${sif_source}" ]] || die "SIF missing: ${sif_source}"
[[ "$("${APPTAINER}" version)" == "${image_apptainer_version}" ]] || die "Apptainer version drift"

mkdir -p "${SMOKE_ROOT}/manifest"
cp "${SOURCE_MATRIX_RUNNER}" "${SMOKE_ROOT}/manifest/run_storage_matrix.sbatch"
cp "${SOURCE_REPLAY_RUNNER}" "${SMOKE_ROOT}/manifest/replay_storage_matrix.sbatch"
chmod 0555 "${SMOKE_ROOT}/manifest/run_storage_matrix.sbatch" \
  "${SMOKE_ROOT}/manifest/replay_storage_matrix.sbatch"
readonly MATRIX_RUNNER="${SMOKE_ROOT}/manifest/run_storage_matrix.sbatch"
readonly REPLAY_RUNNER="${SMOKE_ROOT}/manifest/replay_storage_matrix.sbatch"
readonly CAMPAIGN_ROOT="${SMOKE_ROOT}/job-${SLURM_JOB_ID}"
mkdir -p "${CAMPAIGN_ROOT}/manifest" \
  "${CAMPAIGN_ROOT}/profiles/file" "${CAMPAIGN_ROOT}/profiles/memory"

local_parent="${SLURM_TMPDIR:-/tmp}"
local_root="$(mktemp -d "${local_parent}/aflnet-smoke-${SLURM_JOB_ID}.XXXXXX")"
job_pids=()
cleanup() {
  local pid
  for pid in "${job_pids[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  if [[ -d "${local_root}" ]]; then
    chmod -R u+w "${local_root}" 2>/dev/null || true
    rm -rf -- "${local_root}"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "${local_root}/apptainer-tmp" "${local_root}/cache"
export APPTAINER_TMPDIR="${local_root}/apptainer-tmp"
export APPTAINER_CACHEDIR="${local_root}/cache"
local_sif="${local_root}/image.sif"
local_sandbox="${local_root}/rootfs"
cp "${sif_source}" "${local_sif}"
printf '%s  %s\n' "${sif_sha256}" "${local_sif}" | sha256sum -c -
"${APPTAINER}" build --sandbox "${local_sandbox}" "${local_sif}"

cpu_model="$(lscpu | awk -F: '$1 ~ /^Model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}')"
sockets="$(lscpu | awk -F: '$1 ~ /^Socket\(s\)/ {gsub(/[[:space:]]/, "", $2); print $2; exit}')"
cores_per_socket="$(lscpu | awk -F: '$1 ~ /^Core\(s\) per socket/ {gsub(/[[:space:]]/, "", $2); print $2; exit}')"
threads_per_core="$(lscpu | awk -F: '$1 ~ /^Thread\(s\) per core/ {gsub(/[[:space:]]/, "", $2); print $2; exit}')"
[[ "${cpu_model}" == "${EXPECTED_CPU_MODEL}" ]] || die "unexpected CPU model: ${cpu_model}"
[[ "${sockets}" == 2 && "${cores_per_socket}" == 32 && "${threads_per_core}" == 1 ]] || \
  die "unexpected CPU topology"

local_filesystem="$(stat -f -c %T "${local_root}")"
case "${local_filesystem}" in
  tmpfs|ramfs) die "node-local smoke root is memory-backed (${local_filesystem})" ;;
esac
host_net="$(readlink /proc/self/ns/net)"
host_pid="$(readlink /proc/self/ns/pid)"
# The substitutions intentionally execute inside the contained shell.
# shellcheck disable=SC2016
read -r probe_net probe_pid < <("${APPTAINER}" exec --containall --cleanenv --net --network none \
  "${local_sandbox}" /bin/bash -c 'printf "%s %s\n" "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/pid)"')
[[ -n "${probe_net}" && "${probe_net}" != "${host_net}" ]] || \
  die "Apptainer --network none did not create a private network namespace"
[[ -n "${probe_pid}" && "${probe_pid}" != "${host_pid}" ]] || \
  die "Apptainer --containall did not create a private PID namespace"

for storage_mode in file memory; do
  profile_root="${CAMPAIGN_ROOT}/profiles/${storage_mode}"
  {
    printf 'started=%s\ninstances=1\nfuzz_seconds=%s\nsnapshot_interval=%s\n' \
      "$(date -Iseconds)" "${SMOKE_SECONDS}" "${SNAPSHOT_INTERVAL}"
    printf 'fuzzer=aflnet\ncorpus_variant=selected10\nseed_count=10\n'
    printf 'storage_profile=%s\ncoverage_mode=replay\ncoverage_kind=saved_queue_replay\n' "${storage_mode}"
    printf 'coverage_binary=/opt/fuzzer/aflnet-chip-all-clusters-app-cov\n'
    printf 'execution_mode=slurm-apptainer-private-netns\nnetwork=none\n'
  } > "${profile_root}/eval-meta.txt"
done

for storage_mode in file memory; do
  AF_FUZZ_SECONDS="${SMOKE_SECONDS}" \
  AF_SNAPSHOT_INTERVAL="${SNAPSHOT_INTERVAL}" \
  srun --exclusive -N1 -n1 -c1 --cpu-bind=cores \
    "${MATRIX_RUNNER}" --instance "${storage_mode}" 1 "${local_sandbox}" \
      "${CAMPAIGN_ROOT}" "${APPTAINER}" "${local_root}" "${EXPECTED_SEEDS}" &
  job_pids+=("$!")
done

failures=0
for pid in "${job_pids[@]}"; do
  if ! wait "${pid}"; then
    failures=$((failures + 1))
  fi
done
job_pids=()
(( failures == 0 )) || die "fuzz smoke failed: ${failures}/2 instances"
touch "${CAMPAIGN_ROOT}/profiles/file/fuzz.complete" \
  "${CAMPAIGN_ROOT}/profiles/memory/fuzz.complete"

for storage_mode in file memory; do
  AF_SNAPSHOT_INTERVAL="${SNAPSHOT_INTERVAL}" \
  srun --exclusive -N1 -n1 -c1 --cpu-bind=cores \
    "${REPLAY_RUNNER}" --instance "${storage_mode}" 1 "${local_sandbox}" \
      "${CAMPAIGN_ROOT}" "${APPTAINER}" "${local_root}" 1 &
  job_pids+=("$!")
done
failures=0
for pid in "${job_pids[@]}"; do
  if ! wait "${pid}"; then
    failures=$((failures + 1))
  fi
done
job_pids=()
(( failures == 0 )) || die "coverage replay smoke failed: ${failures}/2 instances"

for storage_mode in file memory; do
  profile_root="${CAMPAIGN_ROOT}/profiles/${storage_mode}"
  "${APPTAINER}" exec --contain --cleanenv \
    --bind "${profile_root}:/campaign" \
    --pwd /campaign \
    --env PATH=/opt/llvm:/usr/bin:/bin \
    --env DEBUGINFOD_URLS= \
    "${local_sandbox}" python3 /opt/fuzzer/aggregate_coverage_over_time.py \
      --eval-dir /campaign \
      --binary /opt/fuzzer/aflnet-chip-all-clusters-app-cov \
      --scope clusters \
      --jobs 1 \
    > "${profile_root}/aggregation.log" 2>&1
  [[ -s "${profile_root}/coverage_over_time.csv" ]] || \
    die "${storage_mode}: aggregate smoke CSV missing"
  python3 - "${profile_root}/coverage_aggregation.json" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if data.get("status") != "pass" or len(data.get("instances", [])) != 1:
    raise SystemExit("invalid smoke aggregation evidence")
PY
done

{
  printf 'slurm_job_id=%s\nnode=%s\n' "${SLURM_JOB_ID}" "$(hostname)"
  printf 'apptainer=%s\nsif_source=%s\nsif_sha256=%s\n' \
    "$("${APPTAINER}" --version)" "${sif_source}" "${sif_sha256}"
  printf 'cpu_model=%s\nsockets=%s\ncores_per_socket=%s\nthreads_per_core=%s\n' \
    "${cpu_model}" "${sockets}" "${cores_per_socket}" "${threads_per_core}"
  printf 'node_local_filesystem=%s\nhost_net_namespace=%s\nnetwork_probe_namespace=%s\n' \
    "${local_filesystem}" "${host_net}" "${probe_net}"
  printf 'host_pid_namespace=%s\npid_probe_namespace=%s\n' "${host_pid}" "${probe_pid}"
} > "${CAMPAIGN_ROOT}/manifest/runtime.env"
cp "${IMAGE_ENV}" "${CAMPAIGN_ROOT}/manifest/IMAGE.env"
scontrol show job -dd "${SLURM_JOB_ID}" > "${CAMPAIGN_ROOT}/manifest/slurm-job.txt"

smoke_env="${image_root}/SMOKE-${SLURM_JOB_ID}.env"
[[ ! -e "${smoke_env}" ]] || die "smoke evidence already exists: ${smoke_env}"
image_env_sha256="$(sha256sum "${IMAGE_ENV}" | awk '{print $1}')"
{
  printf 'status=script_ok\nsmoke_job_id=%s\nsmoke_node=%s\n' \
    "${SLURM_JOB_ID}" "$(hostname)"
  printf 'smoke_evidence_root=%s\nsmoke_profiles=file,memory\n' "${CAMPAIGN_ROOT}"
  printf 'smoke_seconds=%s\nsmoke_result_count=2\nsmoke_exit_zero_count=2\n' "${SMOKE_SECONDS}"
  printf 'smoke_initial_corpus_complete_count=2\nsmoke_replay_complete_count=2\nsmoke_aggregation_pass_count=2\n'
  printf 'matrix_runner_sha256=%s\nreplay_runner_sha256=%s\n' \
    "$(sha256sum "${MATRIX_RUNNER}" | awk '{print $1}')" \
    "$(sha256sum "${REPLAY_RUNNER}" | awk '{print $1}')"
  printf 'smoke_script_sha256=%s\n' "$(sha256sum "${BASH_SOURCE[0]}" | awk '{print $1}')"
  printf 'smoke_image_root=%s\nsmoke_image_env_sha256=%s\nsmoke_sif_sha256=%s\n' \
    "${image_root}" "${image_env_sha256}" "${sif_sha256}"
  printf 'network_isolation=apptainer-network-none\nprocess_isolation=apptainer-containall-pid\n'
  printf 'file_storage_filesystem=%s\n' "${local_filesystem}"
  printf 'validated_memory_per_instance=8G\n'
} > "${smoke_env}"

touch "${CAMPAIGN_ROOT}/SMOKE_SCRIPT_OK"
echo "SMOKE_OK job=${SLURM_JOB_ID} node=$(hostname) evidence=${CAMPAIGN_ROOT}"
echo "NEXT=after sacct reports COMPLETED 0:0, run seal_ready.sh --image-env ${IMAGE_ENV} --smoke-env ${smoke_env}"
