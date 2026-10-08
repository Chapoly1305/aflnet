#!/usr/bin/env bash
# Replay and aggregate both completed AFLNet storage profiles.
#
# submit_storage_matrix.sh submits this job with afterok on the 20-instance fuzz
# job. Twenty two-core replay steps run concurrently; each instance gets
# its own private network namespace. Coverage is then aggregated separately for
# file and memory. The campaign-level .done appears only after both pass.
#SBATCH --job-name=aflnet-replay
#SBATCH --partition=normal
#SBATCH --constraint=amd
#SBATCH --nodes=1
#SBATCH --ntasks=20
#SBATCH --cpus-per-task=2
#SBATCH --mem-per-cpu=4G
#SBATCH --time=12:00:00

set -euo pipefail

readonly APPTAINER_DEFAULT=/opt/sw/other/apps/apptainer/1.4.1/bin/apptainer
readonly REPLAY_WORKERS="${AF_REPLAY_WORKERS:-2}"
readonly AGGREGATE_WORKERS="${AF_AGGREGATE_WORKERS:-8}"
readonly SNAPSHOT_INTERVAL="${AF_SNAPSHOT_INTERVAL:-1800}"
readonly REPLICAS_PER_PROFILE="${AF_REPLICAS_PER_PROFILE:-10}"

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

replay_instance() {
  local storage_mode="$1" replica="$2" runtime_root="$3" campaign_root="$4"
  local apptainer="$5" local_root="$6" workers="$7"
  local idx profile_root instance tmp_root
  printf -v idx '%02d' "${replica}"
  profile_root="${campaign_root}/profiles/${storage_mode}"
  instance="${profile_root}/instance-${idx}"
  tmp_root="${local_root}/replay-tmp/${storage_mode}-${idx}"
  [[ -f "${instance}/slurm-instance.complete" ]] || \
    die "${storage_mode}/${idx}: successful fuzz evidence missing"
  [[ "$(env_value status "${instance}/run.env")" == ok ]] || \
    die "${storage_mode}/${idx}: run.env status is not ok"
  [[ "$(env_value storage_mode "${instance}/run.env")" == "${storage_mode}" ]] || \
    die "${storage_mode}/${idx}: storage mode differs"
  mkdir -p "${tmp_root}"

  "${apptainer}" exec --containall --cleanenv --net --network none \
    --bind "${profile_root}:/campaign" \
    --bind "${tmp_root}:/tmp" \
    --pwd /campaign \
    --env HOME=/tmp \
    --env TMPDIR=/tmp \
    --env PATH=/opt/llvm:/usr/bin:/bin \
    "${runtime_root}" python3 /opt/fuzzer/phase2_parallel.py \
      --eval-dir /campaign \
      --only "instance-${idx}" \
      --cov-dut /opt/fuzzer/aflnet-chip-all-clusters-app-cov \
      --interval "${SNAPSHOT_INTERVAL}" \
      --workers "${workers}" \
      --base-port 5800 \
    > "${instance}/phase2.log" 2>&1

  python3 - "${instance}/measurement.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
if data.get("status") != "complete" or data.get("coverage_kind") != "saved_queue_replay":
    raise SystemExit(f"invalid replay measurement: {path}")
if not isinstance(data.get("seed_count"), int) or data["seed_count"] <= 0:
    raise SystemExit(f"invalid replay seed count: {path}")
if not isinstance(data.get("snapshots"), int) or data["snapshots"] <= 0:
    raise SystemExit(f"invalid replay snapshot count: {path}")
PY
  touch "${instance}/replay.complete"
  echo "REPLAY_OK storage=${storage_mode} replica=${idx}"
}

if [[ "${1:-}" == --instance ]]; then
  shift
  [[ $# -eq 7 ]] || die "internal --instance expects 7 arguments"
  replay_instance "$@"
  exit $?
fi

[[ -n "${SLURM_JOB_ID:-}" ]] || die "submit with sbatch; direct execution is unsupported"
[[ "${REPLAY_WORKERS}" == 2 && "${AGGREGATE_WORKERS}" == 8 && \
   "${SNAPSHOT_INTERVAL}" == 1800 && "${REPLICAS_PER_PROFILE}" == 10 ]] || \
  die "production constants must be replay workers=2, aggregate workers=8, interval=1800, replicas=10"
[[ "${SLURM_NTASKS:-}" == 20 && "${SLURM_CPUS_PER_TASK:-}" == 2 ]] || \
  die "canonical replay job requires 20 tasks x 2 CPUs"

readonly READY_FILE="${AF_READY_FILE:?submitter must export AF_READY_FILE}"
readonly CAMPAIGN_ID="${AF_CAMPAIGN_ID:?submitter must export AF_CAMPAIGN_ID}"
readonly CAMPAIGN_ROOT="${AF_CAMPAIGN_ROOT:?submitter must export AF_CAMPAIGN_ROOT}"
readonly SELF="${AF_REPLAY_SCRIPT:?submitter must export AF_REPLAY_SCRIPT}"
readonly SELF_SHA256="${AF_REPLAY_SCRIPT_SHA256:?submitter must export AF_REPLAY_SCRIPT_SHA256}"
readonly APPTAINER="${AF_APPTAINER:-${APPTAINER_DEFAULT}}"

[[ -f "${READY_FILE}" ]] || die "READY file missing: ${READY_FILE}"
[[ -x "${SELF}" ]] || die "frozen replay runner is not executable: ${SELF}"
[[ "${CAMPAIGN_ROOT}" == "/scratch/jchen73/eclipsefuzz/aflnet/campaigns/${CAMPAIGN_ID}" ]] || \
  die "campaign root does not exactly match campaign id"
[[ "${SELF}" == "${CAMPAIGN_ROOT}/manifest/replay_storage_matrix.sbatch" ]] || \
  die "replay runner must be the copy frozen in the campaign manifest"
printf '%s  %s\n' "${SELF_SHA256}" "${SELF}" | sha256sum -c - >/dev/null || \
  die "campaign replay runner hash mismatch"
cmp -s "${READY_FILE}" "${CAMPAIGN_ROOT}/manifest/READY.env" || \
  die "READY contract differs from the campaign manifest copy"
[[ -x "${APPTAINER}" ]] || die "Apptainer missing: ${APPTAINER}"

ready_status="$(env_value status "${READY_FILE}")"
image_root="$(env_value image_root "${READY_FILE}")"
sif_name="$(env_value sif_name "${READY_FILE}")"
sif_sha256="$(env_value sif_sha256 "${READY_FILE}")"
ready_apptainer_version="$(env_value apptainer_version "${READY_FILE}")"
smoked_replay_sha256="$(env_value replay_runner_sha256 "${READY_FILE}")"
[[ "${ready_status}" == ready ]] || die "image contract is not ready"
[[ "${smoked_replay_sha256}" == "${SELF_SHA256}" ]] || \
  die "replay runner differs from the script that passed smoke"
[[ "$("${APPTAINER}" version)" == "${ready_apptainer_version}" ]] || \
  die "Apptainer version drift"
readonly SIF_SOURCE="${image_root}/${sif_name}"
[[ -f "${SIF_SOURCE}" ]] || die "SIF missing: ${SIF_SOURCE}"

[[ ! -e "${CAMPAIGN_ROOT}/campaign.done" ]] || die "campaign is already complete"
active_profiles=()
for storage_mode in file memory; do
  profile_root="${CAMPAIGN_ROOT}/profiles/${storage_mode}"
  [[ -f "${profile_root}/fuzz.complete" ]] || die "${storage_mode}: fuzz profile is incomplete"
  if [[ -f "${profile_root}/coverage.complete" && -f "${profile_root}/.done" ]]; then
    echo "REPLAY_SKIP storage=${storage_mode} reason=already-complete"
  elif [[ -e "${profile_root}/coverage.complete" || -e "${profile_root}/.done" ]]; then
    die "${storage_mode}: inconsistent partial coverage markers"
  else
    active_profiles+=("${storage_mode}")
  fi
done
(( ${#active_profiles[@]} > 0 )) || die "both profiles are already complete but campaign.done is missing"

readonly JOB_ROOT="${CAMPAIGN_ROOT}/jobs/replay-${SLURM_JOB_ID}"
[[ ! -e "${JOB_ROOT}" ]] || die "job evidence path already exists: ${JOB_ROOT}"
mkdir -p "${JOB_ROOT}/manifest"

local_parent="${SLURM_TMPDIR:-/tmp}"
local_root="$(mktemp -d "${local_parent}/aflnet-replay-${SLURM_JOB_ID}.XXXXXX")"
job_pids=()
cleanup_main() {
  local pid
  for pid in "${job_pids[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  if [[ -d "${local_root}" ]]; then
    chmod -R u+w "${local_root}" 2>/dev/null || true
    rm -rf -- "${local_root}"
  fi
}
trap cleanup_main EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "${local_root}/apptainer-tmp" "${local_root}/cache"
export APPTAINER_TMPDIR="${local_root}/apptainer-tmp"
export APPTAINER_CACHEDIR="${local_root}/cache"
local_sif="${local_root}/image.sif"
local_sandbox="${local_root}/rootfs"
cp "${SIF_SOURCE}" "${local_sif}"
printf '%s  %s\n' "${sif_sha256}" "${local_sif}" | sha256sum -c -
"${APPTAINER}" build --sandbox "${local_sandbox}" "${local_sif}"

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

{
  printf 'slurm_job_id=%s\nnode=%s\nstarted=%s\n' \
    "${SLURM_JOB_ID}" "$(hostname)" "$(date -Iseconds)"
  printf 'profiles=file,memory\nreplicas_per_profile=%s\nreplay_workers_per_instance=%s\n' \
    "${REPLICAS_PER_PROFILE}" "${REPLAY_WORKERS}"
  printf 'aggregate_workers=%s\nsif_sha256=%s\n' "${AGGREGATE_WORKERS}" "${sif_sha256}"
  printf 'host_net_namespace=%s\nnetwork_probe_namespace=%s\n' "${host_net}" "${probe_net}"
  printf 'host_pid_namespace=%s\npid_probe_namespace=%s\n' "${host_pid}" "${probe_pid}"
} > "${JOB_ROOT}/manifest/runtime.env"
cp "${READY_FILE}" "${JOB_ROOT}/manifest/READY.env"
sha256sum "${SELF}" > "${JOB_ROOT}/manifest/replay-script.sha256"
scontrol show job -dd "${SLURM_JOB_ID}" > "${JOB_ROOT}/manifest/slurm-job.txt"

for storage_mode in "${active_profiles[@]}"; do
  for replica in $(seq 1 "${REPLICAS_PER_PROFILE}"); do
    srun --exclusive -N1 -n1 -c"${REPLAY_WORKERS}" --cpu-bind=cores \
      "${SELF}" --instance "${storage_mode}" "${replica}" "${local_sandbox}" \
        "${CAMPAIGN_ROOT}" "${APPTAINER}" "${local_root}" "${REPLAY_WORKERS}" &
    job_pids+=("$!")
  done
done

failures=0
for pid in "${job_pids[@]}"; do
  if ! wait "${pid}"; then
    failures=$((failures + 1))
  fi
done
job_pids=()
(( failures == 0 )) || die "queue replay failed for ${failures}/20 instances"

for storage_mode in "${active_profiles[@]}"; do
  profile_root="${CAMPAIGN_ROOT}/profiles/${storage_mode}"
  replay_count="$(find "${profile_root}" -mindepth 2 -maxdepth 2 -name replay.complete -printf '.\n' | wc -l)"
  [[ "${replay_count}" == "${REPLICAS_PER_PROFILE}" ]] || \
    die "${storage_mode}: replay completion count is ${replay_count}"

  "${APPTAINER}" exec --contain --cleanenv \
    --bind "${profile_root}:/campaign" \
    --pwd /campaign \
    --env PATH=/opt/llvm:/usr/bin:/bin \
    --env DEBUGINFOD_URLS= \
    "${local_sandbox}" python3 /opt/fuzzer/aggregate_coverage_over_time.py \
      --eval-dir /campaign \
      --binary /opt/fuzzer/aflnet-chip-all-clusters-app-cov \
      --scope clusters \
      --jobs "${AGGREGATE_WORKERS}" \
    > "${profile_root}/aggregation.log" 2>&1

  [[ -s "${profile_root}/coverage_over_time.csv" ]] || \
    die "${storage_mode}: aggregate coverage CSV missing"
  python3 - "${profile_root}/coverage_aggregation.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
if data.get("status") != "pass" or len(data.get("instances", [])) != 10:
    raise SystemExit(f"invalid coverage aggregation evidence: {path}")
PY
  for timeline in "${profile_root}"/instance-*/timeline.csv; do
    [[ -f "${timeline}" ]] && sed -i "s#/campaign#${profile_root}#g" "${timeline}"
  done
  printf 'ended=%s\n' "$(date -Iseconds)" >> "${profile_root}/eval-meta.txt"
  touch "${profile_root}/coverage.complete" "${profile_root}/.done"
  echo "PROFILE_COVERAGE_OK storage=${storage_mode} instances=10"
done

for storage_mode in file memory; do
  [[ -f "${CAMPAIGN_ROOT}/profiles/${storage_mode}/coverage.complete" && \
     -f "${CAMPAIGN_ROOT}/profiles/${storage_mode}/.done" ]] || \
    die "${storage_mode}: final profile markers missing"
done
printf 'profiles=2\ninstances=20\nreplay_failures=0\n' > "${JOB_ROOT}/job.result.env"
touch "${JOB_ROOT}/job.complete" "${CAMPAIGN_ROOT}/campaign.done"
echo "REPLAY_MATRIX_OK file=10 memory=10 job=${SLURM_JOB_ID}"
