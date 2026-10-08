#!/usr/bin/env bash
# Run the selected10 AFLNet storage matrix on one Hopper AMD node:
# 10 file-backed replicas + 10 in-memory ablation replicas, one core each.
#
# Submit only through submit_storage_matrix.sh. The two profiles deliberately
# share one allocation and start together so CPU model, node and time block are
# held constant. Each actual fuzz process runs in its own `--network none`
# namespace; production is rejected if Hopper cannot create that namespace.
#SBATCH --job-name=aflnet-storage
#SBATCH --partition=normal
#SBATCH --constraint=amd
#SBATCH --nodes=1
#SBATCH --ntasks=20
#SBATCH --cpus-per-task=1
#SBATCH --mem-per-cpu=8G
#SBATCH --time=25:00:00

set -euo pipefail

readonly APPTAINER_DEFAULT=/opt/sw/other/apps/apptainer/1.4.1/bin/apptainer
readonly EXPECTED_CPU_MODEL="AMD EPYC 7543 32-Core Processor"
readonly EXPECTED_SOCKETS=2
readonly EXPECTED_CORES_PER_SOCKET=32
readonly EXPECTED_THREADS_PER_CORE=1
readonly FUZZ_SECONDS="${AF_FUZZ_SECONDS:-86400}"
readonly SNAPSHOT_INTERVAL="${AF_SNAPSHOT_INTERVAL:-1800}"
readonly REPLICAS_PER_PROFILE="${AF_REPLICAS_PER_PROFILE:-10}"
readonly EXPECTED_SEEDS="${AF_EXPECTED_SEEDS:-10}"

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

run_value() {
  env_value "$1" "$2/run.env"
}

run_instance() {
  local storage_mode="$1" replica="$2" runtime_root="$3" campaign_root="$4"
  local apptainer="$5" local_root="$6" expected_seeds="$7"
  local idx instance profile_root state_root tmp_root state_fs
  local host_net container_net host_pid container_pid

  case "${storage_mode}" in
    file|memory) ;;
    *) die "invalid storage mode: ${storage_mode}" ;;
  esac
  printf -v idx '%02d' "${replica}"
  profile_root="${campaign_root}/profiles/${storage_mode}"
  instance="${profile_root}/instance-${idx}"
  state_root="${local_root}/states/${storage_mode}-${idx}"
  tmp_root="${local_root}/instance-tmp/${storage_mode}-${idx}"
  [[ ! -e "${instance}" ]] || die "refusing to overwrite existing instance: ${instance}"
  mkdir -p "${instance}/dut-state" "${state_root}" "${tmp_root}"

  state_fs="$(stat -f -c %T "${state_root}")"
  if [[ "${storage_mode}" == file ]]; then
    case "${state_fs}" in
      tmpfs|ramfs) die "file profile resolved to memory-backed ${state_fs}: ${state_root}" ;;
    esac
  fi

  host_net="$(readlink /proc/self/ns/net)"
  host_pid="$(readlink /proc/self/ns/pid)"
  {
    printf 'storage_profile=%s\nreplica=%s\nnode=%s\n' \
      "${storage_mode}" "${replica}" "$(hostname)"
    printf 'slurm_job_id=%s\nslurm_step_id=%s\n' \
      "${SLURM_JOB_ID:-smoke}" "${SLURM_STEP_ID:-unknown}"
    printf 'cpus_allowed_list=%s\n' \
      "$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status)"
    printf 'host_net_namespace=%s\nhost_pid_namespace=%s\nstate_filesystem=%s\n' \
      "${host_net}" "${host_pid}" "${state_fs}"
    printf 'state_location=node-local-temporary\n'
  } > "${instance}/slurm-instance.env"

  set +e
  "${apptainer}" exec --containall --cleanenv --net --network none \
    --bind "${instance}:/workdir/output" \
    --bind "${state_root}:/workdir/output/dut-state" \
    --bind "${tmp_root}:/tmp" \
    --pwd /opt/fuzzer \
    --env HOME=/tmp \
    --env TMPDIR=/tmp \
    --env FUZZ_SECONDS="${FUZZ_SECONDS}" \
    --env FUZZ_PORT=5560 \
    --env DELAY_US=10000 \
    --env POLL_MS=100 \
    --env CALIBRATE=0 \
    --env TRANSPORT=udp \
    --env INSTANCE="instance-${idx}" \
    --env SNAPSHOT_INTERVAL="${SNAPSHOT_INTERVAL}" \
    --env STORAGE_MODE="${storage_mode}" \
    "${runtime_root}" /bin/bash -c \
      'readlink /proc/self/ns/net > /workdir/output/apptainer-netns.txt; readlink /proc/self/ns/pid > /workdir/output/apptainer-pidns.txt; exec /opt/fuzzer/entrypoint.sh' \
    > "${instance}/slurm-launcher.log" 2>&1
  local instance_rc=$?
  set -e

  printf 'container_exit=%s\n' "${instance_rc}" >> "${instance}/run.env"
  container_net="$(cat "${instance}/apptainer-netns.txt" 2>/dev/null || true)"
  container_pid="$(cat "${instance}/apptainer-pidns.txt" 2>/dev/null || true)"
  printf 'container_net_namespace=%s\ncontainer_pid_namespace=%s\n' \
    "${container_net:-missing}" "${container_pid:-missing}" \
    >> "${instance}/slurm-instance.env"

  # The KVS must exercise a node-local disk during fuzzing. Persist the exact
  # file afterwards so the run remains auditable when node-local storage is
  # removed at job exit.
  if [[ -f "${state_root}/kvs" ]]; then
    cp --preserve=mode,timestamps "${state_root}/kvs" "${instance}/dut-state/kvs"
  fi

  [[ "${instance_rc}" == 0 ]] || die "${storage_mode}/${idx}: entrypoint exited ${instance_rc}"
  [[ -n "${container_net}" && "${container_net}" != "${host_net}" ]] || \
    die "${storage_mode}/${idx}: Apptainer did not create a private network namespace"
  [[ -n "${container_pid}" && "${container_pid}" != "${host_pid}" ]] || \
    die "${storage_mode}/${idx}: Apptainer did not create a private PID namespace"
  [[ -f "${instance}/.done" ]] || die "${storage_mode}/${idx}: .done missing"
  [[ "$(run_value status "${instance}")" == ok ]] || \
    die "${storage_mode}/${idx}: run.env status is not ok"
  [[ "$(run_value storage_mode "${instance}")" == "${storage_mode}" ]] || \
    die "${storage_mode}/${idx}: recorded storage mode differs"
  [[ "$(run_value seeds "${instance}")" == "${expected_seeds}" ]] || \
    die "${storage_mode}/${idx}: embedded seed count differs"
  [[ "$(run_value initial_queue_entries "${instance}")" == "${expected_seeds}" ]] || \
    die "${storage_mode}/${idx}: initial corpus was not fully calibrated"

  local observed minimum
  observed="$(run_value observed_fuzz_seconds "${instance}")"
  minimum=$(( FUZZ_SECONDS > 10 ? FUZZ_SECONDS - 5 : 1 ))
  if [[ ! "${observed}" =~ ^[0-9]+$ ]] || (( observed < minimum )); then
    die "${storage_mode}/${idx}: observed budget ${observed:-missing}, expected >= ${minimum}"
  fi

  if [[ "${storage_mode}" == file ]]; then
    [[ "$(run_value storage_delegate "${instance}")" == linux-file-backed ]] || \
      die "file/${idx}: wrong delegate"
    [[ "$(run_value storage_filesystem "${instance}")" == "${state_fs}" ]] || \
      die "file/${idx}: recorded filesystem differs from node-local filesystem"
    [[ -s "${instance}/dut-state/kvs" ]] || die "file/${idx}: persisted KVS is missing"
    [[ "$(sha256sum "${instance}/dut-state/kvs" | awk '{print $1}')" == \
       "$(run_value kvs_sha256 "${instance}")" ]] || die "file/${idx}: persisted KVS hash differs"
  else
    [[ "$(run_value storage_delegate "${instance}")" == test-in-memory ]] || \
      die "memory/${idx}: wrong delegate"
    # The common --KVS CLI may create an empty placeholder even though the DUT
    # selected TestPersistentStorageDelegate. Require zero persisted bytes;
    # file existence alone does not identify the active delegate.
    [[ "$(run_value kvs_bytes "${instance}")" == 0 ]] || \
      die "memory/${idx}: unexpected persisted KVS bytes"
  fi

  touch "${instance}/slurm-instance.complete"
  echo "INSTANCE_OK storage=${storage_mode} replica=${idx} node=$(hostname)"
}

if [[ "${1:-}" == --instance ]]; then
  shift
  [[ $# -eq 7 ]] || die "internal --instance expects 7 arguments"
  run_instance "$@"
  exit $?
fi

[[ -n "${SLURM_JOB_ID:-}" ]] || die "submit with sbatch; direct execution is unsupported"
[[ "${FUZZ_SECONDS}" == 86400 && "${SNAPSHOT_INTERVAL}" == 1800 && \
   "${REPLICAS_PER_PROFILE}" == 10 && "${EXPECTED_SEEDS}" == 10 ]] || \
  die "production constants must be 10+10 replicas, 10 seeds, 86400s and 1800s snapshots"
[[ "${SLURM_NTASKS:-}" == 20 ]] || die "canonical matrix requires --ntasks=20"

readonly READY_FILE="${AF_READY_FILE:?submitter must export AF_READY_FILE}"
readonly CAMPAIGN_ID="${AF_CAMPAIGN_ID:?submitter must export AF_CAMPAIGN_ID}"
readonly CAMPAIGN_ROOT="${AF_CAMPAIGN_ROOT:?submitter must export AF_CAMPAIGN_ROOT}"
readonly SELF="${AF_RUNNER_SCRIPT:?submitter must export AF_RUNNER_SCRIPT}"
readonly SELF_SHA256="${AF_RUNNER_SCRIPT_SHA256:?submitter must export AF_RUNNER_SCRIPT_SHA256}"
readonly APPTAINER="${AF_APPTAINER:-${APPTAINER_DEFAULT}}"

[[ -f "${READY_FILE}" ]] || die "READY file missing: ${READY_FILE}"
[[ -x "${SELF}" ]] || die "frozen matrix runner is not executable: ${SELF}"
[[ "${CAMPAIGN_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "invalid campaign id"
[[ "${CAMPAIGN_ROOT}" == "/scratch/jchen73/eclipsefuzz/aflnet/campaigns/${CAMPAIGN_ID}" ]] || \
  die "campaign root does not exactly match campaign id"
[[ "${SELF}" == "${CAMPAIGN_ROOT}/manifest/run_storage_matrix.sbatch" ]] || \
  die "runner must be the copy frozen in the campaign manifest"
printf '%s  %s\n' "${SELF_SHA256}" "${SELF}" | sha256sum -c - >/dev/null || \
  die "campaign runner hash mismatch"
cmp -s "${READY_FILE}" "${CAMPAIGN_ROOT}/manifest/READY.env" || \
  die "READY contract differs from the campaign manifest copy"
[[ -x "${APPTAINER}" ]] || die "Apptainer missing: ${APPTAINER}"

ready_status="$(env_value status "${READY_FILE}")"
image_root="$(env_value image_root "${READY_FILE}")"
sif_name="$(env_value sif_name "${READY_FILE}")"
sif_sha256="$(env_value sif_sha256 "${READY_FILE}")"
seed_count="$(env_value seed_count "${READY_FILE}")"
ready_apptainer_version="$(env_value apptainer_version "${READY_FILE}")"
smoked_runner_sha256="$(env_value matrix_runner_sha256 "${READY_FILE}")"
[[ "${ready_status}" == ready ]] || die "image contract is not ready: ${ready_status}"
[[ "${seed_count}" == 10 ]] || die "READY is not a selected10 image"
[[ "${smoked_runner_sha256}" == "${SELF_SHA256}" ]] || \
  die "matrix runner differs from the script that passed smoke"
[[ "${image_root}" =~ ^/scratch/jchen73/eclipsefuzz/aflnet/images/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || \
  die "READY contains an invalid image root"
[[ "$(realpath -e "${READY_FILE}")" == "$(realpath -e "${image_root}")/READY.env" ]] || \
  die "READY must be the sealed contract in its image root"
[[ "$("${APPTAINER}" version)" == "${ready_apptainer_version}" ]] || \
  die "Apptainer version drift"
readonly SIF_SOURCE="${image_root}/${sif_name}"
[[ -f "${SIF_SOURCE}" ]] || die "SIF missing: ${SIF_SOURCE}"

readonly JOB_ROOT="${CAMPAIGN_ROOT}/jobs/fuzz-${SLURM_JOB_ID}"
[[ ! -e "${JOB_ROOT}" ]] || die "job evidence path already exists: ${JOB_ROOT}"
[[ ! -e "${CAMPAIGN_ROOT}/profiles/file" && ! -e "${CAMPAIGN_ROOT}/profiles/memory" ]] || \
  die "one or both profile result roots already exist"
mkdir -p "${JOB_ROOT}/manifest" "${CAMPAIGN_ROOT}/profiles/file" "${CAMPAIGN_ROOT}/profiles/memory"

local_parent="${SLURM_TMPDIR:-/tmp}"
local_root="$(mktemp -d "${local_parent}/aflnet-storage-${SLURM_JOB_ID}.XXXXXX")"
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

cpu_model="$(lscpu | awk -F: '$1 ~ /^Model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}')"
sockets="$(lscpu | awk -F: '$1 ~ /^Socket\(s\)/ {gsub(/[[:space:]]/, "", $2); print $2; exit}')"
cores_per_socket="$(lscpu | awk -F: '$1 ~ /^Core\(s\) per socket/ {gsub(/[[:space:]]/, "", $2); print $2; exit}')"
threads_per_core="$(lscpu | awk -F: '$1 ~ /^Thread\(s\) per core/ {gsub(/[[:space:]]/, "", $2); print $2; exit}')"
[[ "${cpu_model}" == "${EXPECTED_CPU_MODEL}" ]] || die "unexpected CPU model: ${cpu_model}"
[[ "${sockets}" == "${EXPECTED_SOCKETS}" && "${cores_per_socket}" == "${EXPECTED_CORES_PER_SOCKET}" && \
   "${threads_per_core}" == "${EXPECTED_THREADS_PER_CORE}" ]] || die "unexpected CPU topology"

local_filesystem="$(stat -f -c %T "${local_root}")"
case "${local_filesystem}" in
  tmpfs|ramfs) die "node-local work root is memory-backed (${local_filesystem}); file profile would be invalid" ;;
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

"${APPTAINER}" exec --contain --cleanenv "${local_sandbox}" \
  python3 /opt/fuzzer/validate_input_bundle.py verify \
    --seeds /opt/fuzzer/seeds --dictionary /opt/fuzzer/matter.dict \
    --projection /opt/fuzzer/input-projection.json \
    --fidelity /opt/fuzzer/input-fidelity.json \
    --manifest /opt/fuzzer/input-manifest.json \
  > "${JOB_ROOT}/manifest/input-bundle-check.log"
actual_seed_count="$(find "${local_sandbox}/opt/fuzzer/seeds" -maxdepth 1 -type f -name '*.raw' -printf '.\n' | wc -l)"
[[ "${actual_seed_count}" == "${seed_count}" ]] || die "expanded SIF seed count differs"

{
  printf 'slurm_job_id=%s\nnode=%s\npartition=%s\naccount=%s\n' \
    "${SLURM_JOB_ID}" "$(hostname)" "${SLURM_JOB_PARTITION:-unknown}" "${SLURM_JOB_ACCOUNT:-auto}"
  printf 'profiles=file,memory\nreplicas_per_profile=%s\ntotal_instances=20\n' "${REPLICAS_PER_PROFILE}"
  printf 'launch_order=interleaved-profile-pairs\n'
  printf 'fuzz_seconds=%s\nsnapshot_interval=%s\n' "${FUZZ_SECONDS}" "${SNAPSHOT_INTERVAL}"
  printf 'apptainer=%s\nsif_source=%s\nsif_sha256=%s\n' \
    "$("${APPTAINER}" --version)" "${SIF_SOURCE}" "${sif_sha256}"
  printf 'cpu_model=%s\nsockets=%s\ncores_per_socket=%s\nthreads_per_core=%s\n' \
    "${cpu_model}" "${sockets}" "${cores_per_socket}" "${threads_per_core}"
  printf 'node_local_root=%s\nnode_local_filesystem=%s\n' "${local_root}" "${local_filesystem}"
  printf 'host_net_namespace=%s\nnetwork_probe_namespace=%s\n' "${host_net}" "${probe_net}"
  printf 'host_pid_namespace=%s\npid_probe_namespace=%s\n' "${host_pid}" "${probe_pid}"
  grep -E '^(Cpus_allowed_list|Mems_allowed_list):' /proc/self/status | tr '\t' '='
} > "${JOB_ROOT}/manifest/runtime.env"
cp "${READY_FILE}" "${JOB_ROOT}/manifest/READY.env"
sha256sum "${SELF}" > "${JOB_ROOT}/manifest/runner-script.sha256"
scontrol show job -dd "${SLURM_JOB_ID}" > "${JOB_ROOT}/manifest/slurm-job.txt"

for storage_mode in file memory; do
  profile_root="${CAMPAIGN_ROOT}/profiles/${storage_mode}"
  {
    printf 'started=%s\ninstances=%s\nfuzz_seconds=%s\nsnapshot_interval=%s\n' \
      "$(date -Iseconds)" "${REPLICAS_PER_PROFILE}" "${FUZZ_SECONDS}" "${SNAPSHOT_INTERVAL}"
    printf 'fuzzer=aflnet\ncorpus_variant=selected10\nseed_count=%s\n' "${seed_count}"
    printf 'storage_profile=%s\ncoverage_mode=replay\ncoverage_kind=saved_queue_replay\n' "${storage_mode}"
    printf 'coverage_binary=/opt/fuzzer/aflnet-chip-all-clusters-app-cov\n'
    printf 'execution_mode=slurm-apptainer-private-netns\nnetwork=none\n'
    printf 'replica_model=independent\nrng_source=afl-dev-urandom\nrng_seed_control=unavailable\n'
    printf 'node=%s\nsif_sha256=%s\n' "$(hostname)" "${sif_sha256}"
  } > "${profile_root}/eval-meta.txt"
done

for replica in $(seq 1 "${REPLICAS_PER_PROFILE}"); do
  for storage_mode in file memory; do
    srun --exclusive -N1 -n1 -c1 --cpu-bind=cores \
      "${SELF}" --instance "${storage_mode}" "${replica}" "${local_sandbox}" \
        "${CAMPAIGN_ROOT}" "${APPTAINER}" "${local_root}" "${seed_count}" &
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

for storage_mode in file memory; do
  profile_root="${CAMPAIGN_ROOT}/profiles/${storage_mode}"
  printf 'ended_fuzzing=%s\n' "$(date -Iseconds)" >> "${profile_root}/eval-meta.txt"
  complete_count="$(find "${profile_root}" -mindepth 2 -maxdepth 2 -name slurm-instance.complete -printf '.\n' | wc -l)"
  printf 'profile=%s\nreplicas=%s\ncomplete_instances=%s\n' \
    "${storage_mode}" "${REPLICAS_PER_PROFILE}" "${complete_count}" \
    > "${profile_root}/fuzz-result.env"
  [[ "${complete_count}" == "${REPLICAS_PER_PROFILE}" ]] || \
    failures=$((failures + 1))
done

printf 'profiles=2\ninstances=20\nfailures=%s\n' "${failures}" > "${JOB_ROOT}/job.result.env"
(( failures == 0 )) || die "storage matrix failed; failure count=${failures}"

touch "${CAMPAIGN_ROOT}/profiles/file/fuzz.complete"
touch "${CAMPAIGN_ROOT}/profiles/memory/fuzz.complete"
touch "${JOB_ROOT}/job.complete"
echo "FUZZ_MATRIX_OK file=10 memory=10 job=${SLURM_JOB_ID} node=$(hostname)"
