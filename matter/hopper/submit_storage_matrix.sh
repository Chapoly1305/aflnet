#!/usr/bin/env bash
# Validate and optionally submit selected10 AFLNet file/memory on Hopper.
# Default behavior is a read-only preview. --submit creates one 20-instance
# fuzz job and one dependent replay/aggregation job.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MATRIX_RUNNER="${SCRIPT_DIR}/run_storage_matrix.sbatch"
REPLAY_RUNNER="${SCRIPT_DIR}/replay_storage_matrix.sbatch"
STATUS_SCRIPT="${SCRIPT_DIR}/status.py"

READY_FILE=""
CAMPAIGN_ID=""
RESULT_BASE=/scratch/jchen73/eclipsefuzz/aflnet/campaigns
DO_SUBMIT=0

usage() {
  cat <<'EOF'
Usage: submit_storage_matrix.sh --ready-file PATH --campaign-id ID [options]

Required:
  --ready-file PATH   immutable, smoke-validated AFLNet READY.env on Hopper
  --campaign-id ID    new selected10 output identifier

Options:
  --result-base PATH  default: /scratch/jchen73/eclipsefuzz/aflnet/campaigns
  --submit            create the campaign root and submit the held jobs
  -h, --help          show this help

Without --submit, the script validates the sealed image and prints the exact
two-job submission. The fuzz job contains file=10 plus memory=10 on one AMD
node; replay starts only after all 20 fuzz instances pass.
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

ready_value() {
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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ready-file) READY_FILE="${2:?--ready-file needs a value}"; shift 2 ;;
    --campaign-id) CAMPAIGN_ID="${2:?--campaign-id needs a value}"; shift 2 ;;
    --result-base) RESULT_BASE="${2:?--result-base needs a value}"; shift 2 ;;
    --submit) DO_SUBMIT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "${READY_FILE}" ]] || die "--ready-file is required"
[[ -f "${READY_FILE}" ]] || die "READY file missing: ${READY_FILE}"
READY_FILE="$(realpath -e "${READY_FILE}")"
[[ -n "${CAMPAIGN_ID}" ]] || die "--campaign-id is required"
[[ "${CAMPAIGN_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "invalid campaign id"
[[ "${RESULT_BASE}" == /scratch/jchen73/eclipsefuzz/aflnet/campaigns ]] || \
  die "canonical result base is /scratch/jchen73/eclipsefuzz/aflnet/campaigns"
[[ -x "${MATRIX_RUNNER}" ]] || die "matrix runner is not executable: ${MATRIX_RUNNER}"
[[ -x "${REPLAY_RUNNER}" ]] || die "replay runner is not executable: ${REPLAY_RUNNER}"
[[ -f "${STATUS_SCRIPT}" ]] || die "status script missing: ${STATUS_SCRIPT}"

ready_status="$(ready_value status "${READY_FILE}")"
build_state="$(ready_value build_job_state "${READY_FILE}")"
build_exit="$(ready_value build_job_exit_code "${READY_FILE}")"
smoke_state="$(ready_value smoke_job_state "${READY_FILE}")"
smoke_exit="$(ready_value smoke_job_exit_code "${READY_FILE}")"
image_root="$(ready_value image_root "${READY_FILE}")"
sif_name="$(ready_value sif_name "${READY_FILE}")"
sif_sha256="$(ready_value sif_sha256 "${READY_FILE}")"
seed_count="$(ready_value seed_count "${READY_FILE}")"
corpus_variant="$(ready_value corpus_variant "${READY_FILE}")"
smoked_matrix_sha256="$(ready_value matrix_runner_sha256 "${READY_FILE}")"
smoked_replay_sha256="$(ready_value replay_runner_sha256 "${READY_FILE}")"
matrix_sha256="$(sha256sum "${MATRIX_RUNNER}" | awk '{print $1}')"
replay_sha256="$(sha256sum "${REPLAY_RUNNER}" | awk '{print $1}')"

[[ "${ready_status}" == ready ]] || die "READY status is ${ready_status}, not ready"
[[ "${build_state}" == COMPLETED && "${build_exit}" == 0:0 ]] || \
  die "READY build is not green: state=${build_state} exit=${build_exit}"
[[ "${smoke_state}" == COMPLETED && "${smoke_exit}" == 0:0 ]] || \
  die "READY smoke is not green: state=${smoke_state} exit=${smoke_exit}"
[[ "${corpus_variant}" == selected10 && "${seed_count}" == 10 ]] || \
  die "READY is not the selected10 corpus condition"
[[ "${matrix_sha256}" == "${smoked_matrix_sha256}" ]] || \
  die "run_storage_matrix.sbatch changed after smoke"
[[ "${replay_sha256}" == "${smoked_replay_sha256}" ]] || \
  die "replay_storage_matrix.sbatch changed after smoke"
[[ "${image_root}" =~ ^/scratch/jchen73/eclipsefuzz/aflnet/images/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || \
  die "READY contains an invalid image root"
[[ "$(realpath -e "${READY_FILE}")" == "$(realpath -e "${image_root}")/READY.env" ]] || \
  die "READY must be the sealed contract in its image root"
readonly SIF_SOURCE="${image_root}/${sif_name}"
[[ -f "${SIF_SOURCE}" ]] || die "SIF missing: ${SIF_SOURCE}"
printf '%s  %s\n' "${sif_sha256}" "${SIF_SOURCE}" | sha256sum -c - >/dev/null

campaign_root="${RESULT_BASE}/${CAMPAIGN_ID}"
echo "Hopper AFLNet selected10 storage matrix"
echo "  campaign:      ${CAMPAIGN_ID}"
echo "  image:         ${SIF_SOURCE}"
echo "  image sha:     ${sif_sha256}"
echo "  corpus:        selected10 (${seed_count} raw seeds per replica)"
echo "  fuzz profiles: file=10, memory=10"
echo "  placement:     one AMD node, concurrent, one core per instance"
echo "  fuzz budget:   86400 seconds per instance"
echo "  follow-up:     dependent queue replay + separate aggregation"
echo "  output:        ${campaign_root}"

fuzz_export="ALL,AF_READY_FILE=${READY_FILE},AF_CAMPAIGN_ID=${CAMPAIGN_ID},AF_CAMPAIGN_ROOT=${campaign_root},AF_RUNNER_SCRIPT=${campaign_root}/manifest/run_storage_matrix.sbatch,AF_RUNNER_SCRIPT_SHA256=${matrix_sha256}"
replay_export="ALL,AF_READY_FILE=${READY_FILE},AF_CAMPAIGN_ID=${CAMPAIGN_ID},AF_CAMPAIGN_ROOT=${campaign_root},AF_REPLAY_SCRIPT=${campaign_root}/manifest/replay_storage_matrix.sbatch,AF_REPLAY_SCRIPT_SHA256=${replay_sha256}"

if (( DO_SUBMIT == 0 )); then
  echo
  echo "DRY RUN: no directories created and no jobs submitted."
  printf 'FUZZ:   sbatch --hold --job-name=%q --output=%q --error=%q --export=%q %q\n' \
    "aflnet-storage" "${campaign_root}/slurm/fuzz-%j.out" \
    "${campaign_root}/slurm/fuzz-%j.err" "${fuzz_export}" \
    "${campaign_root}/manifest/run_storage_matrix.sbatch"
  printf 'REPLAY: sbatch --hold --dependency=afterok:<fuzz-job-id> --job-name=%q --output=%q --error=%q --export=%q %q\n' \
    "aflnet-replay" "${campaign_root}/slurm/replay-%j.out" \
    "${campaign_root}/slurm/replay-%j.err" "${replay_export}" \
    "${campaign_root}/manifest/replay_storage_matrix.sbatch"
  echo "RELEASE: scontrol release <fuzz-job-id>,<replay-job-id>"
  exit 0
fi

command -v sbatch >/dev/null || die "sbatch is unavailable; run on Hopper"
command -v scontrol >/dev/null || die "scontrol is unavailable; run on Hopper"
[[ ! -e "${campaign_root}" ]] || die "refusing to reuse campaign root: ${campaign_root}"
mkdir -p "${campaign_root}/manifest" "${campaign_root}/slurm" \
  "${campaign_root}/jobs" "${campaign_root}/profiles"

submission_sealed=0
record_incomplete_submission() {
  local rc=$?
  if (( submission_sealed == 0 )); then
    : > "${campaign_root}/manifest/submission.partial" || true
    echo "ERROR: submission stopped early; retain the manifest and inspect held jobs" >&2
  fi
  return "${rc}"
}
trap record_incomplete_submission EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cp "${MATRIX_RUNNER}" "${campaign_root}/manifest/run_storage_matrix.sbatch"
cp "${REPLAY_RUNNER}" "${campaign_root}/manifest/replay_storage_matrix.sbatch"
cp "${STATUS_SCRIPT}" "${campaign_root}/manifest/status.py"
cp "${READY_FILE}" "${campaign_root}/manifest/READY.env"
chmod 0555 "${campaign_root}/manifest/run_storage_matrix.sbatch" \
  "${campaign_root}/manifest/replay_storage_matrix.sbatch" \
  "${campaign_root}/manifest/status.py"

{
  printf 'schema=aflnet-hopper-selected10-storage-matrix.v1\n'
  printf 'campaign_id=%s\ncreated_at=%s\n' "${CAMPAIGN_ID}" "$(date -Iseconds)"
  printf 'platform=hopper\nruntime=slurm-apptainer\nfuzzer=aflnet\n'
  printf 'corpus_variant=selected10\nseed_count=10\nprofiles=file,memory\n'
  printf 'replicas_per_profile=10\ntotal_instances=20\nfuzz_seconds=86400\n'
  printf 'placement=same-node-same-time\npartition=normal\nconstraint=amd\n'
  printf 'launch_order=interleaved-profile-pairs\n'
  printf 'cpus_per_instance=1\nmem_per_instance=8G\n'
  printf 'ready_file=%s\nsif_sha256=%s\n' "${READY_FILE}" "${sif_sha256}"
  printf 'matrix_runner_sha256=%s\nreplay_runner_sha256=%s\n' \
    "${matrix_sha256}" "${replay_sha256}"
} > "${campaign_root}/manifest/campaign.env"

sha256sum "${campaign_root}/manifest/run_storage_matrix.sbatch" \
  "${campaign_root}/manifest/replay_storage_matrix.sbatch" \
  "${campaign_root}/manifest/status.py" \
  "${campaign_root}/manifest/READY.env" \
  "${campaign_root}/manifest/campaign.env" \
  > "${campaign_root}/manifest/submission-files.sha256"

submission_tsv="${campaign_root}/manifest/submission.tsv"
printf 'stage\tjob_id\tdependency\n' > "${submission_tsv}"
fuzz_job="$(sbatch --parsable --hold \
  --job-name=aflnet-storage \
  --output="${campaign_root}/slurm/fuzz-%j.out" \
  --error="${campaign_root}/slurm/fuzz-%j.err" \
  --export="${fuzz_export}" \
  "${campaign_root}/manifest/run_storage_matrix.sbatch")"
fuzz_job="${fuzz_job%%;*}"
[[ "${fuzz_job}" =~ ^[0-9]+$ ]] || die "sbatch returned invalid fuzz job id: ${fuzz_job}"
printf 'fuzz\t%s\tnone\n' "${fuzz_job}" >> "${submission_tsv}"

replay_job="$(sbatch --parsable --hold \
  --dependency="afterok:${fuzz_job}" \
  --job-name=aflnet-replay \
  --output="${campaign_root}/slurm/replay-%j.out" \
  --error="${campaign_root}/slurm/replay-%j.err" \
  --export="${replay_export}" \
  "${campaign_root}/manifest/replay_storage_matrix.sbatch")"
replay_job="${replay_job%%;*}"
[[ "${replay_job}" =~ ^[0-9]+$ ]] || die "sbatch returned invalid replay job id: ${replay_job}"
printf 'replay\t%s\tafterok:%s\n' "${replay_job}" "${fuzz_job}" >> "${submission_tsv}"

touch "${campaign_root}/manifest/submission.accepted"
scontrol release "${fuzz_job},${replay_job}"
touch "${campaign_root}/manifest/submission.release.complete" \
  "${campaign_root}/manifest/submission.complete"
submission_sealed=1
trap - EXIT INT TERM
echo "SUBMISSION_OK fuzz_job=${fuzz_job} replay_job=${replay_job} campaign_root=${campaign_root}"
echo "Monitor: python3 ${campaign_root}/manifest/status.py ${campaign_root} --no-fail --show-reasons"
