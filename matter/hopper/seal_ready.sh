#!/usr/bin/env bash
# Promote one built SIF plus a completed two-profile smoke to READY.env.
set -euo pipefail

IMAGE_ENV=""
SMOKE_ENV=""

usage() {
  cat <<'EOF'
Usage: seal_ready.sh --image-env PATH --smoke-env PATH

Run on the Hopper login node after smoke.sbatch finishes. This script checks
the top-level build and smoke records with sacct and refuses to overwrite an
existing READY.env.
EOF
}

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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image-env) IMAGE_ENV="${2:?--image-env needs a value}"; shift 2 ;;
    --smoke-env) SMOKE_ENV="${2:?--smoke-env needs a value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -f "${IMAGE_ENV}" ]] || die "IMAGE.env missing: ${IMAGE_ENV}"
[[ -f "${SMOKE_ENV}" ]] || die "SMOKE.env missing: ${SMOKE_ENV}"
command -v sacct >/dev/null || die "sacct unavailable; run on Hopper"

image_status="$(env_value status "${IMAGE_ENV}")"
smoke_status="$(env_value status "${SMOKE_ENV}")"
image_root="$(env_value image_root "${IMAGE_ENV}")"
build_job_id="$(env_value build_job_id "${IMAGE_ENV}")"
smoke_job_id="$(env_value smoke_job_id "${SMOKE_ENV}")"
smoke_evidence_root="$(env_value smoke_evidence_root "${SMOKE_ENV}")"
smoke_image_root="$(env_value smoke_image_root "${SMOKE_ENV}")"
smoke_image_env_sha256="$(env_value smoke_image_env_sha256 "${SMOKE_ENV}")"
smoke_sif_sha256="$(env_value smoke_sif_sha256 "${SMOKE_ENV}")"
image_sif_sha256="$(env_value sif_sha256 "${IMAGE_ENV}")"

[[ "${image_status}" == awaiting_smoke ]] || die "unexpected image status: ${image_status}"
[[ "${smoke_status}" == script_ok ]] || die "unexpected smoke status: ${smoke_status}"
[[ "${image_root}" =~ ^/scratch/jchen73/eclipsefuzz/aflnet/images/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || \
  die "IMAGE.env contains an invalid image root"
[[ "$(realpath -e "${IMAGE_ENV}")" == "$(realpath -e "${image_root}")/IMAGE.env" ]] || \
  die "IMAGE.env is outside its image root"
[[ "$(realpath -e "${SMOKE_ENV}")" == "$(realpath -e "${image_root}")/SMOKE-${smoke_job_id}.env" ]] || \
  die "SMOKE.env is not the expected evidence file in the image root"
[[ "${smoke_image_root}" == "${image_root}" ]] || die "smoke used a different image root"
[[ "${smoke_sif_sha256}" == "${image_sif_sha256}" ]] || die "smoke used a different SIF"
printf '%s  %s\n' "${smoke_image_env_sha256}" "${IMAGE_ENV}" | sha256sum -c - >/dev/null || \
  die "IMAGE.env changed after smoke validation"
[[ -f "${smoke_evidence_root}/SMOKE_SCRIPT_OK" ]] || die "smoke success marker missing"
[[ "$(env_value smoke_profiles "${SMOKE_ENV}")" == file,memory ]] || die "smoke did not cover both profiles"
[[ "$(env_value smoke_initial_corpus_complete_count "${SMOKE_ENV}")" == 2 ]] || \
  die "smoke did not fully calibrate both selected10 corpora"
[[ "$(env_value smoke_replay_complete_count "${SMOKE_ENV}")" == 2 ]] || \
  die "smoke did not replay both queues"
[[ "$(env_value smoke_aggregation_pass_count "${SMOKE_ENV}")" == 2 ]] || \
  die "smoke did not aggregate both profiles"
[[ "$(env_value network_isolation "${SMOKE_ENV}")" == apptainer-network-none ]] || \
  die "smoke did not prove private network namespaces"
[[ "$(env_value process_isolation "${SMOKE_ENV}")" == apptainer-containall-pid ]] || \
  die "smoke did not prove private PID namespaces"
case "$(env_value file_storage_filesystem "${SMOKE_ENV}")" in
  tmpfs|ramfs) die "smoke file profile used memory-backed storage" ;;
esac

job_result() {
  local job_id="$1"
  sacct -j "${job_id}" -X -n -P -o JobIDRaw,State,ExitCode | \
    awk -F'|' -v wanted="${job_id}" '$1 == wanted {print $2 " " $3; exit}'
}

build_row="$(job_result "${build_job_id}")"
[[ -n "${build_row}" ]] || die "sacct has no top-level record for build job ${build_job_id}"
read -r build_job_state build_job_exit_code <<< "${build_row}"
[[ "${build_job_state}" == COMPLETED && "${build_job_exit_code}" == 0:0 ]] || \
  die "build job is not complete and green: state=${build_job_state} exit=${build_job_exit_code}"

smoke_row="$(job_result "${smoke_job_id}")"
[[ -n "${smoke_row}" ]] || die "sacct has no top-level record for smoke job ${smoke_job_id}"
read -r smoke_job_state smoke_job_exit_code <<< "${smoke_row}"
[[ "${smoke_job_state}" == COMPLETED && "${smoke_job_exit_code}" == 0:0 ]] || \
  die "smoke job is not complete and green: state=${smoke_job_state} exit=${smoke_job_exit_code}"

ready="${image_root}/READY.env"
[[ ! -e "${ready}" ]] || die "refusing to overwrite existing READY.env: ${ready}"
temporary="${ready}.tmp.$$"
cleanup() { rm -f -- "${temporary}"; }
trap cleanup EXIT

{
  printf 'status=ready\nsealed_at=%s\n' "$(date -Iseconds)"
  grep -Ev '^(status|runtime_staging)=' "${IMAGE_ENV}"
  grep -v '^status=' "${SMOKE_ENV}"
  printf 'build_job_state=%s\nbuild_job_exit_code=%s\n' \
    "${build_job_state}" "${build_job_exit_code}"
  printf 'smoke_job_state=%s\nsmoke_job_exit_code=%s\n' \
    "${smoke_job_state}" "${smoke_job_exit_code}"
  printf 'runtime_staging=sif_to_node_local_sandbox_once_per_job\n'
  printf 'production_matrix=file10_memory10_same_node_same_time\n'
} > "${temporary}"

mv "${temporary}" "${ready}"
trap - EXIT
sha256sum "${ready}" > "${ready}.sha256"
chmod a-w "${ready}" "${ready}.sha256"
echo "READY_OK image_root=${image_root} ready=${ready} smoke_job=${smoke_job_id}"
