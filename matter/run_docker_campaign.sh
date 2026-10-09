#!/usr/bin/env bash
# Launch independent fuzz-only AFLNet containers. Coverage is post-processed
# from each instance's replayable-queue after this script returns.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)"
IMAGE=aflnet-matter-campaign:local
INSTANCES=10
FUZZ_SECONDS=86400
INTERVAL=1800
CPUS=1
OUT_DIR="${REPO_ROOT}/out/aflnet-docker-$(date +%Y%m%d-%H%M%S)"

usage() {
  echo "Usage: run_docker_campaign.sh [--image TAG] [--instances 10]"
  echo "       [--fuzz-seconds 86400] [--interval 1800] [--cpus 1] [--out-dir DIR]"
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="${2:?}"; shift 2 ;;
    --instances) INSTANCES="${2:?}"; shift 2 ;;
    --fuzz-seconds) FUZZ_SECONDS="${2:?}"; shift 2 ;;
    --interval) INTERVAL="${2:?}"; shift 2 ;;
    --cpus) CPUS="${2:?}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
for value in "${INSTANCES}" "${FUZZ_SECONDS}" "${INTERVAL}"; do
  [[ "${value}" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: invalid numeric argument" >&2; exit 2; }
done
command -v docker >/dev/null || { echo "ERROR: docker required" >&2; exit 1; }
[[ "$(docker image inspect "${IMAGE}" --format '{{index .Config.Labels "aflnet.image_role"}}')" == fuzz-only ]] || {
  echo "ERROR: ${IMAGE} is not a fuzz-only AFLNet image" >&2
  exit 1
}
OUT_DIR="$(realpath -m -- "${OUT_DIR}")"
[[ ! -e "${OUT_DIR}" ]] || { echo "ERROR: output exists: ${OUT_DIR}" >&2; exit 1; }
mkdir -p "${OUT_DIR}"
printf 'started=%s\nimage=%s\ninstances=%s\nfuzz_seconds=%s\nsnapshot_interval=%s\npostprocessing=external\n' \
  "$(date -Iseconds)" "${IMAGE}" "${INSTANCES}" "${FUZZ_SECONDS}" "${INTERVAL}" \
  > "${OUT_DIR}/campaign.env"

containers=()
cleanup() {
  for cid in "${containers[@]}"; do
    docker rm -f "${cid}" >/dev/null 2>&1 || true
  done
}
trap cleanup INT TERM
for replica in $(seq 1 "${INSTANCES}"); do
  printf -v name 'instance-%02d' "${replica}"
  mkdir -p "${OUT_DIR}/${name}"
  cid="$(docker run -d --init --network none --cpus "${CPUS}" \
    --name "aflnet-$$-${replica}" \
    -e INSTANCE="${name}" \
    -e FUZZ_SECONDS="${FUZZ_SECONDS}" \
    -e SNAPSHOT_INTERVAL="${INTERVAL}" \
    -v "${OUT_DIR}/${name}:/workdir/output" \
    "${IMAGE}")"
  containers+=("${cid}")
done

failures=0
for cid in "${containers[@]}"; do
  rc="$(docker wait "${cid}")"
  [[ "${rc}" == 0 ]] || failures=$((failures + 1))
done
docker rm "${containers[@]}" >/dev/null
containers=()
trap - INT TERM
complete="$(find "${OUT_DIR}" -mindepth 2 -maxdepth 2 -name .done -printf '.\n' | wc -l)"
printf 'ended=%s\ncomplete_instances=%s\nfailures=%s\n' \
  "$(date -Iseconds)" "${complete}" "${failures}" >> "${OUT_DIR}/campaign.env"
(( failures == 0 && complete == INSTANCES )) || {
  echo "ERROR: ${complete}/${INSTANCES} complete, ${failures} container failures" >&2
  exit 1
}
touch "${OUT_DIR}/campaign.done"
