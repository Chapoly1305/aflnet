#!/usr/bin/env bash
# Run one saved-queue coverage-replay shard in its own network namespace.
set -euo pipefail

IMAGE=
NAME=
ANALYSIS_DIR=
PROTECTED_RUNS_DIR=
CPUSET=
SETTLE_SECONDS=
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: run_coverage_replay_docker.sh \
  --image TAG --name NAME --analysis-dir DIR --protected-runs-dir DIR \
  --cpuset LIST [--startup-settle-seconds SEC] [--dry-run] -- REPLAY_ARGS...

The container always uses Docker bridge networking.  The replay driver and
DUT communicate over loopback inside that private network namespace; sharing
the host namespace is intentionally unsupported.

Example:
  run_coverage_replay_docker.sh \
    --image matter-ep2-fuzzer:coverage \
    --name aflnet-coverage-full-01 \
    --analysis-dir /data/coverage-analysis \
    --protected-runs-dir /data/protected-runs \
    --cpuset 0-15 --startup-settle-seconds 10 -- \
    --stage run --skip-prepare --no-finalize --workers 16 \
    --export-jobs 4 --base-port 42000 \
    --replay-scripts-dir /data/coverage-analysis/source-coverage/provenance/replay \
    --only full/instance-01
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="${2:?missing image}"; shift 2 ;;
    --name) NAME="${2:?missing container name}"; shift 2 ;;
    --analysis-dir) ANALYSIS_DIR="${2:?missing analysis directory}"; shift 2 ;;
    --protected-runs-dir) PROTECTED_RUNS_DIR="${2:?missing protected-runs directory}"; shift 2 ;;
    --cpuset) CPUSET="${2:?missing CPU set}"; shift 2 ;;
    --startup-settle-seconds) SETTLE_SECONDS="${2:?missing settle duration}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --) shift; break ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown launcher argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "${IMAGE}" && -n "${NAME}" && -n "${ANALYSIS_DIR}" &&
   -n "${PROTECTED_RUNS_DIR}" && -n "${CPUSET}" ]] || {
  echo "ERROR: image, name, analysis directory, protected-runs directory, and cpuset are required" >&2
  exit 2
}
[[ $# -gt 0 ]] || { echo "ERROR: replay arguments are required after --" >&2; exit 2; }
[[ "${NAME}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || {
  echo "ERROR: invalid container name: ${NAME}" >&2
  exit 2
}
if [[ -n "${SETTLE_SECONDS}" ]]; then
  [[ "${SETTLE_SECONDS}" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]] || {
    echo "ERROR: invalid startup settle duration: ${SETTLE_SECONDS}" >&2
    exit 2
  }
  awk -v value="${SETTLE_SECONDS}" 'BEGIN { exit !(value >= 0 && value <= 60) }' || {
    echo "ERROR: startup settle duration must be between 0 and 60 seconds" >&2
    exit 2
  }
fi

ANALYSIS_DIR="$(realpath -e -- "${ANALYSIS_DIR}")"
PROTECTED_RUNS_DIR="$(realpath -e -- "${PROTECTED_RUNS_DIR}")"
[[ -f "${ANALYSIS_DIR}/run_source_coverage.py" ]] || {
  echo "ERROR: missing replay driver: ${ANALYSIS_DIR}/run_source_coverage.py" >&2
  exit 1
}
[[ -d "${PROTECTED_RUNS_DIR}" ]] || {
  echo "ERROR: protected-runs path is not a directory: ${PROTECTED_RUNS_DIR}" >&2
  exit 1
}

command=(
  docker run -d --init
  --name "${NAME}"
  --label eclipsefuzz.coverage-replay-network=private-bridge
  --entrypoint python3
  --user "$(id -u):$(id -g)"
  --network bridge
  --cpuset-cpus "${CPUSET}"
  -v "${ANALYSIS_DIR}:${ANALYSIS_DIR}"
  -v "${PROTECTED_RUNS_DIR}:${PROTECTED_RUNS_DIR}:ro"
  -w "${ANALYSIS_DIR}"
)
if [[ -n "${SETTLE_SECONDS}" ]]; then
  command+=(-e "AFLNET_REPLAY_STARTUP_SETTLE_SECONDS=${SETTLE_SECONDS}")
fi
command+=("${IMAGE}" -u run_source_coverage.py "$@")

if (( DRY_RUN )); then
  printf '%q ' "${command[@]}"
  printf '\n'
  exit 0
fi

command -v docker >/dev/null || { echo "ERROR: docker required" >&2; exit 1; }
docker image inspect "${IMAGE}" >/dev/null
"${command[@]}"
