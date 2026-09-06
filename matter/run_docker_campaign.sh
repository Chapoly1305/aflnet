#!/usr/bin/env bash
# Launch N independent AFLNet instances, one Docker container each, headless.
#
# Created: 2026-09-06
# Purpose: run the AFLNet baseline at high concurrency for the cross-fuzzer
#          benchmark, then produce a coverage-over-time curve on the SAME
#          30-minute cadence and via the SAME aggregator as EP2.
# Retention: PERMANENT (benchmark pipeline step)
#
# Why one container per instance, and --network none:
#   A single Matter DUT binds ~24 UDP sockets -- the operational port plus 11x
#   mDNS :5353 and ~11 ephemeral. Distinct --secured-device-port values (the
#   bare-metal --base-port scheme) separate only the first of those; every
#   instance still shares one mDNS multicast space, which quietly couples
#   "independent" replicas. A private netns per container separates all of them,
#   so every instance can reuse the same port and the replicas are genuinely
#   independent. --network none keeps only lo: no veth, no iptables rules, no
#   docker0 address pool pressure at 32+ containers. Nothing is published to the
#   host, so there is no host-side port to collide with.
#
# Coverage is collected LIVE, the same way EP2 does it: the DUT is built with
#   -fprofile-continuous and run with LLVM_PROFILE_FILE=...%c..., so its counters
#   are mmap'd into one .profraw that stays current even though AFL kills every
#   forked child; profraw_snapshotter.py --continuous samples that file every
#   --interval seconds into instance-NN/snapshots/. Same mechanism, same tool,
#   same cadence, same aggregator as EP2.
#
#   --phase2 selects the old fallback instead: replay each instance's
#   replayable-queue through the profgen DUT. Only needed if continuous mode is
#   unavailable, and it measures a different quantity -- replay covers only the
#   inputs AFL kept in its queue, whereas the live profile counts every
#   execution, including the ones AFL discarded.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AFLNET_DIR="$(dirname "${SCRIPT_DIR}")"
REPO_ROOT="$(cd "${AFLNET_DIR}/../../.." && pwd)"
AGGREGATOR="${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/aggregate_coverage_over_time.py"
DASHBOARD="${REPO_ROOT}/examples/fuzzers/eclipsefuzz/stateful/tools/generate_coverage_dashboard.py"

IMAGE="aflnet-matter-campaign:local"
INSTANCES=20
FUZZ_SECONDS=86400
TRANSPORT=tcp
DELAY_US=10000
POLL_MS=20
CALIBRATE=1
INTERVAL=1800
SCOPE=clusters
COV_MODE=live
# ProFuzzBench runs each repetition in its own container with --cpus=1
# (profuzzbench_exec_common.sh). Pinning matters at 20-way: without it the
# instances contend and neither the throughput nor the comparison is reproducible.
CPUS="1"
OUT_DIR="${REPO_ROOT}/out/aflnet-docker-campaign-$(date +%Y%m%d-%H%M%S)"
PHASE2_WORKERS=16

usage() { cat <<'U'
Usage: run_docker_campaign.sh [--instances 20] [--fuzz-seconds 86400]
         [--image TAG] [--out-dir DIR] [--transport tcp|udp]
         [--delay-us 10000] [--poll-ms 20] [--no-calibrate]
         [--interval 1800] [--scope clusters|sdk] [--cpus N.N]
         [--phase2] [--phase2-workers 16] [--no-coverage]
U
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --instances)      INSTANCES="${2:?}";     shift 2 ;;
    --fuzz-seconds)   FUZZ_SECONDS="${2:?}";  shift 2 ;;
    --image)          IMAGE="${2:?}";         shift 2 ;;
    --out-dir)        OUT_DIR="${2:?}";       shift 2 ;;
    --delay-us)       DELAY_US="${2:?}";      shift 2 ;;
    --poll-ms)        POLL_MS="${2:?}";       shift 2 ;;
    --transport)      TRANSPORT="${2:?}";     shift 2 ;;
    --no-calibrate)   CALIBRATE=0;            shift ;;
    --interval)       INTERVAL="${2:?}";      shift 2 ;;
    --scope)          SCOPE="${2:?}";         shift 2 ;;
    --cpus)           CPUS="${2:?}";          shift 2 ;;
    --phase2-workers) PHASE2_WORKERS="${2:?}"; shift 2 ;;
    --phase2)         COV_MODE=phase2;        shift ;;
    --no-coverage)    COV_MODE=none;          shift ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null || { echo "ERROR: docker required" >&2; exit 1; }
docker image inspect "${IMAGE}" >/dev/null 2>&1 || {
  echo "ERROR: image ${IMAGE} not found -- run build_campaign_image.sh" >&2; exit 1; }
[[ -d "${OUT_DIR}" ]] && { echo "ERROR: out dir exists: ${OUT_DIR}" >&2; exit 1; }
mkdir -p "${OUT_DIR}"

RUN_ID="$(basename "${OUT_DIR}")"
COV_DUT_IN_IMAGE=/opt/fuzzer/chip-all-clusters-app-cov
# llvm-cov must read the profile with the SAME binary that produced it, so the
# live path scores against the fuzz DUT, not the profgen replay DUT.
if [[ "${COV_MODE}" == "live" ]]; then
  HOST_SCORING_DUT="${REPO_ROOT}/out/afl-dut-live-cov/chip-all-clusters-app"
else
  HOST_SCORING_DUT="${REPO_ROOT}/out/afl-dut-replay-cov/chip-all-clusters-app"
fi

{
  echo "started=$(date -Iseconds)"
  echo "image=${IMAGE}"
  echo "instances=${INSTANCES}"
  echo "fuzz_seconds=${FUZZ_SECONDS}"
  echo "transport=${TRANSPORT}"
  echo "delay_us=${DELAY_US}"
  echo "poll_ms=${POLL_MS}"
  echo "calibrate=${CALIBRATE}"
  echo "replica_model=independent"
  echo "snapshot_interval=${INTERVAL}"
  echo "execution_mode=docker-netns-per-instance"
  echo "coverage_mode=${COV_MODE}"
  echo "network=none"
  echo "host=$(hostname)"
  echo "host_cpus=$(nproc)"
  docker image inspect "${IMAGE}" --format '{{range $k,$v := .Config.Labels}}{{$k}}={{$v}}
{{end}}' | sed '/^$/d'
} > "${OUT_DIR}/eval-meta.txt"
# The aggregator and phase2 resolve the coverage binary from this key.
echo "coverage_binary=${COV_DUT_IN_IMAGE}" >> "${OUT_DIR}/eval-meta.txt"

echo "[afl-docker] ${INSTANCES} instances x ${FUZZ_SECONDS}s -> ${OUT_DIR}"

NAMES=()
for i in $(seq 1 "${INSTANCES}"); do
  idx="$(printf '%02d' "${i}")"
  inst="${OUT_DIR}/instance-${idx}"
  mkdir -p "${inst}"
  name="afl-${RUN_ID}-${idx}"
  cpu_arg=(); [[ -n "${CPUS}" ]] && cpu_arg=(--cpus "${CPUS}")
  docker run -d --rm --init --name "${name}" \
    --network none \
    --user "$(id -u):$(id -g)" \
    "${cpu_arg[@]}" \
    -e FUZZ_SECONDS="${FUZZ_SECONDS}" -e DELAY_US="${DELAY_US}" \
    -e CALIBRATE="${CALIBRATE}" -e INSTANCE="instance-${idx}" \
    -e TRANSPORT="${TRANSPORT}" -e POLL_MS="${POLL_MS}" \
    -e SNAPSHOT_INTERVAL="${INTERVAL}" \
    -v "${inst}:/workdir/output" \
    "${IMAGE}" >/dev/null
  NAMES+=("${name}")
done
echo "[afl-docker] launched: ${#NAMES[@]} containers (docker ps --filter name=afl-${RUN_ID})"

# Wait for every container to exit.
for n in "${NAMES[@]}"; do docker wait "${n}" >/dev/null 2>&1 || true; done
echo "ended_fuzzing=$(date -Iseconds)" >> "${OUT_DIR}/eval-meta.txt"

ok=0; bad=0
for i in $(seq 1 "${INSTANCES}"); do
  idx="$(printf '%02d' "${i}")"
  if grep -q '^status=ok' "${OUT_DIR}/instance-${idx}/run.env" 2>/dev/null; then ok=$((ok+1)); else bad=$((bad+1)); fi
done
echo "[afl-docker] fuzzing done: ${ok} ok, ${bad} failed"

if [[ "${COV_MODE}" == "none" ]]; then
  echo "[afl-docker] coverage skipped"; exit 0
fi

if [[ "${COV_MODE}" == "live" ]]; then
  total_snaps=$(ls "${OUT_DIR}"/instance-*/snapshots/snapshot-*s.profdata 2>/dev/null | wc -l)
  echo "[afl-docker] live coverage: ${total_snaps} snapshots already on disk (interval=${INTERVAL}s)"
  [[ "${total_snaps}" -gt 0 ]] || {
    echo "[afl-docker] no live snapshots -- check instance-*/snapshotter.log; \
re-run with --phase2 to fall back to queue replay" >&2; exit 1; }
else
  # Fallback: reconstruct a curve by replaying each queue through the profgen DUT.
  echo "[afl-docker] phase2 replay (interval=${INTERVAL}s)..."
  docker run --rm --init --network none \
    --user "$(id -u):$(id -g)" \
    --entrypoint python3 \
    -e PATH="/usr/lib/llvm-20/bin:/usr/bin:/bin" \
    -v "${OUT_DIR}:/campaign" \
    "${IMAGE}" /opt/fuzzer/phase2_parallel.py \
      --eval-dir /campaign --cov-dut "${COV_DUT_IN_IMAGE}" \
      --interval "${INTERVAL}" --workers "${PHASE2_WORKERS}" \
    || echo "[afl-docker] phase2 failed (rerun that docker run by hand)" >&2
  for tl in "${OUT_DIR}"/instance-*/timeline.csv; do
    [[ -f "${tl}" ]] && sed -i "s#/campaign#${OUT_DIR}#g" "${tl}"
  done
fi

echo "[afl-docker] aggregating (scope=${SCOPE})..."
PIGWEED_BIN="${REPO_ROOT}/.environment/cipd/packages/pigweed/bin"
[[ -d "${PIGWEED_BIN}" ]] && export PATH="${PIGWEED_BIN}:${PATH}"
export DEBUGINFOD_URLS=""
if [[ -x "${HOST_SCORING_DUT}" ]]; then
  python3 "${AGGREGATOR}" --eval-dir "${OUT_DIR}" --binary "${HOST_SCORING_DUT}" --scope "${SCOPE}" \
    || echo "[afl-docker] aggregation failed (scope=${SCOPE})" >&2
  # generate_coverage_dashboard.py consumes instance-*/coverage_timeline.sdk.csv,
  # but this aggregator only implements --scope clusters, so the sdk curve it
  # wants cannot be produced here. Run it only if that input actually exists --
  # never relabel clusters-scope data as sdk to satisfy it.
  if compgen -G "${OUT_DIR}/instance-*/coverage_timeline.sdk.csv" >/dev/null; then
    python3 "${DASHBOARD}" --eval-dir "${OUT_DIR}" || echo "[afl-docker] dashboard failed" >&2
  else
    echo "[afl-docker] dashboard skipped: needs coverage_timeline.sdk.csv, and the"
    echo "[afl-docker]   aggregator supports only --scope clusters. Curve is in"
    echo "[afl-docker]   coverage_over_time.csv / .png."
  fi
else
  echo "[afl-docker] host cov DUT missing (${HOST_SCORING_DUT}); snapshots are in place, run the aggregator manually" >&2
fi

echo "ended=$(date -Iseconds)" >> "${OUT_DIR}/eval-meta.txt"
echo "[afl-docker] done -> ${OUT_DIR}"
