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
# Coverage is collected by QUEUE REPLAY (default, COV_MODE=replay) -- the
#   ProFuzzBench / AFLNet reference design. The target is compiled twice: the
#   fuzz DUT carries AFL instrumentation and NO profiling, and a second profgen
#   DUT is never fuzzed, only replayed against. After fuzzing,
#   phase2_parallel.py replays each instance's replayable-queue in seed-mtime
#   order, cumulatively merging llvm-profdata into snapshot-<elapsed>s.profdata
#   once per --interval. ProFuzzBench: "It runs again the inputs using the
#   target software compiled with gcov ... generates time series ... based on
#   the timestamps at which the inputs were generated." TSE'25 (the AFLNet
#   authors' own re-evaluation) measures branch coverage this way.
#
#   Why not live profiling of the fuzz DUT: it needs -fprofile-continuous
#   (AFL kills every forked child, so a plain profgen build writes nothing),
#   which costs per-counter indirection plus mmap writeback that the compared
#   in-process fuzzer does not pay, and it makes each system's coverage come
#   from its own binary -- so the llvm-cov denominators stop being comparable
#   ("edge counts between different binaries do not translate").
#
#   Caveat, and it MUST be applied symmetrically: replay only covers inputs AFL
#   kept in its queue, while a live profile also counts executions the fuzzer
#   discarded. So EclipseFuzz has to be scored by corpus replay against the SAME
#   profgen binary too; scoring one system live and the other by replay would
#   hand the live one credit for discarded executions.
#
#   --live is REJECTED by this image: the sampler is not installed and the fuzz
#   DUT carries no profiling. Restoring it needs both put back, plus the
#   comparability cost above. --phase2 is kept as an alias of --replay.
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
POLL_MS=100
CALIBRATE=0
INTERVAL=1800
SCOPE=clusters
COV_MODE=replay
# ProFuzzBench runs each repetition in its own container with --cpus=1
# (profuzzbench_exec_common.sh). Pinning matters at 20-way: without it the
# instances contend and neither the throughput nor the comparison is reproducible.
CPUS="1"
OUT_DIR="${REPO_ROOT}/out/aflnet-docker-campaign-$(date +%Y%m%d-%H%M%S)"
REPLAY_WORKERS=16

usage() { cat <<'U'
Usage: run_docker_campaign.sh [--instances 20] [--fuzz-seconds 86400]
         [--image TAG] [--out-dir DIR] [--transport tcp|udp]
         [--delay-us 10000] [--poll-ms 100] [--calibrate]
         [--interval 1800] [--scope clusters|sdk] [--cpus N.N]
         [--replay] [--replay-workers 16] [--no-coverage]
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
    --calibrate)      CALIBRATE=1;            shift ;;
    --interval)       INTERVAL="${2:?}";      shift 2 ;;
    --scope)          SCOPE="${2:?}";         shift 2 ;;
    --cpus)           CPUS="${2:?}";          shift 2 ;;
    --replay-workers|--phase2-workers) REPLAY_WORKERS="${2:?}"; shift 2 ;;
    --replay)         COV_MODE=replay;        shift ;;
    --phase2)         COV_MODE=replay;        shift ;;   # legacy alias
    --live)           # Reject at parse time, not after a full fuzzing budget.
                      # This image carries no sampler (profraw_snapshotter.py is
                      # not installed) and the fuzz DUT is built WITHOUT
                      # use_coverage -- build_campaign_image.sh refuses one that
                      # has it. Restoring live sampling means rebuilding that DUT
                      # with use_coverage=true matter_fuzz_continuous_coverage=true,
                      # putting the sampler back, and accepting the comparability
                      # cost in this script's header.
                      echo "ERROR: --live is not supported by this image: the fuzz DUT" >&2
                      echo "       carries no profiling and no profraw sampler is installed." >&2
                      echo "       Use the default queue replay (--replay)." >&2
                      exit 2 ;;
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
COV_DUT_IN_IMAGE=/opt/fuzzer/aflnet-chip-all-clusters-app-cov
# llvm-cov must read the profile with the SAME binary that produced it, and the
# only binary that produces one is the profgen replay DUT.
HOST_SCORING_DUT="${REPO_ROOT}/out/aflnet-dut-cov/chip-all-clusters-app"

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
# The aggregator and the replay step resolve the coverage binary from this key.
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

# Build the curve by replaying each instance's queue through the profgen DUT.
echo "[afl-docker] queue replay (interval=${INTERVAL}s)..."
  docker run --rm --init --network none \
    --user "$(id -u):$(id -g)" \
    --entrypoint python3 \
    -e PATH="/opt/llvm:/usr/bin:/bin" \
    -v "${OUT_DIR}:/campaign" \
    "${IMAGE}" /opt/fuzzer/phase2_parallel.py \
      --eval-dir /campaign --cov-dut "${COV_DUT_IN_IMAGE}" \
      --interval "${INTERVAL}" --workers "${REPLAY_WORKERS}" \
    || echo "[afl-docker] queue replay failed (rerun that docker run by hand)" >&2
for tl in "${OUT_DIR}"/instance-*/timeline.csv; do
  [[ -f "${tl}" ]] && sed -i "s#/campaign#${OUT_DIR}#g" "${tl}"
done

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
