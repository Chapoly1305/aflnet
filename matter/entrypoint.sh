#!/usr/bin/env bash
# One fuzzing instance: verify the sealed runtime, start periodic receipts, and
# run AFLNet. Coverage is intentionally a separate post-processing step.
set -euo pipefail

readonly OUT=/workdir/output
readonly SEEDS_DIR="${SEEDS_DIR:-/opt/fuzzer/seeds}"
readonly DICT="${DICT:-/opt/fuzzer/matter.dict}"
readonly DUT=/opt/fuzzer/aflnet-chip-all-clusters-app-fuzz
readonly KVS="${OUT}/dut-state/kvs"
readonly INSTANCE="${INSTANCE:-instance-unknown}"

die() { echo "ERROR: $*" >&2; exit 2; }
[[ "${TRANSPORT:-udp}" == udp ]] || die "only UDP is supported"
for value in "${FUZZ_SECONDS:-}" "${SNAPSHOT_INTERVAL:-}" \
             "${CALIBRATION_GUARD_SECONDS:-}" "${FUZZ_PORT:-}" \
             "${DELAY_US:-}" "${POLL_MS:-}" "${TEST_TIMEOUT_MS:-}"; do
  [[ "${value}" =~ ^[1-9][0-9]*$ ]] || die "runtime values must be positive integers"
done
[[ -d "${SEEDS_DIR}" ]] || die "seed directory missing: ${SEEDS_DIR}"
[[ -s "${DICT}" ]] || die "dictionary missing: ${DICT}"
(cd /opt/fuzzer && sha256sum -c runtime.sha256) || die "runtime checksum mismatch"
seed_count="$(find "${SEEDS_DIR}" -maxdepth 1 -type f -name '*.raw' -printf '.\n' | wc -l)"
(( seed_count > 0 )) || die "no raw seeds"

unset MATTER_FUZZ_INMEMORY_STORAGE
mkdir -p "${OUT}/dut-state" "${OUT}/snapshots"
rm -f "${KVS}"
read -r -a algo_args <<< "${AFL_ALGO_FLAGS:-}"
dict_args=()
[[ -f "${DICT}" ]] && dict_args=(-x "${DICT}")
start_epoch="$(date +%s)"
{
  printf 'phase=running\nstarted=%s\nstart_epoch=%s\n' "$(date -Iseconds)" "${start_epoch}"
  printf 'instance=%s\nseeds=%s\nfuzz_seconds=%s\nsnapshot_interval=%s\n' \
    "${INSTANCE}" "${seed_count}" "${FUZZ_SECONDS}" "${SNAPSHOT_INTERVAL}"
  printf 'transport=udp\ndelay_us=%s\npoll_ms=%s\nstorage_mode=file\n' \
    "${DELAY_US}" "${POLL_MS}"
  printf 'protected_operation_policy=reject-list.v1\n'
} > "${OUT}/run.env"

/opt/fuzzer/snapshot.sh "${OUT}" "${SNAPSHOT_INTERVAL}" "${start_epoch}" &
snapshot_pid=$!
cleanup() {
  kill -TERM "${snapshot_pid}" 2>/dev/null || true
  wait "${snapshot_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

export AFL_REQUIRE_CLEAN_INITIAL_CORPUS=1
export AFL_ACTIVE_FUZZ_SECONDS="${FUZZ_SECONDS}"
guard_seconds=$((FUZZ_SECONDS + CALIBRATION_GUARD_SECONDS))
set +e
timeout -s INT -k 10 "${guard_seconds}" "${AFLNET}/afl-fuzz" \
  -i "${SEEDS_DIR}" -o "${OUT}/afl-out" \
  -N "udp://127.0.0.1/${FUZZ_PORT}" -P MATTER \
  -D "${DELAY_US}" -W "${POLL_MS}" \
  "${algo_args[@]}" "${dict_args[@]}" \
  -m none -t "${TEST_TIMEOUT_MS}+" \
  -- "${DUT}" --secured-device-port "${FUZZ_PORT}" --KVS "${KVS}" \
  > "${OUT}/instance.log" 2>&1
afl_rc=$?
set -e
cleanup
trap - EXIT INT TERM

status=ok
[[ "${afl_rc}" == 0 ]] || status="afl-exit-${afl_rc}"
stats="${OUT}/afl-out/fuzzer_stats"
queue="${OUT}/afl-out/replayable-queue"
[[ -s "${stats}" ]] || status=missing-fuzzer-stats
[[ -d "${queue}" ]] || status=missing-replayable-queue
queue_count="$(find "${queue}" -maxdepth 1 -type f -printf '.\n' 2>/dev/null | wc -l)"
(( queue_count > 0 )) || status=empty-replayable-queue
calibration_marker="INITIAL_CORPUS_CALIBRATION_OK seeds=${seed_count} failures=0"
calibration_status=ok
calibration_failures=0
if ! grep -aFxq -- "${calibration_marker}" "${OUT}/instance.log"; then
  status=initial-calibration-failed
  calibration_status=failed
  calibration_failures=1
fi

stat_value() {
  awk -F: -v key="$1" '$1 ~ "^" key " *$" {gsub(/ /, "", $2); print $2; exit}' "${stats}" 2>/dev/null
}
active_start="$(stat_value active_fuzz_start_time || true)"
active_seconds="$(stat_value active_fuzz_seconds || true)"
last_update="$(stat_value last_update || true)"
execs_done="$(stat_value execs_done || true)"
protected_policy="$(stat_value matter_protected_policy || true)"
protected_testcases="$(stat_value matter_protected_testcases || true)"
protected_acl="$(stat_value matter_protected_acl || true)"
protected_group_key="$(stat_value matter_protected_group_key || true)"
protected_fabric="$(stat_value matter_protected_fabric || true)"
protected_admin="$(stat_value matter_protected_admin || true)"
wall_start="$(stat_value start_time || true)"
calibration_seconds=missing
if [[ "${active_start}" =~ ^[0-9]+$ && "${wall_start}" =~ ^[0-9]+$ ]] && \
   (( active_start >= wall_start )); then
  calibration_seconds=$((active_start - wall_start))
fi
minimum=$((FUZZ_SECONDS > 10 ? FUZZ_SECONDS - 5 : 1))
[[ "${active_seconds}" =~ ^[0-9]+$ ]] && (( active_seconds >= minimum )) || status=incomplete-budget
[[ -s "${KVS}" ]] || status=missing-file-kvs
[[ "${protected_policy}" == reject-list.v1 ]] || status=missing-protected-policy
for value in "${protected_testcases}" "${protected_acl}" "${protected_group_key}" \
             "${protected_fabric}" "${protected_admin}"; do
  [[ "${value}" =~ ^[0-9]+$ ]] || status=invalid-protected-counters
done
if [[ "${protected_testcases}" =~ ^[0-9]+$ ]]; then
  for value in "${protected_acl}" "${protected_group_key}" \
               "${protected_fabric}" "${protected_admin}"; do
    [[ "${value}" =~ ^[0-9]+$ ]] && (( value <= protected_testcases )) || \
      status=inconsistent-protected-counters
  done
fi

{
  printf 'ended=%s\nafl_exit=%s\nstatus=%s\n' "$(date -Iseconds)" "${afl_rc}" "${status}"
  printf 'queue_entries=%s\nfuzz_start_epoch=%s\nfuzz_end_epoch=%s\n' \
    "${queue_count}" "${active_start:-missing}" "${last_update:-missing}"
  printf 'observed_fuzz_seconds=%s\nexecs_done=%s\n' \
    "${active_seconds:-missing}" "${execs_done:-missing}"
  printf 'requested_fuzz_seconds=%s\ninitial_calibration_seconds=%s\n' \
    "${FUZZ_SECONDS}" "${calibration_seconds}"
  printf 'initial_calibration_status=%s\ninitial_calibration_failures=%s\n' \
    "${calibration_status}" "${calibration_failures}"
  printf 'observed_protected_operation_policy=%s\nprotected_testcases=%s\n' \
    "${protected_policy:-missing}" "${protected_testcases:-missing}"
  printf 'protected_acl=%s\nprotected_group_key=%s\nprotected_fabric=%s\nprotected_admin=%s\n' \
    "${protected_acl:-missing}" "${protected_group_key:-missing}" \
    "${protected_fabric:-missing}" "${protected_admin:-missing}"
} >> "${OUT}/run.env"
chmod -R a+rX "${OUT}" 2>/dev/null || true
[[ "${status}" == ok ]] || die "campaign failed: ${status}"
touch "${OUT}/.done"
