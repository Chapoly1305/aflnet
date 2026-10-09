#!/usr/bin/env bash
# Record small, immutable progress receipts. The AFL queue itself remains the
# post-processing input and is not recopied every interval.
set -euo pipefail

readonly OUT="${1:?output directory required}"
readonly INTERVAL="${2:?snapshot interval required}"
readonly START_EPOCH="${3:?start epoch required}"

snapshot() {
  local now elapsed tmp final queue_count crash_count hang_count
  now="$(date +%s)"
  elapsed=$((now - START_EPOCH))
  final="${OUT}/snapshots/snapshot-$(printf '%08d' "${elapsed}")s"
  tmp="${final}.tmp-$$"
  mkdir -p "${tmp}"
  [[ ! -f "${OUT}/afl-out/fuzzer_stats" ]] || cp "${OUT}/afl-out/fuzzer_stats" "${tmp}/"
  { find "${OUT}/afl-out/replayable-queue" -maxdepth 1 -type f \
      -printf '%f\t%T@\t%s\n' 2>/dev/null || true; } | \
    LC_ALL=C sort > "${tmp}/queue.tsv"
  queue_count="$(wc -l < "${tmp}/queue.tsv")"
  crash_count="$({ find "${OUT}/afl-out/crashes" -maxdepth 1 -type f ! -name README.txt -printf '.\n' 2>/dev/null || true; } | wc -l)"
  hang_count="$({ find "${OUT}/afl-out/hangs" -maxdepth 1 -type f -printf '.\n' 2>/dev/null || true; } | wc -l)"
  printf 'captured_epoch=%s\nelapsed_seconds=%s\nqueue_entries=%s\ncrashes=%s\nhangs=%s\n' \
    "${now}" "${elapsed}" "${queue_count}" "${crash_count}" "${hang_count}" \
    > "${tmp}/snapshot.env"
  mv "${tmp}" "${final}"
}

trap 'snapshot || true; exit 0' TERM INT
mkdir -p "${OUT}/snapshots"
while :; do
  sleep "${INTERVAL}" &
  wait "$!" || true
  snapshot
done
