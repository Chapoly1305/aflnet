#!/usr/bin/env bash
# Quick coverage snapshot from a running AFLNet campaign instance.
# Usage:
#   ./snapshot_coverage.sh out/aflnet-eval-YYYYMMDD-HHMMSS/instance-01
#   ./snapshot_coverage.sh out/aflnet-eval-YYYYMMDD-HHMMSS/instance-01 5  # SKIPCOUNT

set -euo pipefail

INST_DIR="${1:?usage: $0 <instance-dir> [skipcount] [output-file]}"
SKIPCOUNT="${2:-5}"
OUTPUT="${3:-/dev/stdout}"
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)"
COV_DUT="${REPO_ROOT}/out/afl-dut-replay-cov/chip-all-clusters-app"

AFL_OUT="${INST_DIR}/afl-out"
QUEUE="${AFL_OUT}/replayable-queue"

if [[ ! -d "${QUEUE}" ]]; then
  echo "[snapshot] ERROR: queue not found at ${QUEUE}" >&2; exit 1
fi

PROFRAW_DIR="${INST_DIR}/profraw"
SNAP_DIR="${INST_DIR}/snapshots"
BASELINE="${INST_DIR}/baseline.profdata"
mkdir -p "${PROFRAW_DIR}" "${SNAP_DIR}"

# Collect seeds sorted by time, separate initial from discovered
initial=(); discovered=()
while IFS= read -r ts seed; do
  [[ "$(basename "${seed}")" == *"orig:"* ]] && initial+=("${seed}") || discovered+=("${seed}")
done < <(find "${QUEUE}" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | cut -d' ' -f2-)
total=$(( ${#initial[@]} + ${#discovered[@]} ))
echo "[snapshot] $(date +%H:%M:%S): ${#initial[@]} initial + ${#discovered[@]} discovered = ${total} seeds" >&2

# Per-seed replay helper
replay_one() {
  local seed="$1" count="$2"
  local kvs_dir kvs profraw dut_pid pf
  kvs_dir="$(mktemp -d)"; kvs="${kvs_dir}/chip_kvs"
  profraw="${PROFRAW_DIR}/snap-seed-${count}-%p.profraw"

  env LLVM_PROFILE_FILE="${profraw}" \
      MATTER_FUZZ_STORAGE_DIR="${kvs_dir}" MATTER_FUZZ_KVS_PATH="${kvs}" \
    "${COV_DUT}" --secured-device-port $(( 21000 + (count % 100) )) --KVS "${kvs}" \
    >"${kvs_dir}/dut-stderr.log" 2>&1 &
  dut_pid=$!; sleep 1

  timeout 10 python3 -c "
import socket
data = open('${seed}','rb').read()
MIC=16;TAGLEN=(0,1,2,4,2,4,6,8)
def mh(b,o):
    if o+8>len(b):return -1
    f=b[o];n=8
    if f&4:n+=8
    d=f&3
    if d==1:n+=8
    elif d==2:n+=2
    return n if o+n<=len(b) else -1
def ph(b,o):
    if o+6>len(b):return -1
    f=b[o];n=6
    if f&0x10:n+=2
    if f&2:n+=4
    return n if o+n<=len(b) else -1
def tv(b,o):
    i=o;d=0
    while True:
        if i>=len(b):return -1
        c=b[i];i+=1;e=c&0x1F
        if e==0x18:
            d-=1
            if d<=0:break
            continue
        tl=TAGLEN[(c>>5)&7]
        if i+tl>len(b):return -1
        i+=tl
        if e<=7:i+=1<<(e&3)
        elif e in(8,9):pass
        elif e==0xA:i+=4
        elif e==0xB:i+=8
        elif 0xC<=e<=0x13:
            lf=1<<((e-0xC)&3)
            if i+lf>len(b):return -1
            i+=lf+int.from_bytes(b[i:i+lf],'little')
        elif e==0x14:pass
        elif 0x15<=e<=0x17:d+=1
        else:return -1
        if i>len(b):return -1
    return i-o
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(5)
p=0
while p<len(data):
    a=mh(data,p)
    if a<0:break
    b=ph(data,p+a)
    if b<0:break
    t=tv(data,p+a+b)
    if t<0:break
    msg_end=p+a+b+t+16
    if msg_end>len(data):msg_end=len(data)
    s.sendto(data[p:msg_end],('127.0.0.1',${COV_PORT}))
    try:s.recvfrom(4096)
    except:pass
    p=msg_end
s.close()
" 2>/dev/null

  kill -TERM "${dut_pid}" 2>/dev/null; wait "${dut_pid}" 2>/dev/null
  rm -rf "${kvs_dir}" 2>/dev/null

  find "${PROFRAW_DIR}" -name "snap-seed-${count}-*.profraw" -type f 2>/dev/null | head -1
}

COV_PORT=$(( 21050 + $(date +%S) % 50 ))
count=0; accum=()

echo "seed,elapsed_s,covered_functions,total_functions" > "${OUTPUT}"

for seed in "${initial[@]}"; do
  count=$((count + 1))
  pf=$(replay_one "${seed}" "${count}")
  [[ -n "${pf}" ]] && accum+=("${pf}")
  # Always snapshot initial seeds
  merge_now=1
done

disc_total="${#discovered[@]}"
disc_idx=0
for seed in "${discovered[@]}"; do
  count=$((count + 1)); disc_idx=$((disc_idx + 1))
  pf=$(replay_one "${seed}" "${count}")
  [[ -n "${pf}" ]] && accum+=("${pf}")

  # Snapshot every SKIPCOUNT seeds + last seed
  if [[ $((count % SKIPCOUNT)) -ne 0 && "${disc_idx}" -ne "${disc_total}" ]]; then
    continue
  fi
  [[ "${#accum[@]}" -eq 0 ]] && continue

  # Merge
  local merge_args=()
  [[ -f "${BASELINE}" ]] && merge_args+=("${BASELINE}")
  merge_args+=("${accum[@]}")
  local tmp_out="${SNAP_DIR}/snap-tmp.profdata"
  if llvm-profdata merge --failure-mode=warn "${merge_args[@]}" -o "${tmp_out}" 2>/dev/null && [[ -s "${tmp_out}" ]]; then
    cp "${tmp_out}" "${BASELINE}"
    rm -f "${accum[@]}" 2>/dev/null
    local cov=$(llvm-profdata show --all-functions "${BASELINE}" 2>/dev/null | grep -c "Function count: [1-9]" || echo 0)
    local tot=$(llvm-profdata show --all-functions "${BASELINE}" 2>/dev/null | grep -c "Function count:" || echo 0)
    echo "${count},$(date +%s),${cov},${tot}" >> "${OUTPUT}"
    echo "[snapshot] seed ${count}/${total}: ${cov}/${tot} functions covered" >&2
  fi
  accum=()
done

echo "[snapshot] done: ${count} seeds replayed, baseline at ${BASELINE}" >&2
