#!/usr/bin/env python3
"""Parallel AFLNet Phase-2 coverage replay.

Same result as aflnet_phase2_replay.sh but the expensive part — replaying each
queued seed through a fresh profgen cov DUT — is fanned out across N worker
processes (one dedicated UDP port each). The cheap, order-dependent part
(cumulative llvm-profdata merge into snapshot-<elapsed>s.profdata, in seed-mtime
order) stays sequential.

  elapsed = seed_mtime - fuzzer_stats:start_time   (relative seconds; the
            aggregator reads the filename number as elapsed directly)

Usage: phase2_parallel.py --eval-dir DIR [--workers 20] [--snapshots 220]
                          [--cov-dut PATH] [--base-port 5800]
"""
import argparse, glob, os, shutil, signal, socket, subprocess, sys, tempfile, time
import multiprocessing as mp
from pathlib import Path

MIC = 16

def split_aflnet(data):
    """Split an AFLNet replayable-queue file into its constituent datagrams.

    AFLNet stores each request region as a length-prefixed record:
        [uint32 little-endian length][length bytes of message] ...
    repeated until EOF. This framing MUST be stripped before sending — the
    DUT expects raw Matter datagrams. Feeding the framed bytes straight to a
    Matter-message splitter (split_msgs) misreads the 4-byte length as a
    message header and yields garbage, so the DUT drops everything and only
    process-startup coverage is recorded (the bug that made every replay look
    like ~9% / startup-only). Returns [] if the file is not cleanly framed, so
    the caller can fall back to split_msgs for raw (non-AFLNet) inputs.
    """
    out = []
    o = 0
    n = len(data)
    while o + 4 <= n:
        ln = int.from_bytes(data[o:o+4], "little")
        o += 4
        if ln <= 0 or o + ln > n:
            return []  # not length-framed (or truncated) -> let caller fall back
        out.append(data[o:o+ln])
        o += ln
    return out if o == n else []

def split_msgs(data):
    def mh(b, o):
        if o+8 > len(b): return -1
        fl = b[o]; n = 8
        if fl & 4: n += 8
        d = fl & 3
        if d == 1: n += 8
        elif d == 2: n += 2
        return n if o+n <= len(b) else -1
    def ph(b, o):
        if o+6 > len(b): return -1
        fl = b[o]; n = 6
        if fl & 0x10: n += 2
        if fl & 2: n += 4
        return n if o+n <= len(b) else -1
    def tlv(b, o):
        i = o; dp = 0; T = (0,1,2,4,2,4,6,8)
        while True:
            if i >= len(b): return -1
            c = b[i]; i += 1; e = c & 0x1F
            if e == 0x18:
                dp -= 1
                if dp <= 0: break
                continue
            tl = T[(c >> 5) & 7]
            if i+tl > len(b): return -1
            i += tl
            if e <= 7: i += 1 << (e & 3)
            elif e in (8, 9): pass
            elif e == 0x0A: i += 4
            elif e == 0x0B: i += 8
            elif 0x0C <= e <= 0x13:
                lf = 1 << ((e-0x0C) & 3)
                if i+lf > len(b): return -1
                i += lf + int.from_bytes(b[i:i+lf], 'little')
            elif e == 0x14: pass
            elif 0x15 <= e <= 0x17: dp += 1
            else: return -1
            if i > len(b): return -1
        return i-o
    out = []; pos = 0
    while pos < len(data):
        a = mh(data, pos)
        if a < 0: break
        b2 = ph(data, pos+a)
        if b2 < 0: break
        t = tlv(data, pos+a+b2)
        if t < 0: break
        end = pos+a+b2+t+MIC
        if end > len(data): end = len(data)
        out.append(data[pos:end]); pos = end
    return out

# --- worker globals (each worker owns one port for its whole lifetime) -------
_PORT = None
_COV_DUT = None
_PROFDATA_TOOL = None

def _winit(counter, base_port, cov_dut, profdata_tool):
    global _PORT, _COV_DUT, _PROFDATA_TOOL
    with counter.get_lock():
        _PORT = base_port + counter.value
        counter.value += 1
    _COV_DUT = cov_dut
    _PROFDATA_TOOL = profdata_tool

def _replay(task):
    """Replay one seed on this worker's port; emit a per-seed profdata. Returns
    (idx, ok)."""
    idx, seed, out_profdata = task
    kvs = tempfile.mkdtemp(prefix="p2par-")
    profraw = os.path.join(kvs, "p.profraw")
    env = dict(os.environ)
    env.update(LLVM_PROFILE_FILE=profraw, MATTER_FUZZ_STORAGE_DIR=kvs,
               MATTER_FUZZ_KVS_PATH=os.path.join(kvs, "k"),
               MATTER_FUZZ_INMEMORY_STORAGE="1")
    try:
        p = subprocess.Popen(
            [_COV_DUT, "--secured-device-port", str(_PORT), "--KVS", os.path.join(kvs, "k")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    except Exception:
        shutil.rmtree(kvs, ignore_errors=True); return (idx, False)
    time.sleep(1.5)  # let the IM/session layer come up, not just the UDP bind
    try:
        data = open(seed, "rb").read()
        # replayable-queue entries are AFLNet length-framed; strip the framing.
        # Fall back to the Matter-message splitter only for raw (unframed) inputs.
        msgs = split_aflnet(data) or split_msgs(data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.3)
        for msg in msgs:
            try:
                s.sendto(msg, ("127.0.0.1", _PORT))
                try: s.recvfrom(4096)
                except socket.timeout: pass
            except Exception: pass
        s.close()
    except Exception:
        pass
    p.send_signal(signal.SIGTERM)
    try: p.wait(timeout=10)
    except Exception:
        p.kill()
        try: p.wait(timeout=5)
        except Exception: pass
    ok = False
    if os.path.exists(profraw) and os.path.getsize(profraw) > 0:
        r = subprocess.run([_PROFDATA_TOOL, "merge", "--failure-mode=warn",
                            profraw, "-o", out_profdata],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok = (r.returncode == 0 and os.path.exists(out_profdata)
              and os.path.getsize(out_profdata) > 0)
    shutil.rmtree(kvs, ignore_errors=True)
    return (idx, ok)

def meta_get(meta_path, key):
    if not os.path.isfile(meta_path): return None
    for line in open(meta_path):
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return None

def start_time_for(afl_out):
    fs = os.path.join(afl_out, "fuzzer_stats")
    if os.path.isfile(fs):
        for line in open(fs):
            if line.startswith("start_time"):
                try: return int(line.split(":", 1)[1].strip())
                except Exception: pass
    # fallback: earliest queue mtime
    q = os.path.join(afl_out, "replayable-queue")
    fts = [os.path.getmtime(f) for f in glob.glob(os.path.join(q, "id:*"))]
    return int(min(fts)) if fts else 0

def process_instance(inst_dir, cov_dut, profdata_tool, workers, base_port, n_snapshots):
    afl_out = os.path.join(inst_dir, "afl-out")
    queue = os.path.join(afl_out, "replayable-queue")
    if not os.path.isdir(queue):
        print(f"[p2par] no queue under {inst_dir}, skip"); return
    start = start_time_for(afl_out)
    # seeds sorted by mtime (discovery order)
    seeds = sorted(glob.glob(os.path.join(queue, "id:*")), key=os.path.getmtime)
    if not seeds:
        print(f"[p2par] empty queue {inst_dir}, skip"); return
    snap_dir = os.path.join(inst_dir, "snapshots"); os.makedirs(snap_dir, exist_ok=True)
    pd_dir = os.path.join(inst_dir, "_perseed_pd"); os.makedirs(pd_dir, exist_ok=True)
    timeline = os.path.join(inst_dir, "timeline.csv")
    name = os.path.basename(inst_dir)
    print(f"[p2par] {name}: {len(seeds)} seeds, start={start}, workers={workers}", flush=True)

    tasks = [(i, s, os.path.join(pd_dir, f"s-{i}.profdata")) for i, s in enumerate(seeds)]
    counter = mp.Value("i", 0)
    t0 = time.time()
    done_ok = 0
    with mp.Pool(workers, initializer=_winit,
                 initargs=(counter, base_port, cov_dut, profdata_tool)) as pool:
        for k, (idx, ok) in enumerate(pool.imap_unordered(_replay, tasks, chunksize=4), 1):
            if ok: done_ok += 1
            if k % 250 == 0 or k == len(tasks):
                el = time.time() - t0
                print(f"[p2par] {name}: replayed {k}/{len(tasks)} "
                      f"({done_ok} ok) {el:.0f}s", flush=True)

    # Sequential cumulative merge in mtime order -> snapshots.
    step = max(1, len(seeds) // n_snapshots)
    with open(timeline, "w") as tl:
        tl.write("elapsed_s,snapshot,profraw_count,seed_count\n")
    baseline = None
    accum = []
    last = len(seeds) - 1
    n_snap = 0
    for i, s in enumerate(seeds):
        pd = os.path.join(pd_dir, f"s-{i}.profdata")
        if os.path.exists(pd) and os.path.getsize(pd) > 0:
            accum.append(pd)
        if (i + 1) % step == 0 or i == last:
            if not accum and baseline is None:
                continue
            elapsed = max(0, int(os.path.getmtime(s)) - start)
            out = os.path.join(snap_dir, f"snapshot-{elapsed}s.profdata")
            args = ([baseline] if baseline else []) + accum
            r = subprocess.run([profdata_tool, "merge", "--failure-mode=warn", *args, "-o", out],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0 and os.path.exists(out) and os.path.getsize(out) > 0:
                baseline = out + ".base"
                shutil.copy(out, baseline)
                with open(timeline, "a") as tl:
                    tl.write(f"{elapsed},{out},{len(accum)},{i+1}\n")
                accum = []
                n_snap += 1
    # tidy: drop per-seed profdatas + baseline copies (snapshots are what matter)
    shutil.rmtree(pd_dir, ignore_errors=True)
    for b in glob.glob(os.path.join(snap_dir, "*.base")):
        os.remove(b)
    print(f"[p2par] {name}: {n_snap} snapshots written -> {snap_dir}", flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval-dir", required=True)
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--snapshots", type=int, default=220, help="approx snapshots per instance")
    ap.add_argument("--cov-dut", default=None)
    ap.add_argument("--base-port", type=int, default=5800)
    ap.add_argument("--only", default=None, help="process only this instance (e.g. instance-01)")
    args = ap.parse_args()

    eval_dir = args.eval_dir
    meta = os.path.join(eval_dir, "eval-meta.txt")
    cov_dut = args.cov_dut or meta_get(meta, "coverage_binary")
    if not cov_dut or not os.path.isfile(cov_dut):
        sys.exit(f"[p2par] cov DUT not found: {cov_dut}")
    repo = Path(__file__).resolve().parents[4]
    profdata_tool = shutil.which("llvm-profdata") or str(
        repo / ".environment/cipd/packages/pigweed/bin/llvm-profdata")
    if not (os.path.isfile(profdata_tool) or shutil.which("llvm-profdata")):
        sys.exit("[p2par] llvm-profdata not found")

    insts = sorted(glob.glob(os.path.join(eval_dir, "instance-*")))
    if args.only:
        insts = [d for d in insts if os.path.basename(d) == args.only]
    if not insts:
        sys.exit(f"[p2par] no instances under {eval_dir}")
    print(f"[p2par] cov_dut={cov_dut}\n[p2par] instances={[os.path.basename(d) for d in insts]}", flush=True)
    for inst in insts:
        process_instance(inst, cov_dut, profdata_tool, args.workers, args.base_port, args.snapshots)
    print("[p2par] all instances done", flush=True)

if __name__ == "__main__":
    main()
