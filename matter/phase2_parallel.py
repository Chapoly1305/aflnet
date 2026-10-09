#!/usr/bin/env python3
"""Parallel AFLNet Phase-2 coverage replay.

Same result as aflnet_phase2_replay.sh but the expensive part — replaying each
queued seed through a fresh profgen cov DUT — is fanned out across N worker
processes (one dedicated UDP port each). The cheap, order-dependent part
(cumulative llvm-profdata merge into snapshot-<elapsed>s.profdata, in seed-mtime
order) stays sequential.

  Hopper --require-active-time: elapsed = seed_mtime - fuzz_start_epoch,
  clipped into [0, requested_fuzz_seconds]. The initial dry-run seeds belong
  to t=0. Missing or conflicting active clock evidence is fatal.

Two bucketing modes decide WHEN a cumulative snapshot is emitted:

  --interval SEC  (default 1800)  fixed wall-clock windows. Emits one snapshot
      per window at its right edge (1800s, 3600s, ...) for the whole campaign,
      including windows in which AFL found nothing (the cumulative profile is
      simply carried forward). This is what makes the curve directly comparable
      to EP2, whose profraw_snapshotter.py samples every 1800s.
  --interval 0    legacy behaviour: ~--snapshots buckets of equal SEED COUNT,
      so the x-axis spacing follows discovery rate, not the clock.

Created: 2026-06-26 (interval mode added 2026-09-06)
Purpose: AFLNet/ChatAFL Phase-2 coverage replay for the cross-fuzzer benchmark;
         interval mode added so the baseline curve matches EP2 sampling.
Retention: PERMANENT (benchmark pipeline step)

Usage: phase2_parallel.py --eval-dir DIR [--workers 20] [--interval 1800]
                          [--snapshots 220] [--cov-dut PATH] [--base-port 5800]
"""
import argparse, glob, os, shutil, sys, time
import multiprocessing as mp
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay_worker import (_replay, _winit, cached_profile, cached_raw_record,
                           replay_context)
from replay_snapshots import publish_snapshots, snapshot_plan

def meta_get(meta_path, key):
    if not os.path.isfile(meta_path): return None
    with open(meta_path, encoding="utf-8") as stream:
        for line in stream:
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    return None

def start_time_for(afl_out):
    fs = os.path.join(afl_out, "fuzzer_stats")
    if os.path.isfile(fs):
        with open(fs, encoding="utf-8") as stream:
            for line in stream:
                if line.startswith("start_time"):
                    try: return int(line.split(":", 1)[1].strip())
                    except Exception: pass
    # fallback: earliest queue mtime
    q = os.path.join(afl_out, "replayable-queue")
    fts = [os.path.getmtime(f) for f in glob.glob(os.path.join(q, "id:*"))]
    return int(min(fts)) if fts else 0

def duration_for(afl_out, start, seeds):
    """Campaign wall-clock length: fuzzer_stats last_update - start_time, with
    the newest queue entry as fallback. Bounds how many fixed windows exist."""
    fs = os.path.join(afl_out, "fuzzer_stats")
    if os.path.isfile(fs):
        with open(fs, encoding="utf-8") as stream:
            for line in stream:
                if line.startswith("last_update"):
                    try:
                        d = int(line.split(":", 1)[1].strip()) - start
                        if d > 0:
                            return d
                    except Exception:
                        pass
    return max((int(os.path.getmtime(s)) - start for s in seeds), default=0)


def active_clock_for(inst_dir, afl_out):
    """Return the sealed post-calibration time zero and requested duration."""
    run_env = os.path.join(inst_dir, "run.env")
    stats = os.path.join(afl_out, "fuzzer_stats")
    if not os.path.isfile(run_env) or not os.path.isfile(stats):
        raise RuntimeError(f"{inst_dir}: active-time run.env or fuzzer_stats missing")

    def required_int(value, label):
        if value is None or not value.isdecimal():
            raise RuntimeError(f"{inst_dir}: missing or invalid {label}={value!r}")
        return int(value)

    stat_values = {}
    with open(stats, encoding="utf-8") as stream:
        for line in stream:
            if ":" in line:
                key, value = line.split(":", 1)
                stat_values[key.strip()] = value.strip()
    start = required_int(meta_get(run_env, "fuzz_start_epoch"), "fuzz_start_epoch")
    end = required_int(meta_get(run_env, "fuzz_end_epoch"), "fuzz_end_epoch")
    requested = required_int(meta_get(run_env, "requested_fuzz_seconds"), "requested_fuzz_seconds")
    observed = required_int(meta_get(run_env, "observed_fuzz_seconds"), "observed_fuzz_seconds")
    calibration = required_int(meta_get(run_env, "initial_calibration_seconds"), "initial_calibration_seconds")
    wall_start = required_int(stat_values.get("start_time"), "stats start_time")
    stats_start = required_int(stat_values.get("active_fuzz_start_time"), "stats active_fuzz_start_time")
    stats_observed = required_int(stat_values.get("active_fuzz_seconds"), "stats active_fuzz_seconds")
    stats_end = required_int(stat_values.get("last_update"), "stats last_update")
    if (not start or not requested or start != stats_start or end != stats_end
            or observed != stats_observed or calibration != start - wall_start):
        raise RuntimeError(f"{inst_dir}: inconsistent active-time run.env and fuzzer_stats")
    if end < start or observed < max(1, requested - 5) or observed > end - start + 1:
        raise RuntimeError(f"{inst_dir}: incomplete or impossible active-time budget")
    if (meta_get(run_env, "status") != "ok"
            or meta_get(run_env, "initial_calibration_status") != "ok"
            or meta_get(run_env, "initial_calibration_failures") != "0"):
        raise RuntimeError(f"{inst_dir}: initial corpus calibration was not proven clean")
    return start, requested


def process_instance(inst_dir, cov_dut, profdata_tool, workers, base_port, n_snapshots,
                     interval=1800, require_active_time=False):
    afl_out = os.path.join(inst_dir, "afl-out")
    queue = os.path.join(afl_out, "replayable-queue")
    if not os.path.isdir(queue):
        raise RuntimeError(f"no queue under {inst_dir}")
    if require_active_time:
        start, duration = active_clock_for(inst_dir, afl_out)
    else:
        start = start_time_for(afl_out)
    # seeds sorted by mtime (discovery order)
    seeds = sorted(glob.glob(os.path.join(queue, "id:*")), key=lambda p: (os.path.getmtime(p), os.path.basename(p)))
    if not seeds:
        raise RuntimeError(f"empty queue under {inst_dir}")
    poll_text = meta_get(os.path.join(inst_dir, "run.env"), "poll_ms")
    try:
        poll_ms = int(poll_text) if poll_text is not None else 100
    except ValueError as error:
        raise RuntimeError(f"{inst_dir}: invalid poll_ms={poll_text!r}") from error
    if poll_ms < 0:
        raise RuntimeError(f"{inst_dir}: poll_ms must be nonnegative")
    storage_mode = meta_get(os.path.join(inst_dir, "run.env"), "storage_mode")
    if storage_mode != "file":
        raise RuntimeError(f"{inst_dir}: AFLNet requires file storage; got {storage_mode!r}")
    snap_dir = os.path.join(inst_dir, "snapshots"); os.makedirs(snap_dir, exist_ok=True)
    pd_dir = os.path.join(inst_dir, "_perseed_pd"); os.makedirs(pd_dir, exist_ok=True)
    timeline = os.path.join(inst_dir, "timeline.csv")
    name = os.path.basename(inst_dir)
    print(f"[p2par] {name}: {len(seeds)} seeds, start={start}, workers={workers}, "
          f"poll_ms={poll_ms}, storage_mode={storage_mode}", flush=True)

    all_tasks = [(i, s, os.path.join(pd_dir, f"s-{i}.profdata")) for i, s in enumerate(seeds)]
    # A replay can be interrupted after hours of clean per-seed work. Resume
    # from non-empty indexed profiles instead of replaying successful entries.
    context = replay_context(cov_dut, profdata_tool, poll_ms, storage_mode)
    pending = [task for task in all_tasks if not cached_profile(task, context)]
    t0 = time.time()
    done_ok = len(all_tasks) - len(pending)
    if done_ok:
        print(f"[p2par] {name}: resuming with {done_ok}/{len(all_tasks)} existing profiles",
              flush=True)
    for attempt in range(1, 4):
        if not pending:
            break
        counter = mp.Value("i", 0)
        failed = []
        attempted = 0
        with mp.Pool(workers, initializer=_winit,
                     initargs=(counter, base_port, cov_dut, profdata_tool, poll_ms,
                               storage_mode)) as pool:
            for idx, ok in pool.imap_unordered(_replay, pending, chunksize=4):
                attempted += 1
                if ok:
                    done_ok += 1
                else:
                    failed.append(idx)
                if attempted % 250 == 0 or attempted == len(pending):
                    el = time.time() - t0
                    print(f"[p2par] {name}: attempt {attempt} processed "
                          f"{attempted}/{len(pending)} ({done_ok}/{len(all_tasks)} ok) "
                          f"{el:.0f}s", flush=True)
        pending = [all_tasks[idx] for idx in sorted(failed)]
        if pending:
            print(f"[p2par] {name}: retrying {len(pending)} failed seed(s)", flush=True)
    if pending:
        raise RuntimeError(
            f"{name}: {len(pending)} seed replay(s) still failed after 3 attempts"
        )

    if require_active_time:
        elapsed = [min(duration, max(0, int(os.path.getmtime(s)) - start)) for s in seeds]
    else:
        elapsed = [max(0, int(os.path.getmtime(s)) - start) for s in seeds]
        duration = duration_for(afl_out, start, seeds)
    plan = snapshot_plan(elapsed, duration, interval, n_snapshots)
    raw_records = [cached_raw_record(task, context) for task in all_tasks]
    n_snap = publish_snapshots(inst_dir, raw_records, plan, profdata_tool, context)
    print(f"[p2par] {name}: {n_snap} snapshots written -> {snap_dir}", flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval-dir", required=True)
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--snapshots", type=int, default=220,
                    help="legacy seed-count bucketing: approx snapshots per instance (--interval 0)")
    ap.add_argument("--interval", type=int, default=1800,
                    help="fixed wall-clock snapshot window in seconds (default 1800 = EP2 cadence); "
                         "0 selects the legacy seed-count bucketing")
    ap.add_argument("--cov-dut", default=None)
    ap.add_argument("--base-port", type=int, default=5800)
    ap.add_argument("--only", default=None, help="process only this instance (e.g. instance-01)")
    ap.add_argument("--require-active-time", action="store_true",
                    help="fail closed unless post-calibration time zero and full active budget are proven")
    args = ap.parse_args()

    if args.workers < 1 or args.snapshots < 1 or args.interval < 0:
        ap.error("workers/snapshots must be positive; interval must be nonnegative")
    if not 1 <= args.base_port <= 65535 - args.workers + 1:
        ap.error("worker ports are outside UDP port range")

    eval_dir = args.eval_dir
    meta = os.path.join(eval_dir, "eval-meta.txt")
    cov_dut = args.cov_dut or meta_get(meta, "coverage_binary")
    if not cov_dut or not os.path.isfile(cov_dut):
        sys.exit(f"[p2par] cov DUT not found: {cov_dut}")
    # Resolve llvm-profdata: PATH first, then the pigweed CIPD copy when running
    # from a repo checkout. The repo-relative lookup must not assume a checkout
    # layout -- the same file is copied to /opt/fuzzer inside the container,
    # where parents[4] does not exist.
    #
    # It MUST be the same LLVM that built the cov DUT: profdata and
    # coverage-mapping formats are versioned, and merging with Ubuntu's llvm-20
    # while the aggregator read the result with pigweed's LLVM 21 reported
    # "N functions have mismatched data". The campaign image therefore ships the
    # pigweed tools at /opt/llvm and puts that first on PATH, so this which()
    # finds the matching version by default.
    profdata_tool = shutil.which("llvm-profdata")
    if not profdata_tool:
        try:
            cand = Path(__file__).resolve().parents[4] / \
                ".environment/cipd/packages/pigweed/bin/llvm-profdata"
            if cand.is_file():
                profdata_tool = str(cand)
        except IndexError:
            pass
    if not profdata_tool:
        sys.exit("[p2par] llvm-profdata not found (not on PATH, no pigweed CIPD copy)")

    insts = sorted(glob.glob(os.path.join(eval_dir, "instance-*")))
    if args.only:
        insts = [d for d in insts if os.path.basename(d) == args.only]
    if not insts:
        sys.exit(f"[p2par] no instances under {eval_dir}")
    print(f"[p2par] cov_dut={cov_dut}\n[p2par] instances={[os.path.basename(d) for d in insts]}", flush=True)
    for inst in insts:
        process_instance(inst, cov_dut, profdata_tool, args.workers, args.base_port,
                         args.snapshots, args.interval, args.require_active_time)
    print("[p2par] all instances done", flush=True)

if __name__ == "__main__":
    main()
