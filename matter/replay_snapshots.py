"""Strict cumulative merge and publication for saved-queue measurements."""
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def snapshot_plan(elapsed, duration, interval, n_snapshots):
    if interval > 0:
        duration = max(duration, max(elapsed, default=0), 1)
        windows = max(1, (duration + interval - 1) // interval)
        buckets = {}
        for i, seconds in enumerate(elapsed):
            window = min(max(0, (seconds + interval - 1) // interval - 1), windows - 1)
            buckets.setdefault(window, []).append(i)
        return [(min((w + 1) * interval, duration), buckets.get(w, [])) for w in range(windows)]
    step = max(1, (len(elapsed) + n_snapshots - 1) // n_snapshots)
    plan = []
    for i in range(0, len(elapsed), step):
        end = min(i + step, len(elapsed))
        point = elapsed[end - 1]
        indices = list(range(i, end))
        # Several AFL queue entries can have the same one-second mtime. Merge
        # those buckets so each published snapshot path and timeline row is
        # unique; otherwise later writes silently replace earlier profdata.
        if plan and plan[-1][0] == point:
            plan[-1][1].extend(indices)
        else:
            plan.append((point, indices))
    return plan


def publish_snapshots(instance, raw_records, plan, tool, context, incremental=False):
    """Publish cumulative snapshots with an exact retained-raw input ledger.

    Incremental mode is ONLY for these disjoint fresh-process queue replays:
    add each new raw once to the previous cumulative indexed profile. It is
    not valid for repeated cumulative dumps from a continuously running DUT.
    The complete raw ledger is retained for independent from-scratch rebuilds.
    """
    instance = Path(instance)
    planned = [index for _elapsed, indices in plan for index in indices]
    if sorted(planned) != list(range(len(raw_records))) or len(set(planned)) != len(planned):
        raise RuntimeError("snapshot plan must include every seed index exactly once")
    stage = Path(tempfile.mkdtemp(prefix="_snapshot-stage-", dir=instance))
    snapshots = stage / "snapshots"
    raw_inputs = stage / "raw-inputs"
    snapshots.mkdir()
    raw_inputs.mkdir()
    seen_indices, rows, previous_snapshot = [], [], None
    try:
        for elapsed, indices in plan:
            seen_indices.extend(indices)
            if not seen_indices:
                continue
            output = snapshots / f"snapshot-{elapsed}s.profdata"
            merge_indices = indices if incremental else seen_indices
            inputs = [raw_records[i]["path"] for i in merge_indices]
            if incremental and previous_snapshot is not None:
                inputs.insert(0, str(previous_snapshot))
            r = subprocess.run([tool, "merge", *inputs, "-o", str(output)],
                               capture_output=True, text=True)
            (stage / f"merge-{elapsed}.log").write_text(r.stdout + r.stderr)
            if r.returncode or not output.is_file() or not output.stat().st_size:
                raise RuntimeError(f"cumulative merge failed at {elapsed}s: {r.stderr.strip()}")
            previous_snapshot = output
            manifest = raw_inputs / f"snapshot-{elapsed}s.tsv"
            with manifest.open("w", newline="") as stream:
                writer = csv.writer(stream, delimiter="\t")
                writer.writerow(["seed_index", "profraw", "sha256", "size"])
                for index in seen_indices:
                    raw = raw_records[index]
                    writer.writerow([index, os.path.relpath(raw["path"], instance),
                                     raw["sha256"], raw["size"]])
            rows.append([elapsed, str(instance / "snapshots" / output.name),
                         len(indices), len(seen_indices),
                         str(instance / "raw-inputs" / manifest.name)])
        if not rows or len(seen_indices) != len(raw_records):
            raise RuntimeError(
                f"incomplete cumulative coverage: {len(seen_indices)}/{len(raw_records)} seeds"
            )
        with (stage / "timeline.csv").open("w") as f:
            writer = csv.writer(f)
            writer.writerow(["elapsed_s", "snapshot", "new_profraw_count", "seed_count",
                             "raw_input_manifest"])
            writer.writerows(rows)
        (stage / "measurement.json").write_text(json.dumps(dict(context, status="complete",
                                                            seed_count=len(seen_indices),
                                                            retained_profraw_count=len({
                                                                raw["sha256"] for raw in raw_records
                                                            }),
                                                            snapshots=len(rows)), indent=2) + "\n")
        _publish(instance, stage)
        shutil.rmtree(stage)
    except Exception:
        # Keep the staging directory, logs and per-seed profiles for diagnosis/resume.
        raise
    return len(rows)


def _publish(instance, stage):
    names = ("snapshots", "raw-inputs", "timeline.csv", "measurement.json")
    previous = stage / "previous"
    previous.mkdir()
    published = []
    try:
        for name in names:
            target = instance / name
            if target.exists():
                os.replace(target, previous / name)
            os.replace(stage / name, target)
            published.append(name)
    except Exception:
        for name in reversed(names):
            target = instance / name
            if name in published:
                os.replace(target, stage / name)
            if (previous / name).exists():
                os.replace(previous / name, target)
        raise
