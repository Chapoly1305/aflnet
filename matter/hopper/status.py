#!/usr/bin/env python3
"""Report AFLNet Hopper progress without treating directories as completion."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


PROFILES = ("file", "memory")
REPLICAS = 10


def read_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.is_file():
        return result
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_instance(path: Path, profile: str) -> tuple[str, list[str]]:
    reasons: list[str] = []
    run = read_env(path / "run.env")
    if not path.is_dir():
        return "planned", ["directory missing"]
    if not run:
        return "started", ["run.env missing"]
    if run.get("container_exit") != "0":
        reasons.append(f"container_exit={run.get('container_exit', 'missing')}")
    if run.get("status") != "ok":
        reasons.append(f"status={run.get('status', 'missing')}")
    if run.get("storage_mode") != profile:
        reasons.append(f"storage_mode={run.get('storage_mode', 'missing')}")
    if run.get("seeds") != "10" or run.get("initial_queue_entries") != "10":
        reasons.append(
            f"initial={run.get('initial_queue_entries', 'missing')}/"
            f"{run.get('seeds', 'missing')}"
        )
    observed = run.get("observed_fuzz_seconds", "")
    if not observed.isdigit() or int(observed) < 86_395:
        reasons.append(f"observed_fuzz_seconds={observed or 'missing'}")
    slurm = read_env(path / "slurm-instance.env")
    host_net = slurm.get("host_net_namespace")
    container_net = slurm.get("container_net_namespace")
    if not host_net or not container_net or host_net == container_net:
        reasons.append("private network namespace not proven")
    host_pid = slurm.get("host_pid_namespace")
    container_pid = slurm.get("container_pid_namespace")
    if not host_pid or not container_pid or host_pid == container_pid:
        reasons.append("private PID namespace not proven")
    if profile == "file":
        if run.get("storage_delegate") != "linux-file-backed":
            reasons.append(f"storage_delegate={run.get('storage_delegate', 'missing')}")
        if slurm.get("state_filesystem") in (None, "tmpfs", "ramfs"):
            reasons.append(f"state_filesystem={slurm.get('state_filesystem', 'missing')}")
        if run.get("storage_filesystem") != slurm.get("state_filesystem"):
            reasons.append("recorded file-storage filesystem differs")
        kvs = path / "dut-state" / "kvs"
        if not kvs.is_file() or not kvs.stat().st_size:
            reasons.append("nonempty persisted file KVS missing")
        elif run.get("kvs_sha256") != sha256(kvs):
            reasons.append("persisted file KVS hash differs")
    else:
        if run.get("storage_delegate") != "test-in-memory":
            reasons.append(f"storage_delegate={run.get('storage_delegate', 'missing')}")
        if run.get("kvs_bytes") != "0":
            reasons.append(f"kvs_bytes={run.get('kvs_bytes', 'missing')}")
        kvs = path / "dut-state" / "kvs"
        if kvs.is_file() and kvs.stat().st_size:
            reasons.append("memory profile persisted nonzero KVS bytes")
    if not (path / ".done").is_file() or not (path / "slurm-instance.complete").is_file():
        reasons.append("fuzz completion marker missing")
    if reasons:
        return "invalid", reasons
    if not (path / "replay.complete").is_file():
        return "fuzz-complete", ["queue replay pending"]
    try:
        measurement = json.loads((path / "measurement.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return "replay-invalid", [f"measurement: {error}"]
    if measurement.get("status") != "complete" or measurement.get("coverage_kind") != "saved_queue_replay":
        return "replay-invalid", ["measurement is not complete saved_queue_replay"]
    if not isinstance(measurement.get("seed_count"), int) or measurement["seed_count"] <= 0:
        return "replay-invalid", ["measurement has no replayed seeds"]
    if not isinstance(measurement.get("snapshots"), int) or measurement["snapshots"] <= 0:
        return "replay-invalid", ["measurement has no replay snapshots"]
    coverage = path / "coverage_timeline.clusters.csv"
    if not coverage.is_file() or not coverage.stat().st_size:
        return "replay-complete", ["per-instance coverage export pending"]
    return "coverage-valid", []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_root", type=Path)
    parser.add_argument("--no-fail", action="store_true")
    parser.add_argument("--show-reasons", action="store_true")
    args = parser.parse_args()
    root = args.campaign_root.resolve()

    summary: list[dict[str, object]] = []
    final_ok = (root / "campaign.done").is_file()
    for profile in PROFILES:
        profile_root = root / "profiles" / profile
        counts: dict[str, int] = {}
        failures: list[str] = []
        for replica in range(1, REPLICAS + 1):
            name = f"instance-{replica:02d}"
            state, reasons = inspect_instance(profile_root / name, profile)
            counts[state] = counts.get(state, 0) + 1
            if reasons:
                failures.append(f"{name}: {', '.join(reasons)}")
        aggregate = read_env(profile_root / "eval-meta.txt")
        profile_contract = (
            aggregate.get("instances") == "10"
            and aggregate.get("fuzz_seconds") == "86400"
            and aggregate.get("corpus_variant") == "selected10"
            and aggregate.get("seed_count") == "10"
            and aggregate.get("storage_profile") == profile
            and aggregate.get("coverage_kind") == "saved_queue_replay"
        )
        fuzz_complete = (profile_root / "fuzz.complete").is_file()
        coverage_complete = (profile_root / "coverage.complete").is_file()
        profile_done = (profile_root / ".done").is_file()
        coverage_csv = profile_root / "coverage_over_time.csv"
        aggregation_pass = False
        try:
            data = json.loads((profile_root / "coverage_aggregation.json").read_text(encoding="utf-8"))
            aggregation_pass = data.get("status") == "pass" and len(data.get("instances", [])) == REPLICAS
        except (OSError, json.JSONDecodeError):
            pass
        valid = (
            counts.get("coverage-valid", 0) == REPLICAS
            and profile_contract
            and fuzz_complete
            and coverage_complete
            and profile_done
            and coverage_csv.is_file()
            and coverage_csv.stat().st_size > 0
            and aggregation_pass
        )
        final_ok = final_ok and valid
        summary.append(
            {
                "profile": profile,
                "states": counts,
                "profile_contract": profile_contract,
                "fuzz_complete": fuzz_complete,
                "coverage_complete": coverage_complete,
                "aggregation_pass": aggregation_pass,
                "profile_done": profile_done,
                "declared_instances": aggregate.get("instances"),
                "failures": failures,
            }
        )

    print(f"campaign={root}")
    for row in summary:
        print(
            f"{row['profile']}: states={row['states']} "
            f"profile_contract={int(bool(row['profile_contract']))} "
            f"fuzz_complete={int(bool(row['fuzz_complete']))} "
            f"coverage_complete={int(bool(row['coverage_complete']))} "
            f"aggregation_pass={int(bool(row['aggregation_pass']))} "
            f"profile_done={int(bool(row['profile_done']))}"
        )
        if args.show_reasons:
            for reason in row["failures"]:
                print(f"  {reason}")

    submission = root / "manifest" / "submission.tsv"
    if submission.is_file():
        with submission.open(encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))
        print(f"submitted_jobs={rows}")
    print(f"final_valid={int(final_ok)}")
    return 0 if final_ok or args.no_fail else 1


if __name__ == "__main__":
    raise SystemExit(main())
