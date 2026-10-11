"""Isolated UDP queue replay; infrastructure failures never become coverage."""
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time

_PORT = _COV_DUT = _PROFDATA_TOOL = _CONTEXT = None
_POLL_MS = 100
_STORAGE_MODE = "file"
_DRAIN_IDLE_SECONDS = 0.001
_STARTUP_TIMEOUT_SECONDS = 30.0
_STARTUP_SETTLE_SECONDS = float(os.environ.get(
    "AFLNET_REPLAY_STARTUP_SETTLE_SECONDS", "0.25"))
if not 0 <= _STARTUP_SETTLE_SECONDS <= 60:
    raise ValueError("AFLNET_REPLAY_STARTUP_SETTLE_SECONDS must be between 0 and 60")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def replay_context(cov_dut, tool, poll_ms=100, storage_mode="file"):
    if storage_mode != "file":
        raise ValueError(f"AFLNet requires file storage; got {storage_mode}")
    delegate = "linux-file-backed"
    platform_config = "memory-default"
    return {"schema": "aflnet-queue-replay.v8", "coverage_kind": "saved_queue_replay",
            "cov_dut_sha256": sha(cov_dut), "profdata_tool_sha256": sha(tool),
            "worker_sha256": sha(__file__), "storage_mode": storage_mode,
            "storage_delegate": delegate,
            "platform_config_storage": platform_config,
            "testcase_state_reset": "fresh-process",
            "raw_profile_retention": "content_addressed",
            "snapshot_merge_inputs": "profraw",
            "transport": "udp", "oversized_udp": "attempt-send-stop-on-EMSGSIZE-preserve-prefix",
            "startup_readiness": "process-owned-udp-socket-bound",
            "startup_timeout_seconds": _STARTUP_TIMEOUT_SECONDS,
            "startup_settle_seconds": _STARTUP_SETTLE_SECONDS,
            "first_response_timeout_ms": poll_ms,
            "drain_idle_timeout_ms": int(_DRAIN_IDLE_SECONDS * 1000)}


def _process_socket_inodes(pid, proc_root=Path("/proc")):
    """Return socket inodes currently owned by one process.

    Reading the process fd table prevents a different replay worker that uses
    the same network namespace from satisfying this worker's readiness gate.
    """
    inodes = set()
    try:
        descriptors = (proc_root / str(pid) / "fd").iterdir()
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inodes.add(target[8:-1])
    except OSError:
        pass
    return inodes


def _bound_udp_inodes(port, proc_root=Path("/proc")):
    """Return UDP/UDP6 socket inodes bound to ``port`` in this netns."""
    matches = set()
    for name in ("udp", "udp6"):
        try:
            lines = (proc_root / "net" / name).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) <= 9:
                continue
            try:
                local_port = int(fields[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                continue
            if local_port == port:
                matches.add(fields[9])
    return matches


def wait_for_udp_ready(process, port, timeout_seconds=_STARTUP_TIMEOUT_SECONDS,
                       settle_seconds=_STARTUP_SETTLE_SECONDS, proc_root=Path("/proc")):
    """Wait until this exact DUT process owns the requested bound UDP socket."""
    started = time.monotonic()
    deadline = started + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"DUT exited before UDP readiness: {process.returncode}")
        owned = _process_socket_inodes(process.pid, proc_root)
        if owned and owned & _bound_udp_inodes(port, proc_root):
            if settle_seconds:
                time.sleep(settle_seconds)
            return time.monotonic() - started
        time.sleep(0.01)
    raise RuntimeError(f"DUT did not bind UDP port {port} within {timeout_seconds:g}s")


def split_aflnet(data):
    """Validate file framing, independently of whether messages fit in UDP.

    Historical AFLNet saves the attempted message even when send() fails.
    Keep it so send_requests can reproduce that failure after the valid prefix.
    """
    out, offset = [], 0
    while offset + 4 <= len(data):
        size = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4
        if size <= 0 or offset + size > len(data):
            return []
        out.append(data[offset:offset + size])
        offset += size
    return out if out and offset == len(data) else []


def cached_profile(task, context):
    _, seed, profile = task
    try:
        record = json.loads(Path(profile + ".json").read_text())
        raw = (Path(profile).parent / record["profraw"]).resolve()
        return (record["status"] == "ok" and record["context"] == context
                and record["input_sha256"] == sha(seed)
                and record["profdata_sha256"] == sha(profile)
                and record["profraw_sha256"] == sha(raw)
                and record["profraw_size"] == raw.stat().st_size)
    except (OSError, ValueError, KeyError):
        return False


def cached_raw_record(task, context):
    """Return a verified retained-raw descriptor for a successful cache entry."""
    if not cached_profile(task, context):
        raise RuntimeError(f"invalid replay cache: {task[2]}")
    record = json.loads(Path(task[2] + ".json").read_text())
    raw = (Path(task[2]).parent / record["profraw"]).resolve()
    return {"index": task[0], "path": str(raw),
            "sha256": record["profraw_sha256"], "size": record["profraw_size"]}


def retain_raw(raw, profile):
    """Atomically retain a raw profile under the instance content hash store."""
    digest = sha(raw)
    raw_dir = Path(profile).parent.parent / "_perseed_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    retained = raw_dir / f"sha256_{digest}.profraw"
    if not retained.exists():
        temporary = raw_dir / f".{retained.name}.{os.getpid()}.tmp"
        shutil.copyfile(raw, temporary)
        if sha(temporary) != digest:
            temporary.unlink(missing_ok=True)
            raise RuntimeError("retained raw profile changed during copy")
        os.replace(temporary, retained)
    if sha(retained) != digest:
        raise RuntimeError(f"content-addressed raw profile is corrupt: {retained}")
    return retained, digest


def _winit(counter, base_port, cov_dut, profdata_tool, poll_ms=100, storage_mode="file"):
    global _PORT, _COV_DUT, _PROFDATA_TOOL, _CONTEXT, _POLL_MS, _STORAGE_MODE
    with counter.get_lock():
        _PORT = base_port + counter.value
        counter.value += 1
    _COV_DUT, _PROFDATA_TOOL, _POLL_MS = cov_dut, profdata_tool, poll_ms
    _STORAGE_MODE = storage_mode
    _CONTEXT = replay_context(cov_dut, profdata_tool, poll_ms, storage_mode)


def response_meta(data):
    result = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if len(data) >= 14:
        flags = data[0]
        header = 8 + (8 if flags & 4 else 0) + (8 if flags & 3 == 1 else 2 if flags & 3 == 2 else 0)
        if header + 6 <= len(data):
            result.update(opcode=data[header + 1],
                          exchange_id=int.from_bytes(data[header + 2:header + 4], "little"))
    return result


def recv_burst(sock, first_timeout_seconds):
    """Match AFLNet net_recv: wait for one datagram, then drain until 1 ms idle."""
    replies = []
    sock.settimeout(first_timeout_seconds)
    try:
        replies.append(sock.recv(65536))
    except (socket.timeout, BlockingIOError):
        return replies
    while True:
        sock.settimeout(_DRAIN_IDLE_SECONDS)
        try:
            replies.append(sock.recv(65536))
        except (socket.timeout, BlockingIOError):
            return replies


def send_requests(messages, process):
    requests = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("127.0.0.1", _PORT))
        for msg in messages:
            if process.poll() is not None:
                raise RuntimeError(f"DUT exited before send: {process.returncode}")
            row = {"request": response_meta(msg), "responses": [], "sent": False}
            try:
                sent = sock.send(msg)
            except OSError as error:
                if error.errno != errno.EMSGSIZE or len(msg) <= 65507:
                    raise
                row.update(transport_error={"errno": error.errno, "name": "EMSGSIZE"},
                           timeout=True)
                requests.append(row)
                break  # AFLNet jumps to HANDLE_RESPONSES; it never sends the tail.
            if sent != len(msg):
                raise RuntimeError("short UDP send")
            row["sent"] = True
            for reply in recv_burst(sock, _POLL_MS / 1000.0):
                row["responses"].append(response_meta(reply))
            # No response is a legitimate result for an invalid fuzzed message.
            row["timeout"] = not row["responses"]
            requests.append(row)
        # AFLNet performs one final net_recv after the sequence and attributes
        # any late response to the last request region.
        if requests:
            for reply in recv_burst(sock, _POLL_MS / 1000.0):
                requests[-1]["responses"].append(response_meta(reply))
            requests[-1]["timeout"] = not requests[-1]["responses"]
    return requests


def stop_dut(process):
    if process.poll() is not None:
        raise RuntimeError(f"DUT exited during replay: {process.returncode}")
    process.send_signal(signal.SIGTERM)
    try:
        rc = process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError("DUT failed to shut down and flush its profile")
    if rc not in (0, -signal.SIGTERM):
        raise RuntimeError(f"DUT shutdown failed: {rc}")
    return rc


def _replay(task):
    """Return (index, ok); retain detailed diagnostics alongside the profile."""
    idx, seed, out = task
    record = {"index": idx, "input": seed, "status": "failed", "spawned": False,
              "context": _CONTEXT or replay_context(
                  _COV_DUT, _PROFDATA_TOOL, _POLL_MS, _STORAGE_MODE)}
    work = process = None
    temporary = out + ".tmp"
    try:
        data = Path(seed).read_bytes()
        record["input_sha256"] = hashlib.sha256(data).hexdigest()
        messages = split_aflnet(data)
        if not messages:
            raise ValueError("missing, empty or malformed AFLNet queue framing")
        work = Path(tempfile.mkdtemp(prefix="p2par-"))
        env = dict(os.environ, LLVM_PROFILE_FILE=str(work / "p.profraw"),
                   MATTER_FUZZ_STORAGE_DIR=str(work), MATTER_FUZZ_KVS_PATH=str(work / "k"))
        env.pop("MATTER_FUZZ_INMEMORY_STORAGE", None)
        with open(out + ".dut.log", "wb") as log:
            process = subprocess.Popen([_COV_DUT, "--secured-device-port", str(_PORT),
                                        "--KVS", str(work / "k")],
                                       stdout=log, stderr=subprocess.STDOUT, env=env)
            record["spawned"] = True
            record["startup_wait_seconds"] = wait_for_udp_ready(process, _PORT)
            record["requests"] = send_requests(messages, process)
            record["queued_messages"] = len(messages)
            record["sent_messages"] = sum(row["sent"] for row in record["requests"])
            record["transport_errors"] = [
                {"message_index": i, **row["transport_error"]}
                for i, row in enumerate(record["requests"]) if "transport_error" in row
            ]
            record["dut_exit"] = stop_dut(process)
        raw = work / "p.profraw"
        if not raw.is_file() or not raw.stat().st_size:
            raise RuntimeError("DUT produced no profile")
        retained, raw_digest = retain_raw(raw, out)
        record.update(profraw=os.path.relpath(retained, Path(out).parent),
                      profraw_sha256=raw_digest, profraw_size=retained.stat().st_size)
        merge = subprocess.run([_PROFDATA_TOOL, "merge", str(retained), "-o", temporary],
                               capture_output=True, text=True)
        record["merge_stderr"] = merge.stderr
        if merge.returncode or not Path(temporary).is_file() or not Path(temporary).stat().st_size:
            raise RuntimeError(f"profile merge failed: {merge.returncode}")
        os.replace(temporary, out)
        record.update(status="ok", profdata_sha256=sha(out))
    except Exception as error:
        record["error"] = f"{type(error).__name__}: {error}"
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if work is not None:
            if record["status"] != "ok":
                failure = Path(out + ".failed")
                shutil.rmtree(failure, ignore_errors=True)
                shutil.move(str(work), failure)
            else:
                shutil.rmtree(work)
        Path(temporary).unlink(missing_ok=True)
        Path(out + ".json.tmp").write_text(json.dumps(record, indent=2) + "\n")
        os.replace(out + ".json.tmp", out + ".json")
    return idx, record["status"] == "ok"
