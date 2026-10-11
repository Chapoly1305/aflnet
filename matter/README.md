# AFLNet ↔ Matter integration

AFLNet fuzzes the native Linux `all-clusters-app` over plaintext Matter UDP.
The compile-time transport adapter injects a fixed CASE session so mutations
reach cluster handlers. See `ai_docs/benchmark-fuzzers.md` for the protocol
and fairness boundary.

## Campaign runtime

The campaign image is fuzz-only. It contains:

- `afl-fuzz`;
- the ASAN/AFL-instrumented fuzz DUT;
- one frozen raw seed pool and dictionary;
- `entrypoint.sh` and `snapshot.sh`.

It intentionally does not contain Python, the coverage DUT, LLVM tools, replay
workers, or aggregation code. Bundle validation happens on the build host.
Coverage is reconstructed later from each retained `replayable-queue`.

Coverage replay containers must be launched with
`run_coverage_replay_docker.sh`. The launcher gives every shard its own Docker
bridge network namespace and intentionally provides no host-network option.
The replay worker and coverage DUT communicate over loopback inside the
container, so no host port publication is required. Do not replace this with
`--network host`: many fresh Matter DUT processes enumerate interfaces through
netlink during startup, and sharing one host namespace turns that work into a
serialized kernel bottleneck that can prevent LLVM profiles from flushing.

The batch-specific replay driver remains in its coverage-analysis directory;
pass its ordinary arguments after `--`:

```bash
examples/fuzzers/aflnet/matter/run_coverage_replay_docker.sh \
  --image matter-ep2-fuzzer:coverage \
  --name aflnet-coverage-full-01 \
  --analysis-dir /data/coverage-analysis \
  --protected-runs-dir /data/protected-runs \
  --cpuset 0-15 --startup-settle-seconds 10 -- \
  --stage run --skip-prepare --no-finalize --workers 16 \
  --export-jobs 4 --base-port 42000 \
  --replay-scripts-dir /data/coverage-analysis/source-coverage/provenance/replay \
  --only full/instance-01
```

The benchmark-wide `reject-list.v1` policy comes from
`examples/fuzzers/mgptfuzz/resource/reject_list.json` (the same eight entries
are mirrored by MatterGuard). Protection is deliberately layered:

- Step 3.3 excludes a source scenario when its setup or target contains a
  protected operation, with source/hash/path evidence in the projection.
- `afl-fuzz` parses every mutated Invoke/Write path before `run_target()`.
  A match is neither sent nor scored/saved; policy/category counters appear in
  `fuzzer_stats`.
- The fixed-CASE fuzz DUT independently denies the same parsed `RequestPath`
  with IM `UnsupportedAccess` before cluster dispatch.

Image construction fails if the client parser or DUT fail-safe is absent, or
if the reject-list hash differs from the sealed corpus evidence.

Build and run locally:

```bash
./step3.5_build_campaign_executables.sh --aflnet-only
./step4.1_aflnet_eval.sh --instances 10 --fuzz-seconds 86400 --interval 1800
```

For selected10, prepare its locked bundle and use the selected launcher:

```bash
./step4.1_aflnet_curated.sh --prepare-only
./step4.1_aflnet_curated.sh
```

## Hopper

Hopper has one AFLNet Slurm script: `hopper/run_campaign.sbatch`. It copies and
expands one prebuilt SIF on `$SLURM_TMPDIR`, then starts one `srun` with ten
tasks, one CPU per task. Each task owns one private Apptainer network/PID
namespace and writes its live queue, KVS, and snapshots only to node-local
storage. After `srun` ends, each instance is checksum-verified and published
once to `/scratch`; the NAS is not in AFLNet's hot path.

```bash
sbatch --export=NONE hopper/run_campaign.sbatch \
  /scratch/jchen73/eclipsefuzz/aflnet/images/<image>.sif \
  /scratch/jchen73/eclipsefuzz/aflnet/campaigns/<run-id>
```

The launcher clears inherited conflicting Slurm memory variables before
`srun`. SIF conversion must be done in a compute or interactive allocation,
not on a login node.

## Runtime artifacts

`snapshot.sh` records `fuzzer_stats` and a queue filename/mtime/size inventory
every 1,800 seconds. It does not copy the queue. The complete live
`afl-out/replayable-queue/` is retained for external replay and coverage
aggregation. `run.env status=ok`, an instance `.done`, and campaign-level
`campaign.done` distinguish completed fuzzing from a merely launched job.

AFLNet has one storage configuration: the Linux file-backed delegate at
`<instance>/dut-state/kvs`. There is no memory-storage ablation. The active
24-hour clock begins after the full initial corpus calibration succeeds.
### Instrumentation (trace-pc-guard, not the afl-clang-fast wrapper)

`afl-clang-fast` is not a compiler: it `exec`s `AFL_CC`, which defaults to
`"clang"` (afl-clang-fast.c). Its whole payload is to append
`-fsanitize-coverage=trace-pc-guard` and link `afl-llvm-rt.o`. We take both
directly -- same clang, same *unmodified* `afl-llvm-rt.o.c` (built with
`USE_TRACE_PC`) -- so AFL's own instrumentation is used with zero changes to
AFL's source. Verified empirically:

  * The official wrapper cannot run on any modern clang as shipped:
    `AFL_TRACE_PC=1 make -C llvm_mode` fails its own self-test because
    `-mllvm -sanitizer-coverage-block-threshold=0` is rejected by clang 14, 18,
    19 and 21. Using it therefore requires patching AFL first.
  * Patched, it does build the full DUT -- but it appends `-g -O3
    -funroll-loops` after our flags (suppressible only with
    `AFL_DONT_OPTIMIZE=1`), and links a second copy of `afl-llvm-rt.o`, which
    collides with the GN-side runtime (`duplicate symbol: __afl_area_ptr`).
  * `afl-clang-fast`'s default (non-trace-pc) pass needs LLVM <= 16
    (`PassManagerBuilder.h`), which is mutually exclusive with the clang-21-only
    flags the rest of this tree uses. A **deferred
forkserver** is started after init inside the POSIX event loop, immediately
before `select()`, so each fuzzing child inherits the already-bound socket and
is ready to receive AFLNet's UDP datagram without re-running `Server::Init()`.
Full design: `ai_docs/benchmark-fuzzers.md` §Instrumentation & forkserver.
### Known Linux-host caveats

- The host's `core_pattern` pipes to an external handler and the CPU governor is
  `powersave`; the campaign image sets `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`,
  `AFL_SKIP_CPUFREQ`, `AFL_NO_AFFINITY` so AFLNet proceeds without root.
- The image runs with `-D 10000` (10 ms settle) and `-W 100` (100 ms response
  window). A settle that is too short makes AFLNet abort with "No server states
  detected". Throughput is host and corpus dependent and must be measured again
  for each evaluation run.

## Seed / packet format

One request datagram (see `gen_matter_seeds.py`):

```
[MsgHeader: msgFlags=0x00 sessionId=0x0001(LE) secFlags=0x00 counter(LE)]
[PayloadHeader: exFlags=0x05 opcode exchangeId(LE) protocolId=0x0001(LE)]
[application TLV element]
[16-byte MIC placeholder]   <- stripped by the DUT Decrypt bypass
```

`sessionId` must be 0x0001 (matches the injected session) and nonzero (so
`IsEncrypted()` routes to the secure-unicast cluster path). Responses come back
plaintext with no MIC. Response state 0 is AFLNet's synthetic initial node;
schema-valid IM statuses 0..255 map to states 1..256, and a response without a
decodable StatusIB maps to 257. Protocol/opcode are not part of the state.

Protected-operation direct-wire preflight (all eight entries must return
`UnsupportedAccess`, followed by a successful BasicInformation read in the
same DUT process):

```bash
python3 examples/fuzzers/eclipsefuzz/stateful/tests/e2e/test_aflnet_protected_operation_wire.py \
  --dut out/aflnet-dut-fuzz/chip-all-clusters-app \
  --artifacts results/harness/aflnet-protected-operation-wire-$(date +%Y%m%d)
```
