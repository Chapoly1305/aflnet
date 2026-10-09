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

Hopper has one AFLNet Slurm script: `hopper/run_campaign.sbatch`. It expands
one prebuilt SIF to job-local storage and starts one `srun` with ten tasks, one
CPU per task. Each task owns one private Apptainer network/PID namespace and
one result directory.

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
