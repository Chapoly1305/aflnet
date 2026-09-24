# AFLNet ↔ Matter integration

Benchmark integration of [AFLNet](https://github.com/aflnet/aflnet) against the
`all-clusters-app` Matter DUT. See `ai_docs/benchmark-fuzzers.md` for the full design.

## Contents

| File | Purpose |
|------|---------|
| `gen_matter_seeds.py` | Generate raw plaintext Matter request datagrams (AFLNet seeds) |
| `udp_smoke_test.py` | Send one seed to a running DUT and print/parse the response |
| `test_matter_parser.c` | Standalone unit test for `extract_*_matter` (any platform) |
| `Dockerfile.aflnet` | Build AFLNet (+ Matter parser) on Linux |
| `build_campaign_image.sh` / `Dockerfile.campaign` / `entrypoint.sh` | Campaign image: afl-fuzz, both DUTs, `corpus/derived-afl` seeds + dictionary |
| `run_docker_campaign.sh` | N independent instances, one container each, then queue-replay coverage |
| `phase2_parallel.py` | Queue replay against the cov DUT (runs inside the image) |
| `seeds/` | Hand-rolled seeds for the quick validation below |

## How the pieces fit

```
gen_matter_seeds.py ──► seeds/*.raw ──► AFLNet (-P MATTER, extract_requests_matter)
                                              │  udp://127.0.0.1/5540
                                              ▼
                          all-clusters-app  [matter_fuzz_dut_transport=true]
                                              │  plaintext response
                                              ▼
                          extract_response_codes_matter ──► state feedback
```

The DUT patch (`MATTER_FUZZ_DUT_TRANSPORT`) bypasses AES-CCM decrypt/encrypt +
message-counter replay protection and injects a fixed CASE session (fabric 1,
admin ACL) so the fuzzer's mutated plaintext reaches the cluster layer.

## Quick validation (no AFLNet needed)

```bash
# 1. Generate seeds
python3 gen_matter_seeds.py -o seeds

# 2. Unit-test the parser
cc -c -w -I.. ../aflnet.c -o /tmp/aflnet.o
cc -w -I.. test_matter_parser.c /tmp/aflnet.o -o /tmp/test_matter_parser
/tmp/test_matter_parser seeds/*.raw          # -> ALL TESTS PASSED

# 3. Live DUT smoke test
gn gen out/afl-dut --args='... matter_fuzz_dut_transport=true'   # see ai_docs
ninja -C out/afl-dut chip-all-clusters-app
./out/afl-dut/chip-all-clusters-app --KVS /tmp/kvs &             # logs "[AFL] Installed fixed CASE session ..."
python3 udp_smoke_test.py seeds/read_basicinfo_datamodelrev.raw  # -> 54-byte ReportData response
```

Expected DUT log on receipt:

```
>>> [E:1r S:1 M:1] (S) Msg RX ... Type 0001:02 (IM:ReadRequest) (B:51)
[IM] Received Read request
[DMG]   InteractionModelRevision = 12
[DMG] Building Reports for ReadHandler ...
```

## Full campaign (Docker only)

```bash
# 1. Build the two DUTs, afl-fuzz and the rest (from the EclipseFuzz repo root).
#    This is the ProFuzzBench / AFLNet reference design: the target is compiled
#    once for fuzzing (out/aflnet-dut-fuzz: AFL bitmap + ASAN, no profiling) and
#    once for coverage (out/aflnet-dut-cov: profgen only, with
#    -funique-internal-linkage-names), and the coverage curve comes from
#    replaying the queue against the second binary. step1.2 holds the args.
./step1.2_build_campaign_executables.sh

# 2. Seeds: corpus/derived-afl (UDP datagram chains, timed Write/Invoke already
#    carry the DUT's MRP ack) and corpus/derived-afl.dict come from step3.1.

# 3. Package and run: step4.1 = build_campaign_image.sh + run_docker_campaign.sh
./step4.1_aflnet_eval.sh --instances 10 --fuzz-seconds 3600 --interval 300
```

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
  window), about 3 exec/s per instance (A5000, 2026-09-24). A settle that is too
  short makes AFLNet abort with "No server states detected".

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
plaintext with no MIC; state code = `(protocolId<<8)|opcode`.
