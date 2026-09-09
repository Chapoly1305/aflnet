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
| `run_campaign.sh` | Drive a single campaign |
| `run_coverage_eval_campaign.sh` | N independent instances + coverage-over-time |
| `seeds/` | Hand-rolled seed corpus (used with `--seeds gen`) |

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

## Full campaign (Linux host)

```bash
# 1. Build AFLNet + Matter parser natively
cd ..            # aflnet/ root
make clean all

# 2. Build the TWO DUTs (from the EclipseFuzz repo root). This is the
#    ProFuzzBench / AFLNet reference design: the target is compiled once for
#    fuzzing and a second time for coverage, and the coverage curve comes from
#    replaying the queue against the second binary -- never from profiling the
#    fuzz binary. See run_docker_campaign.sh header for why.
CHIP_ARGS='is_clang=true is_libfuzzer=false chip_build_all_clusters_app=true chip_crypto="mbedtls" chip_enable_ble=false chip_config_network_layer_ble=false chip_enable_wifi=true chip_enable_openthread=true chip_enable_icd_server=true chip_enable_icd_lit=true chip_logging=false chip_enable_access_restrictions=true chip_enable_software_diagnostics_trigger=true chip_enable_wifi_diagnostics_trigger=true chip_enable_smoke_co_trigger=true chip_enable_boolean_state_configuration_trigger=true chip_enable_commodity_tariff_trigger=true chip_enable_energy_evse_trigger=true chip_enable_energy_reporting_trigger=true chip_enable_water_heater_management_trigger=true chip_enable_device_energy_management_trigger=true'

# 2a. fuzz DUT: AFL bitmap + ASAN, and NO coverage-measurement instrumentation.
gn gen out/aflnet-dut-fuzz --args="${CHIP_ARGS} is_asan=true matter_fuzz_dut_transport=true matter_fuzz_afl_instrument=true"
ninja -C out/aflnet-dut-fuzz chip-all-clusters-app

# 2b. cov DUT: profgen only -- never fuzzed, only replayed against. No AFL
#     instrumentation, no ASAN, no sancov allowlist (the reported scope is
#     applied by llvm-cov's path filter at report time, not baked into the
#     binary), so one neutral binary can score every compared fuzzer.
gn gen out/aflnet-dut-cov --args="${CHIP_ARGS} is_asan=false use_coverage=true coverage_allowlist_file=\"\" matter_fuzz_dut_transport=true"
ninja -C out/aflnet-dut-cov chip-all-clusters-app

# 3. Generate seeds and run (PORT avoids a concurrent EP2 campaign on 5540):
cd examples/fuzzers/aflnet/matter && python3 gen_matter_seeds.py -o seeds
AFLNET=../.. DUT=../../../../out/aflnet-dut-fuzz/chip-all-clusters-app \
  PORT=5560 ./run_campaign.sh /tmp/aflnet-out
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
  `powersave`; `run_campaign.sh` exports `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`,
  `AFL_SKIP_CPUFREQ`, `AFL_NO_AFFINITY` to proceed without root.
- The per-run `DELAY` settle (default 1 s) keeps `execs_per_sec ≈ 1`. Sweep it
  down toward the minimum reliable value to raise throughput (too small ⇒ AFLNet
  aborts with "No server states detected").

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
