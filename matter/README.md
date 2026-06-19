# AFLNet ↔ Matter integration

Benchmark integration of [AFLNet](https://github.com/aflnet/aflnet) **and
[ChatAFL](https://github.com/ChatAFLndss/ChatAFL)** against the `all-clusters-app`
Matter DUT. See `ai_docs/benchmark-fuzzers.md` for the full design and rationale.

Both baselines come from this one tree: `make clean all` builds the plain AFLNet
`afl-fuzz`; `make CHATAFL=1 afl-fuzz` builds the ChatAFL-for-Matter LLM-guided
variant (everything behind `#ifdef CHATAFL`). They share the `-P MATTER` parser,
the `MATTER_FUZZ_AFL_TRANSPORT` DUT, and the coverage-over-time eval — so the
EclipseFuzz-vs-AFLNet-vs-ChatAFL comparison isolates exactly the LLM layer.

## Contents

| File | Purpose |
|------|---------|
| `gen_matter_seeds.py` | Generate raw plaintext Matter request datagrams (AFLNet seeds) |
| `udp_smoke_test.py` | Send one seed to a running DUT and print/parse the response |
| `test_matter_parser.c` | Standalone unit test for `extract_*_matter` (any platform) |
| `test_chatafl_tlv.c` | Standalone unit test for the ChatAFL TLV walker + catalog (`make test-chatafl`) |
| `Dockerfile.aflnet` | Build AFLNet + ChatAFL (+ Matter parser) on Linux |
| `run_campaign.sh` | Drive a campaign; `FUZZER=aflnet\|chatafl` |
| `seeds/` | Generated seed corpus |

The ChatAFL LLM layer lives one dir up: `../chat-llm-tlv.{c,h}` (dependency-free
TLV walker + message catalog/encoder) and `../chat-llm.{c,h}` (libcurl/json-c
transport + grammar/enrichment/stall prompts).

## ChatAFL-for-Matter in one paragraph

ChatAFL is text-protocol machinery (RTSP `<<VALUE>>` templates + PCRE2). Matter is
binary TLV, so the LLM layer was rewritten TLV-aware: the LLM operates at the
message-type level (catalog augmentation, enrichment, stall) while mutable spans
are found deterministically by walking the TLV (`matter_get_mutable_ranges` →
value bytes only, never headers/MIC). Enable LLM calls with `CHATAFL=1
CHATAFL_LLM=1 CHATAFL_OPENAI_KEY=sk-…`; with no key it runs catalog-only, offline.
The layer is firewalled from EclipseFuzz internals (FSM catalogs, oracles) to stay
an independent baseline.

## How the pieces fit

```
gen_matter_seeds.py ──► seeds/*.raw ──► AFLNet (-P MATTER, extract_requests_matter)
                                              │  udp://127.0.0.1/5540
                                              ▼
                          all-clusters-app  [matter_fuzz_afl_transport=true]
                                              │  plaintext response
                                              ▼
                          extract_response_codes_matter ──► state feedback
```

The DUT patch (`MATTER_FUZZ_AFL_TRANSPORT`) bypasses AES-CCM decrypt/encrypt +
message-counter replay protection and injects a fixed CASE session (fabric 1,
admin ACL) so the fuzzer's mutated plaintext reaches the cluster layer.

## Quick validation (no AFLNet needed — runs on macOS)

```bash
# 1. Generate seeds
python3 gen_matter_seeds.py -o seeds

# 2. Unit-test the parser
cc -c -w -I.. ../aflnet.c -o /tmp/aflnet.o
cc -w -I.. test_matter_parser.c /tmp/aflnet.o -o /tmp/test_matter_parser
/tmp/test_matter_parser seeds/*.raw          # -> ALL TESTS PASSED

# 3. Live DUT smoke test
gn gen out/afl-dut --args='... matter_fuzz_afl_transport=true'   # see ai_docs
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

## Full campaign (Linux host) — validated 2026-06-19

```bash
# 1. Build AFLNet + Matter parser natively (no Docker; graphviz + libcap dev libs).
#    llvm_mode / afl-clang-fast is NOT needed — see Instrumentation below.
cd ..            # aflnet/ root
make clean all

# 2. Build the instrumented DUT (from the EclipseFuzz repo root):
gn gen out/afl-dut-cov --args='is_clang=true is_libfuzzer=false chip_build_all_clusters_app=true chip_crypto="mbedtls" chip_enable_ble=false chip_config_network_layer_ble=false chip_enable_wifi=false chip_enable_openthread=false matter_fuzz_afl_transport=true matter_fuzz_afl_instrument=true'
ninja -C out/afl-dut-cov chip-all-clusters-app

# 3. Generate seeds and run (PORT avoids a concurrent EP2 campaign on 5540):
cd examples/fuzzers/aflnet/matter && python3 gen_matter_seeds.py -o seeds
AFLNET=../.. DUT=../../../../out/afl-dut-cov/chip-all-clusters-app \
  PORT=5560 ./run_campaign.sh /tmp/aflnet-out
```

### Instrumentation (no afl-clang-fast)

AFLNet's legacy `afl-clang-fast` LLVM pass no longer builds on modern LLVM, and
the SDK is built with pigweed's own clang. So the DUT is instrumented with the
SDK toolchain via `-fsanitize-coverage=trace-pc-guard`, whose callbacks are
provided by AFLNet's `afl-llvm-rt.o.c` (built with `USE_TRACE_PC`). A **deferred
forkserver** is started after init (before the event loop) so each fuzzing child
inherits the already-bound socket instead of re-running `Server::Init()`. Full
design: `ai_docs/benchmark-fuzzers.md` §Instrumentation & forkserver.

### Known Linux-host caveats

- The host's `core_pattern` pipes to an external handler and the CPU governor is
  `powersave`; `run_campaign.sh` exports `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`,
  `AFL_SKIP_CPUFREQ`, `AFL_NO_AFFINITY` to proceed without root.
- The per-run `DELAY` settle (default 1 s) keeps `execs_per_sec ≈ 1`. Sweep it
  down toward the minimum reliable value to raise throughput (too small ⇒ AFLNet
  aborts with "No server states detected").
- `AFL_KEEP_CHILD_STDERR=1` (added to `afl-fuzz.c`) keeps the DUT child's output
  instead of `/dev/null` — useful for debugging the forkserver.

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
