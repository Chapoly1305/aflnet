# AFLNet ↔ Matter integration

Benchmark integration of [AFLNet](https://github.com/aflnet/aflnet) against the
`all-clusters-app` Matter DUT. See `ai_docs/benchmark-fuzzers.md` for the full
design and rationale.

## Contents

| File | Purpose |
|------|---------|
| `gen_matter_seeds.py` | Generate raw plaintext Matter request datagrams (AFLNet seeds) |
| `udp_smoke_test.py` | Send one seed to a running DUT and print/parse the response |
| `test_matter_parser.c` | Standalone unit test for `extract_*_matter` (any platform) |
| `Dockerfile.aflnet` | Build AFLNet (+ Matter parser) on Linux |
| `run_campaign.sh` | Drive an AFLNet campaign against the instrumented DUT |
| `seeds/` | Generated seed corpus |

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

## Full campaign (Linux host)

```bash
# Build AFLNet + Matter parser
docker build -f matter/Dockerfile.aflnet -t aflnet-matter .   # from aflnet/ root

# Build the DUT for Linux with matter_fuzz_afl_transport=true AND afl-clang-fast
# instrumentation (CC/CXX wrappers), then:
AFLNET=/aflnet DUT=/path/to/chip-all-clusters-app ./run_campaign.sh aflnet-out
```

### Known Linux-host caveats

- `llvm_mode` (afl-clang-fast) fails to build on modern LLVM (Ubuntu 22.04). Pin
  LLVM 11/12 (`apt install llvm-12 clang-12`, `LLVM_CONFIG=llvm-config-12 make -C llvm_mode`),
  matching ProfuzzBench's toolchain.
- On Apple Silicon the AFLNet image needs `AFL_NO_X86=1` (set in the Dockerfile);
  x86_64 campaign hosts don't.
- The DUT is a macOS/arm64 binary in local dev — for the actual AFLNet loop the
  DUT must be built for the same Linux host AFLNet runs on (co-located process).

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
