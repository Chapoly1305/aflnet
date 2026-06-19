#!/usr/bin/env bash
# Drive an AFLNet fuzzing campaign against the patched Matter all-clusters-app DUT.
#
# Prerequisites (Linux campaign host):
#   1. AFLNet built with the Matter parser (this tree): `make clean all` + `make -C llvm_mode`
#      (pin LLVM 11/12 for llvm_mode; modern LLVM breaks AFLNet's pass — see README).
#   2. The DUT built for Linux with BOTH:
#        - matter_fuzz_afl_transport=true   (plaintext accept + session injection)
#        - AFL instrumentation via afl-clang-fast (CC/CXX=afl-clang-fast++ in gn)
#      so AFLNet gets the shared-memory coverage bitmap.
#   3. Seeds generated: `python3 gen_matter_seeds.py -o seeds`
#
# Usage:
#   AFLNET=/path/to/aflnet DUT=/path/to/chip-all-clusters-app ./run_campaign.sh [out_dir]
set -euo pipefail

AFLNET="${AFLNET:?set AFLNET to the aflnet checkout}"
DUT="${DUT:?set DUT to the AFL-instrumented all-clusters-app binary}"
OUT="${1:-aflnet-out}"
SEEDS="${SEEDS:-seeds}"
KVS="${KVS:-/tmp/afl-matter-kvs}"

[ -d "$SEEDS" ] || { echo "seed dir '$SEEDS' missing — run gen_matter_seeds.py first"; exit 1; }
rm -f "$KVS"

# Flags:
#   -N udp://127.0.0.1/5540  Matter operational UDP port
#   -P MATTER                Matter request/response parser
#   -E                       state-aware mode (uses extract_response_codes_matter)
#   -R                       region-level mutation operators
#   -D 10000                 wait 10ms for DUT init before each run
#   -q 3 -s 3                state/seed selection algorithms (AFLNet defaults for stateful)
#   -K                       send SIGTERM to gracefully stop the DUT between runs
#   -m none                  no memory limit (ASAN/large DUT)
#   -t 1000+                 per-run timeout
exec "$AFLNET/afl-fuzz" \
  -d \
  -i "$SEEDS" -o "$OUT" \
  -N udp://127.0.0.1/5540 \
  -P MATTER -E -R -K \
  -D 10000 -q 3 -s 3 \
  -m none -t 3000+ \
  -- "$DUT" --KVS "$KVS"
