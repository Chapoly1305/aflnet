#!/usr/bin/env python3
"""Send a raw Matter seed datagram to the patched DUT and print the response.

Validates the matter_fuzz_dut_transport DUT end-to-end without AFLNet: the DUT
should accept our plaintext datagram (session injection + Decrypt bypass), run
the cluster-layer handler, and return a plaintext response (Encrypt bypass).

Usage:
  python3 udp_smoke_test.py seeds/read_basicinfo_datamodelrev.raw [--host 127.0.0.1] [--port 5540]
"""
import argparse
import socket
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("seed", help="raw Matter datagram file")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5540)
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()

    with open(args.seed, "rb") as f:
        data = f.read()

    print(f"-> sending {len(data)} bytes to {args.host}:{args.port}")
    print(f"   {data.hex()}")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(args.timeout)
    s.sendto(data, (args.host, args.port))

    try:
        resp, addr = s.recvfrom(4096)
    except socket.timeout:
        print("<- no response (timeout)")
        print("   NOTE: absence of a response is not necessarily failure — check the")
        print("   DUT log for whether the message reached the cluster layer.")
        return 1

    print(f"<- {len(resp)} bytes from {addr}")
    print(f"   {resp.hex()}")
    # Best-effort decode of the plaintext payload header (after the message header).
    if len(resp) >= 8:
        msg_flags = resp[0]
        hdr = 8
        if msg_flags & 0x04:
            hdr += 8
        dsiz = msg_flags & 0x03
        hdr += 8 if dsiz == 1 else (2 if dsiz == 2 else 0)
        if len(resp) >= hdr + 6:
            ex_flags = resp[hdr]
            opcode = resp[hdr + 1]
            pid_off = hdr + 4 + (2 if (ex_flags & 0x10) else 0)
            protocol_id = resp[pid_off] | (resp[pid_off + 1] << 8)
            print(f"   parsed: protocolId=0x{protocol_id:04x} opcode=0x{opcode:02x} "
                  f"state=0x{((protocol_id & 0xff) << 8) | opcode:04x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
