#!/usr/bin/env python3
"""Generate raw on-the-wire Matter (CHIP) request datagrams as AFLNet seeds.

Targets the all-clusters-app DUT built with `matter_fuzz_dut_transport=true`,
which accepts mutated *plaintext* Matter packets (AES-CCM + MIC verification
bypassed) and emits *plaintext* responses. See ai_docs/benchmark-fuzzers.md.

Datagram layout produced here (matches extract_requests_matter in aflnet.c):

    [Message Header][Payload Header][application TLV][16-byte MIC placeholder]

  Message Header (unencrypted, 8 bytes for our flags):
    msgFlags(1)=0x00  sessionId(2,LE)=0x0001  secFlags(1)=0x00  counter(4,LE)
  Payload Header (plaintext on this DUT, 6 bytes):
    exFlags(1)=0x05(Initiator|NeedsAck)  opcode(1)  exchangeId(2,LE)  protocolId(2,LE)

The fixed session id 0x0001 + fabric 1 are injected by InstallDutTransportSession()
on the DUT. sessionId must be nonzero so IsEncrypted() routes the packet to
SecureUnicastMessageDispatch (the cluster path).
"""
import argparse
import struct
from pathlib import Path

# ---- Matter constants ----
SESSION_ID = 0x0001
PROTOCOL_ID_IM = 0x0001
OPCODE_READ_REQUEST = 0x02
OPCODE_INVOKE_REQUEST = 0x08
EXFLAG_INITIATOR = 0x01
EXFLAG_NEEDS_ACK = 0x04
IM_REVISION = 12
MIC_PLACEHOLDER = b"\x00" * 16

# ---- Minimal Matter TLV encoder ----
# Tag controls
_TC_ANON = 0x00
_TC_CTX = 0x20
# Element types
_ET_UINT8, _ET_UINT16, _ET_UINT32, _ET_UINT64 = 0x04, 0x05, 0x06, 0x07
_ET_BOOL_FALSE, _ET_BOOL_TRUE = 0x08, 0x09
_ET_STRUCT, _ET_ARRAY, _ET_LIST = 0x15, 0x16, 0x17
_ET_END = 0x18


def _ctx(tag: int, elem_type: int) -> bytes:
    return bytes([_TC_CTX | elem_type, tag & 0xFF])


def _anon(elem_type: int) -> bytes:
    return bytes([_TC_ANON | elem_type])


def tlv_ctx_uint(tag: int, value: int) -> bytes:
    if value <= 0xFF:
        return _ctx(tag, _ET_UINT8) + struct.pack("<B", value)
    if value <= 0xFFFF:
        return _ctx(tag, _ET_UINT16) + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return _ctx(tag, _ET_UINT32) + struct.pack("<I", value)
    return _ctx(tag, _ET_UINT64) + struct.pack("<Q", value)


def tlv_ctx_bool(tag: int, value: bool) -> bytes:
    return bytes([_TC_CTX | (_ET_BOOL_TRUE if value else _ET_BOOL_FALSE), tag & 0xFF])


def build_read_request(endpoint: int, cluster: int, attribute: int) -> bytes:
    """ReadRequestMessage TLV: anonymous structure.

    tag 0  AttributeRequests : Array[ AttributePathIB (List) ]
      AttributePathIB tags: 2=Endpoint, 3=Cluster, 4=Attribute
    tag 3  IsFabricFiltered  : bool
    tag 0xFF InteractionModelRevision : uint
    """
    path = _anon(_ET_LIST)  # AttributePathIB as anonymous List inside the array
    path += tlv_ctx_uint(2, endpoint)
    path += tlv_ctx_uint(3, cluster)
    path += tlv_ctx_uint(4, attribute)
    path += bytes([_ET_END])

    attr_requests = _ctx(0, _ET_ARRAY) + path + bytes([_ET_END])

    body = _anon(_ET_STRUCT)
    body += attr_requests
    body += tlv_ctx_bool(3, False)             # IsFabricFiltered = false
    body += tlv_ctx_uint(0xFF, IM_REVISION)    # InteractionModelRevision
    body += bytes([_ET_END])
    return body


def message_header(counter: int) -> bytes:
    return struct.pack("<BHBI", 0x00, SESSION_ID, 0x00, counter)


def payload_header(opcode: int, exchange_id: int) -> bytes:
    ex_flags = EXFLAG_INITIATOR | EXFLAG_NEEDS_ACK
    return struct.pack("<BBHH", ex_flags, opcode, exchange_id, PROTOCOL_ID_IM)


def datagram(opcode: int, tlv: bytes, *, counter: int = 1, exchange_id: int = 1) -> bytes:
    return message_header(counter) + payload_header(opcode, exchange_id) + tlv + MIC_PLACEHOLDER


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--out", default="seeds", help="output directory")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    seeds = {
        # Read BasicInformation(0x0028).DataModelRevision(0x0000) on EP0 — a
        # RAM-backed primitive the DUT can serve without a delegate.
        "read_basicinfo_datamodelrev.raw": datagram(
            OPCODE_READ_REQUEST, build_read_request(0, 0x0028, 0x0000)),
        # Read Descriptor(0x001D).DeviceTypeList(0x0000) on EP0.
        "read_descriptor_devicetypelist.raw": datagram(
            OPCODE_READ_REQUEST, build_read_request(0, 0x001D, 0x0000), exchange_id=2),
        # Read OnOff(0x0006).OnOff(0x0000) on EP1.
        "read_onoff.raw": datagram(
            OPCODE_READ_REQUEST, build_read_request(1, 0x0006, 0x0000), exchange_id=3),
    }

    for name, data in seeds.items():
        (out / name).write_bytes(data)
        print(f"wrote {out/name} ({len(data)} bytes): {data.hex()}")


if __name__ == "__main__":
    main()
