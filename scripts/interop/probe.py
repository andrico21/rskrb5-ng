#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/interop/probe.py kdc HOST:PORT REALM
#             python3 scripts/interop/probe.py kdcproxy URL CA_FILE REALM
"""Protocol-level liveness probes of the interop fixtures (FU-IOP-P21).

`run.sh all` asks each registered fixture that serves a protocol for one answer
after the last suite: a container that is running but no longer answers must fail
the run. This helper sends one real AS-REQ for a principal that does not exist
to a KDC, directly over TCP or through an MS-KKDCP proxy over HTTPS, and requires
a Kerberos reply (a KRB-ERROR or an AS-REP). Standard library only.
"""

from __future__ import annotations

import socket
import ssl
import struct
import sys
import urllib.request

KRB_ERROR = 0x7E
AS_REP = 0x6B


def tlv(tag: int, body: bytes) -> bytes:
    """One DER element with a definite length."""
    size = len(body)
    if size < 0x80:
        return bytes([tag, size]) + body
    length = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body


def integer(value: int) -> bytes:
    return tlv(0x02, value.to_bytes(4, "big", signed=True))


def name(kind: int, parts: list[str]) -> bytes:
    strings = b"".join(tlv(0x1B, part.encode()) for part in parts)
    return tlv(0x30, tlv(0xA0, integer(kind)) + tlv(0xA1, tlv(0x30, strings)))


def as_req(realm: str) -> bytes:
    """An AS-REQ for `liveness-probe@REALM` without preauthentication."""
    body = tlv(
        0x30,
        tlv(0xA0, tlv(0x03, b"\x00\x00\x00\x00\x00"))
        + tlv(0xA1, name(1, ["liveness-probe"]))
        + tlv(0xA2, tlv(0x1B, realm.encode()))
        + tlv(0xA3, name(2, ["krbtgt", realm]))
        + tlv(0xA5, tlv(0x18, b"20371231235959Z"))
        + tlv(0xA7, integer(0x2A2A2A2A))
        + tlv(0xA8, tlv(0x30, integer(18))),
    )
    request = tlv(0x30, tlv(0xA1, integer(5)) + tlv(0xA2, integer(10)) + tlv(0xA4, body))
    return tlv(0x6A, request)


def read_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise SystemExit("the KDC closed the connection before it answered")
        data += chunk
    return data


def check_reply(reply: bytes) -> str:
    if not reply or reply[0] not in (KRB_ERROR, AS_REP):
        raise SystemExit(f"not a Kerberos reply: first byte {reply[:1].hex() or 'none'}")
    return "KRB-ERROR" if reply[0] == KRB_ERROR else "AS-REP"


def probe_kdc(endpoint: str, realm: str) -> str:
    host, _, port = endpoint.rpartition(":")
    request = as_req(realm)
    with socket.create_connection((host, int(port)), timeout=10) as sock:
        sock.settimeout(10)
        sock.sendall(struct.pack(">I", len(request)) + request)
        (length,) = struct.unpack(">I", read_exact(sock, 4))
        if not 2 <= length <= 65536:
            raise SystemExit(f"KDC reply length {length} out of bounds")
        return check_reply(read_exact(sock, length))


def der_value(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """The tag, contents and end of the DER element at `offset`."""
    tag = data[offset]
    first = data[offset + 1]
    if first < 0x80:
        size, start = first, offset + 2
    else:
        count = first & 0x7F
        size = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
        start = offset + 2 + count
    return tag, data[start : start + size], start + size


def probe_kdcproxy(url: str, ca_file: str, realm: str) -> str:
    request = as_req(realm)
    # kdcproxy routes by `target-domain`, which MS-KKDCP makes optional.
    message = tlv(
        0x30,
        tlv(0xA0, tlv(0x04, struct.pack(">I", len(request)) + request))
        + tlv(0xA1, tlv(0x1B, realm.encode())),
    )
    post = urllib.request.Request(
        url, data=message, headers={"Content-Type": "application/kerberos"}
    )
    context = ssl.create_default_context(cafile=ca_file)
    with urllib.request.urlopen(post, timeout=15, context=context) as response:
        body = response.read()
    _, sequence, _ = der_value(body, 0)
    _, wrapped, _ = der_value(sequence, 0)
    _, kerb_message, _ = der_value(wrapped, 0)
    return check_reply(kerb_message[4:])


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "kdc":
        print(f"probe: the KDC answered with a {probe_kdc(argv[1], argv[2])}")
        return 0
    if len(argv) == 4 and argv[0] == "kdcproxy":
        print(f"probe: the KDC proxy relayed a {probe_kdcproxy(argv[1], argv[2], argv[3])}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
