#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/interop/probe.py kdc HOST:PORT REALM
#             python3 scripts/interop/probe.py kdcproxy URL CA_FILE REALM
#             python3 scripts/interop/probe.py dns HOST:PORT NAME
#             python3 scripts/interop/probe.py negotiate URL
#             python3 scripts/interop/probe.py peer HOST:PORT
"""Protocol-level liveness probes of the interop fixtures (FU-IOP-P21).

`run.sh all` asks each registered fixture that serves a protocol for one answer
after the last suite: a container that is running but no longer answers must fail
the run. This helper sends one real AS-REQ for a principal that does not exist
to a KDC, directly over TCP or through an MS-KKDCP proxy over HTTPS, and requires
a Kerberos reply (a KRB-ERROR or an AS-REP). FU-IOP-P22 (plan 2 todo 26) adds the
fixtures that had no probe: `dns` sends one SRV query over UDP and requires an
answer record, `negotiate` sends one unauthenticated GET and requires the 401
`WWW-Authenticate: Negotiate` challenge, and `peer` sends the one-byte `P` ping
frame of the peer adapter and requires its `rskrb5-peer/1` answer. Standard library
only.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import struct
import sys
import urllib.parse
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


def dns_query(name: str) -> bytes:
    """A DNS query for the SRV records of `name` (recursion not desired)."""
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.rstrip(".").split("."))
    return struct.pack(">HHHHHH", 0x5252, 0x0000, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 33, 1)


def probe_dns(endpoint: str, name: str) -> str:
    """One SRV query over UDP: a response with NOERROR and at least one answer."""
    host, _, port = endpoint.rpartition(":")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(10)
        sock.sendto(dns_query(name), (host, int(port)))
        reply, _ = sock.recvfrom(4096)
    if len(reply) < 12:
        raise SystemExit("the DNS reply is shorter than its header")
    ident, flags, _, answers = struct.unpack(">HHHH", reply[:8])
    if ident != 0x5252 or not flags & 0x8000:
        raise SystemExit("not a DNS response to the probe query")
    if flags & 0xF:
        raise SystemExit(f"the DNS response has rcode {flags & 0xF}")
    if answers < 1:
        raise SystemExit("the DNS response has no answer record")
    return f"{answers} SRV answer(s) for {name}"


def probe_negotiate(url: str) -> str:
    """An unauthenticated GET: the server must answer 401 with a Negotiate challenge."""
    parts = urllib.parse.urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=10)
    try:
        connection.request("GET", parts.path or "/")
        response = connection.getresponse()
        challenges = response.getheader("WWW-Authenticate", "")
        response.read()
    finally:
        connection.close()
    if response.status != 401 or not challenges.split(",")[0].strip().lower().startswith("negotiate"):
        raise SystemExit(f"expected 401 with a Negotiate challenge, got {response.status} {challenges!r}")
    return "401 with a Negotiate challenge"


def probe_peer(endpoint: str) -> str:
    """The peer adapter's ping frame: status 0 and its protocol name."""
    host, _, port = endpoint.rpartition(":")
    with socket.create_connection((host, int(port)), timeout=10) as sock:
        sock.settimeout(10)
        sock.sendall(struct.pack(">I", 1) + b"P")
        (length,) = struct.unpack(">I", read_exact(sock, 4))
        if not 1 <= length <= 65536:
            raise SystemExit(f"adapter reply length {length} out of bounds")
        body = read_exact(sock, length)
    if body[:1] != b"\x00" or b"rskrb5-peer/1" not in body:
        raise SystemExit(f"not the adapter's ping answer: {body[:32].hex()}")
    return "the adapter answered the ping frame"


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "kdc":
        print(f"probe: the KDC answered with a {probe_kdc(argv[1], argv[2])}")
        return 0
    if len(argv) == 4 and argv[0] == "kdcproxy":
        print(f"probe: the KDC proxy relayed a {probe_kdcproxy(argv[1], argv[2], argv[3])}")
        return 0
    if len(argv) == 3 and argv[0] == "dns":
        print(f"probe: the DNS server answered {probe_dns(argv[1], argv[2])}")
        return 0
    if len(argv) == 2 and argv[0] == "negotiate":
        print(f"probe: the web server answered {probe_negotiate(argv[1])}")
        return 0
    if len(argv) == 2 and argv[0] == "peer":
        print(f"probe: {probe_peer(argv[1])}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
