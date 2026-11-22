#!/usr/bin/env python3
"""Independent generator of the PAC checksum vectors in tests/support/pac_vectors.rs.

Provenance: written from RFC 3961 section 5.1 (n-fold), RFC 3961 section 5.3 (DK), RFC 3962
section 6 (the simplified-profile checksum: HMAC-SHA1-96 over the derived key Kc =
DK(base, usage || 0x99)) and the MS-PAC layout (2.1 PACTYPE, 2.2 PAC_INFO_BUFFER, 2.8
signatures) with the signing order of MIT krb5 1.22.2 src/lib/krb5/krb/pac_sign.c sign_pac: the
full checksum over the PAC with all three signatures zero, the server checksum over the PAC with
the server and KDC signatures zero, the KDC checksum over the server signature bytes. It shares no
code with the Rust crate; only the `cryptography` package supplies AES.

Run: python3 tests/fixtures/pac/generate.py > tests/support/pac_vectors.rs
The keys are fixed test keys of a fictional realm; no real credential is involved.
"""

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

USAGE = 17  # KRB5_KEYUSAGE_APP_DATA_CKSUM


def nfold(data: bytes, bits: int) -> bytes:
    """RFC 3961 5.1 n-fold."""
    n = bits // 8
    from math import gcd

    lcm = len(data) * n // gcd(len(data), n)
    big = bytearray()
    for i in range(lcm // len(data)):
        # rotate the input right by 13 * i bits
        rot = (13 * i) % (len(data) * 8)
        value = int.from_bytes(data, "big")
        total = len(data) * 8
        rotated = ((value >> rot) | (value << (total - rot))) & ((1 << total) - 1)
        big += rotated.to_bytes(len(data), "big")
    result = bytearray(n)
    carry = 0
    for i in range(len(big) - 1, -1, -1):
        carry += big[i] + result[i % n]
        result[i % n] = carry & 0xFF
        carry >>= 8
    # fold in the remaining carry
    j = n - 1
    while carry:
        carry += result[j]
        result[j] = carry & 0xFF
        carry >>= 8
        j = (j - 1) % n
    return bytes(result)


def aes_block(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def derive(key: bytes, constant: bytes) -> bytes:
    """RFC 3961 DK with the AES random-to-key (identity)."""
    block = nfold(constant, 128)
    out = b""
    while len(out) < len(key):
        block = aes_block(key, block)
        out += block
    return out[: len(key)]


def checksum(key: bytes, data: bytes) -> bytes:
    kc = derive(key, struct.pack(">I", USAGE) + b"\x99")
    return hmac.new(kc, data, hashlib.sha1).digest()[:12]


def pac(buffers, key_server, key_kdc, cksum_type_server, cksum_type_kdc, ticket_input=None,
        wrong_full_key=None, signed_ticket_input=None):
    """buffers: list of (type, bytes); signature buffers are created here."""
    sig_len = 12
    items = []  # (type, bytearray)
    for ul_type, data in buffers:
        items.append([ul_type, bytearray(data)])
    index = {}

    def add(ul_type, data):
        index[ul_type] = len(items)
        items.append([ul_type, bytearray(data)])

    # MIT order (pac_sign.c): the ticket signature first (add_ticket_signature), then sign_pac
    # adds the server, KDC and full checksum buffers, each zero filled.
    if ticket_input is not None:
        covered = signed_ticket_input if signed_ticket_input is not None else ticket_input
        add(16, struct.pack("<I", cksum_type_kdc) + checksum(key_kdc, covered))
    add(6, struct.pack("<I", cksum_type_server) + bytes(sig_len))
    add(7, struct.pack("<I", cksum_type_kdc) + bytes(sig_len))
    if ticket_input is not None:
        add(19, struct.pack("<I", cksum_type_kdc) + bytes(sig_len))

    def encode():
        n = len(items)
        offset = 8 + 16 * n
        table = b""
        body = b""
        for ul_type, data in items:
            table += struct.pack("<IIQ", ul_type, len(data), offset)
            padded = bytes(data) + bytes((-len(data)) % 8)
            body += padded
            offset += len(padded)
        return struct.pack("<II", n, 0) + table + body

    def region(ul_type):
        raw = encode()
        n = len(items)
        for i in range(n):
            t, size, off = struct.unpack_from("<IIQ", raw, 8 + 16 * i)
            if t == ul_type:
                return off, size
        raise KeyError(ul_type)

    def put(ul_type, signature):
        off, size = region(ul_type)
        for entry in items:
            if entry[0] == ul_type:
                entry[1][4 : 4 + len(signature)] = signature

    if ticket_input is not None:
        full_key = wrong_full_key if wrong_full_key is not None else key_kdc
        put(19, checksum(full_key, encode()))  # all three zero at this point
    server_sig = checksum(key_server, encode())
    put(6, server_sig)
    put(7, checksum(key_kdc, server_sig))
    return encode()


def client_info(name: str, filetime: int) -> bytes:
    utf16 = name.encode("utf-16-le")
    return struct.pack("<QH", filetime, len(utf16)) + utf16


def sid(authority: int, subs) -> bytes:
    return struct.pack("<BB", 1, len(subs)) + authority.to_bytes(6, "big") + b"".join(
        struct.pack("<I", s) for s in subs
    )


def rust_hex(name: str, doc: str, data: bytes) -> str:
    text = data.hex()
    chunks = [text[i : i + 96] for i in range(0, len(text), 96)]
    if len(chunks) == 1:
        return f'/// {doc}\npub(crate) const {name}: &str = "{chunks[0]}";\n'
    body = "\n".join(f'    "{c}",' for c in chunks)
    return f"/// {doc}\npub(crate) const {name}: &str = concat!(\n{body}\n);\n"


def main():
    server128 = bytes(range(0x10, 0x20))
    kdc128 = bytes(range(0x30, 0x40))
    server256 = bytes(range(0x40, 0x60))
    kdc256 = bytes(range(0x60, 0x80))
    # 2017-05-06 15:13:11 UTC as a FILETIME, the authtime of the fixtures.
    authtime = (1_494_083_591 + 11_644_473_600) * 10_000_000
    flags_attr = struct.pack("<II", 2, 1)  # PAC_WAS_REQUESTED
    requestor = sid(5, [21, 1, 2, 3, 1104])
    ticket_input = b"ticket-signature-input fixture bytes: not a real ticket"
    out = ["// Generated by tests/fixtures/pac/generate.py: do not edit.\n"]
    out.append(rust_hex("SERVER_KEY_AES256", "aes256-cts-hmac-sha1-96 service key (hex of the 32 key bytes).", server256))
    out.append(rust_hex("KDC_KEY_AES256", "aes256-cts-hmac-sha1-96 KDC key.", kdc256))
    out.append(rust_hex("SERVER_KEY_AES128", "aes128-cts-hmac-sha1-96 service key.", server128))
    out.append(rust_hex("KDC_KEY_AES128", "aes128-cts-hmac-sha1-96 KDC key.", kdc128))
    out.append(rust_hex("TICKET_INPUT", "The bytes the ticket signature of the service-ticket vectors covers.", ticket_input))
    out.append(
        rust_hex(
            "SERVICE_PAC_AES256",
            "A MIT-shaped service-ticket PAC (client info, attributes, requestor, ticket and full checksums, server and KDC signatures; no `KERB_VALIDATION_INFO`), aes256-cts-hmac-sha1-96 keys (checksum type 16), client `pacuser`, authtime 2017-05-06 15:13:11 UTC.",
            pac(
                [(10, client_info("pacuser", authtime)), (17, flags_attr), (18, requestor)],
                server256, kdc256, 16, 16, ticket_input,
            ),
        )
    )
    out.append(
        rust_hex(
            "SERVICE_PAC_AES128",
            "The same PAC under aes128-cts-hmac-sha1-96 keys (checksum type 15).",
            pac(
                [(10, client_info("pacuser", authtime)), (17, flags_attr), (18, requestor)],
                server128, kdc128, 15, 15, ticket_input,
            ),
        )
    )
    out.append(
        rust_hex(
            "WRONG_FULL_PAC_AES256",
            "A service-ticket PAC whose server and KDC signatures are valid over its bytes but whose full checksum was computed under a different key.",
            pac(
                [(10, client_info("pacuser", authtime)), (17, flags_attr), (18, requestor)],
                server256, kdc256, 16, 16, ticket_input, wrong_full_key=bytes(range(0x90, 0xB0)),
            ),
        )
    )
    out.append(
        rust_hex(
            "WRONG_TICKET_PAC_AES256",
            "A service-ticket PAC whose ticket signature covers other bytes than `TICKET_INPUT`; every other signature is valid.",
            pac(
                [(10, client_info("pacuser", authtime)), (17, flags_attr), (18, requestor)],
                server256, kdc256, 16, 16, ticket_input, signed_ticket_input=b"some other ticket",
            ),
        )
    )
    out.append(
        rust_hex(
            "TGS_PAC_AES256",
            "A PAC for a ticket-granting ticket: server and KDC signatures only (no ticket signature, no full checksum).",
            pac([(10, client_info("pacuser", authtime))], server256, kdc256, 16, 16, None),
        )
    )
    out.append(
        rust_hex(
            "EMPTY_CLAIMS_PAC_AES256",
            "A Samba-shaped PAC: client info, a zero-length client claims buffer (type 13), attributes and requestor; server and KDC signatures.",
            pac(
                [(10, client_info("pacuser", authtime)), (13, b""), (17, flags_attr), (18, requestor)],
                server256, kdc256, 16, 16, None,
            ),
        )
    )
    print("\n".join(out))


if __name__ == "__main__":
    main()
