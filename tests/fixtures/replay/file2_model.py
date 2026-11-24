#!/usr/bin/env python3
"""Reference model of the MIT krb5 1.22.2 `file2` replay cache (src/lib/krb5/rcache/rc_file2.c).

Written from the C source (store(), next_table(), read_records(), write_record(), expired()) as a
second, independent implementation: tests/replay_store/layout.rs reproduces its output with the
Rust store, byte for byte. Run `python3 file2_model.py` to print the vectors the test pins.
"""
import hashlib
import struct

M = (1 << 64) - 1
TAG_LEN, RECORD_LEN, SEED_LEN, FIRST = 12, 16, 16, 1023
MAX_SIZE = 0x7FFFFFFF


def rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & M


def siphash24(data, key):
    k0, k1 = struct.unpack("<QQ", key)
    v0, v1 = k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D
    v2, v3 = k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573

    def rnd(v0, v1, v2, v3):
        v0 = (v0 + v1) & M; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32)
        v2 = (v2 + v3) & M; v3 = rotl(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & M; v3 = rotl(v3, 21); v3 ^= v0
        v2 = (v2 + v1) & M; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32)
        return v0, v1, v2, v3

    n = len(data)
    for i in range(0, n - n % 8, 8):
        m = struct.unpack("<Q", data[i:i + 8])[0]
        v3 ^= m
        v0, v1, v2, v3 = rnd(*rnd(v0, v1, v2, v3))
        v0 ^= m
    last = (n & 0xFF) << 56
    for i, byte in enumerate(data[n - n % 8:]):
        last |= byte << (8 * i)
    v3 ^= last
    v0, v1, v2, v3 = rnd(*rnd(v0, v1, v2, v3))
    v0 ^= last
    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = rnd(v0, v1, v2, v3)
    return v0 ^ v1 ^ v2 ^ v3


def next_table(offset, nrecords):
    if offset == -1:
        offset, nrecords = SEED_LEN, FIRST
    elif offset == SEED_LEN:
        offset += nrecords * RECORD_LEN
        nrecords = (FIRST + 1) * 2
    else:
        offset += nrecords * RECORD_LEN
        nrecords *= 2
    if nrecords > MAX_SIZE // RECORD_LEN or offset > MAX_SIZE - nrecords * RECORD_LEN:
        raise OverflowError
    return offset, nrecords


def read_records(buf, offset):
    chunk = bytes(buf[offset:offset + 2 * RECORD_LEN])
    recs = []
    if len(chunk) >= RECORD_LEN:
        recs.append((chunk[:TAG_LEN], struct.unpack(">I", chunk[TAG_LEN:RECORD_LEN])[0]))
    if len(chunk) == 2 * RECORD_LEN:
        recs.append((chunk[RECORD_LEN:RECORD_LEN + TAG_LEN], struct.unpack(">I", chunk[RECORD_LEN + TAG_LEN:])[0]))
    return recs


def expired(stamp, now, skew):
    return now > ((stamp + skew) & 0xFFFFFFFF)


def store(buf, tag, now, skew, seed=None):
    """Mirror of store(); returns True for a fresh tag, False for KRB5KRB_AP_ERR_REPEAT."""
    if len(buf) < SEED_LEN:
        buf[:] = bytearray(seed)
    seed = bytearray(buf[:SEED_LEN])
    table_offset, nrecords, avail = -1, 0, -1
    while True:
        table_offset, nrecords = next_table(table_offset, nrecords)
        ind = siphash24(tag, bytes(seed)) % nrecords
        off = table_offset + ind * RECORD_LEN
        recs = read_records(buf, off)
        nread = len(recs)
        if (nread >= 1 and recs[0][1] and recs[0][0] == tag) or (nread == 2 and recs[1][1] and recs[1][0] == tag):
            return False
        if avail == -1:
            if nread == 0 or not recs[0][1] or expired(recs[0][1], now, skew):
                avail = off
            elif nread == 1 or not recs[1][1] or expired(recs[1][1], now, skew):
                avail = off + RECORD_LEN
        if nread < 2 or not recs[0][1] or not recs[1][1]:
            end = avail + RECORD_LEN
            if len(buf) < end:
                buf.extend(bytes(end - len(buf)))
            buf[avail:end] = tag + struct.pack(">I", now)
            return True
        seed[0] = (seed[0] + 1) & 0xFF


def tag_of(i):
    return hashlib.sha256(b"rskrb5-ng replay tag %d" % i).digest()[:TAG_LEN]


def records(buf):
    """The non-empty records of a file as (offset, tag hex, timestamp) triples."""
    found = []
    for off in range(SEED_LEN, len(buf) - len(buf) % RECORD_LEN, RECORD_LEN):
        tag, stamp = bytes(buf[off:off + TAG_LEN]), struct.unpack(">I", buf[off + TAG_LEN:off + RECORD_LEN])[0]
        if stamp:
            found.append((off, tag.hex(), stamp))
    return found


if __name__ == "__main__":
    assert siphash24(b"", bytes(range(16))) == 0x726FDB47DD0E0E31
    assert siphash24(bytes(range(15)), bytes(range(16))) == 0xA129CA6149BE45E5
    seed = bytes(range(16))
    retention = 2700  # three times a 900 s skew
    small = bytearray()
    for i in range(6):
        assert store(small, tag_of(i), 1_000_000 + i, retention, seed)
    print("small.len", len(small))
    for off, tag, stamp in records(small):
        print("small.record", off, tag, stamp)
    big = bytearray()
    fresh = sum(store(big, tag_of(i), 1_000_000, retention, seed) for i in range(3000))
    print("big.fresh", fresh)
    print("big.len", len(big))
    print("big.sha256", hashlib.sha256(big).hexdigest())
    assert not any(store(bytearray(big), tag_of(i), 1_000_000, retention, seed) for i in range(0, 3000, 97))
    late = bytearray(big)
    fresh_late = sum(store(late, tag_of(i), 1_000_000 + retention + 1, retention, seed) for i in range(3000, 3400))
    print("late.fresh", fresh_late)
    print("late.len", len(late))
    print("late.sha256", hashlib.sha256(late).hexdigest())
