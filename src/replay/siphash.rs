//! SipHash-2-4 with a 16-byte key: the hash of MIT's `file2` slot index
//! (`k5_siphash24`, MIT 1.22.2 `src/util/support/hashtab.c`).

/// One `SipRound` over the four state words.
const fn round(state: [u64; 4]) -> [u64; 4] {
    let [mut v0, mut v1, mut v2, mut v3] = state;
    v0 = v0.wrapping_add(v1);
    v1 = v1.rotate_left(13);
    v1 ^= v0;
    v0 = v0.rotate_left(32);
    v2 = v2.wrapping_add(v3);
    v3 = v3.rotate_left(16);
    v3 ^= v2;
    v0 = v0.wrapping_add(v3);
    v3 = v3.rotate_left(21);
    v3 ^= v0;
    v2 = v2.wrapping_add(v1);
    v1 = v1.rotate_left(17);
    v1 ^= v2;
    v2 = v2.rotate_left(32);
    [v0, v1, v2, v3]
}

/// Little-endian word of up to eight bytes.
fn word(bytes: &[u8]) -> u64 {
    let mut buffer = [0_u8; 8];
    for (slot, byte) in buffer.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    u64::from_le_bytes(buffer)
}

/// SipHash-2-4 of `data` under `key`.
pub(super) fn siphash24(data: &[u8], key: &[u8; 16]) -> u64 {
    let (first, second) = key.split_at(8);
    let (key0, key1) = (word(first), word(second));
    let mut state = [
        key0 ^ 0x736f_6d65_7073_6575,
        key1 ^ 0x646f_7261_6e64_6f6d,
        key0 ^ 0x6c79_6765_6e65_7261,
        key1 ^ 0x7465_6462_7974_6573,
    ];
    let (blocks, remainder) = data.as_chunks::<8>();
    for block in blocks {
        let message = u64::from_le_bytes(*block);
        state[3] ^= message;
        state = round(round(state));
        state[0] ^= message;
    }
    let length_byte = u64::try_from(data.len()).unwrap_or(0) << 56_u32;
    let last = word(remainder) | length_byte;
    state[3] ^= last;
    state = round(round(state));
    state[0] ^= last;
    state[2] ^= 0xff;
    state = round(round(round(round(state))));
    state[0] ^ state[1] ^ state[2] ^ state[3]
}
