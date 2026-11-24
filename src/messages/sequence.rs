//! Sequence-number acceptance (MIT `privsafe.c:k5_privsafe_check_seqnum`).
//!
//! MIT accepts both the signed numbers of its older implementation and the
//! unsigned encodings of Heimdal 0.5.2, which `krb5_rd_priv` cannot tell apart
//! for some counters; the two flags record what the peer is known to be.

use super::AuthContext;

/// Whether `received` is the number `context` expects, updating what the
/// context has learned about its peer.
pub(super) const fn accepts(context: &mut AuthContext, received: u32) -> bool {
    let expected = context.remote_sequence;
    if context.sane_sequence {
        return received == expected;
    }
    if received & 0xFF80_0000 == 0xFF80_0000 {
        if expected & 0xFF80_0000 == 0xFF80_0000 && received == expected {
            return true;
        }
        if !context.heimdal_sequence && received == expected {
            return true;
        }
        if heimdal_form(expected, received) {
            context.heimdal_sequence = true;
            return true;
        }
        return false;
    }
    if received == expected {
        if expected & 0xFFFF_FF80 == 0x0000_0080
            || expected & 0xFFFF_8000 == 0x0000_8000
            || expected & 0xFF80_0000 == 0x0080_0000
        {
            context.sane_sequence = true;
        }
        return true;
    }
    if expected == 0 && !context.heimdal_sequence {
        return match received {
            0x100 | 0x1_0000 | 0x100_0000 => {
                context.heimdal_sequence = true;
                context.remote_sequence = received;
                true
            }
            _ => false,
        };
    }
    false
}

/// Whether `received` is Heimdal's unsigned encoding of `expected` (`chk_heimdal_seqnum`).
const fn heimdal_form(expected: u32, received: u32) -> bool {
    (expected & 0xFF80_0000 == 0x0080_0000
        && received & 0xFF80_0000 == 0xFF80_0000
        && received & 0x00FF_FFFF == expected)
        || (expected & 0xFFFF_8000 == 0x0000_8000
            && received & 0xFFFF_8000 == 0xFFFF_8000
            && received & 0x0000_FFFF == expected)
        || (expected & 0xFFFF_FF80 == 0x0000_0080
            && received & 0xFFFF_FF80 == 0xFFFF_FF80
            && received & 0x0000_00FF == expected)
}
