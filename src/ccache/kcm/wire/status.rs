//! Daemon status codes the client acts on (`src/lib/krb5/error_tables/krb5_err.et`
//! of MIT 1.22.2: the `krb5` table is based at -1765328384 and `KRB5_CC_NOTFOUND`
//! is its entry 141).

/// `KRB5_CC_NOTFOUND`: no matching credential.
pub const CC_NOTFOUND: i32 = -1_765_328_243;
/// `KRB5_CC_END`: end of the cache.
pub const CC_END: i32 = -1_765_328_242;
/// `KRB5_CC_IO`: an I/O failure; SSSD also uses it for an unknown opcode
/// (`cc_kcm.c:147-153`).
pub const CC_IO: i32 = -1_765_328_191;
/// `KRB5_FCC_NOFILE`: no such cache.
pub const FCC_NOFILE: i32 = -1_765_328_189;
/// `KRB5_FCC_INTERNAL`: Heimdal's code for an unsupported opcode.
pub const FCC_INTERNAL: i32 = -1_765_328_188;
/// `KRB5_CC_NOSUPP`: SSSD's code for a recognized but unimplemented opcode.
pub const CC_NOSUPP: i32 = -1_765_328_137;
