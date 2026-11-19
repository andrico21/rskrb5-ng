//! KCM protocol messages: Heimdal KCM 2.0 as MIT 1.22.2 speaks it.
//!
//! Sources: `src/include/kcm.h` and `src/lib/krb5/ccache/cc_kcm.c`. A request is the
//! major and minor version, a big-endian opcode, the NUL-terminated cache
//! name for cache operations, and the operation's arguments
//! (`kcmreq_init`, `cc_kcm.c:164-179`). A reply is a big-endian status, then
//! the result (`kcmio_call`, `cc_kcm.c:452-475`).

use crate::{Secret, error::Platform};

/// The KCM protocol version this client speaks (`kcm.h`).
const VERSION: [u8; 2] = [2, 0];
/// The length of a KCM UUID (`KCM_UUID_LEN`).
pub(crate) const UUID_LEN: usize = 16;
/// The cache type of the KCM store.
const CACHE_TYPE: &str = "KCM";

/// The KCM operations the store uses (`kcm_opcode`, `kcm.h`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Opcode {
    /// `() -> (name)`.
    GenNew,
    /// `(name, principal) -> ()`.
    Initialize,
    /// `(name) -> ()`.
    Destroy,
    /// `(name, credential) -> ()`.
    Store,
    /// `(name) -> (principal)`.
    GetPrincipal,
    /// `(name) -> (uuid, ...)`.
    GetCredUuidList,
    /// `(name, uuid) -> (credential)`.
    GetCredByUuid,
    /// `(name, flags, matching credential) -> ()`.
    RemoveCred,
    /// `() -> (uuid, ...)`.
    GetCacheUuidList,
    /// `(uuid) -> (name)`.
    GetCacheByUuid,
    /// `() -> (name)`.
    GetDefaultCache,
    /// `(name) -> ()`.
    SetDefaultCache,
}

impl Opcode {
    /// The wire value (the `kcm_opcode` enumerator position).
    const fn code(self) -> u16 {
        match self {
            Self::GenNew => 3,
            Self::Initialize => 4,
            Self::Destroy => 5,
            Self::Store => 6,
            Self::GetPrincipal => 8,
            Self::GetCredUuidList => 9,
            Self::GetCredByUuid => 10,
            Self::RemoveCred => 11,
            Self::GetCacheUuidList => 18,
            Self::GetCacheByUuid => 19,
            Self::GetDefaultCache => 20,
            Self::SetDefaultCache => 21,
        }
    }
}

/// A malformed-reply failure.
const fn malformed(reason: &'static str) -> Platform {
    Platform::MalformedReply {
        cache_type: CACHE_TYPE,
        reason,
    }
}

/// Build a request: header, the NUL-terminated `name` when given, then `args`.
/// # Errors
/// Returns [`Platform::MalformedReply`] for a name that holds a NUL byte.
pub(crate) fn request(opcode: Opcode, name: Option<&str>, args: &[u8]) -> Result<Secret, Platform> {
    let mut out = Vec::with_capacity(
        4_usize
            .saturating_add(name.map_or(0, |value| value.len().saturating_add(1)))
            .saturating_add(args.len()),
    );
    out.extend_from_slice(&VERSION);
    out.extend_from_slice(&opcode.code().to_be_bytes());
    if let Some(value) = name {
        if value.as_bytes().contains(&0) {
            return Err(malformed("cache name holds a NUL byte"));
        }
        out.extend_from_slice(value.as_bytes());
        out.push(0);
    }
    out.extend_from_slice(args);
    Ok(Secret::from(out))
}

/// The result of a reply, or the server's nonzero status as an error.
/// # Errors
/// Returns [`Platform::Kcm`] for a nonzero status and
/// [`Platform::MalformedReply`] for a reply shorter than its status.
pub(crate) fn result(reply: &[u8]) -> Result<&[u8], Platform> {
    let (status, rest) = reply
        .split_first_chunk::<4>()
        .ok_or_else(|| malformed("reply shorter than its status"))?;
    match i32::from_be_bytes(*status) {
        0 => Ok(rest),
        code => Err(Platform::Kcm { code }),
    }
}

/// A NUL-terminated cache name that fills the result (`kcmreq_get_name`).
/// # Errors
/// Returns [`Platform::MalformedReply`] for a missing terminator, trailing
/// bytes or a name that is not UTF-8.
pub(crate) fn name(result: &[u8]) -> Result<String, Platform> {
    match result.split_last() {
        Some((0, text)) if !text.contains(&0) => str::from_utf8(text)
            .map(str::to_owned)
            .map_err(|_utf8| malformed("cache name is not UTF-8")),
        Some(_) | None => Err(malformed("cache name is not one NUL-terminated string")),
    }
}

/// A list of UUIDs that fills the result (`kcmreq_get_uuid_list`).
/// # Errors
/// Returns [`Platform::MalformedReply`] when the length is not a multiple
/// of [`UUID_LEN`].
pub(crate) fn uuids(result: &[u8]) -> Result<Vec<[u8; UUID_LEN]>, Platform> {
    let (chunks, rest) = result.as_chunks::<UUID_LEN>();
    if rest.is_empty() {
        Ok(chunks.to_vec())
    } else {
        Err(malformed("UUID list length is not a multiple of 16"))
    }
}

/// The arguments of `REMOVE_CRED` that match every credential of `server`.
///
/// They are no match flags, then a matching credential with only the server
/// set (`kcm_remove_cred`, `cc_kcm.c:1068-1078`; `k5_marshal_mcred`,
/// `ccmarshal.c:450-517`).
pub(crate) fn remove_server_args(server: &[u8]) -> Vec<u8> {
    /// `SC_SERVER_PRINCIPAL`.
    const SERVER_PRINCIPAL: u32 = 0x0002;
    let mut out = Vec::with_capacity(server.len().saturating_add(29));
    out.extend_from_slice(&0_u32.to_be_bytes());
    out.extend_from_slice(&SERVER_PRINCIPAL.to_be_bytes());
    out.extend_from_slice(server);
    out.extend_from_slice(&[0; 17]);
    out.extend_from_slice(&0_u32.to_be_bytes());
    out
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::{Opcode, Platform, name, remove_server_args, request, result, uuids};

    /// The opcodes are the `kcm_opcode` positions.
    #[test]
    fn opcode_values() -> Result<(), Platform> {
        // Given every opcode the store uses.
        let all = [
            (Opcode::GenNew, 3),
            (Opcode::Initialize, 4),
            (Opcode::Destroy, 5),
            (Opcode::Store, 6),
            (Opcode::GetPrincipal, 8),
            (Opcode::GetCredUuidList, 9),
            (Opcode::GetCredByUuid, 10),
            (Opcode::RemoveCred, 11),
            (Opcode::GetCacheUuidList, 18),
            (Opcode::GetCacheByUuid, 19),
            (Opcode::GetDefaultCache, 20),
            (Opcode::SetDefaultCache, 21),
        ];
        // When each is encoded.
        // Then its wire value is MIT's.
        for (opcode, code) in all {
            let encoded = request(opcode, None, &[])?;
            assert_eq!(
                encoded.get(2..),
                Some(&u16::to_be_bytes(code)[..]),
                "{opcode:?}"
            );
        }
        Ok(())
    }

    /// Requests carry the version, the opcode, the terminated name and the arguments.
    #[test]
    fn request_layout() -> Result<(), Platform> {
        // Given a store and a name-free request.
        // When they are built.
        let store = request(Opcode::Store, Some("501:1"), &[9, 9])?;
        let default = request(Opcode::GetDefaultCache, None, &[])?;
        // Then the bytes follow kcmreq_init.
        assert_eq!(
            store.as_slice(),
            [2, 0, 0, 6, b'5', b'0', b'1', b':', b'1', 0, 9, 9]
        );
        assert_eq!(default.as_slice(), [2, 0, 0, 20]);
        assert!(
            request(Opcode::Destroy, Some("a\0b"), &[]).is_err(),
            "NUL in name"
        );
        Ok(())
    }

    /// Replies are split into status and result; malformed results are refused.
    #[test]
    fn reply_parsing() -> Result<(), Platform> {
        // Given replies with and without errors.
        // When they are parsed.
        // Then a nonzero status is the KCM error and shapes are checked.
        assert_eq!(result(&[0, 0, 0, 0, b'x', 0])?, [b'x', 0]);
        assert_eq!(
            result(&[0x96, 0xc7, 0x3a, 0xc3]),
            Err(Platform::Kcm {
                code: -1_765_328_189_i32
            })
        );
        assert!(result(&[0, 0, 0]).is_err(), "short reply");
        assert_eq!(name(b"501:krb5cc\0")?, "501:krb5cc");
        for bad in [&b"no-nul"[..], b"a\0b\0", b"", b"\xff\0"] {
            assert!(name(bad).is_err(), "{bad:?}");
        }
        assert_eq!(uuids(&[1; 32])?, vec![[1; 16], [1; 16]]);
        assert!(uuids(&[1; 17]).is_err(), "partial UUID");
        Ok(())
    }

    /// `REMOVE_CRED` matches on the server only.
    #[test]
    fn remove_matches_the_server() -> Result<(), Platform> {
        // Given a server principal encoding inside a request.
        // When the arguments are built.
        let args = remove_server_args(&[0xaa, 0xbb]);
        let framed = request(Opcode::RemoveCred, Some("c"), &args)?;
        assert_eq!(framed.get(6..), Some(args.as_slice()));
        // Then flags, header, server, empty times, skey, flags follow.
        assert_eq!(
            args,
            [
                vec![0_u8, 0, 0, 0, 0, 0, 0, 2, 0xaa, 0xbb],
                vec![0_u8; 17],
                vec![0_u8, 0, 0, 0]
            ]
            .concat()
        );
        Ok(())
    }
}
