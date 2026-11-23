//! Record marking, the RPC reply and the kadm5 result layouts.
//!
//! RFC 5531 sections 9 and 11 and MIT 1.22.2's `kadm_rpc_xdr.c`, against
//! bytes built by the test's own XDR writer.

use rskrb5_ng::{
    error::{Kadm5, Rpc},
    kadm5::{ApiVersion, PolicyMask, PrincipalMask, Procedure, Response},
    rpcsec_gss::{self, Outcome, Reply},
};

use super::{
    context::{Context as _, TestError},
    wire::Writer,
};

/// The records of a reply split at `at`: two fragments, the second the last.
fn two_fragments(message: &[u8], at: usize) -> Result<Vec<u8>, TestError> {
    let (head, tail) = message.split_at_checked(at).context("split point")?;
    let mut bytes = u32::try_from(head.len())?.to_be_bytes().to_vec();
    bytes.extend_from_slice(head);
    bytes.extend_from_slice(&(u32::try_from(tail.len())? | 0x8000_0000).to_be_bytes());
    bytes.extend_from_slice(tail);
    Ok(bytes)
}

/// A record is one last fragment; two fragments reassemble into one message.
#[test]
fn record_marking_frames_and_reassembles() -> Result<(), TestError> {
    // Given a message, When it is framed, Then one last fragment carries it.
    assert_eq!(
        rpcsec_gss::encode_record(b"abc").as_slice(),
        [0x80, 0, 0, 3, b'a', b'b', b'c']
    );
    // Given two fragments and trailing bytes of the next record.
    let mut bytes = two_fragments(b"abcdef", 2)?;
    let length = bytes.len();
    bytes.extend_from_slice(&[0x80, 0]);
    // When the record is decoded, Then the message and the consumed length come back.
    let (message, consumed) = rpcsec_gss::decode_record(&bytes)?.context("a whole record")?;
    assert_eq!(message.as_slice(), b"abcdef");
    assert_eq!(consumed, length);
    // And a record cut short needs more bytes.
    assert!(rpcsec_gss::decode_record(bytes.get(..length - 1).context("prefix")?)?.is_none());
    Ok(())
}

/// A fragment above the record bound is refused from its header alone.
#[test]
fn oversized_fragment_is_refused_before_allocation() -> Result<(), TestError> {
    // Given a last fragment announcing one byte more than the bound and no body.
    let announced = u32::try_from(rpcsec_gss::MAX_RECORD_SIZE)? + 1;
    let header = (announced | 0x8000_0000).to_be_bytes();
    // When it is decoded, Then the bound refuses it.
    let result = rpcsec_gss::decode_record(&header);
    assert!(
        matches!(result, Err(Rpc::RecordTooLarge { maximum: _, actual: _ })),
        "{result:?}"
    );
    Ok(())
}

/// Fragments whose sum passes the bound are refused at the fragment that passes it.
#[test]
fn record_total_size_is_bounded() -> Result<(), TestError> {
    // Given an eight-byte fragment, then a header that brings the total past the bound.
    let mut bytes = 8_u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(&[0; 8]);
    let rest = u32::try_from(rpcsec_gss::MAX_RECORD_SIZE)? - 7;
    bytes.extend_from_slice(&(rest | 0x8000_0000).to_be_bytes());
    // When it is decoded, Then the total bound refuses it.
    let result = rpcsec_gss::decode_record(&bytes);
    assert!(
        matches!(result, Err(Rpc::RecordTooLarge { maximum: _, actual: _ })),
        "{result:?}"
    );
    Ok(())
}

/// Empty fragments that never end are refused at the fragment bound.
#[test]
fn endless_fragments_are_refused() -> Result<(), TestError> {
    // Given one more empty non-last fragment than the bound allows.
    let count = rpcsec_gss::MAX_FRAGMENTS.checked_add(1).context("a count")?;
    let bytes = [0_u8; 4].repeat(count);
    // When they are decoded, Then the fragment bound refuses them.
    let error = rpcsec_gss::decode_record(&bytes)
        .err()
        .context("the fragment bound")?;
    assert!(matches!(error, Rpc::TooManyFragments(_)), "{error:?}");
    Ok(())
}

/// An accepted reply yields its XID, verifier and results; a denial its status.
#[test]
fn replies_decode() -> Result<(), TestError> {
    // Given an accepted reply with an RPCSEC_GSS verifier and results.
    let accepted = Writer::new()
        .u32(7)
        .u32(1)
        .u32(0)
        .u32(6)
        .opaque(b"mic")
        .u32(0)
        .raw(&[1, 2, 3, 4])
        .finish();
    // When it is decoded, Then every field is the one sent.
    let reply = Reply::decode(&accepted)?;
    assert_eq!(reply.xid(), 7);
    assert_eq!(*reply.outcome(), Outcome::Success);
    let verifier = reply.verifier().context("a verifier")?;
    assert_eq!((verifier.flavor(), verifier.body()), (6, &b"mic"[..]));
    assert_eq!(reply.results(), [1, 2, 3, 4]);
    // Given an AUTH_ERROR denial (AUTH_TOOWEAK), When decoded, Then its status shows.
    let denied = Writer::new().u32(8).u32(1).u32(1).u32(1).u32(5).finish();
    assert_eq!(*Reply::decode(&denied)?.outcome(), Outcome::AuthError(5));
    // Given an RPC version mismatch, When decoded, Then the versions show.
    let mismatch = Writer::new()
        .u32(9)
        .u32(1)
        .u32(1)
        .u32(0)
        .u32(2)
        .u32(2)
        .finish();
    assert_eq!(
        *Reply::decode(&mismatch)?.outcome(),
        Outcome::RpcMismatch { low: 2, high: 2 }
    );
    Ok(())
}

/// Calls, unknown statuses and verifiers above `MAX_AUTH_BYTES` are refused.
#[test]
fn malformed_replies_are_refused() -> Result<(), TestError> {
    // Given a call message instead of a reply.
    let call = Writer::new().u32(1).u32(0).u32(2).finish();
    let error = Reply::decode(&call).err().context("a call is no reply")?;
    assert!(matches!(error, Rpc::Malformed(_)), "{error:?}");
    // Given a reply status that is neither accepted nor denied.
    let status = Writer::new().u32(1).u32(1).u32(2).finish();
    assert!(matches!(Reply::decode(&status), Err(Rpc::Malformed(_))));
    // Given a verifier of 401 bytes (RFC 5531 section 8.2 bounds it at 400).
    let large = Writer::new()
        .u32(1)
        .u32(1)
        .u32(0)
        .u32(6)
        .opaque(&[0; 401])
        .u32(0)
        .finish();
    assert!(matches!(Reply::decode(&large), Err(Rpc::TooLarge { field: _, maximum: _, actual: _ })));
    // Given a truncated reply.
    assert!(matches!(
        Reply::decode(&[0, 0, 0, 1, 0, 0]),
        Err(Rpc::Malformed(_))
    ));
    Ok(())
}

/// The `kadm5_principal_ent_rec` of a `gprinc_ret` in MIT's field order
/// (`kadm_rpc_xdr.c` `_xdr_kadm5_principal_ent_rec`).
fn principal_record() -> Writer {
    Writer::new()
        .nullstring(Some("alice@EXAMPLE.COM"))
        .i32(1_900_000_000)
        .i32(1_700_000_000)
        .i32(0)
        .i32(36_000)
        .u32(0)
        .nullstring(Some("admin/admin@EXAMPLE.COM"))
        .i32(1_700_000_100)
        .i32(0x80)
        .u32(3)
        .u32(1)
        .nullstring(Some("default"))
        .i32(0x800)
        .i32(604_800)
        .i32(1_700_000_200)
        .i32(0)
        .u32(2)
        .i32(2)
        .i32(1)
        .u32(0)
        .u32(1)
        .i32(8)
        .opaque(&[1, 2, 3])
        .u32(0)
        .u32(2)
        .i32(2)
        .u32(3)
        .i32(18)
        .i32(0)
        .i32(2)
        .u32(3)
        .i32(17)
        .i32(0)
}

/// A principal record decodes field by field, key data without key bytes.
#[test]
fn principal_record_decodes() -> Result<(), TestError> {
    // Given a gprinc_ret with code 0 and the record above.
    let bytes = Writer::new()
        .u32(ApiVersion::V4.wire())
        .u32(0)
        .raw(&principal_record().finish())
        .finish();
    // When it is decoded.
    let Response::Principal(record) =
        Response::decode(Procedure::GetPrincipal, ApiVersion::V4, &bytes)?
    else {
        return Err("a principal record".into());
    };
    // Then every field is the one sent.
    assert_eq!(record.principal().components, ["alice"]);
    assert_eq!(record.principal().realm, "EXAMPLE.COM");
    assert_eq!(record.princ_expire_time(), 1_900_000_000_i32);
    assert_eq!(record.last_pwd_change(), 1_700_000_000_i32);
    assert_eq!(record.max_life(), 36_000_i32);
    let modifier = record.mod_name().context("a modifier")?;
    assert_eq!(modifier.components, ["admin", "admin"]);
    assert_eq!(record.attributes(), 0x80_i32);
    assert_eq!((record.kvno(), record.mkvno()), (3, 1));
    assert_eq!(record.policy(), Some("default"));
    assert_eq!(record.aux_attributes(), 0x800_i32);
    assert_eq!(record.max_renewable_life(), 604_800_i32);
    assert_eq!(record.fail_auth_count(), 2);
    let tl = record.tl_data();
    assert_eq!(tl.len(), 1);
    assert_eq!(
        (
            tl.first().context("tl")?.kind(),
            tl.first().context("tl")?.contents()
        ),
        (8, &[1, 2, 3][..])
    );
    let keys = record.key_data();
    assert_eq!(keys.len(), 2);
    let first = keys.first().context("first key")?;
    assert_eq!(
        (first.kvno(), first.enctype(), first.salt_type()),
        (3, 18, 0)
    );
    Ok(())
}

/// A failed `get_principal` carries only its code; the record is not read.
#[test]
fn failed_results_carry_their_code() -> Result<(), TestError> {
    // Given a gprinc_ret with KADM5_UNK_PRINC (43787532) and no record.
    let bytes = Writer::new()
        .u32(ApiVersion::V4.wire())
        .u32(43_787_532)
        .finish();
    // When it is decoded, Then the code is the server's refusal.
    let error = Response::decode(Procedure::GetPrincipal, ApiVersion::V4, &bytes)
        .err()
        .context("the server's refusal")?;
    assert!(
        matches!(error, Kadm5::Server { code: 43_787_532, procedure: _ }),
        "{error:?}"
    );
    Ok(())
}

/// The policy record has the v2 fields, then the v3 and the v4 fields.
#[test]
fn policy_record_follows_the_api_version() -> Result<(), TestError> {
    // Given the six v2 fields, the three v3 fields and the v4 fields.
    let v2 = Writer::new()
        .nullstring(Some("strict"))
        .i32(3600)
        .i32(86_400)
        .i32(12)
        .i32(3)
        .i32(5)
        .i32(0);
    let v3 = Writer::new().raw(&v2.finish()).u32(4).i32(60).i32(600);
    let v4 = Writer::new()
        .raw(&v3.finish())
        .i32(0)
        .i32(36_000)
        .i32(72_000)
        .nullstring(Some("aes256-cts:normal"))
        .i32(0)
        .u32(1)
        .finish();
    let bytes = Writer::new()
        .u32(ApiVersion::V4.wire())
        .u32(0)
        .raw(&v4)
        .finish();
    // When it is decoded under v4.
    let Response::Policy(policy) = Response::decode(Procedure::GetPolicy, ApiVersion::V4, &bytes)?
    else {
        return Err("a policy record".into());
    };
    // Then the v2, v3 and v4 fields are the ones sent.
    assert_eq!(policy.name(), "strict");
    assert_eq!((policy.pw_min_length(), policy.pw_min_classes()), (12_i32, 3_i32));
    assert_eq!(
        (policy.pw_max_fail(), policy.pw_lockout_duration()),
        (4, 600_i32)
    );
    assert_eq!(policy.allowed_keysalts(), Some("aes256-cts:normal"));
    assert_eq!(policy.max_renewable_life(), 72_000_i32);
    // And the same bytes under v2 leave the v3 and v4 fields unread: trailing bytes.
    let result = Response::decode(Procedure::GetPolicy, ApiVersion::V2, &bytes);
    assert!(matches!(result, Err(Kadm5::Malformed(_))), "{result:?}");
    // And the masks name MIT's bits (admin.h:88-133).
    assert_eq!(PrincipalMask::POLICY.bits(), 0x800);
    assert_eq!(PolicyMask::ALLOWED_KEYSALTS.bits(), 0x0400_0000);
    Ok(())
}

/// Name lists: the counts must agree, a count larger than the bytes is
/// refused before allocation, and a name must be a NUL-terminated string.
#[test]
fn name_lists_are_bounded() -> Result<(), TestError> {
    let version = ApiVersion::V4.wire();
    // Given two names under matching counts, When decoded, Then both come back.
    let good = Writer::new()
        .u32(version)
        .u32(0)
        .i32(2)
        .u32(2)
        .nullstring(Some("a@R"))
        .nullstring(Some("b@R"))
        .finish();
    let Response::Names(names) = Response::decode(Procedure::GetPrincipals, ApiVersion::V4, &good)?
    else {
        return Err("a name list".into());
    };
    assert_eq!(names, ["a@R", "b@R"]);
    // Given counts that disagree.
    let disagree = Writer::new().u32(version).u32(0).i32(3).u32(2).finish();
    assert!(matches!(
        Response::decode(Procedure::GetPrincipals, ApiVersion::V4, &disagree),
        Err(Kadm5::Malformed(_))
    ));
    // Given a count of a billion with no bytes behind it.
    let huge = Writer::new()
        .u32(version)
        .u32(0)
        .i32(1_000_000_000)
        .u32(1_000_000_000)
        .finish();
    assert!(matches!(
        Response::decode(Procedure::GetPolicies, ApiVersion::V4, &huge),
        Err(Kadm5::TooLarge { field: _, maximum: _, actual: _ } | Kadm5::Malformed(_))
    ));
    // Given a name without its NUL, and one with a NUL inside (MIT
    // `xdr_nullstring` refuses both, kadm_rpc_xdr.c:64-69).
    for bad in [&b"a@R"[..], b"a\0@R\0"] {
        let bytes = Writer::new()
            .u32(version)
            .u32(0)
            .i32(1)
            .u32(1)
            .opaque(bad)
            .finish();
        assert!(matches!(
            Response::decode(Procedure::GetPrincipals, ApiVersion::V4, &bytes),
            Err(Kadm5::Malformed(_))
        ));
    }
    Ok(())
}

/// Random keys decode into key owners whose `Debug` shows no key bytes.
#[test]
fn random_keys_decode_redacted() -> Result<(), TestError> {
    // Given a chrand_ret with one AES256 key of a recognisable pattern.
    let key = [0xa5_u8; 32];
    let bytes = Writer::new()
        .u32(ApiVersion::V4.wire())
        .u32(0)
        .u32(1)
        .i32(18)
        .opaque(&key)
        .finish();
    // When it is decoded.
    let Response::Keys(keys) = Response::decode(Procedure::RandomizeKeys, ApiVersion::V4, &bytes)?
    else {
        return Err("keys".into());
    };
    // Then the key is there, and its Debug form does not show it.
    let first = keys.first().context("a key")?;
    assert_eq!((first.etype(), first.value().as_ref()), (18_i32, &key[..]));
    let shown = format!("{keys:?}");
    assert!(!shown.contains("a5") && !shown.contains("165"), "{shown}");
    Ok(())
}
