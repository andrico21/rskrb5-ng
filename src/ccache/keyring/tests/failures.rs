//! Kernel failures and malformed keys.

use super::{TestError, cache, credential, kernel, principal};
use crate::ccache::{
    Error,
    keyring::{
        Fault, KernelError,
        backend::{Backend as _, Kind, Ring},
        fake::Op,
    },
};

/// The kernel call and error of a refused operation.
///
/// # Errors
///
/// A description of the result when it is not a kernel refusal.
fn refusal<T>(result: Result<T, Error>) -> Result<(&'static str, KernelError), TestError> {
    match result.map(drop) {
        Err(Error::Keyring(Fault::Kernel { operation, error })) => Ok((operation, error)),
        other => Err(format!("not a kernel refusal: {other:?}").into()),
    }
}

/// A kernel without key management is `ENOSYS`, typed (`cc_keyring.c:229-250`).
#[test]
fn enosys_is_unavailable() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    fake.fail(Op::Search, 1, KernelError::Unavailable);
    let failed = refusal(cache(&engine, "process:krb"))?;
    assert_eq!(failed, ("keyctl_search", KernelError::Unavailable));
    Ok(())
}

/// `EPERM` and `EACCES` are reported as they are, from a call that would
/// create a key.
#[test]
fn permission_errors_are_typed() -> Result<(), TestError> {
    for error in [KernelError::PermissionDenied, KernelError::AccessDenied] {
        let (fake, engine) = kernel();
        let handle = cache(&engine, "process:krb")?;
        fake.fail(Op::Add, 1, error);
        let failed = refusal(handle.initialize(&principal("alice")))?;
        assert_eq!(failed, ("add_key", error));
    }
    Ok(())
}

/// `EDQUOT` on a credential is an error, not a silent retry as a `user`
/// key (`cc_keyring.c:395-408` retries only on `EINVAL` and `ENODEV`).
#[test]
fn quota_is_not_retried() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    fake.fail(Op::AddKey, 1, KernelError::QuotaExceeded);
    let failed = refusal(handle.store(credential("host/a", 0, b"a")))?;
    assert_eq!(failed, ("add_key", KernelError::QuotaExceeded));
    assert!(handle.load()?.credentials().is_empty(), "nothing stored");
    Ok(())
}

/// `EINVAL` from `big_key` falls back to a `user` key.
#[test]
fn einval_falls_back_to_a_user_key() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    fake.fail(Op::AddKey, 1, KernelError::InvalidArgument);
    handle.store(credential("host/a", 0, b"a"))?;
    assert_eq!(handle.load()?.credentials().len(), 1);
    Ok(())
}

/// A credential key that vanished (`ENOKEY`) or cannot be read (`EACCES`) is
/// skipped; any other error stops the read (`cc_keyring.c:1031-1044`).
#[test]
fn unreadable_credentials_are_skipped() -> Result<(), TestError> {
    for skipped in [KernelError::KeyNotFound, KernelError::AccessDenied] {
        let (fake, engine) = kernel();
        let handle = cache(&engine, "process:krb")?;
        handle.initialize(&principal("alice"))?;
        handle.store(credential("host/a", 0, b"a"))?;
        fake.fail(Op::ReadKey, 1, skipped);
        assert!(handle.load()?.credentials().is_empty(), "{skipped}");
    }
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    handle.store(credential("host/a", 0, b"a"))?;
    fake.fail(Op::ReadKey, 1, KernelError::KeyRevoked);
    let failed = refusal(handle.load())?;
    assert_eq!(failed, ("keyctl_read", KernelError::KeyRevoked));
    Ok(())
}

/// Writing into a revoked collection is `EKEYREVOKED`, typed.
#[test]
fn revoked_collection_is_reported() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    let collection = fake.search(Ring::Process, Kind::Keyring, "_krb_krb", None)?;
    fake.revoke(Ring::Key(collection));
    let failed = refusal(handle.initialize(&principal("alice")))?;
    assert_eq!(failed, ("add_key", KernelError::KeyRevoked));
    Ok(())
}

/// A revoked cache keyring is gone: it is not found, and initializing makes a
/// new one.
#[test]
fn revoked_cache_is_absent() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    let collection = fake.search(Ring::Process, Kind::Keyring, "_krb_krb", None)?;
    let ring = fake.search(Ring::Key(collection), Kind::Keyring, "krb", None)?;
    fake.revoke(Ring::Key(ring));
    assert!(
        matches!(handle.load(), Err(Error::CacheNotFound { name: _ })),
        "absent"
    );
    handle.initialize(&principal("bob"))?;
    assert_eq!(handle.load()?.default_principal(), &principal("bob"));
    Ok(())
}

/// A primary-name key with a version other than 1 or a short payload stops
/// resolution (`cc_keyring.c:622-625`).
#[test]
fn malformed_primary_key_stops_resolution() -> Result<(), TestError> {
    let cases: [(&[u8], Fault); 2] = [
        (
            b"\0\0\0\x02\0\0\0\x01a",
            Fault::UnknownCollectionVersion { version: 2_i32 },
        ),
        (b"\0\0\0\x01", Fault::MalformedPrimary),
    ];
    for (payload, expected) in cases {
        let (fake, engine) = kernel();
        drop(cache(&engine, "process:krb")?);
        let collection = fake.search(Ring::Process, Kind::Keyring, "_krb_krb", None)?;
        let _planted = fake.add(
            Ring::Key(collection),
            Kind::User,
            "krb_ccache:primary",
            payload,
        )?;
        let failure = cache(&engine, "process:krb").err().ok_or("resolved")?;
        assert!(
            matches!(failure, Error::Keyring(fault) if fault == expected),
            "{expected}"
        );
    }
    Ok(())
}

/// Bytes after a credential in a key are refused, where MIT would ignore them.
#[test]
fn trailing_bytes_in_a_credential_key_are_refused() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    handle.store(credential("host/a", 0, b"a"))?;
    let collection = fake.search(Ring::Process, Kind::Keyring, "_krb_krb", None)?;
    let ring = fake.search(Ring::Key(collection), Kind::Keyring, "krb", None)?;
    let mut payload = fake
        .payload(Ring::Key(ring), "host/a@EXAMPLE.COM")
        .ok_or("payload")?;
    payload.push(0);
    let _planted = fake.add(
        Ring::Key(ring),
        Kind::BigKey,
        "host/a@EXAMPLE.COM",
        &payload,
    )?;
    assert!(matches!(
        handle.load(),
        Err(Error::Keyring(Fault::MalformedPayload))
    ));
    Ok(())
}
