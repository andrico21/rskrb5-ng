//! Context and credential transfer.
//!
//! The transfer contract of plan 2 todo 19: `export` consumes the context or
//! credential and seals it under a caller-supplied 256-bit [`TransferKey`] in
//! a versioned blob, encrypted and authenticated under the RFC 8009
//! `aes256-cts-hmac-sha384-192` profile, with a random transfer id and the
//! export time; `import` refuses a tampered blob, a wrong key and a transfer id
//! its [`TransferLedger`] has already consumed. Duplicate-use protection holds
//! within one ledger; a copy imported through a separate ledger is accepted,
//! which the API documents (MIT 1.22.2 `export_sec_context.c`,
//! `import_sec_context.c`, `export_cred.c` and `import_cred.c` export without
//! protection and without a ledger; this crate never does).

use std::{env, fs, process};

use rskrb5_ng::{
    error::Gss,
    gss::{
        Acceptor, AcceptorOptions, CredStore, Credential, CredentialUsage, EstablishedContext,
        InitStep, Initiator, InitiatorOptions, MemoryTransferLedger, PrfKey, TransferBlob,
        TransferKey,
    },
};

use super::{
    context::{Context as _, TestError},
    support::{AES256_SHA1, credential, establish, keytab, refused, sequenced, target},
};

/// A fixed transfer key.
fn key() -> TransferKey {
    TransferKey::new([0x42; 32])
}

/// Both directions of a context pair still protect messages.
fn exchange(
    initiator: &mut EstablishedContext,
    acceptor: &mut EstablishedContext,
) -> Result<(), TestError> {
    let token = initiator.wrap(b"after the transfer", true)?;
    assert_eq!(acceptor.unwrap(&token)?.message(), b"after the transfer");
    let reply = acceptor.wrap(b"and back", false)?;
    assert_eq!(initiator.unwrap(&reply)?.message(), b"and back");
    Ok(())
}

/// An exported context imports and continues its keys and sequence numbers.
#[test]
fn an_exported_context_continues_after_import() -> Result<(), TestError> {
    let mut ends = establish(sequenced())?;
    // Given a context that already exchanged a token,
    let first = ends.initiator.wrap(b"before", true)?;
    assert_eq!(ends.acceptor.unwrap(&first)?.message(), b"before");
    let expected = ends.initiator.pseudo_random(PrfKey::Full, b"k", 32)?;
    // when its initiator end is exported and imported,
    let blob = ends.initiator.export(&key())?;
    let mut ledger = MemoryTransferLedger::new();
    let mut imported = EstablishedContext::import(&blob, &key(), &mut ledger)?;
    // then it keeps its role, names, flags, keys and sequence state.
    assert!(imported.inquire().locally_initiated());
    assert_eq!(imported.inquire().flags(), ends.acceptor.inquire().flags());
    assert_eq!(
        imported.pseudo_random(PrfKey::Full, b"k", 32)?.as_slice(),
        expected.as_slice()
    );
    exchange(&mut imported, &mut ends.acceptor)?;
    // The acceptor end transfers too.
    let acceptor_blob = ends.acceptor.export(&key())?;
    let mut acceptor = EstablishedContext::import(&acceptor_blob, &key(), &mut ledger)?;
    assert!(!acceptor.inquire().locally_initiated());
    exchange(&mut imported, &mut acceptor)?;
    Ok(())
}

/// The ledger refuses a second import of the same blob; a separate ledger
/// does not know the first import and accepts the copy (the documented
/// scope of duplicate-use protection).
#[test]
fn a_ledger_refuses_a_second_import() -> Result<(), TestError> {
    let ends = establish(sequenced())?;
    let blob = ends.initiator.export(&key())?;
    let copy = TransferBlob::from_bytes(blob.as_bytes().to_vec());
    let mut ledger = MemoryTransferLedger::new();
    drop(EstablishedContext::import(&blob, &key(), &mut ledger)?);
    assert!(matches!(
        EstablishedContext::import(&copy, &key(), &mut ledger),
        Err(Gss::TransferReplayed)
    ));
    let mut other = MemoryTransferLedger::new();
    drop(EstablishedContext::import(&copy, &key(), &mut other)?);
    Ok(())
}

/// A blob under another key, a blob with any byte flipped, a truncated or
/// extended blob and a credential blob are refused without consuming the
/// transfer id: the genuine blob still imports afterwards.
#[test]
fn tampered_and_foreign_blobs_are_refused() -> Result<(), TestError> {
    let ends = establish(sequenced())?;
    let blob = ends.initiator.export(&key())?;
    let bytes = blob.as_bytes().to_vec();
    let mut ledger = MemoryTransferLedger::new();
    // A wrong key.
    let wrong = TransferKey::new([0x43; 32]);
    assert!(matches!(
        EstablishedContext::import(&blob, &wrong, &mut ledger),
        Err(Gss::TransferRejected(_))
    ));
    // Every flipped byte.
    for at in 0..bytes.len() {
        let mut flipped = bytes.clone();
        if let Some(byte) = flipped.get_mut(at) {
            *byte ^= 0x01;
        }
        refused(EstablishedContext::import(
            &TransferBlob::from_bytes(flipped),
            &key(),
            &mut ledger,
        ))
        .context(&format!("byte {at}"))?;
    }
    // Truncated and extended.
    for cut in [0, 1, 29, 30, 40, bytes.len().saturating_sub(1)] {
        let short = bytes.get(..cut).unwrap_or_default().to_vec();
        refused(EstablishedContext::import(
            &TransferBlob::from_bytes(short),
            &key(),
            &mut ledger,
        ))?;
    }
    let long = [bytes.as_slice(), &[0]].concat();
    refused(EstablishedContext::import(
        &TransferBlob::from_bytes(long),
        &key(),
        &mut ledger,
    ))?;
    // A credential blob is not a context.
    let credential_blob = credential(AES256_SHA1)?.export(&key())?;
    refused(EstablishedContext::import(
        &credential_blob,
        &key(),
        &mut ledger,
    ))?;
    // None of the refusals consumed the genuine transfer id.
    drop(EstablishedContext::import(&blob, &key(), &mut ledger)?);
    Ok(())
}

/// Keys and blobs do not show their bytes, and the blob does not carry the
/// session key in the clear.
#[test]
fn transfer_keys_and_blobs_are_redacted() -> Result<(), TestError> {
    let ends = establish(sequenced())?;
    let session = ends.initiator.session_key().value().to_vec();
    let blob = ends.initiator.export(&key())?;
    let transfer_key = key();
    let shown = format!("{transfer_key:?} {blob:?}");
    assert!(!shown.contains("66, 66"));
    assert!(!shown.contains("0x42"));
    assert!(
        !blob
            .as_bytes()
            .windows(session.len())
            .any(|window| window == session)
    );
    Ok(())
}

/// An initiator credential and an acceptor credential transfer and still
/// establish a context; an in-memory replay cache does not leave its process.
#[test]
fn credentials_transfer_under_the_same_contract() -> Result<(), TestError> {
    let mut ledger = MemoryTransferLedger::new();
    let blob = credential(AES256_SHA1)?.export(&key())?;
    let initiator_credential = Credential::import(&blob, &key(), &mut ledger)?;
    assert_eq!(
        initiator_credential.inquire().usage(),
        CredentialUsage::Initiate
    );
    assert!(matches!(
        Credential::import(&blob, &key(), &mut ledger),
        Err(Gss::TransferReplayed)
    ));
    let acceptor_blob = Credential::from_keytab(keytab()).export(&key())?;
    let acceptor_credential = Credential::import(&acceptor_blob, &key(), &mut ledger)?;
    let mut init = Initiator::new(target()?, InitiatorOptions::new());
    let InitStep::Continue(token) = init.init_sec_context(&initiator_credential, None)? else {
        return Err("a mutual initiator waits".into());
    };
    let mut accept = Acceptor::new(&acceptor_credential, AcceptorOptions::new())?;
    let accepted = accept.accept_sec_context(&token)?;
    let reply = accepted.output_token().context("an AP-REP")?.to_vec();
    let InitStep::Complete(None) = init.init_sec_context(&initiator_credential, Some(&reply))?
    else {
        return Err("the initiator completes".into());
    };
    // A credential with an in-memory replay cache is refused.
    let directory = env::temp_dir();
    let path = directory.join(format!("gss-ext-transfer-{}.keytab", process::id()));
    keytab().save(&path)?;
    let store = CredStore::new()
        .with("keytab", &format!("FILE:{}", path.display()))?
        .with("rcache", "memory:transfer")?;
    let with_rcache = Credential::acquire_cred_from(None, CredentialUsage::Accept, &store)?;
    fs::remove_file(&path)?;
    assert!(matches!(
        with_rcache.export(&key()),
        Err(Gss::NotNegotiated(_))
    ));
    Ok(())
}

/// An oversized blob is refused before it is decrypted.
#[test]
fn an_oversized_blob_is_refused() -> Result<(), TestError> {
    let ends = establish(sequenced())?;
    let mut bytes = ends.initiator.export(&key())?.into_bytes();
    bytes.resize(0x0010_0001, 0);
    let mut ledger = MemoryTransferLedger::new();
    assert!(matches!(
        EstablishedContext::import(&TransferBlob::from_bytes(bytes), &key(), &mut ledger),
        Err(Gss::TokenTooLarge {
            maximum: 0x0010_0000,
            actual: 0x0010_0001
        })
    ));
    Ok(())
}
