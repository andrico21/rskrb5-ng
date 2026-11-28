//! Tickets and AP-REQs built here, not by the crate, for the acceptor's checks.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::{Encoder as _, der};
use rskrb5_ng::{
    client::{TgsRepSession, build_ap_req_with_confounder, options::ApReq, principal::Principal},
    crypto::AesSha1Etype,
    gss::iakerb::Context,
    keytab,
    spnego::{Krb5MechToken, oid::ObjectIdentifier},
};
use zeroize::Zeroizing;

use super::{
    context::{Context as _, TestError},
    kdc,
    seal::{self, REALM},
    support::HOST,
};

/// The user's service ticket for `HTTP/<host>`, sealed in the service key.
///
/// # Errors
///
/// Returns the fixture errors.
pub(super) fn ticket() -> Result<TgsRepSession, TestError> {
    let now = SystemTime::now();
    let start = whole(now.checked_sub(Duration::from_mins(1)).context("start")?)?;
    let end = whole(now.checked_add(Duration::from_hours(1)).context("end")?)?;
    let session = keytab::EncryptionKey::new(18, vec![0x5a; 32]);
    let der = seal::service_ticket(&session, (start, end))?;
    Ok(TgsRepSession::new(
        kdc::client(),
        Principal::new(REALM, 3, ["HTTP", HOST]),
        session,
        Zeroizing::new(der),
        [0x40, 0, 0, 0],
        start,
        end,
    ))
}

/// Whole seconds of `at`.
fn whole(at: SystemTime) -> Result<SystemTime, TestError> {
    let seconds = at.duration_since(UNIX_EPOCH)?.as_secs();
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .context("time is representable")
}

/// The subkey the hand-built AP-REQs of [`ap_req_token`] carry.
pub(super) fn subkey() -> keytab::EncryptionKey {
    keytab::EncryptionKey::new(18, vec![0x77; 32])
}

/// An IAKERB AP-REQ token of the user for `HTTP/<host>`, built here, not by the crate.
///
/// The layout is RFC 4121's checksum and MIT's extension framing
/// (`init_sec_context.c:341-345`: a big-endian type and length): the
/// authenticator's checksum carries `extension` (an `IAKERB-FINISHED`) when given.
///
/// # Errors
///
/// Returns the fixture errors.
pub(super) fn ap_req_token(extension: Option<&[u8]>) -> Result<Vec<u8>, TestError> {
    framed(&Context::mechanism(), ap_req_der(extension)?)
}

/// `der` in the RFC 2743 frame of `mechanism` with the AP-REQ token id.
///
/// # Errors
///
/// Returns the encoding errors.
pub(super) fn framed(mechanism: &ObjectIdentifier, der: Vec<u8>) -> Result<Vec<u8>, TestError> {
    let mut token = Krb5MechToken::ap_req(der);
    token.set_oid(mechanism.clone());
    Ok(token.encode()?)
}

/// The DER AP-REQ of [`ap_req_token`], without a frame.
///
/// # Errors
///
/// Returns the fixture errors.
pub(super) fn ap_req_der(extension: Option<&[u8]>) -> Result<Vec<u8>, TestError> {
    let mut checksum = 16_u32.to_le_bytes().to_vec();
    checksum.extend_from_slice(&[0; 16]);
    checksum.extend_from_slice(&0x32_u32.to_le_bytes());
    if let Some(finished) = extension {
        checksum.extend_from_slice(&2_u32.to_be_bytes());
        checksum.extend_from_slice(&u32::try_from(finished.len())?.to_be_bytes());
        checksum.extend_from_slice(finished);
    }
    let options = ApReq::new()
        .with_ap_option_bits(0x2000_0000)
        .with_checksum(Some(rasn_kerberos::Checksum {
            r#type: 0x8003,
            checksum: checksum.into(),
        }))
        .with_subkey(Some(subkey()))
        .with_sequence_number(Some(0x1234));
    let now = whole(SystemTime::now())?;
    let built = build_ap_req_with_confounder(&ticket()?, options, now, 7, &[0x21; 16])?;
    Ok(built.der().to_vec())
}

/// The `IAKERB-FINISHED` of `transcript` under `key`, derived here, not by the crate.
///
/// The checksum type and key usage are MIT's (`iakerb.c:141`: usage 41), the
/// layout the ASN.1 module's (`asn1_k_encode.c:1102-1107`) and RFC 3961's.
///
/// # Errors
///
/// Returns the fixture errors.
pub(super) fn finished(
    key: &keytab::EncryptionKey,
    transcript: &[u8],
) -> Result<Vec<u8>, TestError> {
    /// `IAKERB-FINISHED ::= SEQUENCE { checksum [1] Checksum }`.
    #[derive(rasn::AsnType, rasn::Encode)]
    struct Finished {
        /// The checksum of the transcript.
        #[rasn(tag(explicit(1)))]
        checksum: rasn_kerberos::Checksum,
    }
    let sum = AesSha1Etype::from_etype_id(key.etype())
        .context("AES")?
        .checksum(key.value(), transcript, 41)?;
    Ok(der::encode(&Finished {
        checksum: rasn_kerberos::Checksum {
            r#type: 16,
            checksum: sum.into(),
        },
    })?)
}
