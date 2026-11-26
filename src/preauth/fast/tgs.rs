//! Implicit FAST armor of TGS requests (RFC 6113 section 5.4.2, MIT
//! `send_tgs.c:178`, `krb5int_fast_tgs_armor` `fast.c:110-142`).
//!
//! The TGT that authenticates the TGS request armors it: the armor key is
//! `KRB-FX-CF2(subkey, TGT session key, "subkeyarmor", "ticketarmor")` with the
//! subkey of the request's authenticator, so the request carries no armor AP-REQ
//! of its own. [`wrap`] turns a TGS-REQ into the armored one; [`unwrap`]
//! authenticates the reply to it and derives its reply key.
//!
//! # Security
//!
//! A reply that fails any FAST check is an error and never a plain exchange: a
//! `PA-FX-FAST` that does not decrypt, bind the request nonce, finish over the
//! ticket with the armor key's own checksum type or carry the strengthen key
//! (RFC 6113 section 5.4.3) ends the exchange under every policy. Only a
//! reply or error without any `PA-FX-FAST` is taken for a KDC that does not do
//! FAST (MIT `krb5int_decode_tgs_rep` takes it as success), and then only
//! under [`Opportunistic`]; [`Required`] refuses it. That
//! reply is encrypted in the request's own subkey, which only the KDC knows,
//! and a genuine armored reply is encrypted in the strengthened subkey, so
//! stripping the armor from one cannot make it acceptable.
//!
//! [`Opportunistic`]: super::Policy::Opportunistic
//! [`Required`]: super::Policy::Required

use rasn::der;
use rasn_kerberos::{KrbError, PaData, TgsReq};
use zeroize::Zeroizing;

use super::{
    KEY_USAGE_FAST_ENC, KEY_USAGE_FAST_REQ_CHKSUM, PA_FX_FAST,
    asn1::{KrbFastArmoredReq, KrbFastReq, PaFxFastRequest},
    keys::{self, encode},
    reply,
};
use crate::{
    client::PA_TGS_REQ,
    crypto::{CryptoPolicy, Use},
    error::{Crypto, Fast as Error},
    keytab::EncryptionKey,
};

/// The armor of one TGS request: the armor key, the authenticator subkey (the
/// key a KDC without FAST encrypts its reply in) and the request's nonce.
pub(crate) type Armor = (EncryptionKey, EncryptionKey, u32);

/// An armored request as a message and as sent, and the armor that
/// authenticates its reply.
pub(crate) type Wrapped = (TgsReq, Zeroizing<Vec<u8>>, Armor);

/// What the KDC's reply to an armored request is.
pub(crate) enum Reply {
    /// The KDC does not do FAST: nothing in the reply is armored.
    Unarmored,
    /// An authenticated KRB-ERROR (RFC 6113 section 5.4.4).
    Error(Zeroizing<Vec<u8>>),
    /// An authenticated TGS-REP and the key it is encrypted in.
    Success {
        /// The TGS-REP with the client the armor authenticated.
        reply: Zeroizing<Vec<u8>>,
        /// `KRB-FX-CF2(strengthen key, subkey, "strengthenkey", "replykey")`.
        key: EncryptionKey,
    },
}

/// Armor `parts.0`, whose `PA-TGS-REQ` carries the AP-REQ `parts.1`, with the
/// authenticator subkey and the TGT session key of `keys`.
///
/// The encrypted `KrbFastReq` holds the body and the padata but `PA-TGS-REQ`;
/// the request checksum covers the AP-REQ (MIT `fast.c:300-303`, the TGS case
/// of `to_be_checksummed`); the outer padata are `PA-TGS-REQ`, `PA-FX-FAST` and
/// a copy of the rest, because a KDC without FAST must still see them
/// (`make_tgs_outer_padata`, `fast.c:231-251`).
///
/// # Errors
/// Returns [`Error::Malformed`] for a request without exactly the `PA-TGS-REQ`
/// of `parts.1`, the policy refusal of the armor key and the encoding errors.
pub(crate) fn wrap(
    parts: (&TgsReq, &[u8]),
    keys: (&EncryptionKey, &EncryptionKey),
    crypto_policy: &CryptoPolicy,
) -> Result<Wrapped, Error> {
    let (original, ap_req) = parts;
    let (subkey, session) = keys;
    let key = keys::cf2((subkey, b"subkeyarmor"), (session, b"ticketarmor"))?;
    crypto_policy
        .check_use(key.etype(), Use::SessionKey)
        .map_err(Crypto::from)?;
    let TgsReq(mut outer) = original.clone();
    let (tgs_entries, rest): (Vec<PaData>, Vec<PaData>) = outer
        .padata
        .take()
        .unwrap_or_default()
        .into_iter()
        .partition(|entry| entry.r#type == PA_TGS_REQ);
    let [tgs] = <[PaData; 1]>::try_from(tgs_entries).map_err(|_not_one| Error::Malformed {
        structure: "TGS-REQ",
        reason: "the request does not carry exactly one PA-TGS-REQ",
    })?;
    if tgs.value.as_ref() != ap_req {
        return Err(Error::Malformed {
            structure: "TGS-REQ",
            reason: "the PA-TGS-REQ is not the AP-REQ the armor covers",
        });
    }
    let inner = encode(
        "KrbFastReq",
        &KrbFastReq {
            fast_options: rasn_kerberos::KerberosFlags::from_slice(&[0; 4]),
            padata: rest.clone(),
            req_body: outer.req_body.clone(),
        },
    )?;
    let armored = PaFxFastRequest::ArmoredData(KrbFastArmoredReq {
        armor: None,
        req_checksum: keys::checksum(&key, KEY_USAGE_FAST_REQ_CHKSUM, ap_req)?,
        enc_fast_req: keys::seal(&key, KEY_USAGE_FAST_ENC, &inner)?,
    });
    let fast = PaData {
        r#type: PA_FX_FAST,
        value: encode("PA-FX-FAST-REQUEST", &armored)?.to_vec().into(),
    };
    let nonce = outer.req_body.nonce;
    outer.padata = Some([tgs, fast].into_iter().chain(rest).collect());
    let armored_request = TgsReq(outer);
    let der = encode("TGS-REQ", &armored_request)?;
    Ok((armored_request, der, (key, subkey.clone(), nonce)))
}

/// Authenticate the KDC's reply `bytes` to the request `armor` armored.
///
/// `required` refuses a KDC without FAST instead of reporting it as
/// [`Reply::Unarmored`].
///
/// # Errors
/// Returns [`Error::Unarmored`] or [`Error::UnarmoredError`] for a reply
/// without `PA-FX-FAST` when `required`, and every FAST failure of an
/// armored reply, among them a missing strengthen key.
pub(crate) fn unwrap(armor: &Armor, bytes: &[u8], required: bool) -> Result<Reply, Error> {
    let (armor_key, subkey, nonce) = armor;
    if let Ok(outer) = der::decode::<KrbError>(bytes) {
        return match reply::error_reply(armor_key, *nonce, &outer) {
            Err(Error::UnarmoredError { code: _ }) if !required => Ok(Reply::Unarmored),
            Err(error) => Err(error),
            Ok(inner) => Ok(Reply::Error(inner.error)),
        };
    }
    let rasn_kerberos::TgsRep(encrypted) = keys::decode("TGS-REP", bytes)?;
    if !encrypted
        .padata
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|entry| entry.r#type == PA_FX_FAST)
    {
        return if required {
            Err(Error::Unarmored)
        } else {
            Ok(Reply::Unarmored)
        };
    }
    let (reply, strengthen_key, _client) = reply::kdc_reply(armor_key, *nonce, encrypted)?;
    let strengthen = strengthen_key.ok_or(Error::Malformed {
        structure: "KrbFastResponse",
        reason: "the TGS reply carries no strengthen key",
    })?;
    Ok(Reply::Success {
        reply: encode("TGS-REP", &rasn_kerberos::TgsRep(reply))?,
        key: keys::cf2((&strengthen, b"strengthenkey"), (subkey, b"replykey"))?,
    })
}
