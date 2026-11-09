//! RFC 4178 integrity for a complete optimistic Kerberos exchange.

use super::{
    ApRepOptions, EncryptionKey, Error, GSS_TOKEN_FLAG_ACCEPTOR_SUBKEY, GSS_TOKEN_FLAG_SEALED,
    GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR, GSSAPI_ACCEPTOR_SIGN_USAGE, GSSAPI_INITIATOR_SIGN_USAGE,
    Krb5MechToken, Krb5TokenId, MicToken, NegTokenInit, ObjectIdentifier, ValidatedApReq,
    der::{DerReader, TAG_APPLICATION_0, TAG_CONTEXT_0, TAG_SEQUENCE, read_single_tlv},
    encryption_key_from_rasn, ensure_kerberos_mechanism,
};
use crate::crypto::Use;

/// Select only an offered Kerberos OID and require integrity for non-first selection.
///
/// # Errors
/// Returns token decode errors, or a named missing mechanism, AP-REQ or MIC error.
pub(super) fn optimistic_token(init: &NegTokenInit) -> Result<Krb5MechToken, Error> {
    ensure_kerberos_mechanism(&init.mech_types)?;
    let token = Krb5MechToken::decode(init.mech_token.as_deref().ok_or(Error::MissingMechToken)?)?;
    if token.token_id != Krb5TokenId::ApReq {
        return Err(Error::MissingApReq);
    }
    // RFC 4178 Appendix C: both OIDs identify the same Kerberos mechanism.
    if !init
        .mech_types
        .first()
        .is_some_and(ObjectIdentifier::is_kerberos_mechanism)
        && init.mech_list_mic.is_none()
    {
        return Err(Error::MissingMechListMic);
    }
    Ok(token)
}

/// Retain the received `MechTypeList` TLV, not a canonicalized or explicitly tagged copy.
///
/// # Errors
/// Returns DER errors or rejects absent or duplicate mechanism-list fields.
pub(super) fn received_mech_types(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let choice = if bytes.first() == Some(&TAG_APPLICATION_0) {
        let wrapper = read_single_tlv(bytes, TAG_APPLICATION_0)?;
        let mut reader = DerReader::new(wrapper.value());
        let _oid = reader.read_tlv()?;
        reader.remaining()
    } else {
        bytes
    };
    let init = read_single_tlv(choice, TAG_CONTEXT_0)?;
    let sequence = read_single_tlv(init.value(), TAG_SEQUENCE)?;
    let mut fields = DerReader::new(sequence.value());
    let mut list = None;
    while !fields.remaining().is_empty() {
        let field = fields.read_tlv()?;
        if field.tag() == TAG_CONTEXT_0 {
            if list.is_some() {
                return Err(Error::InvalidMechListMic);
            }
            list = Some(field.value().to_vec());
        }
    }
    list.ok_or(Error::MissingMechTypes)
}

/// Verify direction, sequence and checksum before the validator commits replay state.
///
/// # Errors
/// Returns `InvalidMechListMic` for malformed or context-inconsistent MICs.
pub(super) fn verify_mic(
    bytes: &[u8],
    list: &[u8],
    authenticator: &rasn_kerberos::Authenticator,
    session_key: &EncryptionKey,
) -> Result<(), Error> {
    let mic = MicToken::decode(bytes, false).map_err(|_source| Error::InvalidMechListMic)?;
    // No acceptor subkey exists before this one-shot AP-REP. Unknown flags are ignored.
    if mic.flags & (GSS_TOKEN_FLAG_ACCEPTOR_SUBKEY | GSS_TOKEN_FLAG_SEALED) != 0
        || Some(mic.snd_seq_num) != authenticator.seq_number.map(u64::from)
    {
        return Err(Error::InvalidMechListMic);
    }
    let subkey = authenticator.subkey.as_ref().map(encryption_key_from_rasn);
    mic.with_payload(list)
        .verify(
            subkey.as_ref().unwrap_or(session_key),
            GSSAPI_INITIATOR_SIGN_USAGE,
        )
        .map_err(|_source| Error::InvalidMechListMic)?;
    Ok(())
}

/// AP-REP options for a reply carrying a reciprocal MIC.
///
/// Without a configured sequence number the MIC uses the authenticator's, so the
/// AP-REP carries that number: MIT initiators read the acceptor sequence number
/// from the AP-REP (0 when absent), and both sides must agree on it.
pub(super) fn response_options(ap_req: &ValidatedApReq, options: &ApRepOptions) -> ApRepOptions {
    let sequence = options
        .sequence_number()
        .or_else(|| ap_req.sequence_number())
        .unwrap_or(0);
    options.clone().with_sequence_number(Some(sequence))
}

/// Sign with the acceptor subkey, initiator subkey, or ticket key, in that order.
///
/// # Errors
/// Returns checksum construction or encoding errors for the selected context key.
pub(super) fn response_mic(
    list: &[u8],
    ap_req: &ValidatedApReq,
    options: &ApRepOptions,
) -> Result<Vec<u8>, Error> {
    let key = options
        .subkey()
        .or_else(|| ap_req.subkey())
        .unwrap_or_else(|| ap_req.session_key());
    let usage = if options.subkey().is_some() || ap_req.subkey().is_some() {
        Use::AcceptorSubkey
    } else {
        Use::SessionKey
    };
    ap_req.crypto_policy().check_use(key.etype(), usage)?;
    let flags = GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR
        | if options.subkey().is_some() {
            GSS_TOKEN_FLAG_ACCEPTOR_SUBKEY
        } else {
            0
        };
    let sequence = options
        .sequence_number()
        .or_else(|| ap_req.sequence_number())
        .unwrap_or(0);
    let mut mic = MicToken::new(flags, u64::from(sequence)).with_payload(list);
    mic.set_checksum(key, GSSAPI_ACCEPTOR_SIGN_USAGE)?;
    mic.encode()
}
