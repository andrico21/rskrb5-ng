//! PAC signature and client verification (MS-PAC 2.8, MIT `pac.c` `krb5_pac_verify_ext`).
//!
//! MIT 1.22.2 `verify_pac_checksums` (`src/lib/krb5/krb/pac.c:517-580`) checks the server
//! signature over a PAC copy with the server and KDC signatures zeroed, the full checksum over a
//! copy with all three zeroed, and the KDC signature over the server signature buffer;
//! `krb5_kdc_verify_ticket` (`pac.c:600-690`) adds the ticket signature over the ticket with the
//! PAC replaced by one zero byte. All use key usage 17 (`KRB5_KEYUSAGE_APP_DATA_CKSUM`).

use zeroize::Zeroizing;

use super::{
    Error, INFO_TYPE_PAC_FULL_SIGNATURE_DATA, INFO_TYPE_PAC_KDC_SIGNATURE_DATA,
    INFO_TYPE_PAC_SERVER_SIGNATURE_DATA, INFO_TYPE_PAC_TICKET_SIGNATURE_DATA,
    PAC_SERVER_CHECKSUM_KEY_USAGE, PAC_SIGNATURE_TYPE_LEN, Pac, SignatureData,
    SignatureRequirement, Verification, Verified, VerifiedChecks, kerberos_etype_for_checksum_type,
};
use crate::{crypto::selection, keytab::EncryptionKey};

/// Name of a PAC buffer type for error messages.
pub(super) const fn buffer_name(ul_type: u32) -> &'static str {
    match ul_type {
        1 => "KerbValidationInfo",
        2 => "Credentials",
        6 => "ServerChecksum",
        7 => "KDCChecksum",
        10 => "ClientInfo",
        11 => "S4UDelegationInfo",
        12 => "UpnDnsInfo",
        13 => "ClientClaimsInfo",
        14 => "DeviceInfo",
        15 => "DeviceClaimsInfo",
        16 => "TicketChecksum",
        17 => "AttributesInfo",
        18 => "Requestor",
        19 => "FullChecksum",
        _ => "buffer of an unnamed type",
    }
}

/// Verify `signature` over `data` with `key` (key usage 17).
///
/// # Errors
///
/// Returns a policy rejection for a rejected key enctype or checksum type and
/// [`Error::UnsupportedChecksumType`] for an unknown checksum type; a key of another enctype than
/// the checksum, or a mismatch, is `Ok(false)`.
pub(super) fn verify_signature(
    key: &EncryptionKey,
    signature: &SignatureData,
    data: &[u8],
) -> Result<bool, Error> {
    selection::reject_enctype(key.etype())?;
    if let Ok(id) = i32::try_from(signature.signature_type) {
        selection::reject_checksum(id)?;
    }
    let etype = kerberos_etype_for_checksum_type(signature.signature_type)
        .ok_or(Error::UnsupportedChecksumType(signature.signature_type))?;
    if key.etype() != etype.etype_id() {
        return Ok(false);
    }
    Ok(etype.verify_checksum(
        key.value(),
        data,
        &signature.signature,
        PAC_SERVER_CHECKSUM_KEY_USAGE,
    ))
}

/// Decide whether one signature is verified now, per its requirement.
///
/// # Errors
///
/// Returns [`Error::MissingRequiredBuffer`] or [`Error::MissingVerificationKey`] when a
/// [`SignatureRequirement::Required`] signature lacks its buffer or its inputs.
const fn should_verify(
    requirement: SignatureRequirement,
    ul_type: u32,
    present: bool,
    inputs: bool,
) -> Result<bool, Error> {
    match (requirement, present, inputs) {
        (_, true, true) => Ok(true),
        (SignatureRequirement::Required, false, _) => {
            Err(Error::MissingRequiredBuffer(buffer_name(ul_type)))
        }
        (SignatureRequirement::Required, true, false) => {
            Err(Error::MissingVerificationKey(buffer_name(ul_type)))
        }
        (SignatureRequirement::IfPresent, ..) => Ok(false),
    }
}

/// One signature check: what the policy demands and what the request supplies.
struct Check<'input> {
    /// The policy's demand.
    requirement: SignatureRequirement,
    /// The buffer type of the signature.
    ul_type: u32,
    /// The parsed signature, when the PAC has it.
    signature: Option<&'input SignatureData>,
    /// The key it is verified under.
    key: Option<&'input EncryptionKey>,
    /// The bytes it covers, when the request supplies them.
    covered: Option<&'input [u8]>,
    /// The error of a mismatch.
    failure: Error,
}

impl Check<'_> {
    /// Run the check: `Ok(true)` verified, `Ok(false)` left unverified by an optional demand.
    ///
    /// # Errors
    ///
    /// Returns the demand's missing-input errors and the check's mismatch error.
    fn run(self) -> Result<bool, Error> {
        let inputs = self.key.zip(self.covered);
        let verify = should_verify(
            self.requirement,
            self.ul_type,
            self.signature.is_some(),
            inputs.is_some(),
        )?;
        let (true, Some(signature), Some((key, covered))) = (verify, self.signature, inputs) else {
            return Ok(false);
        };
        verify_signature(key, signature, covered)?
            .then_some(true)
            .ok_or(self.failure)
    }
}

/// Run every check the request asks for.
///
/// # Errors
///
/// Returns the first failing check as a typed [`Error`].
pub(super) fn run(pac: Pac, request: &Verification<'_>) -> Result<Verified, Error> {
    let policy = request.policy();
    for &ul_type in policy.required_buffers() {
        if pac.buffer(ul_type).is_none() {
            return Err(Error::MissingRequiredBuffer(buffer_name(ul_type)));
        }
    }
    let server = Check {
        requirement: policy.server(),
        ul_type: INFO_TYPE_PAC_SERVER_SIGNATURE_DATA,
        signature: pac.server_checksum(),
        key: request.server_key(),
        covered: Some(pac.zero_signature_data()),
        failure: Error::ServerChecksumVerificationFailed,
    }
    .run()?;
    let kdc = Check {
        requirement: policy.kdc_requirement(),
        ul_type: INFO_TYPE_PAC_KDC_SIGNATURE_DATA,
        signature: pac.kdc_checksum(),
        key: request.kdc_key(),
        covered: server_signature_bytes(&pac)?,
        failure: Error::KdcChecksumVerificationFailed,
    }
    .run()?;
    let (full, ticket) = if request.ticket_kind().expects_ticket_signature() {
        let full_input = full_checksum_input(&pac)?;
        let full = Check {
            requirement: policy.full(),
            ul_type: INFO_TYPE_PAC_FULL_SIGNATURE_DATA,
            signature: pac.full_checksum(),
            key: request.kdc_key(),
            covered: full_input.as_deref().map(Vec::as_slice),
            failure: Error::FullChecksumVerificationFailed,
        }
        .run()?;
        let ticket = Check {
            requirement: policy.ticket(),
            ul_type: INFO_TYPE_PAC_TICKET_SIGNATURE_DATA,
            signature: pac.ticket_checksum(),
            key: request.kdc_key(),
            covered: request.ticket_signature_input(),
            failure: Error::TicketChecksumVerificationFailed,
        }
        .run()?;
        (full, ticket)
    } else {
        (false, false)
    };
    let client = verify_client(&pac, request)?;
    let checks = VerifiedChecks::from_results([server, kdc, ticket, full, client]);
    Ok(Verified { pac, checks })
}

/// The server signature buffer after its four-byte type: what the KDC signature covers
/// (MIT `pac.c:557-570`).
///
/// # Errors
///
/// Returns the buffer-range errors of [`Pac::buffer_bytes`].
fn server_signature_bytes(pac: &Pac) -> Result<Option<&[u8]>, Error> {
    let Some(buffer) = pac.buffer(INFO_TYPE_PAC_SERVER_SIGNATURE_DATA) else {
        return Ok(None);
    };
    Ok(pac.buffer_bytes(buffer)?.get(PAC_SIGNATURE_TYPE_LEN..))
}

/// The PAC with the server, KDC and full signatures zeroed: what the full checksum covers
/// (MIT `pac.c:545-553`); `None` without a full checksum buffer.
///
/// # Errors
///
/// Returns the buffer-range errors of the signature range copy.
fn full_checksum_input(pac: &Pac) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    let (Some(buffer), Some(signature)) = (
        pac.buffer(INFO_TYPE_PAC_FULL_SIGNATURE_DATA),
        pac.full_checksum(),
    ) else {
        return Ok(None);
    };
    let mut covered = Zeroizing::new(pac.zero_signature_data().to_vec());
    buffer.copy_zeroed_signature(&mut covered, signature)?;
    Ok(Some(covered))
}

/// The client info against the ticket's client name and authentication time.
///
/// # Errors
///
/// Returns [`Error::MissingClientBinding`] when the policy binds but the request names no client,
/// [`Error::MissingRequiredBuffer`] without client info and [`Error::ClientInfoMismatch`] when the
/// name or the time differ.
fn verify_client(pac: &Pac, request: &Verification<'_>) -> Result<bool, Error> {
    if !request.policy().client_binding() {
        return Ok(false);
    }
    let binding = request.client().ok_or(Error::MissingClientBinding)?;
    let info = pac
        .client_info()
        .ok_or(Error::MissingRequiredBuffer("ClientInfo"))?;
    (info.name == binding.name() && binding.matches_ticks(info.client_id.ticks()))
        .then_some(true)
        .ok_or(Error::ClientInfoMismatch)
}
