// The bytes a PAC ticket signature covers, included into `pac` (feature `messages`).
//
// MIT `krb5_kdc_verify_ticket` (`src/lib/krb5/krb/pac.c:640-668`) re-encodes the ticket with the
// PAC contents replaced by a single zero byte and verifies the ticket signature over that DER.
// `krb5_kdc_sign_ticket` (`pac_sign.c:315-395`) produces the same input when it signs.

/// The one byte a PAC element holds while the ticket signature is computed.
const TICKET_SIGNATURE_PLACEHOLDER: u8 = 0;

/// The DER of `ticket` with its PAC replaced by one zero byte: the bytes the ticket signature of
/// its PAC covers (MS-PAC 2.8.3, MIT `pac.c:640-668`).
///
/// The PAC is the first one [`find_pac_in_authorization_data`] finds, replaced where it sits (in
/// its `AD-IF-RELEVANT` wrapper), so the signature binds the PAC to the ticket that carries it.
///
/// # Security
///
/// The encoding holds the ticket's session key and is erased when dropped; the decoded ticket's own
/// ASN.1 copies are not erased by this function.
///
/// # Errors
///
/// Returns [`Error::RequiredPacAbsent`] when the ticket carries no PAC, the traversal limits of
/// [`find_pac_in_authorization_data`], [`Error::DerDecode`] for malformed nested authorization data
/// and [`Error::DerEncode`] when the ticket cannot be encoded.
#[inline]
pub fn ticket_signature_input(
    ticket: &rasn_kerberos::EncTicketPart,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let data = ticket
        .authorization_data
        .as_ref()
        .ok_or(Error::RequiredPacAbsent)?;
    let replaced = replace_first_pac(data, 0, &mut 0x0010_0000)?.ok_or(Error::RequiredPacAbsent)?;
    let mut copy = ticket.clone();
    copy.authorization_data = Some(replaced);
    der_encode(&copy)
        .map(Zeroizing::new)
        .map_err(|source| Error::DerEncode(source.to_string()))
}

/// `data` with the first PAC element's contents replaced, or `None` when it holds no PAC.
///
/// Walks the entries exactly as [`find_pac_in_authorization_data`] does (the same wrappers, depth
/// and byte budget) and re-encodes every wrapper above the PAC.
///
/// # Errors
///
/// Returns the traversal limits, [`Error::DerDecode`] and [`Error::DerEncode`].
fn replace_first_pac(
    data: &rasn_kerberos::AuthorizationData,
    depth: usize,
    remaining: &mut usize,
) -> Result<Option<rasn_kerberos::AuthorizationData>, Error> {
    let mut out = data.clone();
    for entry in &mut out {
        *remaining = remaining
            .checked_sub(entry.data.len())
            .ok_or(Error::AuthorizationDataByteLimit)?;
        match entry.r#type {
            AD_WIN2K_PAC => {
                entry.data = vec![TICKET_SIGNATURE_PLACEHOLDER].into();
                return Ok(Some(out));
            }
            AD_IF_RELEVANT | 8_i32 => {
                (depth < 8).ok_or(Error::AuthorizationDataDepthLimit)?;
                let nested =
                    decode_complete::<rasn_kerberos::AuthorizationData>(entry.data.as_ref())
                        .map_err(Error::DerDecode)?;
                if let Some(replaced) =
                    replace_first_pac(&nested, depth.saturating_add(1), remaining)?
                {
                    entry.data = der_encode(&replaced)
                        .map_err(|source| Error::DerEncode(source.to_string()))?
                        .into();
                    return Ok(Some(out));
                }
            }
            _ => {}
        }
    }
    Ok(None)
}
