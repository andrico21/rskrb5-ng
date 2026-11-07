//! Password-specific DER encoding into exact-sized, zeroizing allocations.

use zeroize::Zeroizing;

use super::{ChangePasswdData, Error, codec::encode};
use crate::krb_priv::EncKrbPrivPartOptions;

/// Wrap a DER body without reallocating after secret bytes are written.
///
/// # Errors
/// Returns an encoding error if the combined length cannot fit in memory.
fn wrap(tag: u8, body: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let length_bytes = body.len().to_be_bytes();
    let significant = length_bytes
        .iter()
        .position(|byte| *byte != 0)
        .and_then(|start| length_bytes.get(start..))
        .unwrap_or(&[]);
    let length_size = if body.len() < 128 {
        1
    } else {
        significant.len().saturating_add(1)
    };
    let capacity = body
        .len()
        .checked_add(length_size)
        .and_then(|size| size.checked_add(1))
        .ok_or_else(|| Error::Encode {
            target: "password DER",
            message: "length overflow".to_owned(),
        })?;
    let mut output = Zeroizing::new(Vec::with_capacity(capacity));
    output.push(tag);
    if body.len() < 128 {
        output.push(u8::try_from(body.len()).map_err(|source| Error::Encode {
            target: "password DER",
            message: source.to_string(),
        })?);
    } else {
        output.push(
            0x80 | u8::try_from(significant.len()).map_err(|source| Error::Encode {
                target: "password DER",
                message: source.to_string(),
            })?,
        );
        output.extend_from_slice(significant);
    }
    output.extend_from_slice(body);
    Ok(output)
}

/// Join fields before wrapping them, keeping each intermediate allocation erasable.
///
/// # Errors
/// Returns an encoding error on length overflow.
fn constructed(tag: u8, fields: &[Zeroizing<Vec<u8>>]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let capacity = fields
        .iter()
        .try_fold(0_usize, |total, field| total.checked_add(field.len()))
        .ok_or_else(|| Error::Encode {
            target: "password DER",
            message: "length overflow".to_owned(),
        })?;
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    for field in fields {
        body.extend_from_slice(field);
    }
    wrap(tag, &body)
}

/// Encode RFC 3244 change-password data without an ASN.1 password copy.
///
/// # Errors
/// Returns metadata encoding errors or a length overflow.
pub(super) fn change_data(value: &ChangePasswdData) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut fields = vec![wrap(0xa0, &wrap(0x04, value.new_passwd.as_ref())?)?];
    if let Some(name) = &value.targ_name {
        fields.push(wrap(0xa1, &encode("PrincipalName", name)?)?);
    }
    if let Some(realm) = &value.targ_realm {
        fields.push(wrap(0xa2, &encode("Realm", realm)?)?);
    }
    constructed(0x30, &fields)
}

/// Encode the application-28 password envelope without rasn `OctetString` storage.
///
/// # Errors
/// Returns metadata encoding errors or a length overflow.
pub(super) fn private_part(
    data: &[u8],
    options: EncKrbPrivPartOptions,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut fields = vec![wrap(0xa0, &wrap(0x04, data)?)?];
    if let Some(time) = options.timestamp {
        fields.push(wrap(0xa1, &encode("KerberosTime", &time)?)?);
    }
    if let Some(usec) = options.usec {
        fields.push(wrap(0xa2, &encode("Microseconds", &usec)?)?);
    }
    if let Some(sequence) = options.seq_number {
        fields.push(wrap(0xa3, &encode("UInt32", &sequence)?)?);
    }
    fields.push(wrap(
        0xa4,
        &encode("HostAddress", &options.sender_address)?,
    )?);
    if let Some(address) = options.recipient_address {
        fields.push(wrap(0xa5, &encode("HostAddress", &address)?)?);
    }
    wrap(0x7c, &constructed(0x30, &fields)?)
}

/// Non-secret DER equivalence vectors.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error as StdError;

    use chrono::DateTime;
    use rasn::der;
    use rasn_kerberos::KerberosTime;

    use super::{change_data, private_part};

    /// Secret DER reserves the exact final allocation before any body bytes are appended.
    #[test]
    fn wrap_capacity_matches_final_encoding() -> Result<(), Box<dyn StdError>> {
        for length in [0_usize, 1, 127, 128, 255, 256] {
            let body = vec![42; length];
            let wrapped = super::wrap(4, &body)?;
            assert_eq!(wrapped.capacity(), wrapped.len());
        }
        Ok(())
    }
    use crate::{
        client::Password,
        kadmin::ChangePasswdData,
        krb_priv::{self, EncKrbPrivPartOptions, ipv4_host_address},
    };

    /// Short and long-form DER lengths match the independent ASN.1 encoder.
    #[test]
    fn password_der_matches_rasn() -> Result<(), Box<dyn StdError>> {
        // Given non-secret vectors spanning DER length boundaries and optional targets.
        for length in [0_usize, 1, 127, 128, 255, 256, 1024] {
            for targeted in [false, true] {
                let bytes = vec![0x61; length];
                let value = if targeted {
                    ChangePasswdData::for_target(
                        Password::from_vec(bytes),
                        1,
                        ["testuser"],
                        "TEST.GOKRB5",
                    )?
                } else {
                    ChangePasswdData::new(Password::from_vec(bytes))
                };
                // When the dedicated writer encodes the payload.
                let actual = change_data(&value)?;
                // Then the wire representation is byte-identical to rasn.
                assert_eq!(actual.as_slice(), der::encode(&value)?.as_slice());
            }
        }
        Ok(())
    }

    /// Password envelopes retain the application tag and all optional metadata.
    #[test]
    fn private_der_matches_rasn() -> Result<(), Box<dyn StdError>> {
        // Given non-secret application data and both minimal and populated options.
        for length in [0_usize, 127, 128, 256] {
            for populated in [false, true] {
                let data = vec![0x62; length];
                let options = if populated {
                    EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 1]))
                        .with_timestamp(
                            KerberosTime(
                                DateTime::from_timestamp(1_893_553_452, 0)
                                    .ok_or("fixture time")?
                                    .fixed_offset(),
                            ),
                            999_999,
                        )
                        .with_sequence_number(u32::MAX)
                        .with_recipient_address(ipv4_host_address([127, 0, 0, 2]))
                } else {
                    EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 1]))
                };
                // When the dedicated writer builds the envelope.
                let actual = private_part(&data, options.clone())?;
                // Then rasn agrees on every encoded byte.
                let expected = der::encode(&krb_priv::build_enc_krb_priv_part(&data, options))?;
                assert_eq!(actual.as_slice(), expected.as_slice());
            }
        }
        Ok(())
    }
}
