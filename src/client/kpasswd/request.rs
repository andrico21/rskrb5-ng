//! Request authenticator construction and KRB-PRIV options.

use std::time::UNIX_EPOCH;

use rasn::types::Integer;

use super::RequestOptions;
use crate::{
    client::{
        ApReq, BuiltApReq, Error, TgsRepSession, build_ap_req_with_confounder,
        kerberos_time_from_system_time,
    },
    keytab::EncryptionKey,
    krb_priv::EncKrbPrivPartOptions,
    messages,
};

/// Build the kpasswd AP-REQ that carries `reply_key` as its subkey and the
/// request sequence number.
///
/// # Errors
///
/// Returns an error when the AP-REQ authenticator cannot be built, encrypted
/// or encoded from the service ticket and options.
pub(super) fn build_kpasswd_ap_req_with_confounder(
    service_ticket: &TgsRepSession,
    reply_key: &EncryptionKey,
    options: &RequestOptions,
    ap_req_confounder: &[u8],
) -> Result<BuiltApReq, Error> {
    let _micros = messages::microseconds("request.cusec", &Integer::from(options.cusec)).map_err(
        |source| Error::Encode {
            target: "kpasswd request time",
            message: source.to_string(),
        },
    )?;
    if options.timestamp.duration_since(UNIX_EPOCH).map_or_else(
        |error| error.duration().subsec_nanos() != 0,
        |duration| duration.subsec_nanos() != 0,
    ) {
        return Err(Error::Encode {
            target: "kpasswd request time",
            message: "timestamp must contain whole seconds".to_owned(),
        });
    }
    let mut ap_options = ApReq::new()
        .with_subkey(Some(reply_key.clone()))
        .with_sequence_number(Some(options.sequence_number));
    ap_options.crypto_policy.clone_from(&options.crypto_policy);
    build_ap_req_with_confounder(
        service_ticket,
        ap_options,
        options.timestamp,
        options.cusec,
        ap_req_confounder,
    )
}

/// Translate kpasswd request options into KRB-PRIV encrypted-part options.
///
/// # Errors
///
/// Returns an error when the request timestamp is outside the Kerberos time
/// range.
pub(super) fn kpasswd_krb_priv_options(
    options: &RequestOptions,
) -> Result<EncKrbPrivPartOptions, Error> {
    let mut krb_priv_options = EncKrbPrivPartOptions::new(options.sender_address.clone())
        .with_timestamp(
            kerberos_time_from_system_time(options.timestamp)?,
            options.cusec,
        )
        .with_sequence_number(options.sequence_number);
    if let Some(recipient_address) = &options.recipient_address {
        krb_priv_options = krb_priv_options.with_recipient_address(recipient_address.clone());
    }
    Ok(krb_priv_options)
}

/// Request-side time validation regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error as StdError, time::Duration};
    use std::time::UNIX_EPOCH;

    use super::RequestOptions;
    use crate::{
        client::{
            Password, TgsRepSession, kpasswd::build_kpasswd_request_with_confounders,
            principal::Principal,
        },
        error::Client,
        kadmin::{ChangePasswdData, Request},
        keytab::EncryptionKey,
        krb_priv::ipv4_host_address,
        ticket,
    };

    /// Exercise the synchronous builder before any transport can receive a frame.
    fn build_at(nanos: u64, cusec: u32, before_epoch: bool) -> Result<(), Box<dyn StdError>> {
        let fixture = Request::parse(&hex::decode(
            include_str!("../../../tests/fixtures/kpasswd-request.hex").trim(),
        )?)?;
        let time = if before_epoch {
            UNIX_EPOCH.checked_sub(Duration::from_secs(1))
        } else {
            UNIX_EPOCH.checked_add(Duration::from_secs(1_893_553_452))
        }
        .ok_or("fixture time overflow")?;
        let session = TgsRepSession::new(
            Principal::user("TEST.GOKRB5", "testuser1"),
            Principal::new("TEST.GOKRB5", 2, ["kadmin", "changepw"]),
            EncryptionKey::new(18, vec![0x11; 32]),
            ticket::encode(&fixture.ap_req.ticket)?.into(),
            [0; 4],
            time,
            time,
        );
        let options = RequestOptions::new(
            time.checked_add(Duration::from_nanos(nanos))
                .ok_or("fixture fractional time overflow")?,
            cusec,
            42,
            ipv4_host_address([127, 0, 0, 1]),
        );
        // When the request is built synchronously, no send is possible.
        let result = build_kpasswd_request_with_confounders(
            &session,
            &ChangePasswdData::new(Password::copy_from_str("dummy-password")),
            EncryptionKey::new(18, vec![0x22; 32]),
            &options,
            &[0x33; 16],
            &[0x44; 16],
        );
        // Then invalid inputs are local encoding errors, never reply-control errors.
        if nanos == 0 && cusec < 1_000_000 {
            drop(result?);
        } else {
            assert!(matches!(
                result,
                Err(Client::Encode {
                    target: "kpasswd request time",
                    message: _
                })
            ));
        }
        Ok(())
    }

    /// Legacy password requests require and preserve explicit caller permission.
    #[test]
    fn legacy_request_preserves_explicit_policy() -> Result<(), Box<dyn StdError>> {
        use crate::{
            config::Config,
            crypto::{CryptoPolicy, KerberosEtype},
        };
        let fixture = Request::parse(&hex::decode(
            include_str!("../../../tests/fixtures/kpasswd-request.hex").trim(),
        )?)?;
        for id in [16_i32, 23_i32] {
            let etype = KerberosEtype::from_etype_id(id).ok_or("enctype")?;
            let time = UNIX_EPOCH
                .checked_add(Duration::from_secs(1_893_553_452))
                .ok_or("time")?;
            let session = TgsRepSession::new(
                Principal::user("TEST.GOKRB5", "testuser1"),
                Principal::new("TEST.GOKRB5", 2, ["kadmin", "changepw"]),
                EncryptionKey::new(id, vec![0x11; etype.key_len()]),
                ticket::encode(&fixture.ap_req.ticket)?.into(),
                [0; 4],
                time,
                time,
            );
            let data = ChangePasswdData::new(Password::copy_from_str("legacy-fixture"));
            for permitted in [false, true] {
                let mut options =
                    RequestOptions::new(time, 0, 42, ipv4_host_address([127, 0, 0, 1]));
                if permitted {
                    let config = Config::parse(
                        "[libdefaults]\nallow_rc4 = true\nallow_des3 = true\npermitted_enctypes = DEFAULT rc4 des3",
                    )?;
                    options.crypto_policy =
                        Some(CryptoPolicy::from_libdefaults(&config.libdefaults)?);
                }
                let result = build_kpasswd_request_with_confounders(
                    &session,
                    &data,
                    EncryptionKey::new(id, vec![0x22; etype.key_len()]),
                    &options,
                    &vec![0x33; etype.confounder_len()],
                    &vec![0x44; etype.confounder_len()],
                );
                assert_eq!(result.is_ok(), permitted);
                if permitted {
                    assert_eq!(result?.request.krb_priv.enc_part.etype, id);
                }
            }
        }
        Ok(())
    }

    /// Fractional caller timestamps are rejected before request construction.
    #[test]
    fn fractional_request_time_is_local() -> Result<(), Box<dyn StdError>> {
        // Given a fractional timestamp and valid microseconds. 100 ns is the
        // smallest fraction every platform's `SystemTime` keeps: Windows
        // counts in 100 ns ticks and drops a 1 ns addition.
        build_at(100, 0, false)
    }

    /// The first invalid microsecond value is a request-side error.
    #[test]
    fn excessive_request_microseconds_are_local() -> Result<(), Box<dyn StdError>> {
        // Given whole seconds and an out-of-range microsecond field.
        build_at(0, 1_000_000, false)
    }

    /// The maximum valid microsecond value still builds a complete request.
    #[test]
    fn maximum_request_microseconds_build() -> Result<(), Box<dyn StdError>> {
        // Given the valid upper microsecond boundary.
        build_at(0, 999_999, false)
    }

    /// Whole-second pre-epoch request timestamps retain the same acceptance contract.
    #[test]
    fn whole_pre_epoch_request_builds() -> Result<(), Box<dyn StdError>> {
        build_at(0, 0, true)
    }
}
