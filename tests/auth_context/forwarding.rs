//! KRB-CRED through the context and its transports.

use rskrb5_ng::{
    ccache::{self, Credential},
    error::AuthContext as Error,
    krb_cred::{self, decode_enc_krb_cred_part},
    messages::{AuthContext, CredentialTransport, MessagePolicy, ProtectedChannel},
};
use zeroize::Zeroizing;

use super::support::{acceptor, at, initiator};
use crate::context::TestError;

/// The time of every message.
const NOW: u64 = 1_893_553_447;

/// The ticket of the gokrb5 `KRB-CRED` fixture and its principals, re-keyed with an AES256 session key.
const FIXTURE_CRED: &str = concat!(
    "7681F63081F3A003020105A103020116A281BF3081BC615C305AA003020105A110",
    "1B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866",
    "747361691B056578747261A3253023A003020100A103020105A21704156B726241",
    "534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448",
    "454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B",
    "056578747261A3253023A003020100A103020105A21704156B726241534E2E3120",
    "74657374206D657373616765A3253023A003020100A103020105A21704156B7262",
    "41534E2E312074657374206D657373616765",
);

/// The gokrb5 `EncKrbCredPart` fixture with two ticket infos.
const FIXTURE_PART: &str = concat!(
    "7D8202233082021FA08201DA308201D63081E8A0133011A003020101A10A040831",
    "32333435363738A1101B0E415448454E412E4D49542E454455A21A3018A0030201",
    "01A111300F1B066866747361691B056578747261A307030500FEDCBA98A411180F",
    "31393934303631303036303331375AA511180F3139393430363130303630333137",
    "5AA611180F31393934303631303036303331375AA711180F313939343036313030",
    "36303331375AA8101B0E415448454E412E4D49542E454455A91A3018A003020101",
    "A111300F1B066866747361691B056578747261AA20301E300DA003020102A10604",
    "0412D00023300DA003020102A106040412D000233081E8A0133011A003020101A1",
    "0A04083132333435363738A1101B0E415448454E412E4D49542E454455A21A3018",
    "A003020101A111300F1B066866747361691B056578747261A307030500FEDCBA98",
    "A411180F31393934303631303036303331375AA511180F31393934303631303036",
    "303331375AA611180F31393934303631303036303331375AA711180F3139393430",
    "3631303036303331375AA8101B0E415448454E412E4D49542E454455A91A3018A0",
    "03020101A111300F1B066866747361691B056578747261AA20301E300DA0030201",
    "02A106040412D00023300DA003020102A106040412D00023A10302012AA211180F",
    "31393934303631303036303331375AA305020301E240A40F300DA003020102A106",
    "040412D00023A50F300DA003020102A106040412D00023",
);

/// The fixture credentials with an AES256 session key and AES ticket each, which the import policy admits.
fn credentials() -> Result<Vec<Credential>, TestError> {
    let mut wrapped = krb_cred::decode(&hex::decode(FIXTURE_CRED)?)?;
    let part = decode_enc_krb_cred_part(&hex::decode(FIXTURE_PART)?)?;
    for ticket in &mut wrapped.tickets {
        ticket.enc_part.etype = 18_i32;
    }
    let raw = krb_cred::decrypted_krb_cred_to_ccache_credentials(&wrapped, &part)?;
    Ok(raw
        .into_iter()
        .map(|credential| {
            Credential::new(
                credential.client().clone(),
                credential.server().clone(),
                ccache::EncryptionKey::new(18, vec![0x44; 32]),
                credential.times(),
                credential.ticket_flags(),
                Zeroizing::new(credential.ticket().to_vec()),
            )
        })
        .collect())
}

/// Pins that forwarded credentials round-trip encrypted under the context key and report the time.
#[test]
fn credentials_round_trip_encrypted() -> Result<(), TestError> {
    let mut sender = initiator(MessagePolicy::new(), NOW)?;
    let mut receiver = acceptor(MessagePolicy::new(), NOW)?;
    let sent = credentials()?;

    let wire = sender.mk_cred(&sent, CredentialTransport::Encrypted)?;
    let delivered = receiver.rd_cred(&wire, CredentialTransport::Encrypted)?;

    assert_eq!(delivered.content.len(), sent.len());
    for (got, want) in delivered.content.iter().zip(&sent) {
        assert_eq!(got.client(), want.client());
        assert_eq!(got.server(), want.server());
        assert_eq!(got.ticket(), want.ticket());
    }
    assert_eq!(delivered.timestamp, Some(at(NOW)?));
    assert!(matches!(
        receiver.rd_cred(&wire, CredentialTransport::Encrypted),
        Err(Error::Replay)
    ));
    Ok(())
}

/// Pins that the NULL transport is refused: no key and no proven channel means no KRB-CRED either way.
#[test]
fn the_null_transport_is_refused() -> Result<(), TestError> {
    let mut keyless = AuthContext::without_key(MessagePolicy::new()).with_now(at(NOW)?);
    assert!(matches!(
        keyless.mk_cred(&credentials()?, CredentialTransport::Encrypted),
        Err(Error::NoKey)
    ));

    let channel = ProtectedChannel::vouch("a test channel that is authentic and confidential");
    let plain = keyless.mk_cred(&credentials()?, CredentialTransport::Protected(&channel))?;
    assert!(matches!(
        keyless.rd_cred(&plain, CredentialTransport::Encrypted),
        Err(Error::UnauthenticatedTransport | Error::NoKey)
    ));
    let mut keyed = acceptor(MessagePolicy::new(), NOW)?;
    assert!(matches!(
        keyed.rd_cred(&plain, CredentialTransport::Encrypted),
        Err(Error::UnauthenticatedTransport)
    ));
    Ok(())
}

/// Pins that a caller-proven protected channel carries an unencrypted KRB-CRED (RFC 6448).
#[test]
fn a_proven_channel_carries_an_unencrypted_credential() -> Result<(), TestError> {
    let channel = ProtectedChannel::vouch("TLS with channel binding");
    let mut sender = AuthContext::without_key(MessagePolicy::new().checking_time(false));
    let mut receiver = AuthContext::without_key(MessagePolicy::new().checking_time(false));
    let sent = credentials()?;

    let wire = sender.mk_cred(&sent, CredentialTransport::Protected(&channel))?;
    let delivered = receiver.rd_cred(&wire, CredentialTransport::Protected(&channel))?;

    assert_eq!(delivered.content.len(), sent.len());
    Ok(())
}

/// Pins that an imported credential whose session key the runtime policy does not permit is refused.
#[test]
fn credentials_with_forbidden_session_keys_are_refused() -> Result<(), TestError> {
    let mut sender = initiator(MessagePolicy::new(), NOW)?;
    let mut receiver = acceptor(MessagePolicy::new(), NOW)?;
    let mut wrapped = krb_cred::decode(&hex::decode(FIXTURE_CRED)?)?;
    let part = decode_enc_krb_cred_part(&hex::decode(FIXTURE_PART)?)?;
    for ticket in &mut wrapped.tickets {
        ticket.enc_part.etype = 18_i32;
    }
    let des_keyed = krb_cred::decrypted_krb_cred_to_ccache_credentials(&wrapped, &part)?;

    let wire = sender.mk_cred(&des_keyed, CredentialTransport::Encrypted)?;
    let refused = receiver.rd_cred(&wire, CredentialTransport::Encrypted);

    assert!(matches!(refused, Err(Error::Cred(_))), "{refused:?}");
    Ok(())
}
