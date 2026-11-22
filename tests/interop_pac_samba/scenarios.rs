//! The Samba PAC scenarios: a cross-trust ticket and a claims-less account.

use core::{error::Error, time::Duration};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        KDC_OPTION_CANONICALIZE, TgsRepSession, Tokio, build_ap_req_with_confounder,
        options::{ApReq, AsReq, TgsReq},
        principal::Principal,
        transport::{KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    crypto::KerberosEtype,
    keytab::Keytab,
    pac::{
        ClientBinding, IdentityAttributes, Request, TicketKind, Verification, VerificationPolicy,
        find_pac_in_authorization_data,
    },
    service::{ValidatedApReq, Validator},
    ticket,
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture};

/// The KDC of the user domain.
const SAMBA_USER: Fixture = Fixture::new("samba-user", "INTEROP_SAMBA_USER_KDC");

/// The KDC of the resource domain.
const SAMBA_RES: Fixture = Fixture::new("samba-res", "INTEROP_SAMBA_RES_KDC");

/// Enctype id of aes256-cts-hmac-sha1-96, the strongest key of every Samba account.
const AES256_SHA1: i32 = 18;

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A KDC transport with a ten-second timeout.
fn transport() -> TokioKdcTransport {
    TokioKdcTransport::new().with_timeout(Duration::from_secs(10))
}

/// Both domains with their KDCs, default realm USER.RSKRB5 and no `[domain_realm]`.
fn config() -> Result<Config, Box<dyn Error>> {
    let user_realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
    let res_realm = harness::var("INTEROP_SAMBA_RES_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {user_realm}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n[realms]\n {user_realm} = {{\n  kdc = {}\n }}\n \
         {res_realm} = {{\n  kdc = {}\n }}\n",
        harness::var("INTEROP_SAMBA_USER_KDC")?,
        harness::var("INTEROP_SAMBA_RES_KDC")?,
    ))?)
}

/// A nonce unique to `sequence` and the current time.
fn nonce(sequence: u32) -> Result<u32, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)? | sequence.wrapping_shl(24))
}

/// TGS-REQ options with a one-hour lifetime and AES256.
fn tgs_options(sequence: u32) -> Result<TgsReq, Box<dyn Error>> {
    Ok(TgsReq::new(SystemTime::now(), nonce(sequence)?)
        .with_ticket_lifetime(Duration::from_hours(1))
        .with_etypes(vec![AES256_SHA1]))
}

/// A user-domain principal named by the env-file key `key`.
fn user(key: &str) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::user(
        harness::var("INTEROP_SAMBA_USER_REALM")?,
        harness::var(key)?,
    ))
}

/// Replaces `error` by its `Display` text.
fn shown(error: Box<dyn Error>) -> Box<dyn Error> {
    let text = error.to_string();
    drop(error);
    text.into()
}

/// An AP-REQ for `ticket`, built with a fixed confounder at the current time.
fn ap_req(ticket: &TgsRepSession) -> Result<Vec<u8>, Box<dyn Error>> {
    let etype = KerberosEtype::from_etype_id(ticket.session_key().etype())
        .ok_or("ticket session key etype is supported")?;
    let confounder = vec![0x42_u8; etype.confounder_len()];
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let seconds = UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or("time overflow")?;
    let built = build_ap_req_with_confounder(
        ticket,
        ApReq::new(),
        seconds,
        elapsed.subsec_micros(),
        &confounder,
    )?;
    Ok(built.der().to_vec())
}

/// Validate `ticket` against the keytab file in the env-file key `keytab_key`.
fn accepted(ticket: &TgsRepSession, keytab_key: &str) -> Result<ValidatedApReq, Box<dyn Error>> {
    let keytab = Keytab::load(harness::var(keytab_key)?)?;
    let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
    validator
        .validate_ap_req(&ap_req(ticket)?)
        .map_err(|error| format!("the acceptor refused the Samba-issued ticket: {error}").into())
}

/// FU-IOP-P14: testuser1 (user domain) gets a ticket for `HTTP/host.res.rskrb5` across the
/// forest trust; the ticket's PAC carries a zero-length client-claims buffer (claims do not cross
/// the trust) and the resource-domain acceptor accepts it.
#[test]
fn a_ticket_across_the_trust_with_an_empty_claims_buffer_is_accepted() -> Result<(), Box<dyn Error>>
{
    if !harness::require(
        "a_ticket_across_the_trust_with_an_empty_claims_buffer_is_accepted",
        &[SAMBA_USER, SAMBA_RES],
    )? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let user_realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
            let res_realm = harness::var("INTEROP_SAMBA_RES_REALM")?;
            let profile = config()?;
            let password = harness::var("INTEROP_SAMBA_USER_USER_PASSWORD")?.into_bytes();
            let tgt = transport()
                .login_tgt_with_password_config(
                    &profile,
                    KdcProtocol::Tcp,
                    user("INTEROP_SAMBA_USER_USER")?,
                    &password,
                    AsReq::new(SystemTime::now(), nonce(1)?).with_etypes(vec![AES256_SHA1]),
                )
                .await?;
            let host = harness::var("INTEROP_SAMBA_RES_HTTP_SERVICE")?;
            let options = tgs_options(2)?;
            let bits = options.kdc_option_bits() | KDC_OPTION_CANONICALIZE;
            let result = transport()
                .get_service_ticket_with_referral_trace(
                    &profile,
                    KdcProtocol::Tcp,
                    &tgt,
                    Principal::new("", 2, host.split('/')),
                    options.with_kdc_option_bits(bits),
                )
                .await?;
            assert_eq!(
                result.ticket().service().realm,
                res_realm,
                "the ticket is the resource domain's"
            );
            let validated = accepted(result.ticket(), "INTEROP_SAMBA_RES_HTTP_KEYTAB")?;
            let pac = validated.pac().ok_or("a Samba service ticket has a PAC")?;
            assert_eq!(
                pac.ad_credentials()
                    .ok_or("the PAC has validation info")?
                    .effective_name,
                harness::var("INTEROP_SAMBA_USER_USER")?,
                "the PAC names the user-domain client"
            );
            assert_eq!(
                validated.client().realm,
                user_realm,
                "the resource service sees the user-domain client"
            );
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}

/// FU-IOP-P14: testuser3 has no claim, so Samba sends a zero-length client-claims buffer even
/// within its own domain; its service ticket for `HTTP/user2.user.rskrb5` is accepted.
#[test]
fn a_claims_less_account_ticket_is_accepted() -> Result<(), Box<dyn Error>> {
    if !harness::require("a_claims_less_account_ticket_is_accepted", &[SAMBA_USER])? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
            let mut client = Tokio::with_keytab(
                config()?,
                KdcProtocol::Tcp,
                user("INTEROP_SAMBA_USER_NOPREAUTH_USER")?,
                Keytab::load(harness::var("INTEROP_SAMBA_USER_NOPREAUTH_USER_KEYTAB")?)?,
            )
            .with_transport(transport());
            let name = harness::var("INTEROP_SAMBA_USER_HTTP_SERVICE")?;
            let ticket = client
                .get_service_ticket(Principal::new(realm.as_str(), 2, name.split('/')))
                .await?;
            let keytab = Keytab::load(harness::var("INTEROP_SAMBA_USER_HTTP_ACCOUNT_KEYTAB")?)?;
            let account = harness::var("INTEROP_SAMBA_USER_HTTP_ACCOUNT")?;
            let mut validator = Validator::new(&keytab)
                .with_now(SystemTime::now())
                .with_keytab_principal([account.as_str()]);
            let validated = validator
                .validate_ap_req(&ap_req(&ticket)?)
                .map_err(|error| {
                    format!("the acceptor refused the Samba-issued ticket: {error}")
                })?;
            let pac = validated.pac().ok_or("a Samba service ticket has a PAC")?;
            assert_eq!(
                pac.ad_credentials()
                    .ok_or("the PAC has validation info")?
                    .effective_name,
                harness::var("INTEROP_SAMBA_USER_NOPREAUTH_USER")?,
                "the PAC names the claims-less account"
            );
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}

/// testuser1 (a user with a claim) gets a service ticket for `HTTP/user2.user.rskrb5`, validated
/// with the account keytab and the krbtgt key of the domain under `policy`.
fn own_domain_pac(policy: VerificationPolicy) -> Result<ValidatedApReq, Box<dyn Error>> {
    runtime()?.block_on(async {
        let realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
        let mut client = Tokio::with_keytab(
            config()?,
            KdcProtocol::Tcp,
            user("INTEROP_SAMBA_USER_USER")?,
            Keytab::load(harness::var("INTEROP_SAMBA_USER_USER_KEYTAB")?)?,
        )
        .with_transport(transport());
        let name = harness::var("INTEROP_SAMBA_USER_HTTP_SERVICE")?;
        let granted = client
            .get_service_ticket(Principal::new(realm.as_str(), 2, name.split('/')))
            .await?;
        let krbtgt = Keytab::load(harness::var("INTEROP_SAMBA_USER_KRBTGT_KEYTAB")?)?;
        let (kdc_key, _kvno) = krbtgt.find_key(&["krbtgt"], &realm, 0, AES256_SHA1)?;
        let keytab = Keytab::load(harness::var("INTEROP_SAMBA_USER_HTTP_ACCOUNT_KEYTAB")?)?;
        let account = harness::var("INTEROP_SAMBA_USER_HTTP_ACCOUNT")?;
        Validator::new(&keytab)
            .with_now(SystemTime::now())
            .with_keytab_principal([account.as_str()])
            .with_pac_kdc_key(kdc_key.clone())
            .with_pac_policy(policy)
            .validate_ap_req(&ap_req(&granted)?)
            .map_err(|error| {
                format!("the acceptor refused the Samba-issued ticket: {error}").into()
            })
    })
}

/// MIT-pac-2, MIT-pac-3: with the domain's krbtgt key the acceptor verifies the KDC signature, the
/// ticket signature and the KB5020805 full checksum of the PAC Samba 4.22 issues, besides the
/// server signature and the client info.
#[test]
fn the_kdc_ticket_and_full_signatures_of_a_samba_pac_verify() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "the_kdc_ticket_and_full_signatures_of_a_samba_pac_verify",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    let validated = own_domain_pac(VerificationPolicy::kdc())?;
    let checks = validated
        .pac()
        .ok_or("a Samba service ticket has a PAC")?
        .checks();
    assert!(
        checks.server() && checks.kdc() && checks.ticket() && checks.full() && checks.client(),
        "every check passed: {checks:?}"
    );
    Ok(())
}

/// The claim Samba puts into testuser1's PAC and the AD identity read through the verified PAC as
/// identity attributes.
#[test]
fn the_claims_and_identity_of_a_domain_user_read_through_the_verified_pac()
-> Result<(), Box<dyn Error>> {
    if !harness::require(
        "the_claims_and_identity_of_a_domain_user_read_through_the_verified_pac",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    let validated = own_domain_pac(VerificationPolicy::kdc())?;
    let attributes = IdentityAttributes::from_verified(
        validated.pac().ok_or("a Samba service ticket has a PAC")?,
    );
    let user = harness::var("INTEROP_SAMBA_USER_USER")?;
    assert_eq!(
        attributes.get("ad:effective-name"),
        Some([user.clone()].as_slice())
    );
    assert_eq!(attributes.get("pac:client-name"), Some([user].as_slice()));
    let claim_type = harness::var("INTEROP_SAMBA_USER_CLAIM_TYPE")?;
    let claim_value = harness::var("INTEROP_SAMBA_USER_CLAIM_VALUE")?;
    let claim = attributes
        .names()
        .find(|name| name.starts_with("claim:") && name.contains(claim_type.as_str()))
        .ok_or("the identity attributes include the Department claim")?;
    assert_eq!(attributes.get(claim), Some([claim_value].as_slice()));
    assert!(
        attributes.get("upn:name").is_some(),
        "the UPN/DNS info is read"
    );
    Ok(())
}

/// MIT-pac-5, MIT-pac-6: Samba 4.22.11 puts `PAC_ATTRIBUTES_INFO` and `PAC_REQUESTOR` into the PAC
/// of a TGT and reports the client's `PA-PAC-REQUEST`: `include` sets `PAC_WAS_REQUESTED`, no
/// request sets `PAC_WAS_GIVEN_IMPLICITLY` and `exclude` sets neither (Samba still issues the PAC);
/// the requestor is the client's own SID. The TGT's PAC verifies under the krbtgt key.
#[test]
fn the_pac_attributes_of_a_tgt_report_the_pac_request_and_the_requestor()
-> Result<(), Box<dyn Error>> {
    if !harness::require(
        "the_pac_attributes_of_a_tgt_report_the_pac_request_and_the_requestor",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
            let krbtgt = Keytab::load(harness::var("INTEROP_SAMBA_USER_KRBTGT_KEYTAB")?)?;
            let (kdc_key, _kvno) = krbtgt.find_key(&["krbtgt"], &realm, 0, AES256_SHA1)?;
            let cases = [
                (vec![Request::include().padata()?], 1_u32, "include"),
                (vec![], 2, "no request"),
                (vec![Request::exclude().padata()?], 0, "exclude"),
            ];
            for (padata, flags, label) in cases {
                let session = transport()
                    .login_tgt_with_password_config(
                        &config()?,
                        KdcProtocol::Tcp,
                        user("INTEROP_SAMBA_USER_USER")?,
                        harness::var("INTEROP_SAMBA_USER_USER_PASSWORD")?.as_bytes(),
                        AsReq::new(SystemTime::now(), nonce(1)?)
                            .with_etypes(vec![AES256_SHA1])
                            .with_padata(padata),
                    )
                    .await?;
                let wire = ticket::decode(session.ticket().as_slice())?;
                let part = ticket::decrypt_ticket_enc_part(&wire, kdc_key)?;
                let pac = find_pac_in_authorization_data(
                    part.authorization_data
                        .as_ref()
                        .ok_or("the TGT has authorization data")?,
                )?
                .ok_or("the TGT carries a PAC")?;
                let client = ClientBinding::new(
                    harness::var("INTEROP_SAMBA_USER_USER")?,
                    session.auth_time(),
                );
                let request = Verification::new(VerificationPolicy::kdc())
                    .with_server_key(kdc_key)
                    .with_kdc_key(kdc_key)
                    .with_ticket_kind(TicketKind::of_server(&["krbtgt", realm.as_str()]))
                    .with_client(client);
                let verified = pac.verify_ext(&request)?;
                assert!(
                    verified.checks().server()
                        && verified.checks().kdc()
                        && verified.checks().client()
                );
                let attributes = verified
                    .attributes_info()
                    .ok_or("the TGT PAC has attributes")?;
                assert_eq!(
                    attributes.flags(),
                    flags,
                    "PAC_ATTRIBUTES_INFO flags for {label}"
                );
                let credentials = verified.ad_credentials().ok_or("validation info")?;
                let domain = credentials.logon_domain_id.ok_or("the logon domain SID")?;
                assert_eq!(
                    verified
                        .requestor_sid()
                        .ok_or("the requestor")?
                        .sid()
                        .to_string(),
                    format!("{domain}-{}", credentials.user_id),
                    "the requestor is the client's own SID"
                );
            }
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}
