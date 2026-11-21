//! Expired and expiring passwords of the MIT fixture, changed through its kpasswd service.

extern crate alloc;

use alloc::collections::VecDeque;
use core::{error::Error, net::Ipv4Addr, slice, time::Duration};
use std::{io, time::UNIX_EPOCH};

use rskrb5_ng::{
    client::{
        Password, Tokio,
        kpasswd::{
            last_req::ExpiryNotice,
            password_expiry::{ExpiryResponder, NewPasswordPrompt},
        },
        principal::Principal,
        transport::{KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    error::Client as ClientError,
    extensions::ProviderError,
    krb_priv::ipv4_host_address,
};
use sha2::{Digest as _, Sha256};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{
    self, Fixture, assert_negotiated_padata, assert_ticket_flag, kdc_tap::KdcTap,
};

/// The fixture KDC, reached on `INTEROP_MIT_KDC` (TCP and UDP).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The fixture's kpasswd service (kadmind), on `INTEROP_MIT_KPASSWD`.
const MIT_KPASSWD: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KPASSWD");

/// PA type of the encrypted timestamp (RFC 4120 section 5.2.7.2).
const PA_ENC_TIMESTAMP: i32 = 2;

/// RFC 4120 ticket flag bit `pre-authent`.
const FLAG_PRE_AUTHENT: u32 = 10;

/// KDC error code of failed pre-authentication (the replaced password).
const KDC_ERR_PREAUTH_FAILED: i32 = 24;

/// The banner of an expired password (MIT `gic_pwd.c:243`).
const EXPIRED_BANNER: &str = "Password expired.  You must change it now.";

/// 2037-06-15T00:00:00Z, the password expiry of `expiringpw`.
const EXPIRING_AT: u64 = 2_128_636_800;

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

/// The password of the disposable principal `name`: the host derives it from the admin
/// password as `provision.d/73-kpasswd.sh` does (32 hex digits of sha256).
fn derived(name: &str) -> Result<String, Box<dyn Error>> {
    let admin = harness::var("INTEROP_MIT_ADMIN_PASSWORD")?;
    let digest = Sha256::digest(format!("rskrb5-interop kpasswd {name} v1{admin}").as_bytes());
    Ok(hex::encode(digest).chars().take(32).collect())
}

/// The realm's KDC at `kdc` and its kpasswd service. The realm also offers SPAKE first
/// (plan 2 todo 9), which would answer before the encrypted timestamp: an empty group
/// list keeps these scenarios on the flow they prove.
fn config(kdc: &str) -> Result<Config, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n spake_preauth_groups =\n\
         [realms]\n {realm} = {{\n  kdc = {kdc}\n  kpasswd_server = {}\n }}\n",
        harness::var("INTEROP_MIT_KPASSWD")?,
    ))?)
}

/// The principal `name` of the fixture realm.
fn account(name: &str) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::user(harness::var("INTEROP_MIT_REALM")?, name))
}

/// A responder that offers scripted passwords and records the prompts and the notices.
#[derive(Default)]
struct Scripted {
    /// The passwords to offer, in order.
    answers: VecDeque<String>,
    /// The banner and tries left of every prompt.
    prompts: Vec<(String, u8)>,
    /// The expiry notices heard.
    notices: Vec<ExpiryNotice>,
}

impl Scripted {
    /// A responder offering `answers`.
    fn offering(answers: &[String]) -> Self {
        Self {
            answers: answers.iter().cloned().collect(),
            ..Self::default()
        }
    }
}

impl ExpiryResponder for Scripted {
    fn expiry_notice(&mut self, notice: &ExpiryNotice) {
        self.notices.push(*notice);
    }

    fn new_password(&mut self, prompt: &NewPasswordPrompt<'_>) -> Result<Password, ProviderError> {
        self.prompts
            .push((prompt.reason().to_string(), prompt.tries_left()));
        self.answers
            .pop_front()
            .map(|answer| Password::from_vec(answer.into_bytes()))
            .ok_or_else(|| ProviderError::from("the script has no more answers"))
    }
}

/// The old password is refused and the new one logs in with a pre-authenticated TGT.
async fn assert_replaced(
    config: &Config,
    account: &Principal,
    old: &str,
    new: &str,
) -> Result<(), Box<dyn Error>> {
    let mut stale = Tokio::with_password(
        config.clone(),
        KdcProtocol::Tcp,
        account.clone(),
        old.as_bytes().to_vec(),
    )
    .with_transport(transport());
    let error = stale
        .login()
        .await
        .err()
        .ok_or("the replaced password must not log in")?;
    assert!(
        matches!(&error, ClientError::Kdc(kdc_error) if kdc_error.error_code() == KDC_ERR_PREAUTH_FAILED),
        "expected KDC_ERR_PREAUTH_FAILED for the old password, got {error}"
    );
    let mut changed = Tokio::with_password(
        config.clone(),
        KdcProtocol::Tcp,
        account.clone(),
        new.as_bytes().to_vec(),
    )
    .with_transport(transport());
    let session = changed.login().await?;
    assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, session.ticket_flags())?;
    Ok(())
}

/// The login of a principal whose password expired yesterday gets `KDC_ERR_KEY_EXP`; the
/// flow gets a `kadmin/changepw` ticket with the old password, changes the password
/// through kpasswd, and logs in again with the new one. The old password then fails.
#[test]
fn an_expired_password_is_changed_and_the_login_starts_over() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "an_expired_password_is_changed_and_the_login_starts_over",
        &[MIT_KDC, MIT_KPASSWD],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let direct = config(&harness::var("INTEROP_MIT_KDC")?)?;
        let tap = KdcTap::start(KdcProtocol::Tcp, &harness::var("INTEROP_MIT_KDC")?).await?;
        let tapped = config(tap.endpoint())?;
        let principal = account("expiredpw")?;
        let (old, new) = (derived("expiredpw")?, derived("expiredpw-new")?);
        let mut client = Tokio::with_password(
            tapped,
            KdcProtocol::Tcp,
            principal.clone(),
            old.as_bytes().to_vec(),
        )
        .with_transport(transport());
        let mut responder = Scripted::offering(slice::from_ref(&new));

        let session = client
            .login_with_expiry(
                &mut responder,
                ipv4_host_address(Ipv4Addr::LOCALHOST.octets()),
            )
            .await?;

        assert_eq!(session.client(), &principal);
        assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, session.ticket_flags())?;
        assert_eq!(responder.prompts, [(EXPIRED_BANNER.to_owned(), 3)]);
        assert_eq!(responder.notices.len(), 1);
        // The proof of every login is the encrypted timestamp: the failed login, the
        // kadmin/changepw ticket and the login that followed the change.
        let requests = tap.as_req_padata()?;
        assert_eq!(
            requests.len(),
            6,
            "a probe and a proof for each of three AS exchanges"
        );
        for proof in [1_usize, 3, 5] {
            assert_negotiated_padata(
                "the preauthenticated AS-REQ",
                PA_ENC_TIMESTAMP,
                requests.get(proof).map_or(&[][..], Vec::as_slice),
            )?;
        }
        assert_replaced(&direct, &principal, &old, &new).await
    })
}

/// A new password the policy refuses is a soft error with the server's reason, put to the
/// responder again; the second answer is accepted.
#[test]
fn a_password_policy_rejection_is_put_to_the_responder_again() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "a_password_policy_rejection_is_put_to_the_responder_again",
        &[MIT_KDC, MIT_KPASSWD],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config(&harness::var("INTEROP_MIT_KDC")?)?;
        let principal = account("expiredpolicy")?;
        let (old, new) = (derived("expiredpolicy")?, derived("expiredpolicy-new")?);
        let mut client = Tokio::with_password(
            config.clone(),
            KdcProtocol::Tcp,
            principal.clone(),
            old.as_bytes().to_vec(),
        )
        .with_transport(transport());
        let mut responder = Scripted::offering(&["short".to_owned(), new.clone()]);

        let _session = client
            .login_with_expiry(
                &mut responder,
                ipv4_host_address(Ipv4Addr::LOCALHOST.octets()),
            )
            .await?;

        let [first, (banner, tries_left)] = responder.prompts.as_slice() else {
            return Err(format!("expected two prompts, got {}", responder.prompts.len()).into());
        };
        assert_eq!(first, &(EXPIRED_BANNER.to_owned(), 3));
        assert!(
            banner.starts_with("Password change rejected: ") && banner.contains("short"),
            "the server's policy reason reaches the responder: {banner}"
        );
        assert_eq!(*tries_left, 2);
        assert_replaced(&config, &principal, &old, &new).await
    })
}

/// A password that is about to expire logs in as usual and the KDC's expiry time reaches the
/// responder; nothing is changed.
#[test]
fn an_impending_expiry_reaches_the_responder() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "an_impending_expiry_reaches_the_responder",
        &[MIT_KDC, MIT_KPASSWD],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config(&harness::var("INTEROP_MIT_KDC")?)?;
        let principal = account("expiringpw")?;
        let mut client = Tokio::with_password(
            config,
            KdcProtocol::Tcp,
            principal.clone(),
            derived("expiringpw")?.into_bytes(),
        )
        .with_transport(transport());
        let mut responder = Scripted::default();

        let session = client
            .login_with_expiry(
                &mut responder,
                ipv4_host_address(Ipv4Addr::LOCALHOST.octets()),
            )
            .await?;

        assert_eq!(session.client(), &principal);
        assert!(responder.prompts.is_empty(), "nothing needs changing");
        let [notice] = responder.notices.as_slice() else {
            return Err(format!("expected one notice, got {}", responder.notices.len()).into());
        };
        let expires = notice
            .password()
            .ok_or("the KDC reports the password expiry")?;
        let expected = UNIX_EPOCH + Duration::from_secs(EXPIRING_AT);
        let distance = expires
            .duration_since(expected)
            .unwrap_or_else(|error| error.duration());
        assert!(
            distance <= Duration::from_hours(24),
            "the expiry {expires:?} is the day {expected:?} of the principal"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}
