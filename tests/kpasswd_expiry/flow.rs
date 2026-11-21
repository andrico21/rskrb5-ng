//! The expired-password flow of `Tokio::login_with_expiry` (MIT `gic_pwd.c:171-343`):
//! `KDC_ERR_KEY_EXPIRED` for a password login, a `kadmin/changepw` ticket under the old
//! password, a new password from the responder, the change, and the AS restart with the
//! new password only after an authenticated success.

use core::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
extern crate alloc;

use alloc::{collections::VecDeque, sync::Arc};
use std::time::SystemTime;

use rskrb5_ng::{
    client::{
        Password, Tokio,
        kpasswd::{
            last_req::ExpiryNotice,
            password_expiry::{ExpiryResponder, NewPasswordPrompt},
        },
    },
    error::{Client as Error, Kadmin},
    extensions::ProviderError,
    kadmin::result_text::ResultCode,
    krb_priv::ipv4_host_address,
};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};

use super::{
    KdcProtocol, TestError,
    realm::{AsSeen, ExpiryFields, Realm},
    runtime,
    server::{self, Behavior},
    support::held,
};

/// The account's password before the change.
const OLD: &[u8] = b"old-password-value";
/// A password the responder offers.
const NEW: &str = "new-password-value";

/// A responder that answers from a script and remembers what it was asked.
#[derive(Default)]
struct Script {
    /// The passwords to offer, in order.
    answers: VecDeque<&'static str>,
    /// The banner and tries left of every prompt.
    prompts: Vec<(String, u8)>,
    /// Every expiry notice heard.
    notices: Vec<ExpiryNotice>,
}

impl Script {
    /// A script offering `answers`.
    fn of(answers: &[&'static str]) -> Self {
        Self {
            answers: answers.iter().copied().collect(),
            ..Self::default()
        }
    }
}

impl ExpiryResponder for Script {
    fn expiry_notice(&mut self, notice: &ExpiryNotice) {
        self.notices.push(*notice);
    }

    fn new_password(&mut self, prompt: &NewPasswordPrompt<'_>) -> Result<Password, ProviderError> {
        self.prompts
            .push((prompt.reason().to_string(), prompt.tries_left()));
        self.answers
            .pop_front()
            .map(Password::copy_from_str)
            .ok_or_else(|| ProviderError::from("the script has no more answers"))
    }
}

/// A client against a fake realm.
struct Fixture {
    /// The realm: the account's state and the AS requests seen.
    realm: Arc<Realm>,
    /// The kpasswd requests received.
    kpasswd: Arc<AtomicUsize>,
    /// The client under test.
    client: Tokio,
}

/// Start a realm whose account has the old password, expired or not, and a kpasswd
/// server following `script`.
async fn fixture(expired: bool, script: Vec<Behavior>) -> Result<Fixture, TestError> {
    let realm = Arc::new(Realm::new(OLD, expired));
    let kdc = TcpListener::bind("127.0.0.1:0").await?;
    let kpasswd = TcpListener::bind("127.0.0.1:0").await?;
    let config = server::config(
        Some(&kdc.local_addr()?.to_string()),
        &kpasswd.local_addr()?.to_string(),
    )?;
    server::spawn_kdc(kdc, Arc::clone(&realm));
    let received = server::spawn_kpasswd(kpasswd, Arc::clone(&realm), script);
    let client = Tokio::with_password(config, KdcProtocol::Tcp, Realm::account(), OLD.to_vec());
    Ok(Fixture {
        realm,
        kpasswd: received,
        client,
    })
}

/// The AS requests as `(service, preauthenticated)` pairs.
fn as_requests(realm: &Realm) -> Vec<(String, bool)> {
    realm
        .requests()
        .into_iter()
        .map(
            |AsSeen {
                 service,
                 preauthenticated,
             }| (service, preauthenticated),
        )
        .collect()
}

/// The sequence of one password login for `service`: the probe, then the proof.
fn login_for(service: &str) -> [(String, bool); 2] {
    [(service.to_owned(), false), (service.to_owned(), true)]
}

/// The sender address of every request.
fn sender() -> rasn_kerberos::HostAddress {
    ipv4_host_address([127, 0, 0, 1])
}

/// An expired password is changed through the responder, and the login then succeeds with it.
#[test]
fn an_expired_password_is_changed_and_the_login_restarts_with_the_new_one() -> Result<(), TestError>
{
    runtime()?.block_on(async {
        let mut fixture = fixture(true, vec![Behavior::Succeed]).await?;
        let mut responder = Script::of(&[NEW]);

        let session = fixture
            .client
            .login_with_expiry(&mut responder, sender())
            .await?;
        assert_eq!(session.client(), &Realm::account());

        // The old password logs in for kadmin/changepw only; the new one gets the TGT.
        let tgt = "krbtgt/TEST.GOKRB5";
        let changepw = "kadmin/changepw";
        let mut expected = Vec::new();
        expected.extend(login_for(tgt));
        expected.extend(login_for(changepw));
        expected.extend(login_for(tgt));
        assert_eq!(as_requests(&fixture.realm), expected);
        assert_eq!(fixture.kpasswd.load(Ordering::SeqCst), 1);
        assert_eq!(*held(&fixture.realm.password), NEW.as_bytes());
        assert_eq!(
            responder.prompts,
            [("Password expired.  You must change it now.".to_owned(), 3)]
        );
        assert_eq!(responder.notices.len(), 1);

        // The client keeps the new password for its next login: the realm checks the proof
        // against the account's current password.
        let _session = fixture.client.login().await?;
        let requests = as_requests(&fixture.realm);
        assert_eq!(requests.get(6..), Some(login_for(tgt).as_slice()));
        Ok(())
    })
}

/// The expiry the KDC reports at a login that needs no change reaches the responder.
#[test]
fn a_login_that_needs_no_change_reports_the_expiry_and_asks_for_nothing() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let mut fixture = fixture(false, vec![]).await?;
        let soon = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        *held(&fixture.realm.expiry) = ExpiryFields {
            last_req_password: Some(soon),
            ..ExpiryFields::default()
        };
        let mut responder = Script::default();

        let _session = fixture
            .client
            .login_with_expiry(&mut responder, sender())
            .await?;

        assert_eq!(responder.prompts, []);
        assert_eq!(fixture.kpasswd.load(Ordering::SeqCst), 0);
        let [notice] = responder.notices.as_slice() else {
            return Err("one notice".into());
        };
        assert_eq!(notice.password(), Some(soon));
        assert!(notice.is_last_req());
        Ok(())
    })
}

/// A soft error is retried with the server's reason, three tries in all (MIT `gic_pwd.c:248`).
#[test]
fn a_soft_error_is_retried_with_the_servers_reason() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let mut fixture =
            fixture(true, vec![Behavior::Soft(b"Too short"), Behavior::Succeed]).await?;
        let mut responder = Script::of(&["short", NEW]);

        let _session = fixture
            .client
            .login_with_expiry(&mut responder, sender())
            .await?;

        assert_eq!(fixture.kpasswd.load(Ordering::SeqCst), 2);
        assert_eq!(
            responder.prompts,
            [
                ("Password expired.  You must change it now.".to_owned(), 3),
                (
                    "Password change rejected: Too short.  Please try again.".to_owned(),
                    2
                ),
            ]
        );
        Ok(())
    })
}

/// After three soft errors the change fails with the last rejection and the AS is not restarted.
#[test]
fn three_soft_errors_end_the_flow_without_a_restart() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let mut fixture = fixture(
            true,
            vec![
                Behavior::Soft(b"No"),
                Behavior::Soft(b"No"),
                Behavior::Soft(b"No"),
            ],
        )
        .await?;
        let mut responder = Script::of(&["a", "b", "c", "d"]);

        let result = fixture
            .client
            .login_with_expiry(&mut responder, sender())
            .await;

        let Err(Error::Kadmin(Kadmin::PasswordChangeFailed {
            code,
            text: _,
            text_raw: _,
        })) = result
        else {
            return Err(format!("expected the last rejection, got {result:?}").into());
        };
        assert_eq!(ResultCode::from(code), ResultCode::SoftError);
        assert_eq!(responder.prompts.len(), 3);
        assert_eq!(fixture.kpasswd.load(Ordering::SeqCst), 3);
        // Every AS request was for the failed login or for kadmin/changepw: none is a restart.
        let restarts = as_requests(&fixture.realm)
            .iter()
            .filter(|(service, _)| service == "krbtgt/TEST.GOKRB5")
            .count();
        assert_eq!(
            restarts, 2,
            "only the probe and the proof of the first login"
        );
        Ok(())
    })
}

/// An empty new password is asked for again, and never sent.
#[test]
fn an_empty_new_password_is_asked_for_again_and_not_sent() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let mut fixture = fixture(true, vec![Behavior::Succeed]).await?;
        let mut responder = Script::of(&["", NEW]);

        let _session = fixture
            .client
            .login_with_expiry(&mut responder, sender())
            .await?;

        assert_eq!(fixture.kpasswd.load(Ordering::SeqCst), 1);
        assert_eq!(
            responder.prompts,
            [
                ("Password expired.  You must change it now.".to_owned(), 3),
                (
                    "New password cannot be zero length.  Please try again.".to_owned(),
                    2
                ),
            ]
        );
        Ok(())
    })
}

/// A responder that refuses ends the flow with its error and changes nothing.
#[test]
fn a_responder_that_refuses_ends_the_flow() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let mut fixture = fixture(true, vec![]).await?;
        let mut responder = Script::default();

        let result = fixture
            .client
            .login_with_expiry(&mut responder, sender())
            .await;

        assert!(matches!(result, Err(Error::Responder(_))), "{result:?}");
        assert_eq!(fixture.kpasswd.load(Ordering::SeqCst), 0);
        Ok(())
    })
}

/// QA failure scenario: a change the client cannot authenticate does not restart the AS.
#[test]
fn an_unauthenticated_change_success_does_not_restart_the_as() -> Result<(), TestError> {
    runtime()?.block_on(async {
        for behavior in [Behavior::UnsignedSuccess, Behavior::ForgedSuccess] {
            let mut fixture = fixture(true, vec![behavior]).await?;
            let mut responder = Script::of(&[NEW]);

            let result = fixture
                .client
                .login_with_expiry(&mut responder, sender())
                .await;

            // The outcome is unknown, never a success that restarts the exchange.
            assert!(
                matches!(&result, Err(Error::KpasswdOutcomeUnknown(_))),
                "{result:?}"
            );
            assert_eq!(fixture.kpasswd.load(Ordering::SeqCst), 1);
            let last = as_requests(&fixture.realm)
                .last()
                .map(|(service, _)| service.clone());
            assert_eq!(
                last.as_deref(),
                Some("kadmin/changepw"),
                "no krbtgt request after the unauthenticated success"
            );
            assert!(fixture.client.has_unresolved_password_change());
        }
        Ok(())
    })
}

/// A lost reply is an unknown outcome: no second request, no restart, and nothing is replayed.
#[test]
fn a_lost_reply_is_never_replayed_by_the_flow_or_by_the_next_call() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let mut fixture = fixture(true, vec![Behavior::Lose]).await?;
        let mut responder = Script::of(&[NEW, NEW]);

        let result = fixture
            .client
            .login_with_expiry(&mut responder, sender())
            .await;

        assert!(
            matches!(&result, Err(Error::KpasswdOutcomeUnknown(_))),
            "{result:?}"
        );
        assert_eq!(fixture.kpasswd.load(Ordering::SeqCst), 1);
        assert!(fixture.client.has_unresolved_password_change());
        let requests_before = as_requests(&fixture.realm).len();

        // The next attempt does not prompt and does not touch the network.
        let again = fixture
            .client
            .login_with_expiry(&mut responder, sender())
            .await;
        assert!(
            matches!(again, Err(Error::PasswordChangePending)),
            "{again:?}"
        );
        assert_eq!(responder.prompts.len(), 1);
        assert_eq!(fixture.kpasswd.load(Ordering::SeqCst), 1);
        assert_eq!(as_requests(&fixture.realm).len(), requests_before);

        // Verified by the caller, the marker is cleared and a change may be made again.
        fixture.client.acknowledge_password_change_outcome();
        assert!(!fixture.client.has_unresolved_password_change());
        Ok(())
    })
}

/// Dropping the flow while its request is out leaves the outcome unknown, and nothing is replayed.
#[test]
fn a_cancelled_flow_leaves_the_outcome_unknown() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let (signal, request_arrived) = oneshot::channel();
        let mut fixture = fixture(true, vec![Behavior::Hold(signal)]).await?;
        let mut responder = Script::of(&[NEW]);

        {
            let flow = fixture.client.login_with_expiry(&mut responder, sender());
            // Cancel the flow the moment the server has the request.
            tokio::select! {
                result = flow => return Err(format!("the flow ended first: {result:?}").into()),
                waited = timeout(Duration::from_secs(10), request_arrived) => {
                    waited??;
                }
            }
        }

        assert_eq!(fixture.kpasswd.load(Ordering::SeqCst), 1);
        assert!(fixture.client.has_unresolved_password_change());
        let again = fixture
            .client
            .login_with_expiry(&mut responder, sender())
            .await;
        assert!(
            matches!(again, Err(Error::PasswordChangePending)),
            "{again:?}"
        );
        assert_eq!(fixture.kpasswd.load(Ordering::SeqCst), 1);
        Ok(())
    })
}
