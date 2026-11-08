//! Client tests: AS and TGS exchanges, login with pre-authentication, password
//! change and session caches, run against synthetic KDC replies.
#![cfg(feature = "messages")]

#[cfg(feature = "tokio")]
extern crate alloc;

use core::{error, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "tokio")]
use rskrb5_ng::ccache;
#[cfg(feature = "tokio")]
use rskrb5_ng::client::{
    PrunedSessions, Tokio, transport::KdcProtocol, transport::Tokio as TokioKdcTransport,
};
#[cfg(all(feature = "tokio", feature = "spnego"))]
use rskrb5_ng::client::{
    negotiate::BlockingClient as BlockingNegotiateClient, negotiate::Client as NegotiateClient,
};
use rskrb5_ng::{
    client::{
        AP_REP_ENCPART_USAGE, AP_REQ_AUTHENTICATOR_USAGE, AS_REP_ENCPART_USAGE,
        AS_REQ_CHECKSUM_USAGE, AS_REQ_PA_ENC_TIMESTAMP_USAGE, BuiltAsReq, BuiltTgsReq,
        KDC_ERR_PREAUTH_REQUIRED, KDC_OPTION_CANONICALIZE, KDC_OPTION_CNAME_IN_ADDL_TKT,
        KDC_OPTION_RENEW, KDC_OPTION_RENEWABLE, KdcError, KdcTransport, PA_ENC_TIMESTAMP,
        PA_ETYPE_INFO2, PA_FOR_USER, PA_FOR_USER_CHECKSUM_USAGE, PA_FX_FAST, PA_PAC_OPTIONS,
        PA_REQ_ENC_PA_REP, PA_TGS_REQ, PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION, Password,
        PreauthKeyInfo, TGS_REP_ENCPART_SESSION_KEY_USAGE, TGS_REQ_AUTHENTICATOR_CHECKSUM_USAGE,
        TGS_REQ_AUTHENTICATOR_USAGE, TICKET_FLAG_ENC_PA_REP, build_ap_req_with_confounder,
        build_preauthenticated_as_req, build_s4u2proxy_req_with_confounder,
        build_s4u2self_req_with_confounder, build_tgs_req_for_realm_with_confounder,
        build_tgs_req_for_realm_with_confounder_and_subkey, build_tgs_req_with_confounder,
        build_tgt_as_req, build_tgt_renewal_req_with_confounder,
        build_ticket_renewal_req_with_confounder, default_password_salt, derive_password_reply_key,
        exchange_as_req, exchange_tgs_req,
        kpasswd::{
            RequestOptions, build_kpasswd_request, build_kpasswd_request_with_confounders,
            verify_kpasswd_ap_rep,
        },
        login_as_service_with_keytab, login_as_service_with_password, login_tgt_with_keytab,
        login_tgt_with_password,
        options::{ApReq, AsReq, TgsReq},
        pa_enc_timestamp_with_confounder, pa_for_user_padata, pa_pac_options_padata,
        principal::Principal,
        process_as_rep, process_kdc_error, process_tgs_rep, process_tgs_rep_with_referral,
        renew_tgt, renew_ticket, s4u_byte_array, s4u2proxy, s4u2self, select_preauth_key_info,
    },
    config::Config,
    crypto::{AesSha1Etype, KerberosEtype, kerb_checksum_hmac_md5},
    error::Client as Error,
    kadmin::{ChangePasswdData, Reply as KpasswdReply, Request as KpasswdRequest},
    keytab::{EncryptionKey, Entry as KeytabEntry, Keytab, Principal as KeytabPrincipal},
    krb_priv::{KRB_PRIV_ENCPART_USAGE, ipv4_host_address},
    messages::PaReqEncPaRep,
};
#[cfg(feature = "tokio")]
use rskrb5_ng::{
    kadmin::{KPASSWD_SUCCESS, build_krb_priv_with_confounder},
    krb_priv::EncKrbPrivPartOptions,
};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
#[cfg(feature = "tokio")]
use tokio::net::TcpListener;

#[cfg(feature = "tokio")]
#[path = "support/env.rs"]
mod env;

/// The error a fallible test returns; returning it fails the test.
type TestError = Box<dyn error::Error + Send + Sync>;

const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";
const SESSION_KEY: &str = "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
const SERVICE_SESSION_KEY: &str =
    "7b4115955ac25c69929af6b55c47a81db574cbbf615647e385ea38a58e2a7e9a";
const PREAUTH_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";
const AS_REP_CONFOUNDER: &str = "101112131415161718191a1b1c1d1e1f";
const TGS_REQ_CONFOUNDER: &str = "202122232425262728292a2b2c2d2e2f";
const TGS_REP_CONFOUNDER: &str = "303132333435363738393a3b3c3d3e3f";
const TICKET_FLAGS: &[u8; 4] = &[0x40, 0x81, 0x00, 0x10];
const TESTUSER_PASSWORD: &[u8] = b"passwordvalue";
const TESTUSER_SALT: &str = "TEST.GOKRB5testuser1";

#[path = "client/as_exchange.rs"]
mod as_exchange;
#[path = "client/login_preauth.rs"]
mod login_preauth;
#[path = "client/password_change.rs"]
mod password_change;
#[path = "client/preauth_errors.rs"]
mod preauth_errors;
#[path = "client/reply_fixture.rs"]
mod reply_fixture;
#[path = "client/review.rs"]
mod review;
#[cfg(feature = "tokio")]
#[path = "client/review_cache.rs"]
mod review_cache;
#[cfg(feature = "tokio")]
#[path = "client/review_cache_identity.rs"]
mod review_cache_identity;
#[cfg(feature = "tokio")]
#[path = "client/review_cache_replacement.rs"]
mod review_cache_replacement;
#[cfg(feature = "tokio")]
#[path = "client/review_cache_update.rs"]
mod review_cache_update;
#[path = "client/review_canonical.rs"]
mod review_canonical;
#[path = "client/review_checksums.rs"]
mod review_checksums;
#[path = "client/review_cookie.rs"]
mod review_cookie;
#[cfg(feature = "tokio")]
#[path = "client/review_cross_realm_renewal.rs"]
mod review_cross_realm_renewal;
#[cfg(feature = "tokio")]
#[path = "client/review_debug_audit.rs"]
mod review_debug_audit;
#[cfg(feature = "tokio")]
#[path = "client/review_diagnostics.rs"]
mod review_diagnostics;
#[path = "client/review_discovery.rs"]
mod review_discovery;
#[path = "client/review_integrity.rs"]
mod review_integrity;
#[path = "client/review_keytab_selection.rs"]
mod review_keytab_selection;
#[path = "client/review_optimistic.rs"]
mod review_optimistic;
#[cfg(feature = "tokio")]
#[path = "client/review_password_rotation.rs"]
mod review_password_rotation;
#[cfg(feature = "tokio")]
#[path = "client/review_refresh.rs"]
mod review_refresh;
#[cfg(feature = "tokio")]
#[path = "client/review_renewal_eligibility.rs"]
mod review_renewal_eligibility;
#[path = "client/review_reply_constraints.rs"]
mod review_reply_constraints;
#[path = "client/review_s4u.rs"]
mod review_s4u;
#[path = "client/review_salt.rs"]
mod review_salt;
#[cfg(all(feature = "tokio", feature = "serde"))]
#[path = "client/review_session_json.rs"]
mod review_session_json;
#[path = "client/review_time.rs"]
mod review_time;
#[cfg(feature = "tokio")]
#[path = "client/review_unsigned_rejection.rs"]
mod review_unsigned_rejection;
#[cfg(feature = "tokio")]
#[path = "client/review_validity.rs"]
mod review_validity;
#[path = "client/session_cache.rs"]
#[cfg(feature = "tokio")]
mod session_cache;
#[path = "client/subkey_reply.rs"]
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod subkey_reply;
#[path = "client/tgs_exchange.rs"]
mod tgs_exchange;

use harness::*;

/// Shared fixtures of the client tests: mock KDC transports, synthetic KDC
/// replies, sample sessions and requests, configurations and file names.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod harness {
    use core::{
        fmt::{Display, Write as _},
        str,
    };
    #[cfg(feature = "tokio")]
    use std::{env::temp_dir, path::PathBuf, process};

    use chrono::{DateTime, FixedOffset, Utc};
    use rasn::{der, types::Integer};
    #[cfg(feature = "tokio")]
    use rskrb5_ng::ap_rep::encode_build_ap_rep_with_confounder;
    use rskrb5_ng::{
        client::{AsRepSession, TgsRepSession, kpasswd::BuiltKpasswdRequest},
        messages::PaForUser,
        ticket::build_ticket_with_confounder,
    };
    #[cfg(feature = "tokio")]
    use tokio::{
        net::TcpStream,
        runtime::{Builder as RuntimeBuilder, Runtime},
    };

    use super::*;

    /// Turns a missing value or a failed step into a [`TestError`] that says
    /// what the test expected.
    pub(crate) trait Context<T> {
        /// Returns the value, or a [`TestError`] naming `what` was expected.
        fn context(self, what: &str) -> Result<T, TestError>;
    }

    impl<T> Context<T> for Option<T> {
        fn context(self, what: &str) -> Result<T, TestError> {
            self.ok_or_else(|| what.into())
        }
    }

    impl<T, E: Display> Context<T> for Result<T, E> {
        fn context(self, what: &str) -> Result<T, TestError> {
            self.map_err(|cause| format!("{what}: {cause}").into())
        }
    }

    /// Reports a failed mock KDC step to the client under test.
    fn transport_failure(cause: &TestError) -> Error {
        Error::Transport(format!("mock KDC failed: {cause}"))
    }

    /// Returns `count` plus one transport call.
    fn next_call(count: usize) -> Result<usize, TestError> {
        count
            .checked_add(1)
            .context("transport call count fits usize")
    }

    /// The `FILE:` name a parent test passed to this child run in `key`, and its file path.
    ///
    /// Fails if `key` does not hold a `FILE:` name, which means the test did not run
    /// as the child of `env::run_in_child`.
    #[cfg(feature = "tokio")]
    pub(crate) fn file_name_from_parent(key: &str) -> (String, String) {
        use std::env::var;

        let name = var(key).unwrap_or_default();
        assert!(
            name.starts_with("FILE:"),
            "the parent test sets {key} to a FILE: name, not {name:?}"
        );
        let file = name.trim_start_matches("FILE:").to_owned();
        (name, file)
    }

    /// A KDC that expects one exact request for one realm and answers `response`.
    pub(crate) struct MockTransport {
        /// The realm the client must address.
        pub expected_realm: String,
        /// The exact request bytes the client must send.
        pub expected_request: Vec<u8>,
        /// The reply bytes.
        pub response: Vec<u8>,
        /// Whether the client called the transport.
        pub called: bool,
    }

    impl KdcTransport for MockTransport {
        fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            assert_eq!(realm, self.expected_realm);
            assert_eq!(request, self.expected_request.as_slice());
            self.called = true;
            Ok(self.response.clone())
        }
    }

    /// A KDC that checks an `S4U2Self` TGS-REQ and answers it.
    pub(crate) struct S4uTransport {
        /// The TGS session key the reply is encrypted under.
        pub session_key: EncryptionKey,
        /// The service that asks for a ticket to itself.
        pub expected_service: Principal,
        /// The user the service impersonates.
        pub expected_user: Principal,
        /// The number of transport calls.
        pub calls: usize,
    }

    impl S4uTransport {
        /// Checks the `S4U2Self` `request` and builds the TGS-REP.
        fn reply(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, TestError> {
            assert_eq!(realm, "TEST.GOKRB5");
            let decoded: rasn_kerberos::TgsReq = der::decode(request).context("TGS-REQ decodes")?;
            let body = &decoded.0.req_body;
            assert_eq!(
                principal_from_parts(&body.realm, body.cname.as_ref().context("cname")?)?,
                self.expected_service
            );
            assert_eq!(
                principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
                self.expected_service
            );

            let padata = decoded.0.padata.as_ref().context("S4U TGS-REQ padata")?;
            assert_eq!(padata.len(), 2);
            let [tgs_req, for_user] = padata.as_slice() else {
                return Err("S4U TGS-REQ carries two padata".into());
            };
            assert_eq!(tgs_req.r#type, PA_TGS_REQ);
            assert_eq!(for_user.r#type, PA_FOR_USER);
            let pa_for_user =
                PaForUser::decode_der(for_user.value.as_ref()).context("PA-FOR-USER decodes")?;
            assert_eq!(
                principal_from_parts(&pa_for_user.user_realm, &pa_for_user.user_name)?,
                self.expected_user
            );

            self.calls = next_call(self.calls)?;
            let mut built = built_tgs_request_from_der(decoded, request)?;
            built.client = self.expected_user.clone();
            synthetic_tgs_rep(&built, built.nonce, &self.session_key.clone())
        }
    }

    impl KdcTransport for S4uTransport {
        fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.reply(realm, request)
                .map_err(|cause| transport_failure(&cause))
        }
    }

    /// A KDC that checks an `S4U2Proxy` TGS-REQ and answers it.
    pub(crate) struct S4u2ProxyTransport {
        /// The TGS session key the reply is encrypted under.
        pub session_key: EncryptionKey,
        /// The front-end service that holds the evidence ticket.
        pub expected_frontend_service: Principal,
        /// The back-end service the front end asks a ticket for.
        pub expected_target_service: Principal,
        /// The client the reply names.
        pub expected_client: Principal,
        /// The number of transport calls.
        pub calls: usize,
    }

    impl S4u2ProxyTransport {
        /// Checks the `S4U2Proxy` `request` and builds the TGS-REP.
        fn reply(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, TestError> {
            assert_eq!(realm, "TEST.GOKRB5");
            let decoded: rasn_kerberos::TgsReq = der::decode(request).context("TGS-REQ decodes")?;
            let body = &decoded.0.req_body;
            assert_eq!(
                body.kdc_options.0.as_raw_slice(),
                KDC_OPTION_CNAME_IN_ADDL_TKT.to_be_bytes().as_slice()
            );
            assert_eq!(
                principal_from_parts(&body.realm, body.cname.as_ref().context("cname")?)?,
                self.expected_frontend_service
            );
            assert_eq!(
                principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
                self.expected_target_service
            );

            let padata = decoded
                .0
                .padata
                .as_ref()
                .context("`S4U2Proxy` TGS-REQ padata")?;
            assert_eq!(padata.len(), 1);
            let [tgs_req] = padata.as_slice() else {
                return Err("`S4U2Proxy` TGS-REQ carries one padata".into());
            };
            assert_eq!(tgs_req.r#type, PA_TGS_REQ);
            let additional_tickets = body
                .additional_tickets
                .as_ref()
                .context("S4U2Proxy evidence ticket")?;
            assert_eq!(additional_tickets.len(), 1);
            let [evidence] = additional_tickets.as_slice() else {
                return Err("`S4U2Proxy` TGS-REQ carries one evidence ticket".into());
            };
            assert_eq!(
                principal_from_parts(&evidence.realm, &evidence.sname)?,
                self.expected_frontend_service
            );

            self.calls = next_call(self.calls)?;
            let mut built = built_tgs_request_from_der(decoded, request)?;
            built.client = self.expected_client.clone();
            synthetic_tgs_rep(&built, built.nonce, &self.session_key.clone())
        }
    }

    impl KdcTransport for S4u2ProxyTransport {
        fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.reply(realm, request)
                .map_err(|cause| transport_failure(&cause))
        }
    }

    /// A KDC that checks a renewal TGS-REQ and answers it.
    pub(crate) struct RenewalTransport {
        /// The TGS session key the reply is encrypted under.
        pub session_key: EncryptionKey,
        /// The service whose ticket is renewed.
        pub expected_service: Principal,
        /// The number of transport calls.
        pub calls: usize,
    }

    impl RenewalTransport {
        /// Checks the renewal `request` and builds the TGS-REP.
        fn reply(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, TestError> {
            assert_eq!(realm, "TEST.GOKRB5");
            let decoded: rasn_kerberos::TgsReq = der::decode(request).context("TGS-REQ decodes")?;
            let body = &decoded.0.req_body;
            assert_eq!(
                body.kdc_options.0.as_raw_slice(),
                (KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW)
                    .to_be_bytes()
                    .as_slice()
            );
            assert_eq!(
                principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
                self.expected_service
            );

            self.calls = next_call(self.calls)?;
            let built = built_tgs_request_from_der(decoded, request)?;
            synthetic_tgs_rep(&built, built.nonce, &self.session_key.clone())
        }
    }

    impl KdcTransport for RenewalTransport {
        fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.reply(realm, request)
                .map_err(|cause| transport_failure(&cause))
        }
    }

    /// A KDC that first demands pre-authentication, then checks the
    /// pre-authenticated AS-REQ and answers it.
    pub(crate) struct PreauthTransport {
        /// The reply key the AS-REP is encrypted under.
        pub reply_key: EncryptionKey,
        /// The key version the PA-ENC-TIMESTAMP must name.
        pub expected_pa_kvno: Option<u32>,
        /// Whether the AS-REQ must carry the FAST negotiation marker.
        pub expect_fast_negotiation: bool,
        /// The number of transport calls.
        pub calls: usize,
    }

    impl PreauthTransport {
        /// A transport that expects the FAST negotiation marker.
        pub(crate) const fn new(reply_key: EncryptionKey, expected_pa_kvno: Option<u32>) -> Self {
            Self {
                reply_key,
                expected_pa_kvno,
                expect_fast_negotiation: true,
                calls: 0,
            }
        }

        /// Sets whether the AS-REQ must carry the FAST negotiation marker.
        pub(crate) const fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self {
            self.expect_fast_negotiation = fast_negotiation;
            self
        }

        /// Checks the `request` of this call and builds its reply.
        fn reply(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, TestError> {
            assert_eq!(realm, "TEST.GOKRB5");
            let decoded: rasn_kerberos::AsReq = der::decode(request).context("AS-REQ decodes")?;
            self.calls = next_call(self.calls)?;
            match self.calls {
                1 => {
                    assert_fast_negotiation_marker(&decoded, self.expect_fast_negotiation)?;
                    synthetic_preauth_required_error()
                }
                2 => {
                    assert_fast_negotiation_marker(&decoded, self.expect_fast_negotiation)?;
                    assert_pa_enc_timestamp(&decoded, self.expected_pa_kvno)?;
                    let built = built_request_from_der(decoded, request)?;
                    synthetic_as_rep_with_reply_key(
                        &built,
                        built.nonce,
                        &built.service,
                        &self.reply_key,
                    )
                }
                _ => Err(format!("unexpected transport call {}", self.calls).into()),
            }
        }
    }

    impl KdcTransport for PreauthTransport {
        fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.reply(realm, request)
                .map_err(|cause| transport_failure(&cause))
        }
    }

    /// A KDC that answers a pre-authenticated AS-REQ sent without a prior
    /// `PREAUTH_REQUIRED` round trip.
    pub(crate) struct AssumedPreauthTransport {
        /// The reply key the AS-REP is encrypted under.
        pub reply_key: EncryptionKey,
        /// The key version the PA-ENC-TIMESTAMP must name.
        pub expected_pa_kvno: Option<u32>,
        /// The number of transport calls.
        pub calls: usize,
    }

    impl AssumedPreauthTransport {
        /// A transport for one pre-authenticated AS-REQ.
        pub(crate) const fn new(reply_key: EncryptionKey, expected_pa_kvno: Option<u32>) -> Self {
            Self {
                reply_key,
                expected_pa_kvno,
                calls: 0,
            }
        }

        /// Checks the pre-authenticated `request` and builds the AS-REP.
        fn reply(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, TestError> {
            assert_eq!(realm, "TEST.GOKRB5");
            let decoded: rasn_kerberos::AsReq = der::decode(request).context("AS-REQ decodes")?;
            self.calls = next_call(self.calls)?;
            assert_eq!(self.calls, 1, "assumed preauth should only call KDC once");

            let padata = decoded
                .0
                .padata
                .as_ref()
                .context("assumed preauth request has padata")?;
            assert!(
                padata.iter().any(|entry| entry.r#type == PA_REQ_ENC_PA_REP),
                "assumed preauth keeps PA-REQ-ENC-PA-REP"
            );
            assert_pa_enc_timestamp(&decoded, self.expected_pa_kvno)?;

            let built = built_request_from_der(decoded, request)?;
            synthetic_as_rep_with_reply_key(&built, built.nonce, &built.service, &self.reply_key)
        }
    }

    impl KdcTransport for AssumedPreauthTransport {
        fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.reply(realm, request)
                .map_err(|cause| transport_failure(&cause))
        }
    }

    /// The sample AS-REQ of `testuser1`.
    pub(crate) fn sample_request() -> Result<BuiltAsReq, TestError> {
        build_tgt_as_req(
            Principal::user("TEST.GOKRB5", "testuser1"),
            AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344)
                .with_kdc_option_bits(0x4000_0000)
                .with_renew_lifetime(Some(Duration::from_hours(168))),
        )
        .context("sample request builds")
    }

    /// The sample AS-REQ of `testuser1` with a PA-REQ-ENC-PA-REP marker.
    pub(crate) fn sample_request_with_pa_req_enc_pa_rep() -> Result<BuiltAsReq, TestError> {
        build_tgt_as_req(
            Principal::user("TEST.GOKRB5", "testuser1"),
            AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344).with_padata(vec![
                rasn_kerberos::PaData {
                    r#type: PA_REQ_ENC_PA_REP,
                    value: Vec::new().into(),
                },
            ]),
        )
        .context("sample request builds")
    }

    /// The TGT session of the sample AS exchange.
    pub(crate) fn sample_tgt_session() -> Result<AsRepSession, TestError> {
        let request = sample_request()?;
        let response = synthetic_as_rep(&request, request.nonce)?;
        process_as_rep(&request, &response, &reply_key()?).context("sample TGT validates")
    }

    /// The sample TGT session turned into a referral TGT for `realm`.
    #[cfg(feature = "tokio")]
    pub(crate) fn sample_referral_tgt_session(realm: &str) -> Result<AsRepSession, TestError> {
        let mut tgt = sample_tgt_session()?;
        tgt.service = Principal::new("TEST.GOKRB5", 2, ["krbtgt".to_owned(), realm.to_owned()]);
        tgt.session_key.value = vec![0x9a; 32].into();
        tgt.ticket = marked_ticket(format!("referral-ticket-{realm}").as_bytes())?.into();
        align_ticket_service(&mut tgt)?;
        Ok(tgt)
    }

    /// Keep synthetic ticket envelopes consistent when a test changes service metadata.
    #[cfg(feature = "tokio")]
    pub(crate) fn align_ticket_service(session: &mut AsRepSession) -> Result<(), TestError> {
        use rskrb5_ng::ticket;
        let mut wire = ticket::decode(&session.ticket)?;
        wire.realm = kerberos_string(&session.service.realm)?;
        wire.sname = rasn_kerberos::PrincipalName {
            r#type: session.service.name_type,
            string: session
                .service
                .components
                .iter()
                .map(|value| kerberos_string(value))
                .collect::<Result<_, _>>()?,
        };
        session.ticket = ticket::encode(&wire)?.into();
        Ok(())
    }

    /// Encode cache-test marker bytes inside a real Ticket encrypted-data field.
    #[cfg(feature = "tokio")]
    pub(crate) fn marked_ticket(marker: &[u8]) -> Result<Vec<u8>, TestError> {
        use rskrb5_ng::ticket;
        let session = sample_tgt_session()?;
        let mut ticket = ticket::decode(&session.ticket)?;
        ticket.enc_part.cipher = marker.to_vec().into();
        Ok(ticket::encode(&ticket)?)
    }

    /// A referral TGT for `realm` obtained through a validated TGS exchange with `tgt`.
    #[cfg(feature = "tokio")]
    pub(crate) fn valid_referral_tgt_session(
        tgt: &AsRepSession,
        realm: &str,
    ) -> Result<AsRepSession, TestError> {
        let referral_service = Principal::new(tgt.service.realm.clone(), 2, ["krbtgt", realm]);
        let request = build_tgs_req_with_confounder(
            tgt,
            referral_service.clone(),
            TgsReq::new(timestamp(1_893_553_450)?, 0x8877_6655).with_etypes(vec![18_i32]),
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("referral TGS-REQ builds")?;
        let response = synthetic_tgs_rep_with_service(
            &request,
            request.nonce,
            &tgt.session_key,
            &referral_service,
        )?;
        process_tgs_rep_with_referral(&request, &response, &tgt.session_key)
            .context("referral TGT validates")
    }

    /// The sample TGT, authenticated `auth_age_minutes` ago and valid for
    /// `remaining_minutes` more (already expired when zero).
    #[cfg(feature = "tokio")]
    pub(crate) fn current_tgt_session(
        auth_age_minutes: u64,
        remaining_minutes: u64,
    ) -> Result<AsRepSession, TestError> {
        let now = SystemTime::now();
        let mut tgt = sample_tgt_session()?;
        tgt.auth_time = now
            .checked_sub(Duration::from_mins(auth_age_minutes))
            .context("auth time")?;
        tgt.start_time = tgt.auth_time;
        tgt.end_time = if remaining_minutes == 0 {
            now.checked_sub(Duration::from_mins(1))
                .context("expired end time")?
        } else {
            now.checked_add(Duration::from_mins(remaining_minutes))
                .context("end time")?
        };
        tgt.renew_till = Some(
            now.checked_add(Duration::from_hours(24))
                .context("renew time")?,
        );
        tgt.key_expiration = Some(tgt.end_time);
        Ok(tgt)
    }

    /// The sample TGS-REQ for the sample service, sent with `tgt`.
    pub(crate) fn sample_tgs_request(tgt: &AsRepSession) -> Result<BuiltTgsReq, TestError> {
        build_tgs_req_with_confounder(
            tgt,
            sample_service_principal(),
            TgsReq::new(timestamp(1_893_553_450)?, 0x5566_7788)
                .with_etypes(vec![18_i32])
                .with_kdc_option_bits(0x4000_0000)
                .with_renew_lifetime(Some(Duration::from_hours(168))),
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("sample TGS-REQ builds")
    }

    /// The sample kpasswd request that sets `testuser1`'s password.
    pub(crate) fn sample_built_kpasswd_request() -> Result<BuiltKpasswdRequest, TestError> {
        let tgt = sample_tgt_session()?;
        let request = sample_tgs_request(&tgt)?;
        let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key)?;
        let service_ticket =
            process_tgs_rep(&request, &response, &tgt.session_key).context("TGS-REP validates")?;
        let reply_key = EncryptionKey::new(18, vec![0x55; 32]);
        let change_data = ChangePasswdData::for_target(
            Password::copy_from_str("newpassword"),
            1,
            ["testuser1"],
            "TEST.GOKRB5",
        )
        .context("ChangePasswdData builds")?;

        build_kpasswd_request_with_confounders(
            &service_ticket,
            &change_data,
            reply_key,
            &RequestOptions::new(
                timestamp(1_893_553_452)?,
                456_789,
                42,
                ipv4_host_address([127, 0, 0, 1]),
            ),
            &decode_hex(TGS_REQ_CONFOUNDER)?,
            &decode_hex(PREAUTH_CONFOUNDER)?,
        )
        .context("kpasswd request builds")
    }

    /// The AP-REP a kpasswd server returns for `built`, with microseconds `cusec`.
    pub(crate) fn kpasswd_ap_rep(
        built: &BuiltKpasswdRequest,
        cusec: u32,
    ) -> Result<Vec<u8>, TestError> {
        let enc_part = rasn_kerberos::EncApRepPart {
            ctime: kerberos_time(1_893_553_452)?,
            cusec: Integer::from(cusec),
            subkey: None,
            seq_number: Some(99),
        };
        let plaintext = der::encode(&enc_part).context("EncApRepPart encodes")?;
        let cipher = AesSha1Etype::Aes256
            .encrypt_message_with_confounder(
                &built.ap_req.session_key.value,
                &plaintext,
                AP_REP_ENCPART_USAGE,
                &decode_hex(AS_REP_CONFOUNDER)?,
            )
            .context("AP-REP encrypts")?;
        let ap_rep = rasn_kerberos::ApRep {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(15_i32),
            enc_part: rasn_kerberos::EncryptedData {
                etype: built.ap_req.session_key.etype,
                kvno: None,
                cipher: cipher.into(),
            },
        };
        der::encode(&ap_rep).context("AP-REP encodes")
    }

    /// A kpasswd reply frame that carries `ap_rep` and the KRB-PRIV of `built`.
    pub(crate) fn kpasswd_reply_with_ap_rep(
        built: &BuiltKpasswdRequest,
        ap_rep: &[u8],
    ) -> Result<Vec<u8>, TestError> {
        let mut body = ap_rep.to_vec();
        body.extend_from_slice(&der::encode(&built.request.krb_priv).context("KRB-PRIV encodes")?);
        kpasswd_reply_frame(
            u16::try_from(ap_rep.len()).context("AP-REP length fits u16")?,
            &body,
        )
    }

    /// A kpasswd reply with result `code` and `text`, whose AP-REP (under
    /// `ap_rep_key`) carries the subkey `response_key` that encrypts the KRB-PRIV.
    #[cfg(feature = "tokio")]
    pub(crate) fn kpasswd_success_reply_with_ap_rep_subkey(
        authenticator: &rasn_kerberos::Authenticator,
        ap_rep_key: &EncryptionKey,
        response_key: &EncryptionKey,
        code: u16,
        text: &str,
    ) -> Result<Vec<u8>, TestError> {
        let enc_ap_rep_part = rasn_kerberos::EncApRepPart {
            ctime: authenticator.ctime.clone(),
            cusec: authenticator.cusec.clone(),
            subkey: Some(rasn_encryption_key(response_key)),
            seq_number: Some(99),
        };
        let ap_rep = encode_build_ap_rep_with_confounder(
            &enc_ap_rep_part,
            ap_rep_key,
            None,
            &decode_hex(AS_REP_CONFOUNDER)?,
        )
        .context("AP-REP encodes")?;
        let mut result = Vec::with_capacity(text.len().saturating_add(2));
        result.extend_from_slice(&code.to_be_bytes());
        result.extend_from_slice(text.as_bytes());
        let krb_priv = build_krb_priv_with_confounder(
            result,
            EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 1])).with_sequence_number(99),
            response_key,
            &decode_hex(PREAUTH_CONFOUNDER)?,
        )
        .context("KRB-PRIV builds")?;
        let krb_priv_der = der::encode(&krb_priv).context("KRB-PRIV encodes")?;
        let mut body = ap_rep.clone();
        body.extend_from_slice(&krb_priv_der);
        kpasswd_reply_frame(
            u16::try_from(ap_rep.len()).context("AP-REP length fits u16")?,
            &body,
        )
    }

    /// The sample service principal `HTTP/host.test.gokrb5`.
    pub(crate) fn sample_service_principal() -> Principal {
        Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"])
    }

    /// Frontend keys for synthetic delegated tickets.
    pub(crate) fn delegation_keytab() -> Result<Keytab, TestError> {
        let service = sample_service_principal();
        let mut keys = Keytab::new();
        keys.entries_mut().push(KeytabEntry::new(
            KeytabPrincipal::new(service.realm, service.name_type, service.components),
            1_893_553_440,
            4,
            reply_key()?,
            4,
        ));
        Ok(keys)
    }

    /// A real encrypted frontend ticket binding its protected client identity.
    pub(crate) fn delegated_ticket(
        client: &Principal,
        service: &Principal,
    ) -> Result<rasn_kerberos::Ticket, TestError> {
        let part = rasn_kerberos::EncTicketPart {
            flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(
                TICKET_FLAGS,
            )),
            key: rasn_encryption_key(&EncryptionKey::new(18, decode_hex(SERVICE_SESSION_KEY)?)),
            crealm: realm(&client.realm)?,
            cname: rasn_principal(client)?,
            transited: rasn_kerberos::TransitedEncoding {
                r#type: 1,
                contents: Vec::new().into(),
            },
            auth_time: kerberos_time(1_893_553_445)?,
            start_time: Some(kerberos_time(1_893_553_446)?),
            end_time: kerberos_time(1_893_560_646)?,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        Ok(build_ticket_with_confounder(
            realm(&service.realm)?,
            rasn_principal(service)?,
            &part,
            &reply_key()?,
            Some(4),
            &decode_hex(TGS_REP_CONFOUNDER)?,
        )?)
    }

    /// The kpasswd service principal `kadmin/changepw`.
    pub(crate) fn change_password_principal() -> Principal {
        Principal::new("TEST.GOKRB5", 1, ["kadmin", "changepw"])
    }

    /// The service ticket session of the sample TGS exchange with `tgt`.
    pub(crate) fn sample_service_ticket_session(
        tgt: &AsRepSession,
    ) -> Result<TgsRepSession, TestError> {
        let request = sample_tgs_request(tgt)?;
        let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key)?;
        process_tgs_rep(&request, &response, &tgt.session_key).context("TGS-REP validates")
    }

    /// A synthetic AS-REP that answers `request` with `nonce`.
    pub(crate) fn synthetic_as_rep(request: &BuiltAsReq, nonce: u32) -> Result<Vec<u8>, TestError> {
        synthetic_as_rep_with_ticket_service(request, nonce, &request.service)
    }

    /// A synthetic AS-REP whose ticket names `ticket_service`.
    pub(crate) fn synthetic_as_rep_with_ticket_service(
        request: &BuiltAsReq,
        nonce: u32,
        ticket_service: &Principal,
    ) -> Result<Vec<u8>, TestError> {
        synthetic_as_rep_with_reply_key(request, nonce, ticket_service, &reply_key()?)
    }

    /// A synthetic AS-REP encrypted under `reply_key`, answering the FAST
    /// negotiation marker when `request` carries one.
    pub(crate) fn synthetic_as_rep_with_reply_key(
        request: &BuiltAsReq,
        nonce: u32,
        ticket_service: &Principal,
        reply_key: &EncryptionKey,
    ) -> Result<Vec<u8>, TestError> {
        let encrypted_pa_data = if request_has_padata(request, PA_REQ_ENC_PA_REP) {
            Some(fast_negotiation_encrypted_padata(
                request, reply_key, false,
            )?)
        } else {
            None
        };
        synthetic_as_rep_with_reply_key_and_encrypted_padata(
            request,
            nonce,
            ticket_service,
            reply_key,
            encrypted_pa_data,
        )
    }

    /// A synthetic AS-REP encrypted under `reply_key` that carries `encrypted_pa_data`.
    pub(crate) fn synthetic_as_rep_with_reply_key_and_encrypted_padata(
        request: &BuiltAsReq,
        nonce: u32,
        ticket_service: &Principal,
        reply_key: &EncryptionKey,
        encrypted_pa_data: Option<Vec<rasn_kerberos::PaData>>,
    ) -> Result<Vec<u8>, TestError> {
        let session_key = EncryptionKey::new(18, decode_hex(SESSION_KEY)?);
        let mut enc_part = rasn_kerberos::EncAsRepPart(rasn_kerberos::EncKdcRepPart {
            key: rasn_encryption_key(&session_key),
            last_req: vec![rasn_kerberos::LastReqValue {
                r#type: 0,
                value: kerberos_time(1_893_553_445)?,
            }],
            nonce,
            key_expiration: None,
            flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(
                TICKET_FLAGS,
            )),
            auth_time: kerberos_time(1_893_553_445)?,
            start_time: Some(kerberos_time(1_893_553_445)?),
            end_time: kerberos_time(1_893_639_845)?,
            renew_till: Some(kerberos_time(1_894_071_845)?),
            srealm: realm(&request.service.realm)?,
            sname: rasn_principal(&request.service)?,
            caddr: None,
            encrypted_pa_data,
        });
        reply_fixture::conform(
            &request.message.0.req_body,
            &mut enc_part.0,
            request.reply_clock.0,
        )?;
        let encrypted = encrypt_message(
            reply_key,
            &der::encode(&enc_part).context("EncAsRepPart encodes")?,
            AS_REP_ENCPART_USAGE,
            AS_REP_CONFOUNDER,
        )?;
        let as_rep = rasn_kerberos::AsRep(rasn_kerberos::KdcRep {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(11_i32),
            padata: None,
            crealm: realm(&request.client.realm)?,
            cname: rasn_principal(&request.client)?,
            ticket: rasn_kerberos::Ticket {
                tkt_vno: Integer::from(5_i32),
                realm: realm(&ticket_service.realm)?,
                sname: rasn_principal(ticket_service)?,
                enc_part: rasn_kerberos::EncryptedData {
                    etype: 18,
                    kvno: Some(2),
                    cipher: [0xde, 0xad, 0xbe, 0xef].as_slice().into(),
                },
            },
            enc_part: rasn_kerberos::EncryptedData {
                etype: reply_key.etype,
                kvno: Some(3),
                cipher: encrypted.into(),
            },
        });
        der::encode(&as_rep).context("AS-REP encodes")
    }

    /// The encrypted PA-DATA of a KDC that answers FAST negotiation:
    /// PA-FX-FAST and the PA-REQ-ENC-PA-REP checksum (corrupted on request).
    pub(crate) fn fast_negotiation_encrypted_padata(
        request: &BuiltAsReq,
        reply_key: &EncryptionKey,
        corrupt_checksum: bool,
    ) -> Result<Vec<rasn_kerberos::PaData>, TestError> {
        Ok(vec![
            rasn_kerberos::PaData {
                r#type: PA_FX_FAST,
                value: Vec::new().into(),
            },
            pa_req_enc_pa_rep_padata(request, reply_key, corrupt_checksum)?,
        ])
    }

    /// The PA-REQ-ENC-PA-REP checksum over `request` (corrupted on request).
    pub(crate) fn pa_req_enc_pa_rep_padata(
        request: &BuiltAsReq,
        reply_key: &EncryptionKey,
        corrupt_checksum: bool,
    ) -> Result<rasn_kerberos::PaData, TestError> {
        let etype =
            KerberosEtype::from_etype_id(reply_key.etype).context("supported reply key etype")?;
        let mut checksum = etype
            .checksum(&reply_key.value, &request.der, AS_REQ_CHECKSUM_USAGE)
            .context("AS-REQ checksum computes")?;
        if corrupt_checksum {
            let first = checksum.first_mut().context("checksum is not empty")?;
            *first ^= 0xff;
        }
        let value = PaReqEncPaRep::new(etype.checksum_type_id(), checksum.into());
        Ok(rasn_kerberos::PaData {
            r#type: PA_REQ_ENC_PA_REP,
            value: value
                .encode_der()
                .context("PA-REQ-ENC-PA-REP encodes")?
                .into(),
        })
    }

    /// Whether `request` carries PA-DATA of `padata_type`.
    pub(crate) fn request_has_padata(request: &BuiltAsReq, padata_type: i32) -> bool {
        request
            .message
            .0
            .padata
            .as_ref()
            .is_some_and(|padata| padata.iter().any(|entry| entry.r#type == padata_type))
    }

    /// A synthetic TGS-REP that answers `request` with `nonce`.
    pub(crate) fn synthetic_tgs_rep(
        request: &BuiltTgsReq,
        nonce: u32,
        tgs_session_key: &EncryptionKey,
    ) -> Result<Vec<u8>, TestError> {
        synthetic_tgs_rep_with_service(request, nonce, tgs_session_key, &request.service)
    }

    /// A synthetic TGS-REP whose ticket and encrypted part name `reply_service`.
    pub(crate) fn synthetic_tgs_rep_with_service(
        request: &BuiltTgsReq,
        nonce: u32,
        tgs_session_key: &EncryptionKey,
        reply_service: &Principal,
    ) -> Result<Vec<u8>, TestError> {
        let session_key = EncryptionKey::new(18, decode_hex(SERVICE_SESSION_KEY)?);
        let mut enc_part = rasn_kerberos::EncTgsRepPart(rasn_kerberos::EncKdcRepPart {
            key: rasn_encryption_key(&session_key),
            last_req: vec![rasn_kerberos::LastReqValue {
                r#type: 0,
                value: kerberos_time(1_893_553_445)?,
            }],
            nonce,
            key_expiration: None,
            flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(
                TICKET_FLAGS,
            )),
            auth_time: kerberos_time(1_893_553_445)?,
            start_time: Some(kerberos_time(1_893_553_446)?),
            end_time: kerberos_time(1_893_560_646)?,
            renew_till: Some(kerberos_time(1_894_071_846)?),
            srealm: realm(&reply_service.realm)?,
            sname: rasn_principal(reply_service)?,
            caddr: None,
            encrypted_pa_data: None,
        });
        reply_fixture::conform(
            &request.message.0.req_body,
            &mut enc_part.0,
            request.reply_clock.0,
        )?;
        let encrypted = encrypt_message(
            tgs_session_key,
            &der::encode(&enc_part).context("EncTgsRepPart encodes")?,
            TGS_REP_ENCPART_SESSION_KEY_USAGE,
            TGS_REP_CONFOUNDER,
        )?;
        let mut tgs_rep = rasn_kerberos::TgsRep(rasn_kerberos::KdcRep {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(13_i32),
            padata: None,
            crealm: realm(&request.client.realm)?,
            cname: rasn_principal(&request.client)?,
            ticket: rasn_kerberos::Ticket {
                tkt_vno: Integer::from(5_i32),
                realm: realm(&reply_service.realm)?,
                sname: rasn_principal(reply_service)?,
                enc_part: rasn_kerberos::EncryptedData {
                    etype: 18,
                    kvno: Some(4),
                    cipher: [0xca, 0xfe, 0xba, 0xbe].as_slice().into(),
                },
            },
            enc_part: rasn_kerberos::EncryptedData {
                etype: tgs_session_key.etype,
                kvno: None,
                cipher: encrypted.into(),
            },
        });
        tgs_rep.0.ticket = delegated_ticket(&request.client, reply_service)?;
        der::encode(&tgs_rep).context("TGS-REP encodes")
    }

    /// A `KDC_ERR_PREAUTH_REQUIRED` KRB-ERROR whose `ETYPE-INFO2` names the
    /// `testuser1` salt.
    pub(crate) fn synthetic_preauth_required_error() -> Result<Vec<u8>, TestError> {
        let etype_info2 = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
            etype: 18,
            salt: Some(kerberos_string(TESTUSER_SALT)?),
            s2kparams: Some(vec![0_u8, 0_u8, 16_u8, 0_u8].into()),
        }]);
        let method_data = rasn_kerberos::MethodData::from([rasn_kerberos::PaData {
            r#type: PA_ETYPE_INFO2,
            value: der::encode(&etype_info2)
                .context("ETYPE-INFO2 encodes")?
                .into(),
        }]);
        let error = rasn_kerberos::KrbError {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(30_i32),
            ctime: None,
            cusec: None,
            stime: kerberos_time(1_893_553_440)?,
            susec: Integer::from(0_i32),
            error_code: KDC_ERR_PREAUTH_REQUIRED,
            crealm: Some(realm("TEST.GOKRB5")?),
            cname: Some(rasn_principal(&Principal::user(
                "TEST.GOKRB5",
                "testuser1",
            ))?),
            realm: realm("TEST.GOKRB5")?,
            sname: rasn_principal(&Principal::tgt_service("TEST.GOKRB5"))?,
            e_text: Some(kerberos_string("Additional pre-authentication required")?),
            e_data: Some(
                der::encode(&method_data)
                    .context("METHOD-DATA encodes")?
                    .into(),
            ),
        };
        der::encode(&error).context("KRB-ERROR encodes")
    }

    /// The pre-authentication key info of `testuser1`.
    pub(crate) fn password_key_info() -> PreauthKeyInfo {
        PreauthKeyInfo::new(18)
            .with_salt(Some(TESTUSER_SALT.to_owned()))
            .with_s2kparams(Some(vec![0, 0, 16, 0]))
    }

    /// A keytab with the reply key of `testuser1` at key version `kvno`.
    pub(crate) fn keytab_with_reply_key(kvno: u32) -> Result<Keytab, TestError> {
        let [_, _, _, kvno8] = kvno.to_be_bytes();
        let mut keytab = Keytab::new();
        keytab.entries_mut().push(KeytabEntry::new(
            KeytabPrincipal::new("TEST.GOKRB5", 1, vec!["testuser1".to_owned()]),
            1_893_553_440,
            kvno8,
            reply_key()?,
            kvno,
        ));
        Ok(keytab)
    }

    /// Asserts that `request` carries an AES256 PA-ENC-TIMESTAMP of key
    /// version `expected_kvno`.
    pub(crate) fn assert_pa_enc_timestamp(
        request: &rasn_kerberos::AsReq,
        expected_kvno: Option<u32>,
    ) -> Result<(), TestError> {
        let padata = request
            .0
            .padata
            .as_ref()
            .context("second AS-REQ has padata")?;
        let pa_enc_timestamp = padata
            .iter()
            .find(|entry| entry.r#type == PA_ENC_TIMESTAMP)
            .context("second AS-REQ has PA-ENC-TIMESTAMP")?;
        let encrypted: rasn_kerberos::EncryptedData =
            der::decode(pa_enc_timestamp.value.as_ref()).context("encrypted timestamp decodes")?;
        assert_eq!(encrypted.etype, 18_i32);
        assert_eq!(encrypted.kvno, expected_kvno);
        assert!(
            !encrypted.cipher.as_ref().is_empty(),
            "the encrypted timestamp has a ciphertext"
        );
        Ok(())
    }

    /// Asserts that `request` carries an empty PA-REQ-ENC-PA-REP marker
    /// exactly when `expected`.
    pub(crate) fn assert_fast_negotiation_marker(
        request: &rasn_kerberos::AsReq,
        expected: bool,
    ) -> Result<(), TestError> {
        let marker = request.0.padata.as_ref().and_then(|padata| {
            padata
                .iter()
                .find(|entry| entry.r#type == PA_REQ_ENC_PA_REP)
        });
        if expected {
            let present = marker.context("AS-REQ has PA-REQ-ENC-PA-REP")?;
            assert!(
                present.value.as_ref().is_empty(),
                "the PA-REQ-ENC-PA-REP marker is empty"
            );
        } else {
            assert!(
                marker.is_none(),
                "AS-REQ omits PA-REQ-ENC-PA-REP when fast negotiation is disabled"
            );
        }
        Ok(())
    }

    /// Rebuilds the [`BuiltAsReq`] of a decoded AS-REQ `message` and its `der`.
    pub(crate) fn built_request_from_der(
        message: rasn_kerberos::AsReq,
        der: &[u8],
    ) -> Result<BuiltAsReq, TestError> {
        let body = &message.0.req_body;
        let client = principal_from_parts(&body.realm, body.cname.as_ref().context("cname")?)?;
        let service = principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?;
        let nonce = body.nonce;
        let clock = timestamp(u64::try_from(
            body.till.0.timestamp().saturating_sub(86_400),
        )?)?;
        let mut built = BuiltAsReq::new(message, der.to_vec().into(), client, service, nonce);
        built.reply_clock.0 = clock;
        Ok(built)
    }

    /// Rebuilds the [`BuiltTgsReq`] of a decoded TGS-REQ `message` and its `der`.
    pub(crate) fn built_tgs_request_from_der(
        message: rasn_kerberos::TgsReq,
        der: &[u8],
    ) -> Result<BuiltTgsReq, TestError> {
        let body = &message.0.req_body;
        let client = principal_from_parts(&body.realm, body.cname.as_ref().context("cname")?)?;
        let service = principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?;
        let kdc_realm = kerberos_string_to_string(&body.realm)?;
        let nonce = body.nonce;
        let clock = timestamp(u64::try_from(
            body.till.0.timestamp().saturating_sub(86_400),
        )?)?;
        let mut built = BuiltTgsReq::new(
            message,
            der.to_vec().into(),
            client,
            service,
            kdc_realm,
            nonce,
        );
        built.reply_clock.0 = clock;
        Ok(built)
    }

    /// The AES256 reply key of `testuser1`.
    pub(crate) fn reply_key() -> Result<EncryptionKey, TestError> {
        Ok(EncryptionKey::new(18, decode_hex(REPLY_KEY)?))
    }

    /// `key` as a rasn encryption key.
    pub(crate) fn rasn_encryption_key(key: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
        rasn_kerberos::EncryptionKey {
            r#type: key.etype,
            value: key.value.to_vec().into(),
        }
    }

    /// Encrypts `plaintext` under `key` for `usage` with a fixed confounder.
    pub(crate) fn encrypt_message(
        key: &EncryptionKey,
        plaintext: &[u8],
        usage: u32,
        confounder_hex: &str,
    ) -> Result<Vec<u8>, TestError> {
        let etype =
            AesSha1Etype::from_etype_id(key.etype).context("AES-SHA1 etype is supported")?;
        etype
            .encrypt_message_with_confounder(
                &key.value,
                plaintext,
                usage,
                &decode_hex(confounder_hex)?,
            )
            .context("message encrypts")
    }

    /// `value` as a rasn principal name.
    pub(crate) fn rasn_principal(
        value: &Principal,
    ) -> Result<rasn_kerberos::PrincipalName, TestError> {
        Ok(rasn_kerberos::PrincipalName {
            r#type: value.name_type,
            string: value
                .components
                .iter()
                .map(|component| kerberos_string(component))
                .collect::<Result<_, _>>()?,
        })
    }

    /// The principal of `name` in `realm`.
    pub(crate) fn principal_from_parts(
        realm: &rasn_kerberos::Realm,
        name: &rasn_kerberos::PrincipalName,
    ) -> Result<Principal, TestError> {
        let components = name
            .string
            .iter()
            .map(kerberos_string_to_string)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Principal::new(
            kerberos_string_to_string(realm)?,
            name.r#type,
            components,
        ))
    }

    /// `value` as a rasn realm.
    pub(crate) fn realm(value: &str) -> Result<rasn_kerberos::Realm, TestError> {
        kerberos_string(value)
    }

    /// `value` as a rasn Kerberos string.
    pub(crate) fn kerberos_string(value: &str) -> Result<rasn_kerberos::KerberosString, TestError> {
        rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
            .context("Kerberos string uses permitted characters")
    }

    /// The UTF-8 text of a rasn Kerberos string.
    pub(crate) fn kerberos_string_to_string(
        value: &rasn_kerberos::KerberosString,
    ) -> Result<String, TestError> {
        Ok(str::from_utf8(value.as_bytes())
            .context("Kerberos string is UTF-8")?
            .to_owned())
    }

    /// The Kerberos time `seconds` after the Unix epoch.
    pub(crate) fn kerberos_time(seconds: u64) -> Result<rasn_kerberos::KerberosTime, TestError> {
        let utc = DateTime::<Utc>::from_timestamp(
            i64::try_from(seconds).context("fixture timestamp fits i64")?,
            0,
        )
        .context("fixture timestamp is representable")?;
        let offset = FixedOffset::east_opt(0).context("UTC offset exists")?;
        Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
    }

    /// The system time of a Kerberos `time`.
    pub(crate) fn system_time_from_kerberos_time(
        time: &rasn_kerberos::KerberosTime,
    ) -> Result<SystemTime, TestError> {
        let seconds = u64::try_from(time.0.timestamp()).context("Kerberos time is after 1970")?;
        UNIX_EPOCH
            .checked_add(Duration::new(seconds, time.0.timestamp_subsec_nanos()))
            .context("Kerberos time fits SystemTime")
    }

    /// The system time `seconds` after the Unix epoch.
    pub(crate) fn timestamp(seconds: u64) -> Result<SystemTime, TestError> {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .context("fixture timestamp fits SystemTime")
    }

    /// Makes `credential` valid at `now`: issued a minute ago, valid for an
    /// hour and renewable for two.
    #[cfg(feature = "tokio")]
    pub(crate) fn make_credential_current(
        credential: &mut ccache::Credential,
        now: u32,
    ) -> Result<(), TestError> {
        let issued = now.checked_sub(60).context("issue time fits u32")?;
        credential.times.auth_time = issued;
        credential.times.start_time = issued;
        credential.times.end_time = now.checked_add(60 * 60).context("end time fits u32")?;
        credential.times.renew_till = now
            .checked_add(2 * 60 * 60)
            .context("renew time fits u32")?;
        Ok(())
    }

    /// Makes `credential` expired at `now`: issued two hours ago, expired an
    /// hour ago and not renewable.
    #[cfg(feature = "tokio")]
    pub(crate) fn make_credential_expired(
        credential: &mut ccache::Credential,
        now: u32,
    ) -> Result<(), TestError> {
        let issued = now
            .checked_sub(2 * 60 * 60)
            .context("issue time fits u32")?;
        credential.times.auth_time = issued;
        credential.times.start_time = issued;
        credential.times.end_time = now.checked_sub(60 * 60).context("end time fits u32")?;
        credential.times.renew_till = 0;
        Ok(())
    }

    /// A configuration with the `TEST.GOKRB5` realm and no KDC.
    #[cfg(feature = "tokio")]
    pub(crate) fn config_without_kdcs() -> Result<Config, TestError> {
        Config::parse(
            "
[libdefaults]
 dns_lookup_kdc = false

[realms]
 TEST.GOKRB5 = {
 }
",
        )
        .context("config parses")
    }

    /// A configuration with one KDC for `TEST.GOKRB5` and AES enctypes.
    #[cfg(all(feature = "tokio", feature = "serde"))]
    pub(crate) fn config_with_kdc() -> Result<Config, TestError> {
        Config::parse(
            "
[libdefaults]
 dns_lookup_kdc = false
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 preferred_preauth_types = 18 17

[realms]
 TEST.GOKRB5 = {
  kdc = kdc.test.gokrb5
 }
",
        )
        .context("config parses")
    }

    /// A configuration whose `TEST.GOKRB5` and `RESDOM.GOKRB5` KDC is `server`.
    #[cfg(feature = "tokio")]
    pub(crate) fn config_with_kdc_server(server: &str) -> Result<Config, TestError> {
        let input = format!(
            "
[libdefaults]
 dns_lookup_kdc = false

[realms]
 TEST.GOKRB5 = {{
  kdc = {server}
 }}
 RESDOM.GOKRB5 = {{
  kdc = {server}
 }}
",
        );
        Config::parse(&input).context("config parses")
    }

    /// A configuration whose default client keytab is `keytab_name`.
    #[cfg(all(feature = "tokio", feature = "serde"))]
    pub(crate) fn config_with_client_keytab_name(keytab_name: &str) -> Result<Config, TestError> {
        let input = format!(
            "
[libdefaults]
 dns_lookup_kdc = false
 default_client_keytab_name = {keytab_name}

[realms]
 TEST.GOKRB5 = {{
  kdc = kdc.test.gokrb5
 }}
",
        );
        Config::parse(&input).context("config parses")
    }

    /// A configuration whose default ccache is `cache_name`.
    #[cfg(feature = "tokio")]
    pub(crate) fn config_with_default_ccache_name(cache_name: &str) -> Result<Config, TestError> {
        let input = format!(
            "
[libdefaults]
 dns_lookup_kdc = false
 default_ccache_name = {cache_name}

[realms]
 TEST.GOKRB5 = {{
  kdc = kdc.test.gokrb5
 }}
",
        );
        Config::parse(&input).context("config parses")
    }

    /// A configuration whose `TEST.GOKRB5` kpasswd server is `server`, over TCP.
    #[cfg(feature = "tokio")]
    pub(crate) fn config_with_kpasswd_server(server: &str) -> Result<Config, TestError> {
        let input = format!(
            "
[libdefaults]
 dns_lookup_kdc = false
 udp_preference_limit = 1

[realms]
 TEST.GOKRB5 = {{
  kpasswd_server = {server}
 }}
",
        );
        Config::parse(&input).context("config parses")
    }

    /// Accepts one TCP client on `listener` and reads its length-prefixed request.
    #[cfg(feature = "tokio")]
    pub(crate) async fn read_tcp_kdc_request(
        listener: &TcpListener,
    ) -> Result<(Vec<u8>, TcpStream), TestError> {
        let (mut socket, _) = listener.accept().await.context("accept client")?;
        let mut header = [0_u8; 4];
        let _: usize = socket
            .read_exact(&mut header)
            .await
            .context("read request length")?;
        let request_len =
            usize::try_from(u32::from_be_bytes(header)).context("request length fits usize")?;
        let mut request = vec![0_u8; request_len];
        let _: usize = socket
            .read_exact(&mut request)
            .await
            .context("read request")?;
        Ok((request, socket))
    }

    /// Serves one `S4U2Self` TGS-REQ on `listener`, checking it names
    /// `expected_service` and impersonates `expected_user`.
    #[cfg(feature = "tokio")]
    pub(crate) async fn serve_s4u2self_tcp_request(
        listener: TcpListener,
        reply_key: EncryptionKey,
        expected_service: Principal,
        expected_user: Principal,
    ) -> Result<(), TestError> {
        let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
        let decoded: rasn_kerberos::TgsReq = der::decode(&request).context("TGS-REQ decodes")?;
        let body = &decoded.0.req_body;
        assert_eq!(
            principal_from_parts(&body.realm, body.cname.as_ref().context("cname")?)?,
            expected_service
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
            expected_service
        );

        let padata = decoded.0.padata.as_ref().context("S4U TGS-REQ padata")?;
        assert_eq!(padata.len(), 2);
        let [tgs_req, for_user] = padata.as_slice() else {
            return Err("S4U TGS-REQ carries two padata".into());
        };
        assert_eq!(tgs_req.r#type, PA_TGS_REQ);
        assert_eq!(for_user.r#type, PA_FOR_USER);
        let pa_for_user =
            PaForUser::decode_der(for_user.value.as_ref()).context("PA-FOR-USER decodes")?;
        assert_eq!(
            principal_from_parts(&pa_for_user.user_realm, &pa_for_user.user_name)?,
            expected_user
        );

        let mut built = built_tgs_request_from_der(decoded, &request)?;
        built.client = expected_user;
        let response = synthetic_tgs_rep(&built, built.nonce, &reply_key)?;
        write_tcp_kdc_response(&mut socket, &response).await
    }

    /// Serves one `S4U2Proxy` TGS-REQ on `listener`, checking its evidence
    /// ticket and the services it names.
    #[cfg(feature = "tokio")]
    pub(crate) async fn serve_s4u2proxy_tcp_request(
        listener: TcpListener,
        reply_key: EncryptionKey,
        expected_frontend_service: Principal,
        expected_target_service: Principal,
        expected_client: Principal,
    ) -> Result<(), TestError> {
        let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
        let decoded: rasn_kerberos::TgsReq = der::decode(&request).context("TGS-REQ decodes")?;
        let body = &decoded.0.req_body;
        assert_eq!(
            body.kdc_options.0.as_raw_slice(),
            KDC_OPTION_CNAME_IN_ADDL_TKT.to_be_bytes().as_slice()
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.cname.as_ref().context("cname")?)?,
            expected_frontend_service
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
            expected_target_service
        );

        let padata = decoded
            .0
            .padata
            .as_ref()
            .context("`S4U2Proxy` TGS-REQ padata")?;
        assert_eq!(padata.len(), 1);
        let [tgs_req] = padata.as_slice() else {
            return Err("`S4U2Proxy` TGS-REQ carries one padata".into());
        };
        assert_eq!(tgs_req.r#type, PA_TGS_REQ);
        let additional_tickets = body
            .additional_tickets
            .as_ref()
            .context("S4U2Proxy evidence ticket")?;
        assert_eq!(additional_tickets.len(), 1);
        let [evidence] = additional_tickets.as_slice() else {
            return Err("`S4U2Proxy` TGS-REQ carries one evidence ticket".into());
        };
        assert_eq!(
            principal_from_parts(&evidence.realm, &evidence.sname)?,
            expected_frontend_service
        );

        let mut built = built_tgs_request_from_der(decoded, &request)?;
        built.client = expected_client;
        let response = synthetic_tgs_rep(&built, built.nonce, &reply_key)?;
        write_tcp_kdc_response(&mut socket, &response).await
    }

    /// Writes the length-prefixed KDC `response` to `socket`.
    #[cfg(feature = "tokio")]
    pub(crate) async fn write_tcp_kdc_response(
        socket: &mut TcpStream,
        response: &[u8],
    ) -> Result<(), TestError> {
        let length = u32::try_from(response.len()).context("response length fits u32")?;
        socket
            .write_all(&length.to_be_bytes())
            .await
            .context("write response length")?;
        socket.write_all(response).await.context("write response")
    }

    /// Answers a kpasswd `request` as the fake server would: a success result in
    /// a KRB-PRIV under an AP-REP whose subkey repeats `response_key_byte`.
    ///
    /// A request whose AP-REQ authenticator does not decrypt under `session_key`
    /// gets a `KPASSWD_AUTHERROR` KRB-ERROR reply naming the failure, as a real
    /// server would answer, so the client under test reports it.
    #[cfg(feature = "tokio")]
    pub(crate) fn kpasswd_authenticated_success_reply(
        request: &[u8],
        session_key: &EncryptionKey,
        response_key_byte: u8,
    ) -> Result<Vec<u8>, TestError> {
        use rskrb5_ng::{ap_req::decrypt_ap_req_authenticator, kadmin::KPASSWD_AUTHERROR};

        let authenticated = KpasswdRequest::parse(request)
            .map_err(|error| error.to_string())
            .and_then(|parsed| {
                decrypt_ap_req_authenticator(
                    &parsed.ap_req,
                    session_key,
                    AP_REQ_AUTHENTICATOR_USAGE,
                )
                .map_err(|error| error.to_string())
            });
        match authenticated {
            Err(reason) => {
                kpasswd_reply_frame(0, &kpasswd_result_krb_error(KPASSWD_AUTHERROR, &reason)?)
            }
            Ok(authenticator) => {
                let response_key = EncryptionKey::new(18, vec![response_key_byte; 32]);
                kpasswd_success_reply_with_ap_rep_subkey(
                    &authenticator,
                    session_key,
                    &response_key,
                    KPASSWD_SUCCESS,
                    "password changed",
                )
            }
        }
    }

    /// A kpasswd reply frame: message length, version 1, `ap_rep_length` and `body`.
    pub(crate) fn kpasswd_reply_frame(
        ap_rep_length: u16,
        body: &[u8],
    ) -> Result<Vec<u8>, TestError> {
        let message_length = body
            .len()
            .checked_add(6)
            .context("frame length fits usize")?;
        let header_length = u16::try_from(message_length).context("frame length fits u16")?;

        let mut frame = Vec::with_capacity(message_length);
        frame.extend_from_slice(&header_length.to_be_bytes());
        frame.extend_from_slice(&1_u16.to_be_bytes());
        frame.extend_from_slice(&ap_rep_length.to_be_bytes());
        frame.extend_from_slice(body);
        Ok(frame)
    }

    /// A kpasswd KRB-ERROR whose e-data holds result `code` and `text`.
    #[cfg(feature = "tokio")]
    pub(crate) fn kpasswd_result_krb_error(code: u16, text: &str) -> Result<Vec<u8>, TestError> {
        let mut e_data = Vec::with_capacity(text.len().saturating_add(2));
        e_data.extend_from_slice(&code.to_be_bytes());
        e_data.extend_from_slice(text.as_bytes());

        let error = rasn_kerberos::KrbError {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(30_i32),
            ctime: None,
            cusec: None,
            stime: kerberos_time(1_893_553_440)?,
            susec: Integer::from(0_i32),
            error_code: 52,
            crealm: None,
            cname: None,
            realm: realm("TEST.GOKRB5")?,
            sname: rasn_principal(&change_password_principal())?,
            e_text: Some(kerberos_string(text)?),
            e_data: Some(e_data.into()),
        };
        der::encode(&error).context("KRB-ERROR encodes")
    }

    /// A current-thread Tokio runtime with I/O and time.
    #[cfg(feature = "tokio")]
    pub(crate) fn runtime() -> Result<Runtime, TestError> {
        RuntimeBuilder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context("runtime")
    }

    /// The MIT `X-CACHECONF:` `fast_avail` entry of `client`.
    #[cfg(feature = "tokio")]
    pub(crate) fn x_cacheconf_credential(client: &ccache::Principal) -> ccache::Credential {
        ccache::Credential::new(
            client.clone(),
            ccache::Principal::new(
                "X-CACHECONF:",
                0,
                vec!["krb5_ccache_conf_data".to_owned(), "fast_avail".to_owned()],
            ),
            ccache::EncryptionKey::new(0, Vec::new()),
            ccache::CredentialTimes::default(),
            [0; 4],
            b"yes".to_vec().into(),
        )
        .with_is_skey(false)
        .with_addresses(Vec::new())
        .with_auth_data(Vec::new())
        .with_second_ticket(Vec::new().into())
    }

    /// The credentials of `testuser1` in `cache` for `server`.
    #[cfg(feature = "tokio")]
    pub(crate) fn matching_credentials<'cache>(
        cache: &'cache ccache::CCache,
        server: &ccache::Principal,
    ) -> Vec<&'cache ccache::Credential> {
        cache
            .credentials()
            .iter()
            .filter(|credential| {
                credential.client.realm == "TEST.GOKRB5"
                    && credential.client.components == ["testuser1"]
                    && credential.server == *server
            })
            .collect()
    }

    /// A unique temporary ccache path for test `name`.
    #[cfg(feature = "tokio")]
    pub(crate) fn temp_client_ccache_file(name: &str) -> Result<PathBuf, TestError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("current time is after unix epoch")?
            .as_nanos();
        Ok(temp_dir().join(format!("rskrb5-client-{name}-{}-{nanos}", process::id())))
    }

    /// Saves a ccache with the sample service ticket, valid now, under a
    /// temporary `FILE:` name; returns its path and name.
    #[cfg(all(feature = "tokio", feature = "spnego"))]
    pub(crate) fn save_sample_negotiate_ccache(name: &str) -> Result<(PathBuf, String), TestError> {
        let tgt = sample_tgt_session()?;
        let mut service_ticket = sample_service_ticket_session(&tgt)?;
        let now = timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;
        service_ticket.auth_time = now
            .checked_sub(Duration::from_mins(1))
            .context("auth time")?;
        service_ticket.start_time = service_ticket.auth_time;
        service_ticket.end_time = now
            .checked_add(Duration::from_hours(1))
            .context("end time")?;
        service_ticket.renew_till = Some(
            now.checked_add(Duration::from_hours(2))
                .context("renew time")?,
        );
        service_ticket.key_expiration = Some(service_ticket.end_time);
        let mut cache = ccache::CCache::new(ccache::Principal::new(
            tgt.client.realm,
            tgt.client.name_type,
            tgt.client.components,
        ));
        drop(
            cache.upsert_credential(
                service_ticket
                    .to_ccache_credential()
                    .context("service ticket exports ccache credential")?,
            ),
        );
        let path = temp_client_ccache_file(name)?;
        let cache_name = format!("FILE:{}", path.display());
        cache
            .save_name(&cache_name)
            .context("ccache saves by name")?;
        Ok((path, cache_name))
    }

    /// A unique temporary ccache directory path for test `name`.
    #[cfg(feature = "tokio")]
    pub(crate) fn temp_client_ccache_dir(name: &str) -> Result<PathBuf, TestError> {
        temp_client_ccache_file(name)
    }

    /// A unique temporary keytab path for test `name`.
    #[cfg(all(feature = "tokio", feature = "serde"))]
    pub(crate) fn temp_client_keytab_file(name: &str) -> Result<PathBuf, TestError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("current time is after unix epoch")?
            .as_nanos();
        Ok(temp_dir().join(format!(
            "rskrb5-client-keytab-{name}-{}-{nanos}",
            process::id()
        )))
    }

    /// The bytes of the hexadecimal `input`.
    pub(crate) fn decode_hex(input: &str) -> Result<Vec<u8>, TestError> {
        let (pairs, rest) = input.as_bytes().as_chunks::<2>();
        assert!(rest.is_empty(), "hex input has even length");
        pairs
            .iter()
            .map(|pair| {
                let digits = str::from_utf8(pair).context("hex input is ASCII")?;
                u8::from_str_radix(digits, 16).context("hex input holds hex digits")
            })
            .collect()
    }

    /// The lowercase hexadecimal text of `bytes`.
    pub(crate) fn hex_encode(bytes: &[u8]) -> Result<String, TestError> {
        let mut out = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            write!(out, "{byte:02x}")?;
        }
        Ok(out)
    }
}
