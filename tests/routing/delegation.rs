//! Delegation, user-to-user tickets and `verify_init_creds` through the Tokio
//! client against the in-memory KDC (`proxy_kdc.rs`).

use std::time::SystemTime;

use rskrb5_ng::{
    client::{
        Tokio,
        options::TgsReq,
        principal::Principal,
        transport::{KdcProtocol, Tokio as Transport},
    },
    config::Config,
    error::Client as ClientError,
    keytab::{EncryptionKey, Keytab, Principal as KeytabPrincipal},
    routing::{
        CertificateIdentity,
        impersonation::{DelegationOptions, S4uIdentity},
        init_creds::{Verification, VerifyOptions},
    },
    ticket,
};
use zeroize::Zeroizing;

use crate::{
    TestError,
    proxy_kdc::{Kdc, profile},
};

/// The service realm.
const SERVICE_REALM: &str = "SVC.TEST";
/// The user realm.
const USER_REALM: &str = "USER.TEST";
/// The resource realm of the cross-realm delegation target.
const RESOURCE_REALM: &str = "RES.TEST";

/// A keytab with one AES256 key for `principal`, and that key.
fn keytab(principal: &Principal, password: &str) -> Result<(Keytab, EncryptionKey), TestError> {
    let mut keytab = Keytab::default();
    keytab.add_entry_from_password(
        KeytabPrincipal::new(
            principal.realm.as_str(),
            principal.name_type,
            principal.components.iter().map(String::as_str),
        ),
        Zeroizing::new(password.as_bytes().to_vec()),
        SystemTime::now(),
        1,
        18,
    )?;
    let components: Vec<&str> = principal.components.iter().map(String::as_str).collect();
    let key = keytab
        .find_key(&components, &principal.realm, 1, 18)?
        .0
        .clone();
    Ok((keytab, key))
}

/// A Tokio client for `principal` with `keytab` and a TGT from `kdc`.
fn client(
    config: Config,
    kdc: &'static Kdc,
    principal: &Principal,
    keytab: Keytab,
) -> Result<Tokio, TestError> {
    let mut client = Tokio::with_keytab(config, KdcProtocol::Tcp, principal.clone(), keytab)
        .with_transport(Transport::new().with_kdc_proxy(kdc));
    client.cache_tgt_session(kdc.tgt(principal.clone())?)?;
    Ok(client)
}

/// `result`, or its error with the KDC's unanswered requests.
fn explained<T>(result: Result<T, ClientError>, kdc: &Kdc) -> Result<T, TestError> {
    result.map_err(|error| format!("{error}; KDC failures: {:?}", kdc.failures()).into())
}

/// The client name of a ticket decrypted with `keytab`.
fn decrypted_client(ticket_bytes: &[u8], key: &EncryptionKey) -> Result<String, TestError> {
    let wire = ticket::decode(ticket_bytes)?;
    let part = ticket::decrypt_ticket_enc_part(&wire, key)?;
    Ok(part
        .cname
        .string
        .iter()
        .map(|component| String::from_utf8(component.as_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()?
        .join("/"))
}

/// MIT-client-6 (cross-realm `S4U2Self`, `s4u_creds.c:420-645`): the service
/// asks its realm for a TGT to the user's realm, the user's KDC answers the
/// enterprise request with a referral naming the user, and the service's KDC
/// issues the evidence ticket; the service's keytab decrypts it and finds the
/// user the KDC named under the `PA-S4U-X509-USER` checksum.
#[tokio::test]
async fn cross_realm_s4u2self_crosses_back_to_the_service_realm() -> Result<(), TestError> {
    // Given a service in SVC.TEST and a user in USER.TEST, the realms trusting each other.
    let service = Principal::user(SERVICE_REALM, "svc");
    let (tab, key) = keytab(&service, "service-password")?;
    let kdc = Kdc::new(&[(SERVICE_REALM, USER_REALM)])
        .with_service(service.clone(), key.clone())
        .leak();
    let mut client = client(
        profile(&[SERVICE_REALM, USER_REALM], "")?,
        kdc,
        &service,
        tab,
    )?;
    let user = Principal::user(USER_REALM, "alice");
    // When the service impersonates the user.
    let evidence = explained(
        client
            .s4u2self_identity(
                S4uIdentity::Principal(user.clone()),
                DelegationOptions::new(),
            )
            .await,
        kdc,
    )?;
    // Then the evidence names the user, is for the service, and was routed through USER.TEST.
    assert_eq!(evidence.client(), &user);
    assert_eq!(evidence.service().components, service.components);
    assert_eq!(decrypted_client(evidence.ticket(), &key)?, "alice");
    let realms: Vec<String> = kdc.log().into_iter().map(|(realm, _)| realm).collect();
    assert_eq!(realms, [SERVICE_REALM, USER_REALM, SERVICE_REALM]);
    Ok(())
}

/// MIT-client-6 (certificate `S4U2Self`): the request carries the certificate
/// and no name; the KDC maps it to a user, and the evidence is bound to the
/// user the KDC named and the service decrypts.
#[tokio::test]
async fn certificate_s4u2self_binds_the_user_the_kdc_names() -> Result<(), TestError> {
    // Given a KDC that maps the certificate to carol.
    let service = Principal::user(SERVICE_REALM, "svc");
    let (tab, key) = keytab(&service, "service-password")?;
    let carol = Principal::user(SERVICE_REALM, "carol");
    let kdc = Kdc::new(&[])
        .with_service(service.clone(), key.clone())
        .with_certificate_user(carol.clone())
        .leak();
    let mut client = client(profile(&[SERVICE_REALM], "")?, kdc, &service, tab)?;
    // When the service asks for the user of a certificate.
    let identity = CertificateIdentity::new(vec![0x30, 0x03, 0x02, 0x01, 0x05], SERVICE_REALM)?;
    let evidence = explained(
        client
            .s4u2self_identity(S4uIdentity::Certificate(identity), DelegationOptions::new())
            .await,
        kdc,
    )?;
    // Then the evidence names carol, as its decrypted part does.
    assert_eq!(evidence.client(), &carol);
    assert_eq!(decrypted_client(evidence.ticket(), &key)?, "carol");
    Ok(())
}

/// MIT-client-8 (cross-realm resource-based constrained delegation,
/// `s4u_creds.c:984-1145`): the service's realm answers the `S4U2Proxy`
/// request with a proxy TGT to the target's realm, the service gets its own
/// TGT there, and the target realm issues the ticket in the user's name.
#[tokio::test]
async fn cross_realm_rbcd_reaches_the_target_realm() -> Result<(), TestError> {
    // Given a target in RES.TEST that trusts the service.
    let service = Principal::user(SERVICE_REALM, "svc");
    let (tab, key) = keytab(&service, "service-password")?;
    let target = Principal::new(RESOURCE_REALM, 2, ["HTTP", "app.res.test"]);
    let (_, target_key) = keytab(&target, "target-password")?;
    let kdc = Kdc::new(&[(SERVICE_REALM, RESOURCE_REALM)])
        .with_service(service.clone(), key)
        .with_service(target.clone(), target_key.clone())
        .with_delegation(service.clone(), target.clone())
        .leak();
    let mut client = client(
        profile(&[SERVICE_REALM, RESOURCE_REALM], "")?,
        kdc,
        &service,
        tab,
    )?;
    let user = Principal::user(SERVICE_REALM, "alice");
    // When the service delegates the user to the target.
    let delegation = explained(
        client
            .delegate(
                S4uIdentity::Principal(user.clone()),
                target.clone(),
                DelegationOptions::new(),
            )
            .await,
        kdc,
    )?;
    // Then the target's key opens a ticket in the user's name.
    assert_eq!(delegation.ticket().client(), &user);
    assert_eq!(delegation.ticket().service(), &target);
    assert_eq!(
        decrypted_client(delegation.ticket().ticket(), &target_key)?,
        "alice"
    );
    let last = kdc.log().last().cloned().ok_or("no request")?;
    assert_eq!(
        last.0, RESOURCE_REALM,
        "the last request goes to the target realm"
    );
    Ok(())
}

/// A target that does not trust the service refuses the delegation.
#[tokio::test]
async fn rbcd_to_an_untrusting_target_is_refused() -> Result<(), TestError> {
    // Given a target in the service realm that trusts nobody.
    let service = Principal::user(SERVICE_REALM, "svc");
    let (tab, key) = keytab(&service, "service-password")?;
    let target = Principal::new(SERVICE_REALM, 2, ["HTTP", "denied.svc.test"]);
    let (_, target_key) = keytab(&target, "target-password")?;
    let kdc = Kdc::new(&[])
        .with_service(service.clone(), key)
        .with_service(target.clone(), target_key)
        .leak();
    let mut client = client(profile(&[SERVICE_REALM], "")?, kdc, &service, tab)?;
    // When the service delegates to it.
    let refused = client
        .delegate(
            S4uIdentity::Principal(Principal::user(SERVICE_REALM, "alice")),
            target,
            DelegationOptions::new(),
        )
        .await;
    // Then the KDC's refusal is returned.
    assert!(
        matches!(&refused, Err(ClientError::Kdc(error)) if error.error_code() == 13_i32),
        "{refused:?}"
    );
    Ok(())
}

/// GO-client-3 and GO-messages-1: the user-to-user ticket is sealed in the
/// session key of the target's TGT.
#[tokio::test]
async fn user_to_user_ticket_is_sealed_in_the_target_tgt_session_key() -> Result<(), TestError> {
    // Given alice and bob of one realm, bob with a TGT.
    let alice = Principal::user(USER_REALM, "alice");
    let (tab, _) = keytab(&alice, "alice-password")?;
    let bob = Principal::user(USER_REALM, "bob");
    let kdc = Kdc::new(&[]).leak();
    let bob_tgt = kdc.tgt(bob.clone())?;
    let mut client = client(profile(&[USER_REALM], "")?, kdc, &alice, tab)?;
    // When alice asks for a user-to-user ticket to bob.
    let ticket = explained(
        client
            .user_to_user_ticket(bob.clone(), bob_tgt.ticket())
            .await,
        kdc,
    )?;
    // Then bob's TGT session key opens it.
    assert_eq!(ticket.service(), &bob);
    assert_eq!(
        decrypted_client(ticket.ticket(), bob_tgt.session_key())?,
        "alice"
    );
    Ok(())
}

/// MIT-client-12 and MIT-config-42 (`vfy_increds.c:259-321` and the plan's
/// truth table): the host key verifies; a wrong key for the host principal is
/// rejected whatever nofail says; no host key is an error unless nofail is
/// `false`, from the call or from the profile.
#[tokio::test]
async fn verify_init_creds_follows_the_nofail_truth_table() -> Result<(), TestError> {
    // Given a host service whose key the KDC seals tickets in.
    let alice = Principal::user(USER_REALM, "alice");
    let (tab, _) = keytab(&alice, "alice-password")?;
    let host = Principal::new(USER_REALM, 2, ["host", "box.user.test"]);
    let (host_tab, host_key) = keytab(&host, "host-password")?;
    let (wrong_tab, _) = keytab(&host, "not-the-host-password")?;
    let (http_tab, _) = keytab(
        &Principal::new(USER_REALM, 2, ["HTTP", "box.user.test"]),
        "http-password",
    )?;
    let kdc = Kdc::new(&[]).with_service(host.clone(), host_key).leak();
    let mut client = client(profile(&[USER_REALM], "")?, kdc, &alice, tab.clone())?;
    // Then the real host key verifies.
    assert_eq!(
        client
            .verify_init_creds(&host_tab, VerifyOptions::new())
            .await?,
        Verification::Verified(host.clone())
    );
    // And a wrong host key is rejected, nofail or not.
    for nofail in [true, false] {
        let rejected = client
            .verify_init_creds(&wrong_tab, VerifyOptions::new().with_nofail(nofail))
            .await;
        assert!(
            matches!(rejected, Err(ClientError::VerifyInitCredsRejected(_))),
            "{rejected:?}"
        );
    }
    // And no host key is an error, unset or true, and a skip only for false.
    for options in [VerifyOptions::new(), VerifyOptions::new().with_nofail(true)] {
        let missing = client.verify_init_creds(&http_tab, options).await;
        assert!(
            matches!(missing, Err(ClientError::VerifyInitCredsNoHostKey)),
            "{missing:?}"
        );
    }
    assert_eq!(
        client
            .verify_init_creds(&http_tab, VerifyOptions::new().with_nofail(false))
            .await?,
        Verification::Skipped
    );
    // And the profile's verify_ap_req_nofail = false tolerates it too; true does not.
    for (setting, skipped) in [("false", true), ("true", false)] {
        let profiled = profile(
            &[USER_REALM],
            &format!("[libdefaults]\n verify_ap_req_nofail = {setting}\n"),
        )?;
        let mut configured = self::client(profiled, kdc, &alice, tab.clone())?;
        let result = configured
            .verify_init_creds(&http_tab, VerifyOptions::new())
            .await;
        assert_eq!(
            matches!(result, Ok(Verification::Skipped)),
            skipped,
            "{setting}: {result:?}"
        );
    }
    Ok(())
}

/// Same-realm resource-based delegation (`s4u_creds.c:1004-1016`): the
/// service's own KDC answers the `S4U2Proxy` request with the target's
/// ticket, which ends the exchange; the evidence of the first leg names the
/// user and the service.
#[tokio::test]
async fn same_realm_rbcd_ends_with_the_first_proxy_reply() -> Result<(), TestError> {
    // Given a target in the service realm that trusts the service.
    let service = Principal::user(SERVICE_REALM, "svc");
    let (tab, key) = keytab(&service, "service-password")?;
    let target = Principal::new(SERVICE_REALM, 2, ["HTTP", "app.svc.test"]);
    let (_, target_key) = keytab(&target, "target-password")?;
    let kdc = Kdc::new(&[])
        .with_service(service.clone(), key.clone())
        .with_service(target.clone(), target_key.clone())
        .with_delegation(service.clone(), target.clone())
        .leak();
    let mut client = client(profile(&[SERVICE_REALM], "")?, kdc, &service, tab)?;
    let user = Principal::user(SERVICE_REALM, "alice");
    // When the service delegates the user to the target.
    let delegation = explained(
        client
            .delegate(
                S4uIdentity::Principal(user.clone()),
                target.clone(),
                DelegationOptions::new(),
            )
            .await,
        kdc,
    )?;
    // Then the evidence is the user's ticket to the service.
    assert_eq!(delegation.evidence().client(), &user);
    assert_eq!(delegation.evidence().service().components, service.components);
    assert_eq!(decrypted_client(delegation.evidence().ticket(), &key)?, "alice");
    // And the target's key opens the delegated ticket in the user's name.
    assert_eq!(delegation.ticket().client(), &user);
    assert_eq!(delegation.ticket().service(), &target);
    assert_eq!(
        decrypted_client(delegation.ticket().ticket(), &target_key)?,
        "alice"
    );
    // And the KDC saw exactly the S4U2Self and the S4U2Proxy request.
    let requested: Vec<Vec<String>> = kdc
        .log()
        .into_iter()
        .map(|(realm, principal)| {
            assert_eq!(realm, SERVICE_REALM, "every request stays in the service realm");
            principal.components
        })
        .collect();
    assert_eq!(requested, [service.components.clone(), target.components]);
    Ok(())
}

/// A certificate `S4U2Self` reply without the `PA-S4U-X509-USER` answer names
/// no user, so the request is refused as modified (MIT `s4u_creds.c:302-310`
/// and `:529-533`).
#[tokio::test]
async fn certificate_s4u2self_without_the_kdc_answer_is_refused() -> Result<(), TestError> {
    // Given a KDC that maps the certificate to carol but omits its answer.
    let service = Principal::user(SERVICE_REALM, "svc");
    let (tab, key) = keytab(&service, "service-password")?;
    let kdc = Kdc::new(&[])
        .with_service(service.clone(), key)
        .with_certificate_user(Principal::user(SERVICE_REALM, "carol"))
        .without_s4u_answer()
        .leak();
    let mut client = client(profile(&[SERVICE_REALM], "")?, kdc, &service, tab)?;
    // When the service asks for the user of a certificate.
    let identity = CertificateIdentity::new(vec![0x30, 0x03, 0x02, 0x01, 0x05], SERVICE_REALM)?;
    let refused = client
        .s4u2self_identity(S4uIdentity::Certificate(identity), DelegationOptions::new())
        .await;
    // Then the reply is refused as modified, after one request.
    assert!(
        matches!(refused, Err(ClientError::S4uReplyModified)),
        "{refused:?}"
    );
    assert_eq!(kdc.log().len(), 1);
    Ok(())
}

/// A named-user `S4U2Self` reply without the `PA-S4U-X509-USER` answer is
/// accepted as an older KDC's (MIT `s4u_creds.c:302-310`): the evidence is
/// still bound to the requested user through its decrypted part.
#[tokio::test]
async fn named_s4u2self_without_the_kdc_answer_is_bound_to_the_user() -> Result<(), TestError> {
    // Given a KDC that omits the PA-S4U-X509-USER answer.
    let service = Principal::user(SERVICE_REALM, "svc");
    let (tab, key) = keytab(&service, "service-password")?;
    let kdc = Kdc::new(&[])
        .with_service(service.clone(), key.clone())
        .without_s4u_answer()
        .leak();
    let mut client = client(profile(&[SERVICE_REALM], "")?, kdc, &service, tab)?;
    let user = Principal::user(SERVICE_REALM, "alice");
    // When the service impersonates the user.
    let evidence = explained(
        client
            .s4u2self_identity(S4uIdentity::Principal(user.clone()), DelegationOptions::new())
            .await,
        kdc,
    )?;
    // Then the evidence names the user and decrypts to the user.
    assert_eq!(evidence.client(), &user);
    assert_eq!(decrypted_client(evidence.ticket(), &key)?, "alice");
    Ok(())
}

/// MIT `vfy_increds.c:222-257`: a host principal with several keys in the
/// keytab is one candidate, and its key verifies.
#[tokio::test]
async fn verify_init_creds_takes_a_host_principal_once() -> Result<(), TestError> {
    // Given a host keytab with two key versions of one host principal.
    let alice = Principal::user(USER_REALM, "alice");
    let (tab, _) = keytab(&alice, "alice-password")?;
    let host = Principal::new(USER_REALM, 2, ["host", "box.user.test"]);
    let (mut host_tab, host_key) = keytab(&host, "host-password")?;
    host_tab.add_entry_from_password(
        KeytabPrincipal::new(USER_REALM, 2, ["host", "box.user.test"]),
        Zeroizing::new(b"older-host-password".to_vec()),
        SystemTime::now(),
        0,
        18,
    )?;
    assert_eq!(host_tab.entries().len(), 2);
    let kdc = Kdc::new(&[]).with_service(host.clone(), host_key).leak();
    let mut client = client(profile(&[USER_REALM], "")?, kdc, &alice, tab)?;
    // When the credentials are verified with it.
    let verified = client
        .verify_init_creds(&host_tab, VerifyOptions::new())
        .await?;
    // Then the host principal verifies, after one ticket request for it.
    assert_eq!(verified, Verification::Verified(host.clone()));
    assert_eq!(
        kdc.log()
            .into_iter()
            .filter(|(_, requested)| requested.components == host.components)
            .count(),
        1
    );
    Ok(())
}

/// The referral-following TGS exchange reports the service ticket and the
/// cross-realm TGT it crossed on the way (`get_creds.c:561-634`).
#[tokio::test]
async fn referral_trace_reports_the_ticket_and_the_crossed_tgt() -> Result<(), TestError> {
    // Given a user in USER.TEST and a service in RES.TEST, the realms trusting each other.
    let alice = Principal::user(USER_REALM, "alice");
    let target = Principal::new(RESOURCE_REALM, 2, ["HTTP", "app.res.test"]);
    let (_, target_key) = keytab(&target, "target-password")?;
    let kdc = Kdc::new(&[(USER_REALM, RESOURCE_REALM)])
        .with_service(target.clone(), target_key.clone())
        .leak();
    let tgt = kdc.tgt(alice.clone())?;
    // When the user asks for a ticket to the service.
    let result = explained(
        Transport::new()
            .with_kdc_proxy(kdc)
            .get_service_ticket_with_referral_trace(
                &profile(&[USER_REALM, RESOURCE_REALM], "")?,
                KdcProtocol::Tcp,
                &tgt,
                target.clone(),
                TgsReq::new(SystemTime::now(), 0x0a0b_0c0d).with_etypes(vec![18_i32]),
            )
            .await,
        kdc,
    )?;
    // Then the ticket is the user's ticket to the service.
    assert_eq!(result.ticket().client(), &alice);
    assert_eq!(result.ticket().service(), &target);
    assert_eq!(
        decrypted_client(result.ticket().ticket(), &target_key)?,
        "alice"
    );
    // And the one crossed TGT is krbtgt/RES.TEST@USER.TEST.
    let crossed: Vec<&Principal> = result.referral_tgts().iter().map(|tgt| tgt.service()).collect();
    assert_eq!(
        crossed,
        [&Principal::new(USER_REALM, 2, ["krbtgt", RESOURCE_REALM])]
    );
    Ok(())
}

/// `KDCOptions` forwardable.
const FORWARDABLE: u32 = 0x4000_0000;
/// `KDCOptions` proxiable.
const PROXIABLE: u32 = 0x1000_0000;
/// `KDCOptions` canonicalize.
const CANONICALIZE: u32 = 0x0001_0000;

/// A cross-realm certificate `S4U2Self` sends the certificate on the first
/// hop only (MIT `s4u_creds.c:420-490`): the user's KDC names the user, and
/// the request back to the service's realm carries that name instead.
#[tokio::test]
async fn cross_realm_certificate_s4u2self_sends_the_certificate_once() -> Result<(), TestError> {
    // Given a service in SVC.TEST and a certificate the USER.TEST KDC maps to alice.
    let service = Principal::user(SERVICE_REALM, "svc");
    let (tab, key) = keytab(&service, "service-password")?;
    let alice = Principal::user(USER_REALM, "alice");
    let kdc = Kdc::new(&[(SERVICE_REALM, USER_REALM)])
        .with_service(service.clone(), key.clone())
        .with_certificate_user(alice.clone())
        .leak();
    let mut client = client(
        profile(&[SERVICE_REALM, USER_REALM], "")?,
        kdc,
        &service,
        tab,
    )?;
    // When the service asks for the user of a USER.TEST certificate.
    let identity = CertificateIdentity::new(vec![0x30, 0x03, 0x02, 0x01, 0x05], USER_REALM)?;
    let evidence = explained(
        client
            .s4u2self_identity(S4uIdentity::Certificate(identity), DelegationOptions::new())
            .await,
        kdc,
    )?;
    // Then the evidence names alice, and only the first S4U request carried the certificate.
    assert_eq!(evidence.client(), &alice);
    assert_eq!(decrypted_client(evidence.ticket(), &key)?, "alice");
    let certified: Vec<bool> = kdc
        .s4u_requests()
        .into_iter()
        .map(|(_, certified)| certified)
        .collect();
    assert_eq!(certified, [true, false]);
    Ok(())
}

/// The `S4U2Self` request keeps the profile's options and adds CANONICALIZE,
/// and FORWARDABLE when the delegation asks for forwardable evidence
/// (MIT `s4u_creds.c:557-561`).
#[tokio::test]
async fn s4u2self_options_add_canonicalize_and_forwardable() -> Result<(), TestError> {
    let cases = [
        (" forwardable = true\n proxiable = true\n canonicalize = true\n", true, true),
        (" forwardable = true\n proxiable = true\n canonicalize = true\n", false, true),
        (" proxiable = true\n", true, true),
        (" proxiable = true\n", false, false),
    ];
    for (libdefaults, forwardable, expected_forwardable) in cases {
        // Given a profile with `libdefaults` and a service with a TGT.
        let service = Principal::user(SERVICE_REALM, "svc");
        let (tab, key) = keytab(&service, "service-password")?;
        let kdc = Kdc::new(&[])
            .with_service(service.clone(), key)
            .leak();
        let profiled = profile(&[SERVICE_REALM], libdefaults)?;
        let mut client = client(profiled, kdc, &service, tab)?;
        // When the service impersonates alice.
        drop(explained(
            client
                .s4u2self_identity(
                    S4uIdentity::Principal(Principal::user(SERVICE_REALM, "alice")),
                    DelegationOptions::new().with_forwardable(forwardable),
                )
                .await,
            kdc,
        )?);
        // Then the request asks for the profile's options plus CANONICALIZE,
        // and FORWARDABLE from the profile or the delegation.
        let [(options, _)] = kdc.s4u_requests()[..] else {
            return Err(format!("{libdefaults:?} {forwardable}: one S4U request expected").into());
        };
        let case = format!("{libdefaults:?} {forwardable}: {options:#010x}");
        assert_eq!(options & CANONICALIZE, CANONICALIZE, "{case}");
        assert_eq!(options & PROXIABLE, PROXIABLE, "{case}");
        assert_eq!(options & FORWARDABLE != 0, expected_forwardable, "{case}");
    }
    Ok(())
}
