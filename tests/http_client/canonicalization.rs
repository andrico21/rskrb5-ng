//! The service name of `HTTP/<host>` under an explicit host-name policy.
//!
//! MIT-dns-4, FU-HTC-P08: canonicalization may change the principal the token
//! is for and nothing else. The TLS peer, the `Host`, the redirect and cookie
//! origin and the channel binding stay the URI host's.

use alloc::sync::Arc;

use http_types::StatusCode;
use pretty_assertions::assert_eq;
use rskrb5_ng::{Config, error::HttpClient as ClientError, http::agent::NegotiateHttpClient};

use super::{
    context::{Context as _, TestError},
    support::{Kerberos, Network, negotiate_client_in, redirect, run},
};

/// The host the caller asks for: one label.
const SHORT: &str = "short";
/// Its qualified form, the host the Kerberos service is registered under.
const CANONICAL: &str = "short.example.com";

/// A profile that qualifies one-label hosts and asks DNS nothing.
fn profile() -> Result<Config, TestError> {
    Ok(Config::parse(
        "[libdefaults]\n default_realm = EXAMPLE.COM\n dns_lookup_kdc = false\n\
         dns_lookup_realm = false\n dns_canonicalize_hostname = false\n\
         qualify_shortname = example.com\n[realms]\n EXAMPLE.COM = {\n kdc = 127.0.0.1:1\n }\n",
    )?)
}

/// A client for `network` holding a ticket for `HTTP/<CANONICAL>` only.
fn client(network: &Network) -> Result<NegotiateHttpClient<Network>, TestError> {
    Ok(NegotiateHttpClient::new(
        negotiate_client_in(profile()?, &[CANONICAL])?,
        network.clone(),
    ))
}

/// The network of one origin, `short`, whose Kerberos service is `CANONICAL`'s.
fn network() -> Result<Network, TestError> {
    let server = Arc::new(Kerberos::new(&[CANONICAL]));
    Network::new().serve(&format!("https://{SHORT}/"), move |request| {
        server.respond(request, &|_| http_types::Response::new(b"ok".to_vec()))
    })
}

/// With a policy that approves the qualified name, the token is for
/// `HTTP/short.example.com` while every request goes to `short`.
#[test]
fn http_host_target_uses_explicit_canonicalization() -> Result<(), TestError> {
    let network = network()?;
    let approve = |_requested: &str, candidate: &str| candidate == CANONICAL;
    let mut client = client(&network)?.with_host_name_policy(approve);
    let result = run(async { client.get(&format!("https://{SHORT}/page")).await })??;
    assert_eq!(result.response().status(), StatusCode::OK);
    let context = result.context().context("the final request had a token")?;
    assert_eq!(
        context.service().components,
        ["HTTP".to_owned(), CANONICAL.to_owned()]
    );
    let seen = network.seen_by(&format!("https://{SHORT}/"))?;
    assert_eq!(seen.len(), 2, "the challenge and the authenticated request");
    assert!(seen.iter().all(|request| request.target == "/page"));
    Ok(())
}

/// Without a policy the client never canonicalizes: the service is the URI host's,
/// no ticket for it exists, and no token is sent.
#[test]
fn default_http_client_does_not_canonicalize() -> Result<(), TestError> {
    let network = network()?;
    let mut client = client(&network)?;
    let result = run(async { client.get(&format!("https://{SHORT}/page")).await })?;
    assert!(
        matches!(result, Err(ClientError::Negotiate(_))),
        "{:?}",
        result.err()
    );
    let seen = network.seen_by(&format!("https://{SHORT}/"))?;
    assert!(seen.iter().all(|request| request.authorization().is_none()));
    Ok(())
}

/// A policy that approves nothing sends no token, and the failure names the host.
#[test]
fn an_unapproved_name_sends_no_token() -> Result<(), TestError> {
    let network = network()?;
    let mut client = client(&network)?.with_host_name_policy(|_: &str, _: &str| false);
    let result = run(async { client.get(&format!("https://{SHORT}/page")).await })?;
    assert!(matches!(result, Err(ClientError::Negotiate(_))));
    let seen = network.seen_by(&format!("https://{SHORT}/"))?;
    assert!(seen.iter().all(|request| request.authorization().is_none()));
    Ok(())
}

/// The canonical name never becomes the origin: a redirect to it is another
/// origin and is returned, not followed, and the other origin sees nothing.
#[test]
fn canonicalization_cannot_change_http_origin() -> Result<(), TestError> {
    let server = Arc::new(Kerberos::new(&[CANONICAL]));
    let moved = redirect(StatusCode::FOUND, &format!("https://{CANONICAL}/page"))?;
    let network = Network::new()
        .serve(&format!("https://{SHORT}/"), move |request| {
            server.respond(request, &|_| moved.clone())
        })?
        .serve(&format!("https://{CANONICAL}/"), |_| {
            http_types::Response::new(b"canonical origin".to_vec())
        })?;
    let approve = |_requested: &str, candidate: &str| candidate == CANONICAL;
    let mut client = client(&network)?.with_host_name_policy(approve);
    let result = run(async { client.get(&format!("https://{SHORT}/page")).await })??;
    assert_eq!(result.response().status(), StatusCode::FOUND);
    assert_eq!(result.uri().host(), Some(SHORT));
    assert_eq!(network.seen_by(&format!("https://{CANONICAL}/"))?.len(), 0);
    Ok(())
}
