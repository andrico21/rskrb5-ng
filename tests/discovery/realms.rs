//! Host-to-realm mapping: opt-in TXT records, `realm_try_domains`, the provider chain
//! (MIT-config-16, -36, MIT-dns-3, MIT-authz-6, MIT-plugin-3).

extern crate alloc;

use alloc::sync::Arc;

use hickory_resolver::proto::{op::ResponseCode, rr::RecordType};
use rskrb5_ng::{
    client::transport::Tokio,
    config::Config,
    error::Client as ClientError,
    extensions::{Extension, HostRealm, ProviderError, RealmQuery, Registry},
};

use crate::{
    TestError,
    fixture::{Dns, Reply, txt},
};

/// A transport that asks `dns`.
fn via(dns: &Dns) -> Result<Tokio, TestError> {
    Ok(Tokio::new().with_dns_server(&dns.address().to_string())?)
}

/// A profile with the given `[libdefaults]` lines and realm entries.
fn profile(lines: &str, realms: &str) -> Result<Config, TestError> {
    Ok(Config::parse(&format!("[libdefaults]\n{lines}\n{realms}"))?)
}

/// MIT-config-16: with `dns_lookup_realm` off (the default) no TXT record is asked.
#[tokio::test]
async fn txt_lookup_is_off_by_default() -> Result<(), TestError> {
    // Given a TXT record that would name another realm than the domain heuristic.
    let dns = Dns::start([(
        "_kerberos.host.example.com.",
        RecordType::TXT,
        Reply::Records(vec![txt("TXT.REALM")]),
    )])
    .await?;
    // When the fallback realm of the host is asked with and without the relation.
    let off = profile("dns_lookup_realm = false", "")?;
    let on = profile("dns_lookup_realm = true", "")?;
    let without = via(&dns)?
        .host_realms(&off)
        .fallback_realm(None, "host.example.com")
        .await?;
    let asked_off = dns.questions()?.len();
    let with = via(&dns)?
        .host_realms(&on)
        .fallback_realm(None, "host.example.com")
        .await?;
    // Then only the enabled relation asks, and it wins over the parent-domain heuristic.
    assert_eq!(without.as_deref(), Some("EXAMPLE.COM"));
    assert_eq!(asked_off, 0);
    assert_eq!(with.as_deref(), Some("TXT.REALM"));
    Ok(())
}

/// The TXT lookup walks the host and its parents, a trailing dot is removed, and an
/// untrusted value that is not a realm name is ignored.
#[tokio::test]
async fn txt_lookup_walks_the_parents_and_distrusts_the_answer() -> Result<(), TestError> {
    // Given a bad value at the host, a good one with a trailing dot at the parent.
    let dns = Dns::start([
        (
            "_kerberos.a.b.example.com.",
            RecordType::TXT,
            Reply::Records(vec![txt("BAD@REALM")]),
        ),
        (
            "_kerberos.example.com.",
            RecordType::TXT,
            Reply::Records(vec![txt("PARENT.REALM.")]),
        ),
    ])
    .await?;
    let on = profile("dns_lookup_realm = true", "")?;
    // When the realm of a host is asked.
    let realm = via(&dns)?
        .host_realms(&on)
        .fallback_realm(None, "A.B.Example.COM.")
        .await?;
    // Then the walk goes host, parent, parent and stops at the first valid answer.
    assert_eq!(realm.as_deref(), Some("PARENT.REALM"));
    assert_eq!(
        dns.questions()?,
        [
            "TXT _kerberos.a.b.example.com.",
            "TXT _kerberos.b.example.com.",
            "TXT _kerberos.example.com."
        ]
    );
    Ok(())
}

/// An address literal is never looked up, and a failing TXT lookup is an error.
#[tokio::test]
async fn txt_lookup_skips_addresses_and_reports_failures() -> Result<(), TestError> {
    // Given a zone whose TXT lookups fail.
    let dns = Dns::start([(
        "_kerberos.host.example.com.",
        RecordType::TXT,
        Reply::Code(ResponseCode::ServFail),
    )])
    .await?;
    let on = profile("dns_lookup_realm = true", "")?;
    let resolver = via(&dns)?;
    // When literals and then a name are asked.
    let v4 = resolver
        .host_realms(&on)
        .fallback_realm(None, "192.0.2.1")
        .await?;
    let v6 = resolver
        .host_realms(&on)
        .fallback_realm(None, "fd00::1")
        .await?;
    let failed = resolver
        .host_realms(&on)
        .fallback_realm(None, "host.example.com")
        .await;
    // Then literals give no realm and no query, and the failure is not turned into a parent's answer.
    assert_eq!((v4, v6), (None, None));
    assert!(
        matches!(
            failed,
            Err(ClientError::DnsSrvLookup {
                realm: _,
                protocol: _,
                message: _
            })
        ),
        "{failed:?}"
    );
    assert!(
        dns.questions()?
            .iter()
            .all(|question| question.contains("host.example.com")),
        "the walk went on to a parent: {:?}",
        dns.questions()?
    );
    Ok(())
}

/// MIT-config-36: `realm_try_domains` searches the host's domain and as many parents as it
/// says, only names that are realms, never a one-label name.
#[tokio::test]
async fn realm_try_domains_is_bounded_and_needs_a_realm() -> Result<(), TestError> {
    // Given a realm for the grandparent domain only.
    let dns = Dns::start([]).await?;
    let realms = "[realms]\nEXAMPLE.COM = {\nkdc = kdc.example.com\n}\n";
    // When the realm of a.b.example.com is asked with each limit.
    let mut found = Vec::new();
    for limit in [-1_i32, 0_i32, 1_i32, 5_i32] {
        let config = profile(&format!("realm_try_domains = {limit}"), realms)?;
        found.push(
            via(&dns)?
                .host_realms(&config)
                .fallback_realm(None, "a.b.example.com")
                .await?,
        );
    }
    // Then -1 and 0 reach no realm and use the parent domain, 1 and more find EXAMPLE.COM.
    let expected: Vec<Option<String>> = vec![
        Some("B.EXAMPLE.COM".to_owned()),
        Some("B.EXAMPLE.COM".to_owned()),
        Some("EXAMPLE.COM".to_owned()),
        Some("EXAMPLE.COM".to_owned()),
    ];
    assert_eq!(found, expected);
    Ok(())
}

/// A bounded search asks no one-label realm, however large the limit.
#[tokio::test]
async fn realm_try_domains_stops_before_a_one_label_name() -> Result<(), TestError> {
    // Given DNS discovery of KDCs and a large limit, with no realm anywhere.
    let dns = Dns::start([]).await?;
    let config = profile("dns_lookup_kdc = true\nrealm_try_domains = 99", "")?;
    // When the realm of a deep host is asked.
    let realm = via(&dns)?
        .host_realms(&config)
        .fallback_realm(None, "a.b.example.com")
        .await?;
    // Then the parent domain is the answer, and `com` was never tried as a realm.
    assert_eq!(realm.as_deref(), Some("B.EXAMPLE.COM"));
    let questions = dns.questions()?;
    assert!(
        questions
            .iter()
            .any(|question| question.contains("_kerberos._udp.example.com.")),
        "{questions:?}"
    );
    assert!(
        questions
            .iter()
            .all(|question| !question.ends_with("._udp.com.")),
        "{questions:?}"
    );
    Ok(())
}

/// A registered mapper answers before the profile.
struct Mapper;

impl HostRealm for Mapper {
    fn id(&self) -> &'static str {
        "mapper"
    }

    fn realms(&self, query: &RealmQuery<'_>) -> Result<Option<Vec<String>>, ProviderError> {
        if matches!(query, RealmQuery::Host("mapped.example.com")) {
            Ok(Some(vec!["PROVIDED.REALM".to_owned()]))
        } else if matches!(query, RealmQuery::Default) {
            Ok(Some(vec!["DEFAULT.PROVIDED".to_owned()]))
        } else {
            Ok(None)
        }
    }
}

/// MIT-authz-6, MIT-plugin-3: registered mappers, then `[domain_realm]`, then `default_realm`.
#[tokio::test]
async fn the_provider_chain_is_registry_then_profile_then_default() -> Result<(), TestError> {
    // Given a mapper, a `[domain_realm]` entry and a default realm.
    let dns = Dns::start([]).await?;
    let mut registry = Registry::new();
    registry.register(Extension::HostRealm(Arc::new(Mapper)))?;
    let config = profile(
        "default_realm = DEFAULT.REALM",
        "[domain_realm]\n.example.com = DOMAIN.REALM\n",
    )?;
    let transport = via(&dns)?;
    let resolver = transport.host_realms(&config);
    let chained = Some(&registry);
    // When hosts are mapped without and with the registry.
    let results = (
        resolver.host_realm(None, "mapped.example.com")?,
        resolver.host_realm(chained, "mapped.example.com")?,
        resolver.host_realm(chained, "other.example.com")?,
        resolver.service_realm(None, "elsewhere.test").await?,
        resolver.default_realm(chained, None).await?,
        resolver.default_realm(None, None).await?,
    );
    // Then each step wins in its turn, and no DNS is asked without an opt-in.
    assert_eq!(
        results,
        (
            Some("DOMAIN.REALM".to_owned()),
            Some("PROVIDED.REALM".to_owned()),
            Some("DOMAIN.REALM".to_owned()),
            Some("DEFAULT.REALM".to_owned()),
            Some("DEFAULT.PROVIDED".to_owned()),
            Some("DEFAULT.REALM".to_owned()),
        )
    );
    assert_eq!(dns.questions()?, Vec::<String>::new());
    Ok(())
}

/// With the opt-in, the service realm uses a TXT record before `default_realm`.
#[tokio::test]
async fn the_service_realm_prefers_an_opted_in_txt_record_to_the_default() -> Result<(), TestError>
{
    // Given a TXT record and a default realm.
    let dns = Dns::start([(
        "_kerberos.svc.example.net.",
        RecordType::TXT,
        Reply::Records(vec![txt("NET.REALM")]),
    )])
    .await?;
    let on = profile("default_realm = DEFAULT.REALM\ndns_lookup_realm = true", "")?;
    let off = profile("default_realm = DEFAULT.REALM", "")?;
    // When the service realm is asked with and without the relation.
    let with = via(&dns)?
        .host_realms(&on)
        .service_realm(None, "svc.example.net")
        .await?;
    let without = via(&dns)?
        .host_realms(&off)
        .service_realm(None, "svc.example.net")
        .await?;
    // Then the opt-in changes the answer.
    assert_eq!(with.as_deref(), Some("NET.REALM"));
    assert_eq!(without.as_deref(), Some("DEFAULT.REALM"));
    Ok(())
}

/// `[plugins] hostrealm` controls apply to the built-in modules (MIT-config-54).
///
/// A disabled `profile` module maps no host and gives no default realm, and
/// `enable_only` keeps only the named modules, in its order.
#[tokio::test]
async fn disabled_builtin_hostrealm_is_not_consulted() -> Result<(), TestError> {
    // Given `[domain_realm]`, a default realm and a registered mapper.
    let dns = Dns::start([]).await?;
    let mut registry = Registry::new();
    registry.register(Extension::HostRealm(Arc::new(Mapper)))?;
    let chained = Some(&registry);
    let lines = "default_realm = DEFAULT.REALM";
    let domains = "[domain_realm]\n.example.com = DOMAIN.REALM\n";
    let without_profile = profile(
        lines,
        &format!("{domains}[plugins]\nhostrealm = {{\n disable = profile\n}}\n"),
    )?;
    let profile_first = profile(
        lines,
        &format!(
            "{domains}[plugins]\nhostrealm = {{\n enable_only = profile\n enable_only = mapper\n}}\n"
        ),
    )?;
    let transport = via(&dns)?;
    // When hosts and the default realm are mapped.
    let off = transport.host_realms(&without_profile);
    let first = transport.host_realms(&profile_first);
    let results = (
        off.host_realm(None, "other.example.com")?,
        off.service_realm(None, "elsewhere.test").await?,
        off.default_realm(None, None).await?,
        off.host_realm(chained, "mapped.example.com")?,
        first.host_realm(chained, "mapped.example.com")?,
        first.default_realm(chained, None).await?,
    );
    // Then the disabled profile answers nothing, the mapper still does, and
    // `enable_only` puts the profile before the mapper.
    assert_eq!(
        results,
        (
            None,
            None,
            None,
            Some("PROVIDED.REALM".to_owned()),
            Some("DOMAIN.REALM".to_owned()),
            Some("DEFAULT.REALM".to_owned()),
        )
    );
    assert_eq!(dns.questions()?, Vec::<String>::new());
    Ok(())
}
