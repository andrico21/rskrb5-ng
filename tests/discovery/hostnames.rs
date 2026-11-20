//! Hostname canonicalization (MIT-config-14, -34, -35, MIT-dns-4).

use hickory_resolver::proto::rr::RecordType;
use rskrb5_ng::{
    client::transport::Tokio, config::Config, discovery::hostname::CanonicalizationPolicy,
};

use crate::{
    TestError,
    fixture::{Dns, Reply, cname, documentation, ptr},
};

/// A transport that asks `dns`.
fn via(dns: &Dns) -> Result<Tokio, TestError> {
    Ok(Tokio::new().with_dns_server(&dns.address().to_string())?)
}

/// The policy of a profile with the given `[libdefaults]` lines.
fn policy(lines: &str) -> Result<CanonicalizationPolicy, TestError> {
    Ok(CanonicalizationPolicy::from_config(&Config::parse(
        &format!("[libdefaults]\n{lines}\n"),
    )?))
}

/// A zone where `short` is a CNAME of `real.example.com`, whose address has a PTR name.
async fn zone() -> Result<Dns, TestError> {
    Dns::start([
        (
            "short.",
            RecordType::A,
            Reply::Owned(vec![
                ("short.", cname("real.example.com.")?),
                ("real.example.com.", documentation()),
            ]),
        ),
        (
            "real.example.com.",
            RecordType::A,
            Reply::Records(vec![documentation()]),
        ),
        (
            "7.2.0.192.in-addr.arpa.",
            RecordType::PTR,
            Reply::Records(vec![ptr("Ptr.Example.COM.")?]),
        ),
    ])
    .await
}

/// MIT-config-14: `true` is DNS only, `false` none, `fallback` none first and DNS second.
#[test]
fn the_three_modes_order_their_forms() -> Result<(), TestError> {
    for (value, forms) in [
        ("true", &[true][..]),
        ("false", &[false][..]),
        ("fallback", &[false, true][..]),
    ] {
        assert_eq!(
            policy(&format!("dns_canonicalize_hostname = {value}"))?.uses_dns(),
            forms,
            "{value}"
        );
    }
    Ok(())
}

/// MIT-config-34: a one-label name gets the suffix only without DNS and only when one is set.
#[test]
fn qualify_shortname_adds_a_suffix_to_one_label_names() -> Result<(), TestError> {
    let set = policy("qualify_shortname = Example.ORG")?;
    assert_eq!(set.expand_without_dns("KDC"), "kdc.example.org");
    assert_eq!(set.expand_without_dns("kdc.other.net."), "kdc.other.net");
    for lines in ["qualify_shortname = \"\"", "rdns = true"] {
        assert_eq!(policy(lines)?.expand_without_dns("Kdc."), "kdc", "{lines}");
    }
    Ok(())
}

/// MIT-config-14, -35: DNS follows the CNAME, and `rdns` then takes the PTR name of the address.
#[tokio::test]
async fn dns_canonicalization_follows_the_name_and_then_the_address() -> Result<(), TestError> {
    // Given a zone with a CNAME and a PTR record.
    let dns = zone().await?;
    let transport = via(&dns)?;
    // When a short name is expanded with DNS, with and without `rdns`.
    let forward = policy("rdns = false")?
        .expand(&transport, "SHORT", true)
        .await?;
    let reverse = policy("rdns = true")?
        .expand(&transport, "SHORT", true)
        .await?;
    // Then the forward name is the CNAME target, and the reverse name replaces it.
    assert_eq!(forward, "real.example.com");
    assert_eq!(reverse, "ptr.example.com");
    Ok(())
}

/// An address literal is not looked up forward; `rdns` names it.
#[tokio::test]
async fn an_address_literal_is_named_only_by_the_reverse_lookup() -> Result<(), TestError> {
    let dns = zone().await?;
    let transport = via(&dns)?;
    let reverse = policy("rdns = true")?
        .expand(&transport, "192.0.2.7", true)
        .await?;
    let none = policy("rdns = false")?
        .expand(&transport, "192.0.2.7", true)
        .await?;
    assert_eq!(reverse, "ptr.example.com");
    assert_eq!(none, "192.0.2.7");
    assert!(
        dns.questions()?
            .iter()
            .all(|question| question.starts_with("PTR")),
        "{:?}",
        dns.questions()?
    );
    Ok(())
}

/// A lookup that fails leaves the name as it was, and a name longer than a DNS name is
/// not looked up at all.
#[tokio::test]
async fn a_failed_lookup_keeps_the_name() -> Result<(), TestError> {
    let dns = Dns::start([]).await?;
    let transport = via(&dns)?;
    let any = policy("rdns = true\nqualify_shortname = example.org")?;
    // A short name that DNS does not know counts as not canonicalized, so it is qualified:
    // MIT's `qualify_shortname` applies "because forward canonicalization failed".
    assert_eq!(
        any.expand(&transport, "Nowhere", true).await?,
        "nowhere.example.org"
    );
    let long = format!("{}.example", "a".repeat(300));
    let before = dns.questions()?.len();
    assert_eq!(any.expand(&transport, &long, true).await?, long);
    assert_eq!(dns.questions()?.len(), before);
    Ok(())
}

/// MIT-dns-4: `fallback` yields the plain name and then the DNS name, without duplicates.
#[tokio::test]
async fn fallback_candidates_are_distinct_and_ordered() -> Result<(), TestError> {
    let dns = zone().await?;
    let transport = via(&dns)?;
    let both = policy("dns_canonicalize_hostname = fallback\nrdns = false")?;
    assert_eq!(
        both.candidates(&transport, "short").await?,
        ["short", "real.example.com"]
    );
    assert_eq!(
        both.candidates(&transport, "real.example.com").await?,
        ["real.example.com"]
    );
    let never = policy("dns_canonicalize_hostname = false")?;
    assert_eq!(never.candidates(&transport, "short").await?, ["short"]);
    Ok(())
}
