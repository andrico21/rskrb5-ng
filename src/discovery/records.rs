//! DNS lookups of the discovery chain: names, URI and TXT answers, bounds.

use core::net::IpAddr;

use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig},
    net::runtime,
    proto::rr::{RData, RecordType},
};

use crate::{client::transport::KdcProtocol, discovery::uri, error::Client as Error};

/// The DNS record type code of URI records (RFC 7553); the resolver has no typed form.
const URI_TYPE: u16 = 256;

/// Build the DNS resolver using the explicitly selected server, if any.
///
/// # Errors
///
/// Returns [`Error::DnsResolverConfig`] when the override is invalid or the
/// resolver cannot be built.
pub(crate) fn dns_resolver(server: Option<(IpAddr, u16)>) -> Result<TokioResolver, Error> {
    if let Some((ip, port)) = server {
        let mut udp = ConnectionConfig::udp();
        udp.port = port;
        let mut tcp = ConnectionConfig::tcp();
        tcp.port = port;

        let mut config = ResolverConfig::default();
        config.name_servers = vec![NameServerConfig::new(ip, true, vec![udp, tcp])];

        return TokioResolver::builder_with_config(
            config,
            runtime::TokioRuntimeProvider::default(),
        )
        .build()
        .map_err(|source| Error::DnsResolverConfig(source.to_string()));
    }

    TokioResolver::builder_tokio()
        .map_err(|source| Error::DnsResolverConfig(source.to_string()))?
        .build()
        .map_err(|source| Error::DnsResolverConfig(source.to_string()))
}

/// The label `<service>.[<protocol>.][<site>._sites.]<realm>.`, as MIT's
/// `make_lookup_name` builds it (`src/lib/krb5/os/dnssrv.c:42-75`), always fully
/// qualified so that the resolver adds no search domain.
pub(crate) fn lookup_name(
    service: &str,
    label: Option<&str>,
    site: Option<&str>,
    realm: &str,
) -> String {
    let mut name = format!("{service}.");
    if let Some(transport) = label {
        name.push_str(transport);
        name.push('.');
    }
    if let Some(named) = site {
        name.push_str(named);
        name.push_str("._sites.");
    }
    name.push_str(realm);
    if !name.ends_with('.') {
        name.push('.');
    }
    name
}

/// The URI records of one name as `(priority, target)`, ordered by priority.
///
/// MIT collects `priority`, `weight` and the target text and orders by priority
/// alone, keeping the order of records with equal priority
/// (`src/lib/krb5/os/dnssrv.c:77-103,214-257`). `Ok(None)` means the name holds
/// no URI record: NXDOMAIN or an empty NOERROR answer.
///
/// # Errors
///
/// Returns [`Error::DnsSrvLookup`] when the lookup fails for another reason than
/// finding no record.
///
/// # Cancel safety
///
/// cancel-safe: a DNS lookup changes no state.
async fn uri_at(
    resolver: &TokioResolver,
    name: &str,
    realm: &str,
    protocol: KdcProtocol,
) -> Result<Option<Vec<(u16, Vec<u8>)>>, Error> {
    let lookup = match resolver.lookup(name, RecordType::Unknown(URI_TYPE)).await {
        Ok(lookup) => lookup,
        Err(source) if source.is_no_records_found() => return Ok(None),
        Err(source) => {
            return Err(Error::DnsSrvLookup {
                realm: realm.to_owned(),
                protocol,
                message: format!("URI {name}: {source}"),
            });
        }
    };
    let mut records: Vec<(u16, Vec<u8>)> = lookup
        .answers()
        .iter()
        .filter_map(|record| {
            let RData::Unknown { code, rdata } = &record.data else {
                return None;
            };
            if u16::from(*code) != URI_TYPE {
                return None;
            }
            let (priority, target) = uri::split_rdata(&rdata.anything)?;
            Some((priority, target.to_vec()))
        })
        .collect();
    records.sort_by_key(|record| record.0);
    Ok(Some(records))
}

/// The URI records for `service` in `realm`: the site's first, then the generic name.
///
/// MIT asks `<service>.<site>._sites.<realm>` and, when that query yields
/// nothing, the name without the site (`src/lib/krb5/os/dnssrv.c:202-211`). A
/// site name that fails for any reason still falls back, since the fallback stays
/// within the same realm. A failure of the generic name is an error.
///
/// # Errors
///
/// Returns [`Error::DnsSrvLookup`] when the generic lookup fails for another
/// reason than finding no record.
///
/// # Cancel safety
///
/// cancel-safe: DNS lookups change no state.
pub(crate) async fn uri_records(
    resolver: &TokioResolver,
    (service, site, realm): (&str, Option<&str>, &str),
    protocol: KdcProtocol,
) -> Result<Vec<(u16, Vec<u8>)>, Error> {
    if let Some(named) = site {
        let name = lookup_name(service, None, Some(named), realm);
        if let Ok(Some(records)) = uri_at(resolver, &name, realm, protocol).await
            && !records.is_empty()
        {
            return Ok(records);
        }
    }
    let name = lookup_name(service, None, None, realm);
    Ok(uri_at(resolver, &name, realm, protocol)
        .await?
        .unwrap_or_default())
}

/// The realm of the first string of the first TXT record at `name`, or `None`.
///
/// MIT takes the first character-string of the first record and removes a
/// trailing dot (`src/lib/krb5/os/dnsglue.c:476-489`). The text is untrusted:
/// it is accepted only as a realm name ([`uri::realm_from_txt`]).
///
/// # Errors
///
/// Returns [`Error::DnsSrvLookup`] when the lookup fails for another reason than
/// finding no record: a failing name never lets the lookup continue at its
/// parent, which would choose a realm by breaking a query.
///
/// # Cancel safety
///
/// cancel-safe: DNS lookups change no state.
pub(crate) async fn txt_realm(
    resolver: &TokioResolver,
    name: &str,
    realm: &str,
) -> Result<Option<String>, Error> {
    let lookup = match resolver.txt_lookup(name).await {
        Ok(lookup) => lookup,
        Err(source) if source.is_no_records_found() => return Ok(None),
        Err(source) => {
            return Err(Error::DnsSrvLookup {
                realm: realm.to_owned(),
                protocol: KdcProtocol::Auto,
                message: format!("TXT {name}: {source}"),
            });
        }
    };
    let Some(first) = lookup.answers().iter().find_map(|record| {
        if let RData::TXT(txt) = &record.data {
            txt.txt_data.first().map(|bytes| bytes.to_vec())
        } else {
            None
        }
    }) else {
        return Ok(None);
    };
    Ok(uri::realm_from_txt(&first))
}
