//! In-process fixtures.
//!
//! Tickets, keytabs and credential caches made in process for the GSS scenarios.
//!
//! Every ticket is an RFC 4120 `Ticket` encrypted under a fixed AES256 service
//! key that a keytab built here also holds, so the crate's own acceptor opens
//! it; the session key is fixed too. Times are taken from the clock, a minute
//! back and an hour ahead, so the contexts are live while a test runs.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, FixedOffset, Utc};
use rskrb5_ng::{
    ccache::{self, CCache, CredentialTimes},
    client::{TgsRepSession, principal::Principal},
    gss::{
        Acceptor, AcceptorOptions, Credential, EstablishedContext, InitStep, Initiator,
        InitiatorOptions, Name, NameType,
    },
    keytab::{self, EncryptionKey, Keytab},
    ticket,
};
use zeroize::Zeroizing;

use super::context::{Context as _, TestError};

/// The realm of every ticket.
pub(super) const REALM: &str = "EXAMPLE.COM";

/// The client's user name.
pub(super) const USER: &str = "alice";

/// The host of the default service.
pub(super) const HOST: &str = "www.example.com";

/// aes256-cts-hmac-sha1-96.
const ETYPE: i32 = 18;

/// `FORWARDABLE`, ticket flag 1 (RFC 4120 section 5.3).
pub(super) const FORWARDABLE: usize = 1;

/// `OK-AS-DELEGATE`, ticket flag 13 (RFC 4120 section 5.3).
pub(super) const OK_AS_DELEGATE: usize = 13;

/// The service key of `HTTP/<host>`, distinct per host.
fn service_key(host: &str) -> EncryptionKey {
    let seed = host.bytes().fold(0x5c_u8, u8::wrapping_add);
    EncryptionKey::new(ETYPE, vec![seed; 32])
}

/// The session key every service ticket carries.
pub(super) fn session_key() -> EncryptionKey {
    EncryptionKey::new(ETYPE, vec![0x5a; 32])
}

/// The client principal.
pub(super) fn client() -> Principal {
    Principal::user(REALM, USER)
}

/// The `HTTP/<host>` service principal (host-based, name type 3).
pub(super) fn service(host: &str) -> Principal {
    Principal::new(REALM, 3, ["HTTP", host])
}

/// The host-based GSS name `HTTP@<host>`.
pub(super) fn target(host: &str) -> Result<Name, TestError> {
    Name::import(
        format!("HTTP@{host}").as_bytes(),
        NameType::HostbasedService,
    )
    .context("host-based name imports")
}

/// A keytab with the `HTTP/<host>` key of every host.
pub(super) fn keytab(hosts: &[&str]) -> Keytab {
    let mut keytab = Keytab::new();
    for host in hosts {
        keytab.entries_mut().push(keytab::Entry::new(
            keytab::Principal::new(REALM, 3, ["HTTP", *host]),
            0,
            1,
            service_key(host),
            1,
        ));
    }
    keytab
}

/// A Kerberos string.
fn text(value: &str) -> Result<rasn_kerberos::KerberosString, TestError> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|cause| format!("Kerberos string: {cause:?}").into())
}

/// A principal name.
fn name(kind: i32, components: &[&str]) -> Result<rasn_kerberos::PrincipalName, TestError> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: kind,
        string: components
            .iter()
            .map(|component| text(component))
            .collect::<Result<_, _>>()?,
    })
}

/// A whole-second Kerberos time.
fn time(at: SystemTime) -> Result<rasn_kerberos::KerberosTime, TestError> {
    let seconds = at.duration_since(UNIX_EPOCH)?.as_secs();
    let utc = DateTime::<Utc>::from_timestamp(i64::try_from(seconds)?, 0)
        .context("time is representable")?;
    let offset = FixedOffset::east_opt(0).context("UTC offset")?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
}

/// Whole seconds of `at`.
fn whole(at: SystemTime) -> Result<SystemTime, TestError> {
    let seconds = at.duration_since(UNIX_EPOCH)?.as_secs();
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .context("time is representable")
}

/// The validity of every ticket: a minute ago to an hour ahead, in whole seconds.
fn validity() -> Result<(SystemTime, SystemTime), TestError> {
    let now = SystemTime::now();
    Ok((
        whole(now.checked_sub(Duration::from_mins(1)).context("start")?)?,
        whole(now.checked_add(Duration::from_hours(1)).context("end")?)?,
    ))
}

/// The ticket flag bits `set`, as the RFC 4120 bit string and as ccache bytes.
fn flags(set: &[usize]) -> (rasn_kerberos::TicketFlags, [u8; 4]) {
    let mut bits = rasn_kerberos::KerberosFlags::repeat(false, 32);
    let mut word = 0_u32;
    for bit in set {
        bits.set(*bit, true);
        word |= 0x8000_0000_u32
            .checked_shr(u32::try_from(*bit).unwrap_or(31))
            .unwrap_or(0);
    }
    (rasn_kerberos::TicketFlags(bits), word.to_be_bytes())
}

/// The DER ticket of `client` for `server`, sealed in `key`, with flags `set`.
fn sealed(
    server: (&[&str], &EncryptionKey),
    set: &[usize],
    at: (SystemTime, SystemTime),
) -> Result<(Vec<u8>, [u8; 4]), TestError> {
    let (bits, bytes) = flags(set);
    let session = session_key();
    let part = rasn_kerberos::EncTicketPart {
        flags: bits,
        key: rasn_kerberos::EncryptionKey {
            r#type: session.etype(),
            value: session.value().to_vec().into(),
        },
        crealm: text(REALM)?,
        cname: name(1, &[USER])?,
        transited: rasn_kerberos::TransitedEncoding {
            r#type: 1,
            contents: Vec::new().into(),
        },
        auth_time: time(at.0)?,
        start_time: None,
        end_time: time(at.1)?,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let der = ticket::encode_build_ticket_with_confounder(
        text(REALM)?,
        name(3, server.0)?,
        &part,
        server.1,
        Some(1),
        &[0x11; 16],
    )?;
    Ok((der, bytes))
}

/// A service ticket of the client for `HTTP/<host>` with the ticket flags `set`.
pub(super) fn ticket_for(host: &str, set: &[usize]) -> Result<TgsRepSession, TestError> {
    let at = validity()?;
    let (der, bytes) = sealed((&["HTTP", host], &service_key(host)), set, at)?;
    Ok(TgsRepSession::new(
        client(),
        service(host),
        session_key(),
        Zeroizing::new(der),
        bytes,
        at.0,
        at.1,
    ))
}

/// The ccache form of a principal.
fn cache_principal(principal: &Principal) -> ccache::Principal {
    ccache::Principal::new(
        principal.realm.clone(),
        principal.name_type,
        principal.components.clone(),
    )
}

/// The ccache times of a ticket valid over `at`.
fn times(at: (SystemTime, SystemTime)) -> Result<CredentialTimes, TestError> {
    let mut value = CredentialTimes::default();
    value.auth_time = u32::try_from(at.0.duration_since(UNIX_EPOCH)?.as_secs())?;
    value.start_time = value.auth_time;
    value.end_time = u32::try_from(at.1.duration_since(UNIX_EPOCH)?.as_secs())?;
    Ok(value)
}

/// The client's TGT as a ccache credential, with the ticket flags `set`.
pub(super) fn tgt(set: &[usize]) -> Result<ccache::Credential, TestError> {
    let at = validity()?;
    let key = EncryptionKey::new(ETYPE, vec![0x7e; 32]);
    let (der, bytes) = sealed((&["krbtgt", REALM], &key), set, at)?;
    Ok(ccache::Credential::new(
        cache_principal(&client()),
        ccache::Principal::new(REALM, 2, vec!["krbtgt".to_owned(), REALM.to_owned()]),
        ccache::EncryptionKey::new(ETYPE, vec![0x6d; 32]),
        times(at)?,
        bytes,
        Zeroizing::new(der),
    ))
}

/// The ccache form of a service ticket.
pub(super) fn cached(ticket: &TgsRepSession) -> Result<ccache::Credential, TestError> {
    let at = (ticket.auth_time(), ticket.end_time());
    Ok(ccache::Credential::new(
        cache_principal(ticket.client()),
        cache_principal(ticket.service()),
        ccache::EncryptionKey::new(
            ticket.session_key().etype(),
            ticket.session_key().value().to_vec(),
        ),
        times(at)?,
        ticket.ticket_flags(),
        Zeroizing::new(ticket.ticket().to_vec()),
    ))
}

/// A credential cache of the client holding `entries`.
pub(super) fn cache(entries: Vec<ccache::Credential>) -> CCache {
    let mut value = CCache::new(cache_principal(&client()));
    for entry in entries {
        drop(value.upsert_credential(entry));
    }
    value
}

/// The two ends of one context and the tokens that went on the wire.
#[derive(Debug)]
pub(super) struct Pair {
    /// The initiator's context.
    pub initiator: EstablishedContext,
    /// The acceptor's context.
    pub acceptor: EstablishedContext,
    /// The initiator's first token.
    pub first: Vec<u8>,
    /// The acceptor's reply, when it sent one.
    pub reply: Option<Vec<u8>>,
}

/// Establish a context for `HTTP@<host>` with `credential`, the acceptor
/// holding the keys of `hosts`.
///
/// # Errors
///
/// Returns the first error of either end.
pub(super) fn establish(
    credential: &Credential,
    initiator: InitiatorOptions,
    acceptor: (AcceptorOptions, &[&str], Option<Name>),
) -> Result<Pair, TestError> {
    let mut init = Initiator::new(target(HOST)?, initiator);
    let (first, waiting) = match init.init_sec_context(credential, None)? {
        InitStep::Continue(token) => (token, true),
        InitStep::Complete(Some(token)) => (token, false),
        InitStep::Complete(_) | _ => return Err("the first step sends a token".into()),
    };
    let (options, hosts, name) = acceptor;
    let mut store = Credential::from_keytab(keytab(hosts));
    if let Some(desired) = name {
        store = store.with_name(desired)?;
    }
    let mut accept = Acceptor::new(&store, options)?;
    let accepted = accept.accept_sec_context(&first)?;
    let reply = accepted.output_token().map(<[u8]>::to_vec);
    match (&reply, waiting) {
        (Some(token), true) => {
            let InitStep::Complete(None) = init.init_sec_context(credential, Some(token))? else {
                return Err("the AP-REP completes the initiator without a token".into());
            };
        }
        (None, false) => {}
        _ => return Err("the acceptor's reply does not match the initiator's state".into()),
    }
    Ok(Pair {
        initiator: init.into_established()?,
        acceptor: accepted.into_context(),
        first,
        reply,
    })
}
