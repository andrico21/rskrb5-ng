//! In-process fixtures for the GSS extension scenarios.
//!
//! Tickets, keytabs and credential caches made in process, as the GSS core
//! scenarios make them, with the session key's enctype chosen per test so the
//! AES-SHA1, AES-SHA2 and the opted-in legacy contexts are all reachable.
//!
//! Every ticket is sealed under a fixed AES256 service key that a keytab built
//! here also holds; the session key is fixed per enctype. Times are taken from
//! the clock, a minute back and an hour ahead.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, FixedOffset, Utc};
use rskrb5_ng::{
    ccache::{self, CCache, CredentialTimes},
    client::{TgsRepSession, principal::Principal},
    crypto::CryptoPolicy,
    error::Gss,
    gss::{
        Acceptor, AcceptorOptions, ContextFlags, Credential, EstablishedContext, InitStep,
        Initiator, InitiatorOptions, Name, NameType,
    },
    keytab::{self, EncryptionKey, Keytab},
    service::Validator,
    ticket,
};
use zeroize::Zeroizing;

use super::context::{Context as _, TestError};

/// The realm of every ticket.
pub(super) const REALM: &str = "EXAMPLE.COM";

/// The client's user name.
pub(super) const USER: &str = "alice";

/// The host of the service.
pub(super) const HOST: &str = "www.example.com";

/// aes256-cts-hmac-sha1-96.
pub(super) const AES256_SHA1: i32 = 18;

/// aes256-cts-hmac-sha384-192.
pub(super) const AES256_SHA384: i32 = 20;

/// aes128-cts-hmac-sha1-96.
pub(super) const AES128_SHA1: i32 = 17;

/// des3-cbc-sha1-kd.
pub(super) const DES3: i32 = 16;

/// rc4-hmac.
pub(super) const RC4: i32 = 23;

/// The service key of `HTTP/<host>`: always AES256.
fn service_key() -> EncryptionKey {
    EncryptionKey::new(AES256_SHA1, vec![0x5c; 32])
}

/// The key length of `etype`.
fn key_len(etype: i32) -> usize {
    match etype {
        AES128_SHA1 | RC4 | 19 => 16,
        DES3 => 24,
        _ => 32,
    }
}

/// The session key of a ticket of `etype`.
pub(super) fn session_key(etype: i32) -> EncryptionKey {
    let mut value = vec![0x5a; key_len(etype)];
    if etype == DES3 {
        // DES keys carry odd parity in every byte.
        value.fill(0x5b);
    }
    EncryptionKey::new(etype, value)
}

/// The client principal.
pub(super) fn client() -> Principal {
    Principal::user(REALM, USER)
}

/// The `HTTP/<host>` service principal.
pub(super) fn service() -> Principal {
    Principal::new(REALM, 3, ["HTTP", HOST])
}

/// The host-based GSS name `HTTP@<host>`.
pub(super) fn target() -> Result<Name, TestError> {
    Name::import(
        format!("HTTP@{HOST}").as_bytes(),
        NameType::HostbasedService,
    )
    .context("host-based name imports")
}

/// A keytab with the `HTTP/<host>` key.
pub(super) fn keytab() -> Keytab {
    let mut keytab = Keytab::new();
    keytab.entries_mut().push(keytab::Entry::new(
        keytab::Principal::new(REALM, 3, ["HTTP", HOST]),
        0,
        1,
        service_key(),
        1,
    ));
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

/// A minute ago to an hour ahead, in whole seconds.
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

/// A service ticket of the client for `HTTP/<host>` with a session key of
/// `etype` and the ticket flags `set`.
///
/// # Errors
///
/// Returns the encoding errors.
pub(super) fn ticket_for(etype: i32, set: &[usize]) -> Result<TgsRepSession, TestError> {
    let at = validity()?;
    let (bits, bytes) = flags(set);
    let session = session_key(etype);
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
        name(3, &["HTTP", HOST])?,
        &part,
        &service_key(),
        Some(1),
        &[0x11; 16],
    )?;
    Ok(TgsRepSession::new(
        client(),
        service(),
        session,
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

/// The ccache form of a service ticket.
///
/// # Errors
///
/// Returns the time conversion errors.
pub(super) fn cached(ticket: &TgsRepSession) -> Result<ccache::Credential, TestError> {
    let mut times = CredentialTimes::default();
    times.auth_time = u32::try_from(ticket.auth_time().duration_since(UNIX_EPOCH)?.as_secs())?;
    times.start_time = times.auth_time;
    times.end_time = u32::try_from(ticket.end_time().duration_since(UNIX_EPOCH)?.as_secs())?;
    Ok(ccache::Credential::new(
        cache_principal(ticket.client()),
        cache_principal(ticket.service()),
        ccache::EncryptionKey::new(
            ticket.session_key().etype(),
            ticket.session_key().value().to_vec(),
        ),
        times,
        ticket.ticket_flags(),
        Zeroizing::new(ticket.ticket().to_vec()),
    ))
}

/// An initiator credential holding a service ticket with a session key of `etype`.
///
/// # Errors
///
/// Returns the ticket errors.
pub(super) fn credential(etype: i32) -> Result<Credential, TestError> {
    let mut value = CCache::new(cache_principal(&client()));
    drop(value.upsert_credential(cached(&ticket_for(etype, &[])?)?));
    Ok(Credential::from_ccache(value)?)
}

/// The two ends of one context and the tokens that went on the wire.
#[derive(Debug)]
pub(super) struct Pair {
    /// The initiator's context.
    pub initiator: EstablishedContext,
    /// The acceptor's context.
    pub acceptor: EstablishedContext,
}

/// The flags of a sequenced, mutually authenticated context.
pub(super) fn sequenced() -> ContextFlags {
    ContextFlags::MUTUAL
        | ContextFlags::SEQUENCE
        | ContextFlags::REPLAY
        | ContextFlags::CONF
        | ContextFlags::INTEG
}

/// Establish a context with a session key of `etype`, requesting `flags`,
/// both ends under `policy`.
///
/// # Errors
///
/// Returns the first error of either end.
pub(super) fn establish_with(
    etype: i32,
    flags: ContextFlags,
    policy: &CryptoPolicy,
) -> Result<Pair, TestError> {
    let credential = credential(etype)?;
    let mut init = Initiator::new(
        target()?,
        InitiatorOptions::new()
            .with_flags(flags)
            .with_crypto_policy(policy.clone()),
    );
    let keys = keytab();
    let mut accept = Acceptor::from_validator(
        Validator::new(&keys).with_crypto_policy(policy.clone()),
        AcceptorOptions::new(),
    );
    let (first, waiting) = match init.init_sec_context(&credential, None)? {
        InitStep::Continue(token) => (token, true),
        InitStep::Complete(Some(token)) => (token, false),
        InitStep::Complete(_) | _ => return Err("the first step sends a token".into()),
    };
    let mut accepted = accept.accept_sec_context(&first)?;
    if waiting {
        let reply = accepted
            .output_token()
            .context("the acceptor answers a waiting initiator")?
            .to_vec();
        match init.init_sec_context(&credential, Some(&reply))? {
            InitStep::Complete(None) => {}
            InitStep::Complete(Some(third)) => accepted.complete_dce(&third)?,
            InitStep::Continue(_) | _ => return Err("the initiator completes".into()),
        }
    }
    Ok(Pair {
        initiator: init.into_established()?,
        acceptor: accepted.into_context(),
    })
}

/// Establish an AES256-SHA1 context requesting `flags`.
///
/// # Errors
///
/// Returns the first error of either end.
pub(super) fn establish(flags: ContextFlags) -> Result<Pair, TestError> {
    establish_with(AES256_SHA1, flags, &CryptoPolicy::default())
}

/// Fail unless `result` is a refusal.
///
/// # Errors
///
/// Returns a test error when the call succeeded.
pub(super) fn refused<T>(result: Result<T, Gss>) -> Result<(), TestError> {
    result.map_or_else(|_refusal| Ok(()), |_accepted| Err("the call was accepted".into()))
}
