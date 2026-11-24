//! In-process origins, tickets and Kerberos servers.
//!
//! A [`Network`] is the client's [`HttpExchange`]: it routes a request to the
//! handler registered for its origin and records what every origin saw. Tickets
//! are RFC 4120 tickets sealed under a fixed AES256 key that the server's
//! keytab holds, so the crate's own acceptor opens what its own client sends.

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, FixedOffset, Utc};
use http_types::{
    HeaderMap, Method, Request, Response, StatusCode, Uri,
    header::{AUTHORIZATION, HeaderValue, LOCATION, WWW_AUTHENTICATE},
};
use rskrb5_ng::{
    client::{
        TgsRepSession, Tokio, negotiate::Client as NegotiateClient, principal::Principal,
        transport::KdcProtocol,
    },
    config::Config,
    error::{Http as HttpError, HttpExchange as ExchangeError},
    http::{
        self,
        origin::Origin,
        wire::{ExchangeFuture, HttpExchange},
    },
    keytab::{self, EncryptionKey, Keytab},
    service::{ApRepOptions, Validator},
    ticket,
};
use zeroize::Zeroizing;

use super::context::{Context as _, TestError};

/// The realm of every ticket.
pub(super) const REALM: &str = "EXAMPLE.COM";
/// The client's user name.
const USER: &str = "alice";
/// aes256-cts-hmac-sha1-96.
const ETYPE: i32 = 18;

/// What the success branch of a [`Kerberos`] origin answers.
pub(super) type Success<'handler> = &'handler dyn Fn(&Request<Vec<u8>>) -> Response<Vec<u8>>;

/// A handler: the response of one origin to one request.
pub(super) type Handler = Box<dyn Fn(&Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync>;

/// What an origin saw of one request.
#[derive(Clone, Debug)]
pub(super) struct Seen {
    /// The method.
    pub method: Method,
    /// The path and query.
    pub target: String,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Vec<u8>,
}

impl Seen {
    /// The `Authorization` header, if any.
    pub(super) fn authorization(&self) -> Option<String> {
        self.headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }
}

/// The routing table and the log of every request; clones share both.
#[derive(Clone, Default)]
pub(super) struct Network {
    /// The handler of every origin.
    handlers: HashMap<Origin, Arc<Handler>>,
    /// What every origin saw, in order.
    log: Arc<Mutex<Vec<(Origin, Seen)>>>,
}

impl Network {
    /// An empty network.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Serve `uri`'s origin with `handler`.
    pub(super) fn serve<H>(mut self, uri: &str, handler: H) -> Result<Self, TestError>
    where
        H: Fn(&Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync + 'static,
    {
        let origin = Origin::of(&uri.parse::<Uri>().context("origin URI parses")?)
            .context("origin URI has an origin")?;
        drop(self.handlers.insert(origin, Arc::new(Box::new(handler))));
        Ok(self)
    }

    /// Everything the origin of `uri` saw.
    pub(super) fn seen_by(&self, uri: &str) -> Result<Vec<Seen>, TestError> {
        let origin = Origin::of(&uri.parse::<Uri>().context("origin URI parses")?)
            .context("origin URI has an origin")?;
        Ok(self
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(seen_by, _)| *seen_by == origin)
            .map(|(_, seen)| seen.clone())
            .collect())
    }
}

impl HttpExchange for Network {
    fn exchange(&self, request: Request<Vec<u8>>) -> ExchangeFuture<'_> {
        Box::pin(async move {
            let origin =
                Origin::of(request.uri()).map_err(|_refused| ExchangeError::InvalidRequest {
                    reason: "the test network needs an absolute URI",
                })?;
            let handler = self
                .handlers
                .get(&origin)
                .ok_or(ExchangeError::InvalidRequest {
                    reason: "no origin is registered for the URI",
                })?;
            self.log
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((
                    origin,
                    Seen {
                        method: request.method().clone(),
                        target: request
                            .uri()
                            .path_and_query()
                            .map_or_else(String::new, |target| target.as_str().to_owned()),
                        headers: request.headers().clone(),
                        body: request.body().clone(),
                    },
                ));
            Ok(handler(&request))
        })
    }
}

/// The service key of `HTTP/<host>`, distinct per host.
fn service_key(host: &str) -> EncryptionKey {
    let seed = host.bytes().fold(0x5c_u8, u8::wrapping_add);
    EncryptionKey::new(ETYPE, vec![seed; 32])
}

/// The session key every service ticket carries.
fn session_key() -> EncryptionKey {
    EncryptionKey::new(ETYPE, vec![0x5a; 32])
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

/// The service ticket of the client for `HTTP/<host>`, valid a minute ago to an hour ahead.
fn ticket_for(host: &str) -> Result<TgsRepSession, TestError> {
    let now = SystemTime::now();
    let start = whole(now.checked_sub(Duration::from_mins(1)).context("start")?)?;
    let end = whole(now.checked_add(Duration::from_hours(1)).context("end")?)?;
    let session = session_key();
    let part = rasn_kerberos::EncTicketPart {
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::repeat(false, 32)),
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
        auth_time: time(start)?,
        start_time: None,
        end_time: time(end)?,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let der = ticket::encode_build_ticket_with_confounder(
        text(REALM)?,
        name(3, &["HTTP", host])?,
        &part,
        &service_key(host),
        Some(1),
        &[0x11; 16],
    )?;
    Ok(TgsRepSession::new(
        Principal::user(REALM, USER),
        Principal::new(REALM, 3, ["HTTP", host]),
        session,
        Zeroizing::new(der),
        [0; 4],
        start,
        end,
    ))
}

/// A Negotiate client holding a ticket for each of `hosts`.
pub(super) fn negotiate_client(hosts: &[&str]) -> Result<NegotiateClient, TestError> {
    let mut client = Tokio::with_password(
        Config::new(),
        KdcProtocol::Auto,
        Principal::user(REALM, USER),
        b"unused".to_vec(),
    );
    for host in hosts {
        client
            .cache_service_ticket(ticket_for(host)?)
            .context("the ticket matches the client")?;
    }
    Ok(NegotiateClient::from_tokio_client(client))
}

/// A response with `status` and an empty body.
pub(super) fn status(code: StatusCode) -> Response<Vec<u8>> {
    let mut response = Response::new(Vec::new());
    *response.status_mut() = code;
    response
}

/// A redirect with `code` to `location`.
pub(super) fn redirect(code: StatusCode, location: &str) -> Result<Response<Vec<u8>>, TestError> {
    let mut response = status(code);
    drop(response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(location).context("location")?,
    ));
    Ok(response)
}

/// A Kerberos origin: Negotiate on every request, the body of `ok` on success.
///
/// A request with a token the server accepts gets `200` with an AP-REP;
/// one without gets the bare challenge; one with a bad token gets `401`.
pub(super) struct Kerberos {
    /// The acceptor.
    validator: Mutex<Validator<'static>>,
}

impl Kerberos {
    /// A server holding the keys of `hosts`.
    pub(super) fn new(hosts: &[&str]) -> Self {
        Self {
            validator: Mutex::new(Validator::from_keytab(keytab(hosts))),
        }
    }

    /// Answer `request` with `ok` once it is authenticated.
    pub(super) fn respond(&self, request: &Request<Vec<u8>>, ok: Success<'_>) -> Response<Vec<u8>> {
        let mut copy = Request::new(());
        *copy.headers_mut() = request.headers().clone();
        let mut validator = self
            .validator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match http::accept_request(&mut validator, &mut copy) {
            Err(HttpError::MissingAuthorization) => http::challenge_response(),
            Err(_rejected) => http::reject_response()
                .unwrap_or_else(|_unencodable| status(StatusCode::UNAUTHORIZED)),
            Ok(accepted) => {
                let mut response = ok(request);
                if let Ok(header) = accepted.ap_rep_response_header(&ApRepOptions::default())
                    && let Ok(value) = HeaderValue::from_str(&header)
                {
                    drop(response.headers_mut().insert(WWW_AUTHENTICATE, value));
                }
                response
            }
        }
    }
}
