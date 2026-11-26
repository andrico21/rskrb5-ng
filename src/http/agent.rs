//! A ready HTTP client for Negotiate (SPNEGO) servers: redirects, challenge
//! bounds, a cookie jar hook, mutual authentication and `get`/`post`.
//!
//! [`NegotiateHttpClient`] sends [`http::Request<Vec<u8>>`] values through an
//! [`HttpExchange`] and answers a `401` Negotiate challenge with a token built
//! by the [`NegotiateClient`]. The request body is a `Vec<u8>`: it is sent
//! again for every challenge retry and redirect that keeps it (a `303`, and a
//! `301` or `302` of a `POST`, become body-less `GET`s).
//!
//! # Security
//!
//! * Credentials stay on their origin (scheme, host and port). The default
//!   [`RedirectPolicy`] follows same-origin redirects only; a redirect to
//!   another origin is returned to the caller. With
//!   [`RedirectPolicy::AnyOrigin`] it is followed with the `Authorization`,
//!   `Proxy-Authorization` and caller `Cookie` headers removed, and no
//!   Negotiate token is ever sent to an origin other than the one the caller
//!   asked for.
//! * A redirect from `https` to `http` is an error, never a request.
//! * Every request goes over a connection the exchange opened first
//!   ([`HttpExchange::connect`]); a token is built afterwards, bound to that
//!   connection's RFC 5929 `tls-server-end-point` bindings under the
//!   [`ChannelBindingPolicy`], and sent over it. A retry connection whose TLS
//!   peer certificate differs from the one that carried the challenge is
//!   refused with [`HttpClient::ChannelChanged`] before any token is built,
//!   and [`ChannelBindingPolicy::Required`] sends no token over a connection
//!   without bindings.
//! * A Negotiate token is used once: every redirect drops the previous token,
//!   and a same-origin hop of an authenticated chain gets a fresh one.
//! * The challenge rounds, the `WWW-Authenticate` bytes, the redirects and the
//!   replayed body are bounded.
//! * When the [`InitiatorContextOptions`] ask for mutual authentication, the
//!   final response must answer an authenticated request and carry an AP-REP
//!   that verifies; otherwise the call fails with
//!   [`HttpClient::MutualAuthenticationNotProven`] and the response is kept
//!   only inside the error.
//!
//! # Cancel safety
//!
//! NOT cancel-safe: once a request was sent, dropping the future leaves it
//! unknown whether the server received it, so a request that is not idempotent
//! must be treated as possibly delivered.
//!
//! [`http::Request<Vec<u8>>`]: http_types::Request
//! [`NegotiateClient`]: crate::client::negotiate::Client
//! [`HttpClient::MutualAuthenticationNotProven`]: crate::error::HttpClient::MutualAuthenticationNotProven
//! [`HttpClient::ChannelChanged`]: crate::error::HttpClient::ChannelChanged

use core::fmt;

use http_types::{
    Method, Request, Response, StatusCode, Uri,
    header::{CONTENT_TYPE, HeaderValue, InvalidHeaderValue, WWW_AUTHENTICATE},
};

use self::chain::Chain;
use super::{
    ClientNegotiateResponse, classify_negotiate_response, mutual_requested_by,
    negotiate_challenge_is_bare,
    origin::Origin,
    wire::{CookieJar, HttpExchange, TlsChannel},
    www_authenticate_negotiate_header,
};
use crate::{
    client::{negotiate::Client as NegotiateClient, principal::Principal},
    error::{Http, HttpClient as Error},
    spnego::{InitiatorContext, InitiatorContextOptions},
    trace::{Event, Guard, Identity, TransportStep, TransportWire},
};

/// The request chain and its redirect rules.
mod chain;

/// Which redirects the client follows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RedirectPolicy {
    /// Follow nothing: the redirect response is the result.
    Never,
    /// Follow up to `max` redirects that stay on one origin; any other redirect
    /// response is the result.
    SameOrigin {
        /// The most redirects followed.
        max: u8,
    },
    /// Follow up to `max` redirects to any origin, without credentials (see
    /// the module documentation).
    AnyOrigin {
        /// The most redirects followed.
        max: u8,
    },
}

impl RedirectPolicy {
    /// The redirect limit of the default policy.
    pub const DEFAULT_MAX: u8 = 10;

    /// The limit and whether other origins are followed; `None` for [`Self::Never`].
    const fn limit(self) -> Option<(u8, bool)> {
        match self {
            Self::Never => None,
            Self::SameOrigin { max } => Some((max, false)),
            Self::AnyOrigin { max } => Some((max, true)),
        }
    }
}

impl Default for RedirectPolicy {
    #[inline]
    fn default() -> Self {
        Self::SameOrigin {
            max: Self::DEFAULT_MAX,
        }
    }
}

/// Whether Negotiate tokens are bound to the TLS channel that carries them
/// (RFC 5929 `tls-server-end-point`, see [`TlsChannel`]).
///
/// [`TlsChannel`]: super::wire::TlsChannel
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum ChannelBindingPolicy {
    /// Never derive bindings from the connection; a token carries the
    /// bindings of the [`InitiatorContextOptions`], if any.
    Off,
    /// Bind a token to its connection when the exchange reports a TLS channel
    /// with `tls-server-end-point` bindings; send it unbound otherwise.
    #[default]
    WhenAvailable,
    /// Bind every token to its connection; with no bindings, fail with
    /// [`Error::ChannelBindingUnavailable`] and send no token.
    Required,
}

/// The authenticated context of a request and its classified response.
struct Negotiated {
    /// The initiator context that built the request's token.
    context: InitiatorContext,
    /// The classification of the response against that context.
    negotiation: ClientNegotiateResponse,
}

/// What the request of one round carries.
#[derive(Clone, Copy)]
enum Attempt<'challenge> {
    /// No token.
    Anonymous,
    /// A fresh token for the connection that carries it.
    Token {
        /// The TLS peer of the connection that carried the challenge this
        /// token answers, if any: the retry connection must present it too.
        challenge: Option<&'challenge TlsChannel>,
    },
}

/// The response of one round, the context of its token and the TLS peer of
/// its connection.
type Round = (
    Response<Vec<u8>>,
    Option<InitiatorContext>,
    Option<TlsChannel>,
);

/// The result of [`NegotiateHttpClient::send`].
#[non_exhaustive]
pub struct ClientResponse {
    /// The final response.
    response: Response<Vec<u8>>,
    /// The URI the final response answers.
    uri: Uri,
    /// The redirects followed.
    redirects: u8,
    /// The authentication of the final request, when it had a token.
    negotiated: Option<Negotiated>,
}

impl fmt::Debug for ClientResponse {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientResponse")
            .field("status", &self.response.status())
            .field("redirects", &self.redirects)
            .field("negotiation", &self.negotiation())
            .finish_non_exhaustive()
    }
}

impl ClientResponse {
    /// The final response.
    #[inline]
    #[must_use]
    pub const fn response(&self) -> &Response<Vec<u8>> {
        &self.response
    }

    /// The URI the final response answers.
    #[inline]
    #[must_use]
    pub const fn uri(&self) -> &Uri {
        &self.uri
    }

    /// The redirects followed.
    #[inline]
    #[must_use]
    pub const fn redirects(&self) -> u8 {
        self.redirects
    }

    /// The classification of the final response, when its request had a token.
    #[inline]
    #[must_use]
    pub fn negotiation(&self) -> Option<&ClientNegotiateResponse> {
        self.negotiated.as_ref().map(|found| &found.negotiation)
    }

    /// The initiator context of the final request, when it had a token.
    #[inline]
    #[must_use]
    pub fn context(&self) -> Option<&InitiatorContext> {
        self.negotiated.as_ref().map(|found| &found.context)
    }

    /// Consume the result and return the final response.
    #[inline]
    #[must_use]
    pub fn into_response(self) -> Response<Vec<u8>> {
        self.response
    }
}

/// An HTTP client that authenticates with Kerberos Negotiate.
pub struct NegotiateHttpClient<X> {
    /// The Kerberos client that builds the tokens.
    negotiate: NegotiateClient,
    /// The transport.
    exchange: X,
    /// The initiator options of every token.
    options: InitiatorContextOptions,
    /// The redirect policy.
    redirect: RedirectPolicy,
    /// When tokens are bound to their TLS channel.
    binding: ChannelBindingPolicy,
    /// The most tokens sent after a challenge, per hop.
    max_challenges: u8,
    /// The most `WWW-Authenticate` bytes of one response.
    max_challenge_bytes: usize,
    /// The longest replayable request body.
    max_body_bytes: usize,
    /// The realm of the `HTTP/<host>` service, when it is not looked up.
    service_realm: Option<String>,
    /// The cookie jar.
    jar: Option<Box<dyn CookieJar>>,
    /// The trace guard.
    trace: Guard,
}

impl<X> fmt::Debug for NegotiateHttpClient<X> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NegotiateHttpClient")
            .field("redirect", &self.redirect)
            .field("max_challenges", &self.max_challenges)
            .field("channel_binding", &self.binding)
            .field("cookie_jar", &self.jar.is_some())
            .finish_non_exhaustive()
    }
}

impl<X: HttpExchange> NegotiateHttpClient<X> {
    /// The default limit of Negotiate tokens per hop.
    pub const DEFAULT_MAX_CHALLENGES: u8 = 2;
    /// The default limit of `WWW-Authenticate` bytes per response.
    pub const DEFAULT_MAX_CHALLENGE_BYTES: usize = 16 * 1024;
    /// The default limit of the replayed request body.
    pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

    /// A client that authenticates with `negotiate` and sends through `exchange`.
    ///
    /// The tokens do not request mutual authentication, the redirect policy is
    /// [`RedirectPolicy::default`] and there is no cookie jar.
    #[inline]
    #[must_use]
    pub fn new(negotiate: NegotiateClient, exchange: X) -> Self {
        Self {
            negotiate,
            exchange,
            options: InitiatorContextOptions::new(),
            redirect: RedirectPolicy::default(),
            binding: ChannelBindingPolicy::default(),
            max_challenges: Self::DEFAULT_MAX_CHALLENGES,
            max_challenge_bytes: Self::DEFAULT_MAX_CHALLENGE_BYTES,
            max_body_bytes: Self::DEFAULT_MAX_BODY_BYTES,
            service_realm: None,
            jar: None,
            trace: Guard::disabled(),
        }
    }

    /// Build every token with `options`; a mutual-authentication flag makes the
    /// final response prove the server.
    #[inline]
    #[must_use]
    pub fn with_options(mut self, options: InitiatorContextOptions) -> Self {
        self.options = options;
        self
    }

    /// Follow redirects under `policy`.
    #[inline]
    #[must_use]
    pub const fn with_redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.redirect = policy;
        self
    }

    /// Bind tokens to their TLS channel under `policy` (the default is
    /// [`ChannelBindingPolicy::WhenAvailable`]).
    #[inline]
    #[must_use]
    pub const fn with_channel_binding_policy(mut self, policy: ChannelBindingPolicy) -> Self {
        self.binding = policy;
        self
    }

    /// Send at most `max` tokens per hop after a challenge.
    #[inline]
    #[must_use]
    pub const fn with_max_challenges(mut self, max: u8) -> Self {
        self.max_challenges = max;
        self
    }

    /// Accept at most `max` bytes of `WWW-Authenticate` headers per response.
    #[inline]
    #[must_use]
    pub const fn with_max_challenge_bytes(mut self, max: usize) -> Self {
        self.max_challenge_bytes = max;
        self
    }

    /// Replay request bodies of at most `max` bytes.
    #[inline]
    #[must_use]
    pub const fn with_max_body_bytes(mut self, max: usize) -> Self {
        self.max_body_bytes = max;
        self
    }

    /// Name the realm of the `HTTP/<host>` services instead of looking it up.
    #[inline]
    #[must_use]
    pub fn with_service_realm<R>(mut self, realm: R) -> Self
    where
        R: Into<String>,
    {
        self.service_realm = Some(realm.into());
        self
    }

    /// Keep and send cookies through `jar`.
    #[inline]
    #[must_use]
    pub fn with_cookie_jar<J>(mut self, jar: J) -> Self
    where
        J: CookieJar + 'static,
    {
        self.jar = Some(Box::new(jar));
        self
    }

    /// Emit a transport event for every request and response through `guard`.
    ///
    /// Hosts are identities: the guard withholds them unless the application
    /// opted in, and no header, token or cookie is ever traced.
    #[inline]
    #[must_use]
    pub fn with_trace(mut self, guard: Guard) -> Self {
        self.trace = guard;
        self
    }

    /// Send a `GET` request for `uri`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::send`], and [`Error::InvalidUri`] when `uri`
    /// does not parse.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe, see the module documentation.
    #[inline]
    pub async fn get(&mut self, uri: &str) -> Result<ClientResponse, Error> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Vec::new())
            .map_err(|_build| Error::InvalidUri {
                reason: "the URI does not parse",
            })?;
        self.send(request).await
    }

    /// Send a `POST` request for `uri` with `body` of `content_type`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::send`], and [`Error::InvalidUri`] when `uri`
    /// or `content_type` does not parse.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe, see the module documentation.
    #[inline]
    pub async fn post(
        &mut self,
        uri: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<ClientResponse, Error> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(CONTENT_TYPE, content_type)
            .body(body)
            .map_err(|_build| Error::InvalidUri {
                reason: "the URI or content type does not parse",
            })?;
        self.send(request).await
    }

    /// Send `request` (an absolute `http` or `https` URI) and follow the
    /// client's redirect and Negotiate rules.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidUri`], [`Error::BodyTooLarge`], the exchange's
    /// errors, [`Error::Negotiate`] when no token can be built,
    /// [`Error::ChallengeLimit`] and [`Error::ChallengeTooLarge`], the redirect
    /// errors of the module documentation and
    /// [`Error::MutualAuthenticationNotProven`].
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe, see the module documentation.
    #[inline]
    pub async fn send(&mut self, request: Request<Vec<u8>>) -> Result<ClientResponse, Error> {
        let mutual = mutual_requested_by(&self.options);
        let mut chain = Chain::start(request, self.max_body_bytes)?;
        loop {
            let (response, negotiated) = self.hop(&mut chain, mutual).await?;
            if chain.follow(self.redirect, &response)? {
                continue;
            }
            if mutual && negotiated.is_none() {
                return Err(Error::MutualAuthenticationNotProven {
                    negotiation: None,
                    response: Box::new(response),
                });
            }
            return Ok(ClientResponse {
                response,
                uri: chain.uri().clone(),
                redirects: chain.redirects(),
                negotiated,
            });
        }
    }

    /// One hop: the request, its challenge retries and the verification of the
    /// response to the authenticated request.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::round`], [`Error::ChallengeLimit`],
    /// [`Error::ChallengeTooLarge`] and, when `mutual` is set,
    /// [`Error::MutualAuthenticationNotProven`].
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe, see the module documentation.
    async fn hop(
        &mut self,
        chain: &mut Chain,
        mutual: bool,
    ) -> Result<(Response<Vec<u8>>, Option<Negotiated>), Error> {
        let first = if chain.is_authenticated() {
            Attempt::Token { challenge: None }
        } else {
            Attempt::Anonymous
        };
        let (mut response, mut sent, mut channel) = self.round(chain, first).await?;
        let mut rounds = 0_u8;
        while chain.on_home() && is_fresh_challenge(&response)? {
            check_challenge_size(&response, self.max_challenge_bytes)?;
            if rounds >= self.max_challenges {
                return Err(Error::ChallengeLimit {
                    limit: self.max_challenges,
                });
            }
            rounds = rounds.saturating_add(1);
            let attempt = Attempt::Token {
                challenge: channel.as_ref(),
            };
            (response, sent, channel) = self.round(chain, attempt).await?;
            chain.authenticate();
        }
        let Some(context) = sent else {
            return Ok((response, None));
        };
        check_challenge_size(&response, self.max_challenge_bytes)?;
        let negotiation = classify_negotiate_response(&context, &response);
        if mutual
            && !matches!(
                negotiation,
                ClientNegotiateResponse::Accepted { ap_rep: Some(_) }
            )
        {
            return Err(Error::MutualAuthenticationNotProven {
                negotiation: Some(negotiation),
                response: Box::new(response),
            });
        }
        Ok((
            response,
            Some(Negotiated {
                context,
                negotiation,
            }),
        ))
    }

    /// The `HTTP/<host>` service of `origin`: the one place the client derives
    /// the service name from the URI host (lower-cased by [`Origin`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Negotiate`] when the service name is invalid.
    fn service_for(&self, origin: &Origin) -> Result<Principal, Error> {
        self.service_realm
            .as_ref()
            .map_or_else(
                || Principal::host_based_service("HTTP", origin.host()),
                |realm| Principal::host_based_service_in_realm("HTTP", origin.host(), realm),
            )
            .map_err(|source| Error::Negotiate(Http::from(source)))
    }

    /// The initiator options of a token sent over a connection whose TLS peer
    /// is `channel`, under the channel-binding policy.
    ///
    /// With a connection binding, it replaces any bindings of the configured
    /// options: a token describes the connection that carries it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChannelBindingUnavailable`] when bindings are required
    /// and the connection has none.
    fn options_for(&self, channel: Option<&TlsChannel>) -> Result<InitiatorContextOptions, Error> {
        let bindings = channel.and_then(TlsChannel::server_end_point);
        let options = self.options.clone();
        match (self.binding, bindings) {
            (ChannelBindingPolicy::Off, _) | (ChannelBindingPolicy::WhenAvailable, None) => {
                Ok(options)
            }
            (ChannelBindingPolicy::WhenAvailable | ChannelBindingPolicy::Required, Some(found)) => {
                Ok(options.with_channel_bindings(found.clone()))
            }
            (ChannelBindingPolicy::Required, None) => Err(Error::ChannelBindingUnavailable {
                reason: if channel.is_some() {
                    "RFC 5929 defines no tls-server-end-point hash this client computes for the peer certificate"
                } else {
                    "the exchange reports no TLS channel for the connection"
                },
            }),
        }
    }

    /// Open a connection for the current request of `chain`, add the jar's
    /// cookies and, for [`Attempt::Token`], a token built for that connection,
    /// send it over that connection and feed the jar with the response.
    ///
    /// Returns the response, the context of the token sent and the TLS peer of
    /// the connection. The token is built after the connection is open, so the
    /// service ticket may be requested from the KDC while it waits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChannelChanged`] when the connection presents another
    /// certificate than the one that carried the challenge, the errors of
    /// [`Self::options_for`] and [`Self::service_for`], [`Error::Negotiate`]
    /// when no token can be built or it is not a header value, and the
    /// exchange's errors. Every failure before the send sends nothing.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe, see the module documentation.
    async fn round(&mut self, chain: &Chain, attempt: Attempt<'_>) -> Result<Round, Error> {
        let connection = self
            .exchange
            .connect(chain.uri())
            .await
            .map_err(Error::Exchange)?;
        let channel = connection.tls_channel().cloned();
        let context = match attempt {
            Attempt::Anonymous => None,
            Attempt::Token { challenge } => {
                if challenge.is_some_and(|seen| channel.as_ref() != Some(seen)) {
                    return Err(Error::ChannelChanged);
                }
                let options = self.options_for(channel.as_ref())?;
                let service = self.service_for(chain.origin())?;
                Some(
                    self.negotiate
                        .authorization_context_with_options(service, options)
                        .await
                        .map_err(|source| Error::Negotiate(Http::from(source)))?,
                )
            }
        };
        let authorization = context
            .as_ref()
            .map(|found| {
                let mut value = HeaderValue::from_str(found.header_ref())?;
                value.set_sensitive(true);
                Ok::<_, InvalidHeaderValue>(value)
            })
            .transpose()
            .map_err(|source| Error::Negotiate(Http::from(source)))?;
        let cookie = self
            .jar
            .as_ref()
            .and_then(|jar| jar.cookie_header(chain.uri()));
        let request = chain.request(authorization, cookie)?;
        let wire = if chain.origin().is_secure() {
            TransportWire::Https
        } else {
            TransportWire::Tcp
        };
        self.trace.emit(&Event::Transport {
            step: TransportStep::Sending,
            wire,
            target: Identity::new(chain.origin().host()),
            size: request.body().len(),
        });
        let response = connection.send(request).await.map_err(Error::Exchange)?;
        self.trace.emit(&Event::Transport {
            step: TransportStep::Answered,
            wire,
            target: Identity::new(chain.origin().host()),
            size: response.body().len(),
        });
        if let Some(jar) = self.jar.as_mut() {
            jar.store(chain.uri(), response.headers());
        }
        Ok((response, context, channel))
    }
}

/// Whether `response` is a `401` with a bare Negotiate challenge: a request for
/// a token, not the rejection of one.
///
/// # Errors
///
/// Returns [`Error::Negotiate`] when a `WWW-Authenticate` value of a `401` is
/// not visible ASCII.
fn is_fresh_challenge(response: &Response<Vec<u8>>) -> Result<bool, Error> {
    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(false);
    }
    match www_authenticate_negotiate_header(response) {
        Ok(challenge) => Ok(negotiate_challenge_is_bare(challenge)),
        Err(Http::MissingWwwAuthenticate | Http::MissingNegotiateChallenge) => Ok(false),
        Err(other) => Err(other.into()),
    }
}

/// Refuse a response whose `WWW-Authenticate` headers total more than `limit` bytes.
///
/// # Errors
///
/// Returns [`Error::ChallengeTooLarge`].
fn check_challenge_size(response: &Response<Vec<u8>>, limit: usize) -> Result<(), Error> {
    let actual = response
        .headers()
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .map(|value| value.as_bytes().len())
        .fold(0_usize, usize::saturating_add);
    if actual > limit {
        return Err(Error::ChallengeTooLarge { limit, actual });
    }
    Ok(())
}
