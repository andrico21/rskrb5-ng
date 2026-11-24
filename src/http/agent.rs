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

use core::fmt;

use http_types::{
    HeaderMap, Method, Request, Response, StatusCode, Uri,
    header::{CONTENT_TYPE, HeaderValue, InvalidHeaderValue, WWW_AUTHENTICATE},
};

use self::chain::Chain;
use super::{
    ClientNegotiateResponse, classify_negotiate_response, mutual_requested_by,
    negotiate_challenge_is_bare, origin::Origin, wire::HttpExchange,
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

/// A cookie jar the client consults for every request and feeds with every
/// response (the `http-client` leaf provides [`CookieStore`]).
///
/// [`CookieStore`]: super::cookies::CookieStore
pub trait CookieJar: Send {
    /// The `Cookie` header value for a request to `uri`, if the jar holds any.
    fn cookie_header(&self, uri: &Uri) -> Option<HeaderValue>;

    /// Store the `Set-Cookie` headers of a response to a request for `uri`;
    /// a cookie the jar refuses is dropped.
    fn store(&mut self, uri: &Uri, headers: &HeaderMap);
}

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

/// The authenticated context of a request and its classified response.
struct Negotiated {
    /// The initiator context that built the request's token.
    context: InitiatorContext,
    /// The classification of the response against that context.
    negotiation: ClientNegotiateResponse,
}

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
    /// Returns the errors of [`Self::round`] and [`Self::context_for`],
    /// [`Error::ChallengeLimit`], [`Error::ChallengeTooLarge`] and, when
    /// `mutual` is set, [`Error::MutualAuthenticationNotProven`].
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe, see the module documentation.
    async fn hop(
        &mut self,
        chain: &mut Chain,
        mutual: bool,
    ) -> Result<(Response<Vec<u8>>, Option<Negotiated>), Error> {
        let mut sent = if chain.is_authenticated() {
            Some(self.context_for(chain.origin()).await?)
        } else {
            None
        };
        let mut response = self.round(chain, sent.as_ref()).await?;
        let mut rounds = 0_u8;
        while chain.on_home() && is_fresh_challenge(&response)? {
            check_challenge_size(&response, self.max_challenge_bytes)?;
            if rounds >= self.max_challenges {
                return Err(Error::ChallengeLimit {
                    limit: self.max_challenges,
                });
            }
            rounds = rounds.saturating_add(1);
            let fresh = self.context_for(chain.origin()).await?;
            response = self.round(chain, Some(&fresh)).await?;
            sent = Some(fresh);
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

    /// The initiator context for the `HTTP/<host>` service of `origin`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Negotiate`] when the service name is invalid or no
    /// token can be built.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: the client caches a service ticket only after its exchange
    /// completes, so dropping the future leaves it consistent.
    async fn context_for(&mut self, origin: &Origin) -> Result<InitiatorContext, Error> {
        let service = self
            .service_realm
            .as_ref()
            .map_or_else(
                || Principal::host_based_service("HTTP", origin.host()),
                |realm| Principal::host_based_service_in_realm("HTTP", origin.host(), realm),
            )
            .map_err(Http::from)?;
        Ok(self
            .negotiate
            .authorization_context_with_options(service, self.options.clone())
            .await
            .map_err(Http::from)?)
    }

    /// Send the current request of `chain`, with `context`'s token and the
    /// jar's cookies, and feed the jar with the response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Negotiate`] for a token that is not a header value and
    /// the exchange's errors.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe, see the module documentation.
    async fn round(
        &mut self,
        chain: &Chain,
        context: Option<&InitiatorContext>,
    ) -> Result<Response<Vec<u8>>, Error> {
        let authorization = context
            .map(|found| {
                let mut value = HeaderValue::from_str(found.header_ref())?;
                value.set_sensitive(true);
                Ok::<_, InvalidHeaderValue>(value)
            })
            .transpose()
            .map_err(Http::from)?;
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
        let response = self.exchange.exchange(request).await?;
        self.trace.emit(&Event::Transport {
            step: TransportStep::Answered,
            wire,
            target: Identity::new(chain.origin().host()),
            size: response.body().len(),
        });
        if let Some(jar) = self.jar.as_mut() {
            jar.store(chain.uri(), response.headers());
        }
        Ok(response)
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
