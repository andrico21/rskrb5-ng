//! HTTP and Tower adapters for SPNEGO Negotiate authentication.
//!
//! The plain HTTP helpers are available with the `http` feature. The Tower
//! middleware is available with the `tower` feature and validates service-side
//! `Authorization: Negotiate ...` headers before forwarding requests.

#[cfg(feature = "tower")]
use alloc::{borrow::Cow, sync::Arc};
#[cfg(feature = "tower")]
use core::task::{Context, Poll};
#[cfg(feature = "tower")]
use core::time::Duration;
use core::{fmt, result::Result as CoreResult};
#[cfg(feature = "tower")]
use core::{mem, pin::Pin};
#[cfg(feature = "tower")]
use std::{sync::Mutex, time::SystemTime};

use http_types::{
    Request, Response, StatusCode,
    header::{AUTHORIZATION, HeaderValue, WWW_AUTHENTICATE},
};
#[cfg(feature = "tower")]
use tower_layer::Layer;
#[cfg(feature = "tower")]
use tower_service::Service;

#[cfg(feature = "tokio")]
use crate::client::{
    Tokio, negotiate::BlockingClient as BlockingNegotiateClient,
    negotiate::Client as NegotiateClient, principal::Principal,
};
#[cfg(feature = "tower")]
use crate::config::{Config, parameters::DefaultName, restrictions};
#[cfg(feature = "tower")]
use crate::crypto::CryptoPolicy;
#[cfg(feature = "tower")]
use crate::keytab::{self, Keytab};
#[cfg(feature = "tower")]
use crate::service::{ApRepOptions, HostAddress, SharedReplayCache, TransitValidator};
use crate::{
    ap_req::ap_options_to_bits,
    service::{Validator, VerifiedApRep},
    spnego::{self, AcceptedContext},
};

/// HTTP Negotiate adapter result.
pub type Result<T> = CoreResult<T, Error>;

use crate::error::Http as Error;
#[cfg(feature = "tower")]
use crate::error::{Service as ServiceError, Spnego as SpnegoError};

/// Tower Negotiate middleware error.
#[cfg(feature = "tower")]
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum TowerError<E> {
    /// HTTP Negotiate processing failed.
    #[error("{0}")]
    Http(#[from] Error),
    /// Wrapped Tower service failed.
    #[error("inner service error")]
    Inner(E),
}

#[cfg(feature = "tower")]
impl<E> fmt::Debug for TowerError<E> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(_) => f.write_str("TowerError::Http"),
            Self::Inner(_) => f.write_str("TowerError::Inner"),
        }
    }
}

/// Client-side HTTP Negotiate wrapper error.
///
/// `E` is the caller-provided sender's error type and `B` is the response body
/// type, so a response that failed mutual authentication can be returned to the
/// caller for diagnostics.
#[cfg(feature = "tokio")]
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum NegotiateHttpError<E, B> {
    /// HTTP Negotiate processing failed.
    #[error("{0}")]
    Http(#[from] Error),
    /// The caller-provided HTTP sender failed.
    #[error("HTTP sender failed")]
    Sender(E),
    /// Mutual authentication was requested, but the final response did not
    /// carry an AP-REP that verified against the initiator context.
    ///
    /// The response must not be treated as coming from an authenticated server.
    #[error("mutual authentication was requested but the server did not prove its identity")]
    MutualAuthenticationNotProven {
        /// Classification of the final response.
        ///
        /// `None` when the first response never issued a `401 WWW-Authenticate:
        /// Negotiate` challenge, so no authenticated retry was sent.
        negotiation: Option<ClientNegotiateResponse>,
        /// The final HTTP response, kept for diagnostics.
        response: Box<Response<B>>,
    },
}

#[cfg(feature = "tokio")]
impl<E, B> fmt::Debug for NegotiateHttpError<E, B> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(_) => f.write_str("NegotiateHttpError::Http"),
            Self::Sender(_) => f.write_str("NegotiateHttpError::Sender"),
            Self::MutualAuthenticationNotProven {
                negotiation,
                response,
            } => f
                .debug_struct("MutualAuthenticationNotProven")
                .field("negotiation", negotiation)
                .field("status", &response.status())
                .finish(),
        }
    }
}

/// Client-side HTTP Negotiate response classification.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientNegotiateResponse {
    /// The response did not contain any `WWW-Authenticate` header.
    NoAuthenticateHeader,
    /// The response contained authentication challenges, but none were Negotiate.
    NoNegotiateChallenge,
    /// The response contains a bare `Negotiate` challenge and the request should be retried with
    /// an Authorization token.
    Challenge,
    /// The response accepted the context. AP-REP details are present when the server returned an
    /// AP-REP token and it verified successfully.
    Accepted {
        /// Verified AP-REP data when mutual authentication was returned by the server.
        ap_rep: Option<VerifiedApRep>,
    },
    /// The peer explicitly rejected the SPNEGO negotiation.
    Rejected,
    /// The peer returned a malformed or unexpected Negotiate token.
    InvalidToken {
        /// Human-readable parse or validation failure.
        message: String,
    },
}

impl fmt::Debug for ClientNegotiateResponse {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAuthenticateHeader => f.write_str("NoAuthenticateHeader"),
            Self::NoNegotiateChallenge => f.write_str("NoNegotiateChallenge"),
            Self::Challenge => f.write_str("Challenge"),
            Self::Accepted { ap_rep } => {
                f.debug_struct("Accepted").field("ap_rep", ap_rep).finish()
            }
            Self::Rejected => f.write_str("Rejected"),
            Self::InvalidToken { message } => f
                .debug_struct("InvalidToken")
                .field("message_len", &message.len())
                .finish(),
        }
    }
}

/// Result of a client-side HTTP Negotiate send wrapper.
#[cfg(feature = "tokio")]
#[non_exhaustive]
pub struct NegotiateHttpResponse<B> {
    /// The final HTTP response.
    ///
    /// This is the first response when no `401 WWW-Authenticate: Negotiate`
    /// challenge was present, or the retried authenticated response otherwise.
    response: Response<B>,
    /// Initiator context used for the retry, when a Negotiate retry happened.
    context: Option<spnego::InitiatorContext>,
    /// Classification of the final response's Negotiate authentication state.
    ///
    /// `None` means no Negotiate retry was attempted. When present, this is
    /// computed with [`classify_negotiate_response`] and may be
    /// [`ClientNegotiateResponse::NoAuthenticateHeader`] for servers that accept
    /// the request without returning a final `WWW-Authenticate` token.
    negotiation: Option<ClientNegotiateResponse>,
}

#[cfg(feature = "tokio")]
impl<B> fmt::Debug for NegotiateHttpResponse<B> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            response,
            context,
            negotiation,
        } = self;
        f.debug_struct("NegotiateHttpResponse")
            .field("status", &response.status())
            .field("context", context)
            .field("negotiation", negotiation)
            .finish()
    }
}

#[cfg(feature = "tokio")]
impl<B> NegotiateHttpResponse<B> {
    /// Borrow the application response.
    #[inline]
    #[must_use]
    pub const fn response(&self) -> &Response<B> {
        &self.response
    }
    /// Borrow the retained authentication context.
    #[inline]
    #[must_use]
    pub const fn context(&self) -> Option<&spnego::InitiatorContext> {
        self.context.as_ref()
    }
    /// Borrow the negotiation classification.
    #[inline]
    #[must_use]
    pub const fn negotiation(&self) -> Option<&ClientNegotiateResponse> {
        self.negotiation.as_ref()
    }
    /// Transfer the response and context without copying credentials.
    #[inline]
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Response<B>,
        Option<spnego::InitiatorContext>,
        Option<ClientNegotiateResponse>,
    ) {
        let Self {
            response,
            context,
            negotiation,
        } = self;
        (response, context, negotiation)
    }
    /// The result for a first response that issued no Negotiate challenge.
    const fn not_negotiated(response: Response<B>) -> Self {
        Self {
            response,
            context: None,
            negotiation: None,
        }
    }

    /// The result of an authenticated retry with its initiator context and the
    /// classification of its final response.
    const fn negotiated(
        response: Response<B>,
        context: spnego::InitiatorContext,
        negotiation: ClientNegotiateResponse,
    ) -> Self {
        Self {
            response,
            context: Some(context),
            negotiation: Some(negotiation),
        }
    }

    /// Return whether the wrapper retried after a Negotiate challenge.
    #[inline]
    pub const fn did_negotiate(&self) -> bool {
        self.context.is_some()
    }

    /// Consume the wrapper result and return the final HTTP response.
    #[inline]
    pub fn into_response(self) -> Response<B> {
        self.response
    }
}

/// Return the HTTP Authorization header as a string.
///
/// # Errors
///
/// Returns [`Error::MissingAuthorization`] when the header is absent and
/// [`Error::InvalidHeader`] when its value is not visible ASCII.
#[inline]
pub fn authorization_header<B>(request: &Request<B>) -> Result<&str> {
    request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(Error::MissingAuthorization)?
        .to_str()
        .map_err(Error::InvalidHeader)
}

/// Set the HTTP Authorization header.
///
/// # Errors
///
/// Returns [`Error::InvalidHeaderValue`] when `value` is not a valid header
/// value.
#[inline]
pub fn set_authorization_header<B>(request: &mut Request<B>, value: &str) -> Result<()> {
    let mut header = HeaderValue::from_str(value)?;
    header.set_sensitive(true);
    drop(request.headers_mut().insert(AUTHORIZATION, header));
    Ok(())
}

/// Add a SPNEGO Authorization header to an HTTP request using a high-level client.
///
/// # Errors
///
/// Returns the errors of [`authorize_request_context`].
///
/// # Cancel safety
///
/// cancel-safe: the header is set only after the initiator context is built,
/// and the client caches a service ticket only after its exchange completes,
/// so dropping the future leaves the request and the client consistent.
#[cfg(feature = "tokio")]
#[inline]
pub async fn authorize_request<B>(
    client: &mut Tokio,
    request: &mut Request<B>,
    service: Principal,
) -> Result<()> {
    drop(authorize_request_context(client, request, service).await?);
    Ok(())
}

/// Add a SPNEGO Authorization header and return the retained initiator context.
///
/// # Errors
///
/// Returns [`Error::Client`] when the service ticket or the initiator context
/// cannot be obtained, and [`Error::InvalidHeaderValue`] when the token is not
/// a valid header value.
///
/// # Cancel safety
///
/// cancel-safe: the header is set only after the initiator context is built,
/// and the client caches a service ticket only after its exchange completes,
/// so dropping the future leaves the request and the client consistent.
#[cfg(feature = "tokio")]
#[inline]
pub async fn authorize_request_context<B>(
    client: &mut Tokio,
    request: &mut Request<B>,
    service: Principal,
) -> Result<spnego::InitiatorContext> {
    let context = client.spnego_context(service).await?;
    set_authorization_header(request, context.header_ref())?;
    Ok(context)
}

/// Add a SPNEGO Authorization header with explicit initiator options.
///
/// # Errors
///
/// Returns the errors of [`authorize_request_context`].
///
/// # Cancel safety
///
/// cancel-safe: the header is set only after the initiator context is built,
/// and the client caches a service ticket only after its exchange completes,
/// so dropping the future leaves the request and the client consistent.
#[cfg(feature = "tokio")]
#[inline]
pub async fn authorize_request_context_with_options<B>(
    client: &mut Tokio,
    request: &mut Request<B>,
    service: Principal,
    options: spnego::InitiatorContextOptions,
) -> Result<spnego::InitiatorContext> {
    let context = client.spnego_context_with_options(service, options).await?;
    set_authorization_header(request, context.header_ref())?;
    Ok(context)
}

/// Add a SPNEGO Authorization header using a high-level Negotiate client wrapper.
///
/// # Errors
///
/// Returns the errors of [`authorize_request_context`].
///
/// # Cancel safety
///
/// cancel-safe: the header is set only after the initiator context is built,
/// and the client caches a service ticket only after its exchange completes,
/// so dropping the future leaves the request and the client consistent.
#[cfg(feature = "tokio")]
#[inline]
pub async fn authorize_request_context_with_negotiate_client<B>(
    client: &mut NegotiateClient,
    request: &mut Request<B>,
    service: Principal,
) -> Result<spnego::InitiatorContext> {
    let context = client.authorization_context(service).await?;
    set_authorization_header(request, context.header_ref())?;
    Ok(context)
}

/// Add a SPNEGO Authorization header using a Negotiate client and explicit initiator options.
///
/// # Errors
///
/// Returns the errors of [`authorize_request_context`].
///
/// # Cancel safety
///
/// cancel-safe: the header is set only after the initiator context is built,
/// and the client caches a service ticket only after its exchange completes,
/// so dropping the future leaves the request and the client consistent.
#[cfg(feature = "tokio")]
#[inline]
pub async fn authorize_request_context_with_negotiate_client_options<B>(
    client: &mut NegotiateClient,
    request: &mut Request<B>,
    service: Principal,
    options: spnego::InitiatorContextOptions,
) -> Result<spnego::InitiatorContext> {
    let context = client
        .authorization_context_with_options(service, options)
        .await?;
    set_authorization_header(request, context.header_ref())?;
    Ok(context)
}

/// Send an HTTP request with a 401 Negotiate retry using a high-level client.
///
/// `make_request` is called once for the unauthenticated request and a second
/// time only when the first response is `401 Unauthorized` with a Negotiate
/// challenge. It must therefore build a fresh replayable request body each time
/// it is called. `send_request` can adapt any HTTP client by accepting the
/// generic `http::Request` value and returning a generic `http::Response`.
///
/// The default initiator options do not request mutual authentication, so the
/// final response is returned with its [`ClientNegotiateResponse`]
/// classification and the caller decides how to treat it. Use
/// [`send_with_negotiate_options`] to require mutual authentication.
///
/// # Errors
///
/// Returns the errors of [`send_with_negotiate_options`].
///
/// # Cancel safety
///
/// NOT cancel-safe. Once `send_request` has been called, dropping the future
/// leaves unknown whether the server received the unauthenticated request or
/// the authenticated retry, so the caller must treat a request that is not
/// idempotent as possibly delivered.
#[cfg(feature = "tokio")]
#[inline]
pub async fn send_with_negotiate<
    ReqBody,
    RespBody,
    MakeRequest,
    SendRequest,
    SendFuture,
    SendError,
>(
    client: &mut NegotiateClient,
    service: Principal,
    make_request: MakeRequest,
    send_request: SendRequest,
) -> CoreResult<NegotiateHttpResponse<RespBody>, NegotiateHttpError<SendError, RespBody>>
where
    MakeRequest: FnMut() -> Request<ReqBody>,
    SendRequest: FnMut(Request<ReqBody>) -> SendFuture,
    SendFuture: Future<Output = CoreResult<Response<RespBody>, SendError>>,
{
    send_with_negotiate_options(
        client,
        service,
        spnego::InitiatorContextOptions::new(),
        make_request,
        send_request,
    )
    .await
}

/// Send an HTTP request with a 401 Negotiate retry and explicit initiator options.
///
/// `make_request` must be replayable: the wrapper calls it again after a
/// Negotiate challenge so request bodies are never cloned or buffered
/// implicitly.
///
/// When `options` request mutual authentication (the AP option
/// `mutual-required`, `0x2000_0000`, or [`spnego::CONTEXT_FLAG_MUTUAL`]), the
/// wrapper fails closed: unless the final response carries an AP-REP that
/// verifies against the initiator context, it returns
/// [`NegotiateHttpError::MutualAuthenticationNotProven`] with the final
/// response. This covers a first response that never issued a Negotiate
/// challenge and a final response without `WWW-Authenticate`, without a
/// Negotiate challenge, or without a valid AP-REP. Without a mutual request
/// the final response is returned with its classification.
///
/// # Errors
///
/// Returns [`NegotiateHttpError::Sender`] when `send_request` fails,
/// [`NegotiateHttpError::Http`] when a challenge header is malformed or the
/// initiator context cannot be built, and
/// [`NegotiateHttpError::MutualAuthenticationNotProven`] as described above.
///
/// # Cancel safety
///
/// NOT cancel-safe. Once `send_request` has been called, dropping the future
/// leaves unknown whether the server received the unauthenticated request or
/// the authenticated retry, so the caller must treat a request that is not
/// idempotent as possibly delivered.
#[cfg(feature = "tokio")]
#[inline]
pub async fn send_with_negotiate_options<
    ReqBody,
    RespBody,
    MakeRequest,
    SendRequest,
    SendFuture,
    SendError,
>(
    client: &mut NegotiateClient,
    service: Principal,
    options: spnego::InitiatorContextOptions,
    mut make_request: MakeRequest,
    mut send_request: SendRequest,
) -> CoreResult<NegotiateHttpResponse<RespBody>, NegotiateHttpError<SendError, RespBody>>
where
    MakeRequest: FnMut() -> Request<ReqBody>,
    SendRequest: FnMut(Request<ReqBody>) -> SendFuture,
    SendFuture: Future<Output = CoreResult<Response<RespBody>, SendError>>,
{
    let mutual = mutual_requested_by(&options);
    let first = send_request(make_request())
        .await
        .map_err(NegotiateHttpError::Sender)?;
    if !should_retry_with_negotiate(&first)? {
        return unchallenged_result(mutual, first);
    }

    let mut retry = make_request();
    let context = client
        .authorization_context_with_options(service, options)
        .await
        .map_err(Error::from)?;
    set_authorization_header(&mut retry, context.header_ref())?;

    let response = send_request(retry)
        .await
        .map_err(NegotiateHttpError::Sender)?;
    negotiated_result(mutual, response, context)
}

/// Send an HTTP request with a 401 Negotiate retry using a blocking client.
///
/// `make_request` has the same replay contract as [`send_with_negotiate`]: it
/// is called once for the first request and again after a Negotiate challenge.
///
/// The default initiator options do not request mutual authentication; use
/// [`send_with_blocking_negotiate_options`] to require it.
///
/// # Errors
///
/// Returns the errors of [`send_with_blocking_negotiate_options`].
#[cfg(feature = "tokio")]
#[inline]
pub fn send_with_blocking_negotiate<ReqBody, RespBody, MakeRequest, SendRequest, SendError>(
    client: &mut BlockingNegotiateClient,
    service: Principal,
    make_request: MakeRequest,
    send_request: SendRequest,
) -> CoreResult<NegotiateHttpResponse<RespBody>, NegotiateHttpError<SendError, RespBody>>
where
    MakeRequest: FnMut() -> Request<ReqBody>,
    SendRequest: FnMut(Request<ReqBody>) -> CoreResult<Response<RespBody>, SendError>,
{
    send_with_blocking_negotiate_options(
        client,
        service,
        spnego::InitiatorContextOptions::new(),
        make_request,
        send_request,
    )
}

/// Send an HTTP request with a blocking 401 Negotiate retry and explicit initiator options.
///
/// Requested mutual authentication fails closed exactly as in
/// [`send_with_negotiate_options`]: without a verified AP-REP the wrapper
/// returns [`NegotiateHttpError::MutualAuthenticationNotProven`].
///
/// # Errors
///
/// Returns [`NegotiateHttpError::Sender`] when `send_request` fails,
/// [`NegotiateHttpError::Http`] when a challenge header is malformed or the
/// initiator context cannot be built, and
/// [`NegotiateHttpError::MutualAuthenticationNotProven`] as described above.
#[cfg(feature = "tokio")]
#[inline]
pub fn send_with_blocking_negotiate_options<
    ReqBody,
    RespBody,
    MakeRequest,
    SendRequest,
    SendError,
>(
    client: &mut BlockingNegotiateClient,
    service: Principal,
    options: spnego::InitiatorContextOptions,
    mut make_request: MakeRequest,
    mut send_request: SendRequest,
) -> CoreResult<NegotiateHttpResponse<RespBody>, NegotiateHttpError<SendError, RespBody>>
where
    MakeRequest: FnMut() -> Request<ReqBody>,
    SendRequest: FnMut(Request<ReqBody>) -> CoreResult<Response<RespBody>, SendError>,
{
    let mutual = mutual_requested_by(&options);
    let first = send_request(make_request()).map_err(NegotiateHttpError::Sender)?;
    if !should_retry_with_negotiate(&first)? {
        return unchallenged_result(mutual, first);
    }

    let mut retry = make_request();
    let context = client
        .authorization_context_with_options(service, options)
        .map_err(Error::from)?;
    set_authorization_header(&mut retry, context.header_ref())?;

    let response = send_request(retry).map_err(NegotiateHttpError::Sender)?;
    negotiated_result(mutual, response, context)
}

/// Validate the request's Negotiate header and attach the accepted context to extensions.
///
/// Incoming Authorization values are retained for forwarding, but marked sensitive
/// before validation so downstream Debug output and HTTP compression respect them.
///
/// # Errors
///
/// Returns the errors of [`authorization_header`], and [`Error::Spnego`] when
/// the token is malformed or its AP-REQ fails validation.
#[inline]
pub fn accept_request<B>(
    validator: &mut Validator<'_>,
    request: &mut Request<B>,
) -> Result<AcceptedContext> {
    for (name, header) in request.headers_mut() {
        if name == AUTHORIZATION {
            header.set_sensitive(true);
        }
    }
    let accepted = spnego::accept_sec_context_header(validator, authorization_header(request)?)?;
    drop(request.extensions_mut().insert(accepted.clone()));
    Ok(accepted)
}

/// Return the first Negotiate challenge from all WWW-Authenticate headers.
///
/// # Errors
///
/// Returns [`Error::InvalidHeader`] when a header value before the challenge
/// is not visible ASCII, [`Error::MissingWwwAuthenticate`] when there is no
/// `WWW-Authenticate` header, and [`Error::MissingNegotiateChallenge`] when
/// none of them carries a Negotiate challenge.
#[inline]
pub fn www_authenticate_negotiate_header<B>(response: &Response<B>) -> Result<&str> {
    let mut saw_www_authenticate = false;
    for value in response.headers().get_all(WWW_AUTHENTICATE) {
        saw_www_authenticate = true;
        let header = value.to_str().map_err(Error::InvalidHeader)?;
        if let Some(challenge) = negotiate_challenge(header) {
            return Ok(challenge);
        }
    }

    if saw_www_authenticate {
        Err(Error::MissingNegotiateChallenge)
    } else {
        Err(Error::MissingWwwAuthenticate)
    }
}

/// Verify a SPNEGO AP-REP response token from WWW-Authenticate headers.
///
/// # Errors
///
/// Returns the errors of [`www_authenticate_negotiate_header`], and
/// [`Error::Spnego`] with the errors of
/// [`spnego::InitiatorContext::verify_ap_rep_response_header`] when the token
/// is malformed, the negotiation is incomplete, a mechanism was not offered, a
/// mechListMIC does not verify or its AP-REP fails verification.
#[inline]
pub fn verify_ap_rep_response<B>(
    context: &spnego::InitiatorContext,
    response: &Response<B>,
) -> Result<VerifiedApRep> {
    Ok(context.verify_ap_rep_response_header(www_authenticate_negotiate_header(response)?)?)
}

/// Classify a response in a client-side HTTP Negotiate exchange.
///
/// If the response carries an AP-REP token, this verifies it with the retained initiator context.
#[inline]
pub fn classify_negotiate_response<B>(
    context: &spnego::InitiatorContext,
    response: &Response<B>,
) -> ClientNegotiateResponse {
    let mut saw_www_authenticate = false;
    for value in response.headers().get_all(WWW_AUTHENTICATE) {
        saw_www_authenticate = true;
        let header = match value.to_str() {
            Ok(header) => header,
            Err(source) => {
                return ClientNegotiateResponse::InvalidToken {
                    message: source.to_string(),
                };
            }
        };
        if let Some(challenge) = negotiate_challenge(header) {
            return classify_negotiate_challenge(context, challenge);
        }
    }

    if saw_www_authenticate {
        ClientNegotiateResponse::NoNegotiateChallenge
    } else {
        ClientNegotiateResponse::NoAuthenticateHeader
    }
}

/// Whether a first response is a `401 Unauthorized` with a Negotiate
/// challenge, so the request is retried with a token.
///
/// # Errors
///
/// Returns [`Error::InvalidHeader`] when a `WWW-Authenticate` value of a 401
/// response is not visible ASCII.
#[cfg(feature = "tokio")]
fn should_retry_with_negotiate<B>(response: &Response<B>) -> Result<bool> {
    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(false);
    }

    match www_authenticate_negotiate_header(response) {
        Ok(_) => Ok(true),
        Err(Error::MissingWwwAuthenticate | Error::MissingNegotiateChallenge) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Whether the initiator options ask for mutual authentication in any supported form.
#[cfg(feature = "tokio")]
fn mutual_requested_by(options: &spnego::InitiatorContextOptions) -> bool {
    options.ap_option_bits() & AP_OPTION_MUTUAL_REQUIRED != 0
        || mutual_requested(options.context_flags())
}

/// Test every flag mask, matching the authenticator's bitwise encoding.
fn mutual_requested(flags: &[u32]) -> bool {
    flags
        .iter()
        .any(|mask| mask & spnego::CONTEXT_FLAG_MUTUAL != 0)
}

/// The outcome when the first response carried no Negotiate challenge, so no
/// authenticated retry was sent.
///
/// # Errors
///
/// Returns [`NegotiateHttpError::MutualAuthenticationNotProven`] with that
/// response when mutual authentication was requested: no AP-REP can have
/// proven the server.
#[cfg(feature = "tokio")]
fn unchallenged_result<E, B>(
    mutual: bool,
    first: Response<B>,
) -> CoreResult<NegotiateHttpResponse<B>, NegotiateHttpError<E, B>> {
    if mutual {
        return Err(NegotiateHttpError::MutualAuthenticationNotProven {
            negotiation: None,
            response: Box::new(first),
        });
    }
    Ok(NegotiateHttpResponse::not_negotiated(first))
}

/// The outcome of an authenticated retry: its final response, classified
/// against the initiator context that produced the request's token.
///
/// # Errors
///
/// Returns [`NegotiateHttpError::MutualAuthenticationNotProven`] with the
/// final response when mutual authentication was requested and the response
/// did not carry an AP-REP that verified against `context`.
#[cfg(feature = "tokio")]
fn negotiated_result<E, B>(
    mutual: bool,
    response: Response<B>,
    context: spnego::InitiatorContext,
) -> CoreResult<NegotiateHttpResponse<B>, NegotiateHttpError<E, B>> {
    let negotiation = classify_negotiate_response(&context, &response);
    if mutual
        && !matches!(
            negotiation,
            ClientNegotiateResponse::Accepted { ap_rep: Some(_) }
        )
    {
        return Err(NegotiateHttpError::MutualAuthenticationNotProven {
            negotiation: Some(negotiation),
            response: Box::new(response),
        });
    }
    Ok(NegotiateHttpResponse::negotiated(
        response,
        context,
        negotiation,
    ))
}

/// Build a `401 Unauthorized` response that starts Negotiate authentication.
#[inline]
pub fn challenge_response<B>() -> Response<B>
where
    B: Default,
{
    let mut response = Response::new(B::default());
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    drop(response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(spnego::HTTP_NEGOTIATE),
    ));
    harden_response(&mut response);
    response
}

/// Build a `401 Unauthorized` response that carries a SPNEGO reject token.
///
/// # Errors
///
/// Returns [`Error::Spnego`] when the reject token cannot be encoded and
/// [`Error::InvalidHeaderValue`] when it is not a valid header value.
#[inline]
pub fn reject_response<B>() -> Result<Response<B>>
where
    B: Default,
{
    response_with_www_authenticate(StatusCode::UNAUTHORIZED, &spnego::reject_header()?)
}

/// The first Negotiate challenge (scheme and token) among the
/// comma-separated challenges of one `WWW-Authenticate` value.
fn negotiate_challenge(header: &str) -> Option<&str> {
    for segment in WwwAuthenticateSegments::new(header) {
        let challenge = segment.trim();
        if let Some((scheme, suffix)) = challenge.split_at_checked(spnego::HTTP_NEGOTIATE.len())
            && scheme.eq_ignore_ascii_case(spnego::HTTP_NEGOTIATE)
            && (suffix.is_empty() || suffix.starts_with(char::is_whitespace))
        {
            return Some(challenge);
        }
    }
    None
}

/// RFC 4120 AP option `mutual-required`.
const AP_OPTION_MUTUAL_REQUIRED: u32 = 0x2000_0000;

/// Whether the initiator asked for mutual authentication in any supported form.
fn mutual_authentication_requested(context: &spnego::InitiatorContext) -> bool {
    ap_options_to_bits(&context.ap_req_ref().ap_options) & AP_OPTION_MUTUAL_REQUIRED != 0
        || mutual_requested(context.context_flags())
}

/// Classify one Negotiate challenge of a client-side exchange, verifying an
/// AP-REP token against `context`.
fn classify_negotiate_challenge(
    context: &spnego::InitiatorContext,
    challenge: &str,
) -> ClientNegotiateResponse {
    if negotiate_challenge_is_bare(challenge) {
        return ClientNegotiateResponse::Challenge;
    }

    let token = match spnego::parse_negotiate_header(challenge) {
        Ok(token) => token,
        Err(source) => {
            return ClientNegotiateResponse::InvalidToken {
                message: source.to_string(),
            };
        }
    };

    let response = match token {
        spnego::Token::Resp(response) => response,
        spnego::Token::Init(_) => {
            return ClientNegotiateResponse::InvalidToken {
                message: "expected NegTokenResp, got NegTokenInit".to_owned(),
            };
        }
    };

    if response.neg_state() == Some(spnego::NegState::Reject) {
        return ClientNegotiateResponse::Rejected;
    }
    if let Err(source) = context.validate_completion(&response) {
        return ClientNegotiateResponse::InvalidToken {
            message: source.to_string(),
        };
    }

    let Some(response_token) = response.response_token() else {
        if mutual_authentication_requested(context) {
            return ClientNegotiateResponse::InvalidToken {
                message: "mutual authentication was requested but the peer returned no AP-REP"
                    .to_owned(),
            };
        }
        return ClientNegotiateResponse::Accepted { ap_rep: None };
    };
    let krb5 = match spnego::Krb5MechToken::decode(response_token) {
        Ok(krb5) => krb5,
        Err(source) => {
            return ClientNegotiateResponse::InvalidToken {
                message: source.to_string(),
            };
        }
    };

    match krb5.token_id() {
        spnego::Krb5TokenId::ApRep => match context.verify_ap_rep(krb5.message()) {
            Ok(ap_rep) => ClientNegotiateResponse::Accepted {
                ap_rep: Some(ap_rep),
            },
            Err(source) => ClientNegotiateResponse::InvalidToken {
                message: source.to_string(),
            },
        },
        spnego::Krb5TokenId::KrbError => ClientNegotiateResponse::Rejected,
        spnego::Krb5TokenId::ApReq => ClientNegotiateResponse::InvalidToken {
            message: "expected AP-REP token, got AP-REQ token".to_owned(),
        },
    }
}

/// Whether the challenge is the bare `Negotiate` scheme without a token.
fn negotiate_challenge_is_bare(challenge: &str) -> bool {
    let mut parts = challenge.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or_default();
    scheme.eq_ignore_ascii_case(spnego::HTTP_NEGOTIATE)
        && parts.next().is_none_or(|value| value.trim().is_empty())
}

/// Iterator over the comma-separated challenges of one `WWW-Authenticate`
/// value. Commas inside quoted strings do not split, and the whitespace after
/// a separating comma is skipped.
struct WwwAuthenticateSegments<'value> {
    /// The text not yet split.
    remaining: &'value str,
}

impl<'value> WwwAuthenticateSegments<'value> {
    /// Split `value` from its start.
    const fn new(value: &'value str) -> Self {
        Self { remaining: value }
    }
}

impl<'value> Iterator for WwwAuthenticateSegments<'value> {
    type Item = &'value str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }

        let mut quoted = false;
        let mut escaped = false;
        let mut comma = None;
        for (index, byte) in self.remaining.bytes().enumerate() {
            if escaped {
                escaped = false;
            } else if byte == b'\\' && quoted {
                escaped = true;
            } else if byte == b'"' {
                quoted = !quoted;
            } else if byte == b',' && !quoted {
                comma = Some(index);
                break;
            } else {
                // Any other byte belongs to the current segment.
            }
        }

        // A comma is ASCII, so its index is always a char boundary.
        let (segment, rest) = comma
            .and_then(|index| self.remaining.split_at_checked(index))
            .unwrap_or((self.remaining, ""));
        self.remaining = rest
            .strip_prefix(',')
            .unwrap_or(rest)
            .trim_start_matches(|character: char| character.is_ascii_whitespace());
        Some(segment)
    }
}

/// Build a response with `status` and one `WWW-Authenticate` header.
///
/// # Errors
///
/// Returns [`Error::InvalidHeaderValue`] when `header` is not a valid header
/// value.
fn response_with_www_authenticate<B>(status: StatusCode, header: &str) -> Result<Response<B>>
where
    B: Default,
{
    let mut response = Response::new(B::default());
    *response.status_mut() = status;
    let mut value = HeaderValue::from_str(header)?;
    value.set_sensitive(true);
    drop(response.headers_mut().insert(WWW_AUTHENTICATE, value));
    harden_response(&mut response);
    Ok(response)
}

/// Apply secure defaults without overriding the application's explicit policy.
fn harden_response<B>(response: &mut Response<B>) {
    let headers = response.headers_mut();
    for name in [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
    ] {
        drop(headers.remove(name));
    }
    for (name, value) in [
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "deny"),
        (
            "content-security-policy",
            "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
        ),
        ("referrer-policy", "no-referrer"),
        (
            "permissions-policy",
            "accelerometer=(), camera=(), geolocation=(), microphone=()",
        ),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("cache-control", "no-store, max-age=0"),
        ("x-dns-prefetch-control", "off"),
        ("x-permitted-cross-domain-policies", "none"),
    ] {
        if !headers.contains_key(name) {
            drop(headers.insert(name, HeaderValue::from_static(value)));
        }
    }
}

/// Tower layer for service-side HTTP Negotiate validation.
///
/// Clones and services built from one layer share a replay cache by default.
/// Independently constructed layers accepting the same service principal MUST
/// use one [`SharedReplayCache`] via [`Self::with_shared_replay_cache`]. Do not
/// construct a fresh layer/cache per request. In-process sharing does not span
/// replicas, hosts or process restarts; those require coordinated replay state
/// outside this adapter or a deployment with a single accepting boundary.
///
/// Acceptance authenticates the AP-REQ, not the HTTP method, URI, headers or
/// body. This API has no TLS channel-binding input and does not verify channel
/// bindings. TLS is required but does not itself supply request binding here.
/// A stolen token can win its first presentation; replay detection prevents
/// subsequent presentations only within the configured cache scope.
#[cfg(feature = "tower")]
#[derive(Clone)]
pub struct NegotiateLayer<'keytab> {
    /// The service keytab, borrowed or owned.
    keytab: Cow<'keytab, Keytab>,
    /// Options for the validator each service gets.
    validator: ValidatorOptions,
    /// How services answer accepted and rejected requests.
    response: NegotiateResponseOptions,
}

#[cfg(feature = "tower")]
impl fmt::Debug for NegotiateLayer<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            keytab,
            validator,
            response,
        } = self;
        f.debug_struct("NegotiateLayer")
            .field("keytab_entries", &keytab.entries().len())
            .field("validator", validator)
            .field("response", response)
            .finish()
    }
}

#[cfg(feature = "tower")]
impl<'keytab> NegotiateLayer<'keytab> {
    /// Apply one runtime enctype policy to every validator built by this layer.
    #[inline]
    #[must_use]
    pub fn with_crypto_policy(mut self, policy: CryptoPolicy) -> Self {
        self.validator.crypto_policy = policy;
        self
    }
    /// Apply missing security headers and strip fingerprints on inner responses (default: on).
    /// Library-generated challenge and rejection responses are always hardened.
    #[must_use]
    #[inline]
    pub const fn with_response_hardening(mut self, enabled: bool) -> Self {
        self.response.harden_inner = enabled;
        self
    }
    /// Create a Negotiate layer backed by a service keytab.
    #[must_use]
    #[inline]
    pub fn new(keytab: &'keytab Keytab) -> Self {
        Self {
            keytab: Cow::Borrowed(keytab),
            validator: ValidatorOptions::default(),
            response: NegotiateResponseOptions::default(),
        }
    }

    /// Override the validation clock. Useful for deterministic tests.
    #[must_use]
    #[inline]
    pub const fn with_now(mut self, now: SystemTime) -> Self {
        self.validator.now = Some(now);
        self
    }

    /// Override the maximum accepted clock skew.
    ///
    /// # Errors
    ///
    /// Returns a service policy error for incompatible replay retention.
    #[inline]
    pub fn with_max_clock_skew(mut self, max_clock_skew: Duration) -> Result<Self> {
        if let Some(cache) = &self.validator.shared_replay_cache {
            let result = if self.validator.owned_replay_cache {
                cache.configure_owned_skew(max_clock_skew)
            } else {
                cache.ensure_skew(max_clock_skew)
            };
            result.map_err(|error| Error::Spnego(SpnegoError::Service(error)))?;
        }
        self.validator.max_clock_skew = Some(max_clock_skew);
        Ok(self)
    }

    /// Override the principal used for keytab lookup.
    #[must_use]
    #[inline]
    pub fn with_keytab_principal<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.validator.keytab_principal = Some(components.into_iter().map(Into::into).collect());
        self
    }

    /// Provide the client address observed by the service.
    #[must_use]
    #[inline]
    pub fn with_client_address(mut self, client_address: HostAddress) -> Self {
        self.validator.client_address = Some(client_address);
        self
    }

    /// Require the ticket to contain client addresses.
    #[must_use]
    #[inline]
    pub const fn require_client_address(mut self, require_client_address: bool) -> Self {
        self.validator.require_client_address = require_client_address;
        self
    }

    /// Apply this explicit policy to unchecked cross-realm tickets and to
    /// unchecked same-realm tickets with a nonempty transited path.
    ///
    /// AD cross-domain tickets lack TRANSITED-POLICY-CHECKED and are rejected
    /// by default. Opt in for a trusted endpoint pair with
    /// `Arc::new(service::TransitPolicy::direct("USER.REALM", "SERVICE.REALM"))`,
    /// or use [`crate::service::TransitPolicy::domain_x500_paths`] for exact trusted paths.
    #[must_use]
    #[inline]
    pub fn with_transit_validator(mut self, validator: Arc<dyn TransitValidator>) -> Self {
        self.validator.transit_validator = Some(validator);
        self
    }

    /// Share replay detection state with validators built from this layer.
    ///
    /// # Errors
    ///
    /// Returns a service policy error for incompatible replay retention.
    #[inline]
    pub fn with_shared_replay_cache(mut self, replay_cache: SharedReplayCache) -> Result<Self> {
        replay_cache
            .ensure_skew(
                self.validator
                    .max_clock_skew
                    .unwrap_or(Duration::from_mins(5)),
            )
            .map_err(|error| Error::Spnego(SpnegoError::Service(error)))?;
        self.validator.shared_replay_cache = Some(replay_cache);
        self.validator.owned_replay_cache = false;
        Ok(self)
    }

    /// Disable shared replay state for validators built from this layer.
    #[must_use]
    #[inline]
    pub fn without_shared_replay_cache(mut self) -> Self {
        self.validator.shared_replay_cache = None;
        self
    }

    /// Control optional `WWW-Authenticate` AP-REP replies. Required reciprocal
    /// mechanism-list MIC completion still includes its AP-REP.
    #[must_use]
    #[inline]
    pub const fn with_ap_rep(mut self, emit_ap_rep: bool) -> Self {
        self.response.emit_ap_rep = emit_ap_rep;
        self
    }

    /// Override AP-REP response options.
    #[must_use]
    #[inline]
    pub fn with_ap_rep_options(mut self, ap_rep_options: ApRepOptions) -> Self {
        self.response.ap_rep_options = ap_rep_options;
        self
    }

    /// Control whether invalid tokens receive a SPNEGO reject token.
    #[must_use]
    #[inline]
    pub const fn with_reject_invalid(mut self, reject_invalid: bool) -> Self {
        self.response.reject_invalid = reject_invalid;
        self
    }
}

#[cfg(feature = "tower")]
impl NegotiateLayer<'static> {
    #[must_use]
    /// Create a Negotiate layer from an owned service keytab.
    #[inline]
    pub fn from_keytab(keytab: Keytab) -> Self {
        Self {
            keytab: Cow::Owned(keytab),
            validator: ValidatorOptions::default(),
            response: NegotiateResponseOptions::default(),
        }
    }

    /// Create a Negotiate layer by loading a file-backed keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported by the keytab
    /// module. Other keytab stores are rejected explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the name is not a file keytab or the
    /// file cannot be read or parsed.
    #[inline]
    pub fn from_keytab_name<P>(keytab_name: P) -> Result<Self>
    where
        P: AsRef<str>,
    {
        Ok(Self::from_keytab(Keytab::load_name(keytab_name)?))
    }

    /// Create a Negotiate layer from `config.libdefaults.default_keytab_name`.
    ///
    /// # Ambient input
    /// Expands templates using `TMPDIR`, `TEMP`, `APPDATA` and process identity.
    /// Use `from_keytab_name` with a literal name to avoid this discovery.
    ///
    /// The configured `[libdefaults] clockskew` becomes the acceptance window;
    /// [`Self::new`] keeps the gokrb5-compatible 300 s default.
    /// Enctype permission is taken from the same configuration, including legacy opt-ins.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the configured name is not a file keytab
    /// or the file cannot be read or parsed.
    #[inline]
    pub fn from_default_keytab_name(config: &Config) -> Result<Self> {
        restrictions::config(config).map_err(|error| restrictions::configuration_policy(&error))?;
        let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)
            .map_err(|error| restrictions::configuration_policy(&error))?;
        Self::from_keytab(keytab::configured_keytab(
            &config.libdefaults,
            DefaultName::Keytab,
        )?)
        .with_crypto_policy(policy)
        .with_max_clock_skew(config.libdefaults.clockskew)
    }

    /// Create a Negotiate layer from the default keytab.
    ///
    /// # Ambient input
    /// Reads `KRB5_KTNAME` before the configured fallback; invalid Unicode is an
    /// expansion error when `TMPDIR`, `TEMP` or `APPDATA` supplies invalid text;
    /// process identity is read for identity tokens. An invalid `KRB5_KTNAME` is an
    /// error. Use [`Self::from_keytab_name`] for an explicit keytab name.
    ///
    /// `KRB5_KTNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_keytab_name`. The configured
    /// `[libdefaults] clockskew` becomes the acceptance window.
    /// Enctype permission is taken from the same configuration, including legacy opt-ins.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the selected name is not a file keytab
    /// or the file cannot be read or parsed.
    #[inline]
    pub fn from_default_keytab(config: &Config) -> Result<Self> {
        restrictions::config(config).map_err(|error| restrictions::configuration_policy(&error))?;
        let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)
            .map_err(|error| restrictions::configuration_policy(&error))?;
        Self::from_keytab(keytab::default_keytab_name(&config.libdefaults)?)
            .with_crypto_policy(policy)
            .with_max_clock_skew(config.libdefaults.clockskew)
    }

    /// Create a Negotiate layer by loading the file keytab named by `KRB5_KTNAME`.
    ///
    /// # Ambient input
    /// Reads `KRB5_KTNAME`; unset or non-Unicode values are errors. Use
    /// [`Self::from_keytab_name`] for an explicit keytab name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the variable is unset, names a
    /// non-file keytab, or the file cannot be read or parsed.
    #[inline]
    pub fn from_keytab_env() -> Result<Self> {
        Ok(Self::from_keytab(Keytab::load_from_env()?))
    }
}

#[cfg(feature = "tower")]
impl<'layer, S> Layer<S> for NegotiateLayer<'layer> {
    type Service = NegotiateService<'layer, S>;

    #[inline]
    fn layer(&self, inner: S) -> Self::Service {
        NegotiateService {
            inner,
            validator: Arc::new(Mutex::new(self.validator.build(self.keytab.clone()))),
            settings: self.clone(),
            response: self.response.clone(),
        }
    }
}

/// Tower service for service-side HTTP Negotiate validation.
///
/// Internal validation faults produce opaque 500 responses. Their typed cause is
/// retained as `Arc<error::Http>` in response extensions for caller diagnostics;
/// extensions are not serialized onto the wire.
#[cfg(feature = "tower")]
#[derive(Clone)]
pub struct NegotiateService<'keytab, S> {
    /// The wrapped service.
    inner: S,
    /// The validator of this service's requests.
    validator: Arc<Mutex<Validator<'keytab>>>,
    /// Construction settings retained for consuming configuration builders.
    settings: NegotiateLayer<'keytab>,
    /// How accepted and rejected requests are answered.
    response: NegotiateResponseOptions,
}

#[cfg(feature = "tower")]
impl<S> fmt::Debug for NegotiateService<'_, S> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            inner: _,
            validator: _,
            settings,
            response,
        } = self;
        f.debug_struct("NegotiateService")
            .field("settings", settings)
            .field("response", response)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "tower")]
impl<'keytab, S> NegotiateService<'keytab, S> {
    /// Apply runtime enctype permission without clearing replay evidence.
    #[inline]
    #[must_use]
    pub fn with_crypto_policy(self, policy: CryptoPolicy) -> Self {
        self.configure_validator(|validator| validator.with_crypto_policy(policy));
        self
    }
    /// Apply a consuming validator builder without discarding admitted replay records.
    /// A poisoned validator stays poisoned and refuses subsequent requests.
    fn configure_validator<F>(&self, configure: F)
    where
        F: FnOnce(Validator<'keytab>) -> Validator<'keytab>,
    {
        if let Ok(mut guard) = self.validator.lock() {
            let previous = mem::replace(
                &mut *guard,
                self.settings.validator.build(self.settings.keytab.clone()),
            );
            *guard = configure(previous);
        }
    }

    /// Wrap an inner service with default Negotiate validation.
    #[inline]
    pub fn new(inner: S, keytab: &'keytab Keytab) -> Self {
        NegotiateLayer::new(keytab).layer(inner)
    }

    /// Return a shared reference to the wrapped service.
    #[inline]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Return a mutable reference to the wrapped service.
    #[inline]
    pub const fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Override the validation clock. Useful for deterministic tests.
    #[must_use]
    #[inline]
    pub fn with_now(mut self, now: SystemTime) -> Self {
        self.settings = self.settings.with_now(now);
        self.configure_validator(|validator| validator.with_now(now));
        self
    }

    /// Override the maximum accepted clock skew.
    ///
    /// # Errors
    ///
    /// Returns a cache policy error for an incompatible window or poisoned lock.
    #[inline]
    pub fn with_max_clock_skew(mut self, max_clock_skew: Duration) -> Result<Self> {
        self.settings = self.settings.with_max_clock_skew(max_clock_skew)?;
        let mut guard = self.validator.lock().map_err(|_poisoned| {
            Error::Spnego(SpnegoError::Service(ServiceError::ReplayCachePoisoned))
        })?;
        guard
            .set_max_clock_skew(max_clock_skew)
            .map_err(|error| Error::Spnego(SpnegoError::Service(error)))?;
        drop(guard);
        Ok(self)
    }

    /// Override the principal used for keytab lookup.
    #[must_use]
    #[inline]
    pub fn with_keytab_principal<I, T>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.settings = self.settings.with_keytab_principal(components);
        let principal = self
            .settings
            .validator
            .keytab_principal
            .clone()
            .unwrap_or_default();
        self.configure_validator(|validator| validator.with_keytab_principal(principal));
        self
    }

    /// Provide the client address observed by the service.
    #[must_use]
    #[inline]
    pub fn with_client_address(mut self, client_address: HostAddress) -> Self {
        self.settings = self.settings.with_client_address(client_address.clone());
        self.configure_validator(|validator| validator.with_client_address(client_address));
        self
    }

    /// Require the ticket to contain client addresses.
    #[must_use]
    #[inline]
    pub fn require_client_address(mut self, require_client_address: bool) -> Self {
        self.settings = self.settings.require_client_address(require_client_address);
        self.configure_validator(|validator| {
            validator.require_client_address(require_client_address)
        });
        self
    }

    /// Share replay detection state with other validators.
    ///
    /// # Errors
    ///
    /// Returns a cache policy error for incompatible retention or a poisoned lock.
    #[inline]
    pub fn with_shared_replay_cache(mut self, replay_cache: SharedReplayCache) -> Result<Self> {
        self.settings = self
            .settings
            .with_shared_replay_cache(replay_cache.clone())?;
        let mut guard = self.validator.lock().map_err(|_poisoned| {
            Error::Spnego(SpnegoError::Service(ServiceError::ReplayCachePoisoned))
        })?;
        guard
            .attach_replay_cache(replay_cache)
            .map_err(|error| Error::Spnego(SpnegoError::Service(error)))?;
        drop(guard);
        Ok(self)
    }

    /// Disable shared replay state and use this service validator's local cache.
    #[must_use]
    #[inline]
    pub fn without_shared_replay_cache(mut self) -> Self {
        self.settings = self.settings.without_shared_replay_cache();
        self.configure_validator(Validator::without_shared_replay_cache);
        self
    }

    /// Control optional `WWW-Authenticate` AP-REP replies. Required reciprocal
    /// mechanism-list MIC completion still includes its AP-REP.
    #[must_use]
    #[inline]
    pub const fn with_ap_rep(mut self, emit_ap_rep: bool) -> Self {
        self.response.emit_ap_rep = emit_ap_rep;
        self
    }

    /// Override AP-REP response options.
    #[must_use]
    #[inline]
    pub fn with_ap_rep_options(mut self, ap_rep_options: ApRepOptions) -> Self {
        self.response.ap_rep_options = ap_rep_options;
        self
    }

    /// Control whether invalid tokens receive a SPNEGO reject token.
    #[must_use]
    #[inline]
    pub const fn with_reject_invalid(mut self, reject_invalid: bool) -> Self {
        self.response.reject_invalid = reject_invalid;
        self
    }
}

#[cfg(feature = "tower")]
impl<S> NegotiateService<'static, S> {
    /// Wrap an inner service with an owned keytab.
    #[inline]
    pub fn from_keytab(inner: S, keytab: Keytab) -> Self {
        NegotiateLayer::from_keytab(keytab).layer(inner)
    }

    /// Wrap an inner service by loading a file-backed keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported by the keytab
    /// module. Other keytab stores are rejected explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the name is not a file keytab or the
    /// file cannot be read or parsed.
    #[inline]
    pub fn from_keytab_name<P>(inner: S, keytab_name: P) -> Result<Self>
    where
        P: AsRef<str>,
    {
        Ok(NegotiateLayer::from_keytab_name(keytab_name)?.layer(inner))
    }

    /// Wrap an inner service by loading `config.libdefaults.default_keytab_name`.
    ///
    /// # Ambient input
    /// Expands templates using `TMPDIR`, `TEMP`, `APPDATA` and process identity.
    /// Use `from_keytab_name` with a literal name to avoid this discovery.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the configured name is not a file keytab
    /// or the file cannot be read or parsed.
    #[inline]
    pub fn from_default_keytab_name(inner: S, config: &Config) -> Result<Self> {
        Ok(NegotiateLayer::from_default_keytab_name(config)?.layer(inner))
    }

    /// Wrap an inner service with the default keytab.
    ///
    /// # Ambient input
    /// Configured templates read `TMPDIR`, `TEMP`, `APPDATA` and process identity.
    /// Reads `KRB5_KTNAME` before the configured fallback; invalid Unicode is an
    /// error. Use [`Self::from_keytab_name`] for an explicit keytab name.
    ///
    /// `KRB5_KTNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_keytab_name`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the selected name is not a file keytab
    /// or the file cannot be read or parsed.
    #[inline]
    pub fn from_default_keytab(inner: S, config: &Config) -> Result<Self> {
        Ok(NegotiateLayer::from_default_keytab(config)?.layer(inner))
    }

    /// Wrap an inner service by loading the file keytab named by `KRB5_KTNAME`.
    ///
    /// # Ambient input
    /// Reads `KRB5_KTNAME`; unset or non-Unicode values are errors. Use
    /// [`Self::from_keytab_name`] for an explicit keytab name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the variable is unset, names a
    /// non-file keytab, or the file cannot be read or parsed.
    #[inline]
    pub fn from_keytab_env(inner: S) -> Result<Self> {
        Ok(NegotiateLayer::from_keytab_env()?.layer(inner))
    }
}

#[cfg(feature = "tower")]
impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for NegotiateService<'_, S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: 'static,
    S::Error: 'static,
    ResBody: Default + 'static,
{
    type Response = Response<ResBody>;
    type Error = TowerError<S::Error>;
    type Future = NegotiateFuture<S::Future, ResBody, S::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<CoreResult<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(TowerError::Inner)
    }

    #[inline]
    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let Ok(mut validator) = self.validator.lock() else {
            let mut response = Response::new(ResBody::default());
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            drop(
                response
                    .extensions_mut()
                    .insert(Arc::new(Error::Spnego(SpnegoError::Service(
                        ServiceError::ReplayCachePoisoned,
                    )))),
            );
            harden_response(&mut response);
            return NegotiateFuture::ready(Ok(response));
        };
        let accepted = match accept_request(&mut validator, &mut req) {
            Ok(accepted) => accepted,
            Err(Error::MissingAuthorization | Error::InvalidHeader(_)) => {
                return NegotiateFuture::ready(Ok(challenge_response()));
            }
            Err(Error::Spnego(source)) => {
                if matches!(
                    &source,
                    SpnegoError::Service(
                        ServiceError::ReplayCachePoisoned
                            | ServiceError::ReplayCacheClockRollback
                            | ServiceError::ReplayCacheCapacityExceeded { capacity: _ }
                    )
                ) {
                    let mut response = Response::new(ResBody::default());
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    drop(
                        response
                            .extensions_mut()
                            .insert(Arc::new(Error::Spnego(source))),
                    );
                    harden_response(&mut response);
                    return NegotiateFuture::ready(Ok(response));
                }
                let response = if self.response.reject_invalid {
                    reject_response().unwrap_or_else(|_| challenge_response())
                } else {
                    challenge_response()
                };
                return NegotiateFuture::ready(Ok(response));
            }
            Err(error) => {
                return NegotiateFuture::ready(Err(TowerError::Http(error)));
            }
        };

        drop(validator);
        let ap_rep_header = if self.response.emit_ap_rep || accepted.mech_types_der.is_some() {
            match accepted.ap_rep_response_header(&self.response.ap_rep_options.clone()) {
                Ok(header) => Some(header),
                Err(error) => {
                    return NegotiateFuture::ready(Err(TowerError::Http(Error::Spnego(error))));
                }
            }
        } else {
            None
        };

        NegotiateFuture {
            inner: Some(Box::pin(self.inner.call(req))),
            ready: None,
            header: ap_rep_header.map(zeroize::Zeroizing::new),
            harden: self.response.harden_inner,
        }
    }
}

/// Negotiate response future, preserving the inner future's Send capability.
#[cfg(feature = "tower")]
pub struct NegotiateFuture<F, B, E> {
    /// Pinned inner operation, absent for immediate authentication responses.
    inner: Option<Pin<Box<F>>>,
    /// Immediate outcome, boxed so moving the adapter never moves its body.
    ready: Option<Box<CoreResult<Response<B>, TowerError<E>>>>,
    /// Credential header to attach after inner completion.
    header: Option<zeroize::Zeroizing<String>>,
    /// Whether the inner response receives secure defaults.
    harden: bool,
}

#[cfg(feature = "tower")]
impl<F, B, E> fmt::Debug for NegotiateFuture<F, B, E> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            inner,
            ready,
            header,
            harden,
        } = self;
        f.debug_struct("NegotiateFuture")
            .field("pending", &inner.is_some())
            .field("ready", &ready.is_some())
            .field("header_len", &header.as_ref().map(|value| value.len()))
            .field("harden", harden)
            .finish()
    }
}

#[cfg(feature = "tower")]
impl<F, B, E> NegotiateFuture<F, B, E> {
    /// Construct an immediate response without polling an inner service.
    fn ready(result: CoreResult<Response<B>, TowerError<E>>) -> Self {
        Self {
            inner: None,
            ready: Some(Box::new(result)),
            header: None,
            harden: false,
        }
    }
}

#[cfg(feature = "tower")]
impl<F, B, E> Future for NegotiateFuture<F, B, E>
where
    F: Future<Output = CoreResult<Response<B>, E>>,
{
    type Output = CoreResult<Response<B>, TowerError<E>>;
    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let state = self.get_mut();
        if let Some(result) = state.ready.take() {
            return Poll::Ready(*result);
        }
        let Some(inner) = state.inner.as_mut() else {
            return Poll::Pending;
        };
        let mut response = match inner.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(TowerError::Inner(error))),
            Poll::Ready(Ok(response)) => response,
        };
        if let Some(header) = state.header.take() {
            let mut value = HeaderValue::from_str(&header)
                .map_err(Error::InvalidHeaderValue)
                .map_err(TowerError::Http)?;
            value.set_sensitive(true);
            drop(response.headers_mut().insert(WWW_AUTHENTICATE, value));
        }
        if state.harden {
            harden_response(&mut response);
        }
        Poll::Ready(Ok(response))
    }
}

#[cfg(feature = "tower")]
#[derive(Clone, Debug)]
/// Validator settings a layer applies to every service it builds.
struct ValidatorOptions {
    /// Runtime enctype permission, independent of replay and transit settings.
    crypto_policy: CryptoPolicy,
    /// Explicit policy for unchecked cross-realm transit.
    transit_validator: Option<Arc<dyn TransitValidator>>,
    /// The accepted clock skew; `None` keeps the validator default.
    max_clock_skew: Option<Duration>,
    /// A fixed validation time; `None` uses the system clock.
    now: Option<SystemTime>,
    /// Keytab principal components that override the ticket's server name.
    keytab_principal: Option<Vec<String>>,
    /// The peer address matched against the ticket's client addresses.
    client_address: Option<HostAddress>,
    /// Whether a ticket without client addresses is rejected.
    require_client_address: bool,
    /// The replay cache shared by every service the layer builds.
    shared_replay_cache: Option<SharedReplayCache>,
    /// Whether this layer owns the cache's skew configuration.
    owned_replay_cache: bool,
}

#[cfg(feature = "tower")]
impl Default for ValidatorOptions {
    fn default() -> Self {
        Self {
            crypto_policy: CryptoPolicy::default(),
            transit_validator: None,
            max_clock_skew: None,
            now: None,
            keytab_principal: None,
            client_address: None,
            require_client_address: false,
            shared_replay_cache: Some(SharedReplayCache::new()),
            owned_replay_cache: true,
        }
    }
}

#[cfg(feature = "tower")]
impl ValidatorOptions {
    /// Build a validator over `keytab` with these settings.
    fn build<'keytab>(&self, keytab: Cow<'keytab, Keytab>) -> Validator<'keytab> {
        let mut validator =
            Validator::from_keytab_cow(keytab).with_crypto_policy(self.crypto_policy.clone());
        if let Some(policy) = &self.transit_validator {
            validator = validator.with_transit_validator(Arc::clone(policy));
        }
        if let Some(now) = self.now {
            validator = validator.with_now(now);
        }
        validator.apply_replay_settings(
            self.max_clock_skew.unwrap_or(Duration::from_mins(5)),
            self.shared_replay_cache.clone(),
        );
        if let Some(keytab_principal) = &self.keytab_principal {
            validator = validator.with_keytab_principal(keytab_principal.clone());
        }
        if let Some(client_address) = &self.client_address {
            validator = validator.with_client_address(client_address.clone());
        }
        validator.require_client_address(self.require_client_address)
    }
}

#[cfg(feature = "tower")]
#[derive(Clone, Debug, Eq, PartialEq)]
/// How a Negotiate service answers requests.
struct NegotiateResponseOptions {
    /// Whether inner service responses receive missing secure defaults.
    harden_inner: bool,
    /// Whether an accepted request's response carries an AP-REP token.
    emit_ap_rep: bool,
    /// Options of the emitted AP-REP.
    ap_rep_options: ApRepOptions,
    /// Whether an invalid token is answered with a SPNEGO reject token
    /// instead of a bare challenge.
    reject_invalid: bool,
}

#[cfg(feature = "tower")]
impl Default for NegotiateResponseOptions {
    fn default() -> Self {
        Self {
            harden_inner: true,
            emit_ap_rep: true,
            ap_rep_options: ApRepOptions::default(),
            reject_invalid: true,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error;

    use http_types::{Response, StatusCode, header::HeaderValue};

    use super::{NegotiateHttpError, unchallenged_result};

    /// Challenge splitting respects quoted commas, escaped quotes and unquoted backslashes.
    #[test]
    fn challenge_segments_preserve_quoted_boundaries() -> Result<(), Box<dyn error::Error>> {
        drop(HeaderValue::from_str("Negotiate")?);
        for (input, expected) in [
            (
                "Basic realm=\"a,b\", Negotiate token",
                vec!["Basic realm=\"a,b\"", "Negotiate token"],
            ),
            (
                "Basic realm=\"a\\\",b\", Negotiate token",
                vec!["Basic realm=\"a\\\",b\"", "Negotiate token"],
            ),
            (
                "Basic x=\\, Negotiate token",
                vec!["Basic x=\\", "Negotiate token"],
            ),
        ] {
            let mut segments = super::WwwAuthenticateSegments::new(input);
            for value in expected {
                assert_eq!(segments.next(), Some(value));
            }
            assert_eq!(segments.next(), None);
        }
        Ok(())
    }

    /// A poisoned validator retains a typed cause without exposing it on the wire.
    #[cfg(feature = "tower")]
    #[test]
    fn poisoned_validator_retains_cause() -> Result<(), Box<dyn error::Error>> {
        use alloc::sync::Arc;
        use core::{
            convert::Infallible,
            future::{Ready, ready},
            task::{Context, Poll},
        };
        use std::thread;

        use http_types::Request;
        use tokio::runtime::Builder;
        use tower_service::Service;

        use crate::keytab::Keytab;
        #[derive(Clone)]
        struct Inner;
        impl Service<Request<()>> for Inner {
            type Response = Response<()>;
            type Error = Infallible;
            type Future = Ready<Result<Response<()>, Infallible>>;
            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, _req: Request<()>) -> Self::Future {
                ready(Ok(Response::new(())))
            }
        }
        let mut service = super::NegotiateService::from_keytab(Inner, Keytab::new());
        let validator = Arc::clone(&service.validator);
        let poisoned = thread::spawn(move || {
            let _guard = validator.lock();
            assert!(validator.is_poisoned(), "injected validator poison");
        })
        .join();
        assert!(poisoned.is_err());
        let runtime = Builder::new_current_thread().build()?;
        let response = runtime.block_on(service.call(Request::new(())))?;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.extensions().get::<Arc<super::Error>>().is_some());
        Ok(())
    }

    /// A first response without a Negotiate challenge fails closed when
    /// mutual authentication was requested, keeping the response for
    /// diagnostics, and is returned as not negotiated otherwise.
    #[test]
    fn unchallenged_response_fails_closed_only_when_mutual_was_requested()
    -> Result<(), Box<dyn error::Error>> {
        let refused = unchallenged_result::<(), &str>(true, Response::new("first"));
        assert!(
            matches!(
                &refused,
                Err(NegotiateHttpError::MutualAuthenticationNotProven {
                    negotiation: None,
                    response,
                }) if *response.body() == "first"
            ),
            "requested mutual authentication with no challenge is not proven: {refused:?}"
        );

        let accepted = unchallenged_result::<(), &str>(false, Response::new("first"))?;
        assert!(
            !accepted.did_negotiate(),
            "without mutual authentication the response is passed through"
        );
        assert_eq!(accepted.into_response().status(), StatusCode::OK);
        Ok(())
    }
}
