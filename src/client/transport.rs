//! Tokio-backed KDC transport, endpoint discovery, and network exchanges.

use core::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

/// Service-specific TCP record length validation.
mod framing;

/// Validate a KDC TCP record mark before allocating its response body, and
/// return the record length it declares.
///
/// # Errors
/// Returns [`Error::TcpReservedBitSet`] for the RFC 4120 reserved high bit,
/// otherwise [`Error::TcpResponseTooLarge`] above `max` and
/// [`Error::EmptyKdcResponse`] for a zero-length record. This validator does
/// not apply to kpasswd framing.
#[inline]
pub fn kdc_tcp_record_length(header: [u8; 4], max: usize) -> Result<usize, Error> {
    framing::kdc_record_length(header, max)
}
/// Loopback port numbers that the in-crate tests need refused.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod closed_port_tests;
/// DNS server literal boundary tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod dns_literal_tests;
/// MIT-shaped password transport for `KdcProtocol::Auto`.
mod password_auto;
/// Single-delivery password mutation transport.
mod password_delivery;
/// Configured password endpoint selection.
mod password_discovery;
/// DNS password-service fallback.
mod password_dns;
/// Password result consumption after a transport exchange.
mod password_result;
/// Configured realm protocol preference.
mod realm_auto;
/// Ordered SRV target address resolution.
mod srv_targets;
/// Bounded UDP socket primitives.
mod udp;
use framing::tcp_request_length;
#[cfg(test)]
use framing::validate_tcp_length;
use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig},
    net::runtime,
    proto::rr,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpStream, ToSocketAddrs},
    time::timeout,
};

use super::{
    AsRepSession, AsReq, BuiltAsReq, BuiltTgsReq, Error, KRB_ERR_RESPONSE_TOO_BIG, Password,
    Principal, ReferralTgsResult, TgsRepSession, TgsReq, build_s4u2proxy_req, build_s4u2self_req,
    build_tgt_renewal_req, build_ticket_renewal_req, keytab_initial_as_rep_session,
    keytab_initial_as_req, password_initial_as_rep_session, password_initial_as_req,
    preauth::{keytab_preauth_request, password_preauth_request},
    process_as_rep, process_tgs_rep, service_realm,
    stepwise::{InitCreds, InitCredsOptions, NoResponder, TicketCreds, TicketOptions, drive_tokio},
    tgt_realm,
};
use crate::{
    client::kpasswd::{BuiltKpasswdRequest, RequestOptions},
    config::{Config, restrictions},
    error::Config as ConfigError,
    kadmin,
    keytab::{EncryptionKey, Keytab},
    krb_error::decode as decode_krb_error,
    messages::secret_der::SecretDer,
};

/// Default timeout applied to each KDC exchange.
#[cfg(feature = "tokio")]
const DEFAULT_KDC_TIMEOUT: Duration = Duration::from_secs(5);
/// Default maximum accepted TCP response body size, 16 MiB.
#[cfg(feature = "tokio")]
const DEFAULT_TCP_RESPONSE_LIMIT: usize = 16 * 1024 * 1024;
/// Largest UDP payload over IPv4: 65,535 minus the 8-byte UDP and 20-byte IP
/// headers.
#[cfg(feature = "tokio")]
const MAX_UDP_DATAGRAM: usize = 65_507;
/// Default maximum number of cross-realm referrals followed for one ticket.
#[cfg(feature = "tokio")]
const DEFAULT_MAX_REFERRALS: usize = 5;
/// Byte length of the RFC 4120 section 7.2.2 record mark prefixing each TCP message.
#[cfg(feature = "tokio")]
const TCP_RECORD_MARK_LEN: usize = 4;

/// The record `mark` followed by `request`, in one allocation sized for both.
///
/// The reserved capacity holds the whole frame and a `Vec` does not reallocate within its
/// capacity, so no earlier allocation keeps an unerased copy of `request`.
#[cfg(feature = "tokio")]
fn tcp_record_frame(mark: [u8; TCP_RECORD_MARK_LEN], request: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(TCP_RECORD_MARK_LEN.saturating_add(request.len()));
    frame.extend_from_slice(&mark);
    frame.extend_from_slice(request);
    frame
}

/// TCP length rules belong to the service, not to the underlying stream.
#[derive(Clone, Copy)]
enum TcpFraming {
    /// RFC 4120 reserves the high bit for KDC messages.
    Kdc,
    /// RFC 3244 uses its own unsigned length field.
    Kpasswd,
}

/// Wire protocol for Tokio transport operations.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KdcProtocol {
    /// UDP: the request and the reply are one datagram each, with no length
    /// prefix (RFC 4120 for KDC messages, RFC 3244 for password changes).
    Udp,
    /// TCP: each message is preceded by its four-byte big-endian length (RFC
    /// 4120 section 7.2.2 for KDC messages, whose length's high bit is
    /// reserved; RFC 3244 for password changes).
    Tcp,
    /// gokrb5-style UDP/TCP fallback for KDC requests: UDP first to an explicit
    /// address ([`Tokio::send`]), and for a realm in the order that
    /// `udp_preference_limit` selects ([`Tokio::send_to_realm`]). Password
    /// changes follow MIT's `changepw.c` instead: one discovery for both
    /// protocols, then TCP first (every endpoint), then UDP (one datagram per
    /// endpoint, no retransmit) only after a definite TCP failure, whatever
    /// `udp_preference_limit` says. They never fail over once
    /// a request may have been delivered, so UDP is never tried after a TCP
    /// request that may have been delivered.
    Auto,
}

/// Where a [`KdcEndpoint`] came from.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KdcEndpointSource {
    /// Built from a configured value by [`KdcEndpoint::configured`] or
    /// [`KdcEndpoint::configured_with_default_port`]; discovery uses them for the
    /// realm's configured KDCs and kpasswd servers.
    Config,
    /// Came from a DNS SRV record found by discovery (`_kerberos`, `_kpasswd`
    /// or `_kerberos-adm`).
    DnsSrv,
}

/// One endpoint of a KDC or kpasswd server.
#[cfg(feature = "tokio")]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct KdcEndpoint {
    /// Wire protocol to use for this endpoint.
    pub protocol: KdcProtocol,
    /// Host name or IP literal.
    pub host: String,
    /// Kerberos service port.
    pub port: u16,
    /// Where this endpoint came from.
    pub source: KdcEndpointSource,
}

#[cfg(feature = "tokio")]
impl KdcEndpoint {
    /// Create a configured endpoint from a `host[:port]` value with default
    /// port 88, as [`Self::configured_with_default_port`] does.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::configured_with_default_port`].
    #[inline]
    pub fn configured(protocol: KdcProtocol, value: &str) -> Result<Self, Error> {
        Self::configured_with_default_port(protocol, value, 88)
    }

    /// Create a configured endpoint from a `host[:port]` value and default port.
    ///
    /// `value` is trimmed with `str::trim`. A value that parses as a
    /// `core::net::IpAddr` is the host, with `default_port` (so `fd00::1:88` is
    /// an IPv6 address). A value that starts with `[` takes the host from between
    /// that `[` and the first `]`, and after that `]` has either nothing (the port
    /// is `default_port`) or a `:` and the port. Otherwise, when the text after
    /// the last `:` is one or more ASCII digits and the text before it is not
    /// empty and does not end in `:`, they are the port and the host; without
    /// such a port the whole value is the host, with `default_port`. In a value
    /// that does not start with `[`, a `[` or `]` is an ordinary character.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKdcEndpoint`] when the trimmed `value` is empty;
    /// when it starts with `[` and has no `]`, has nothing between the `[` and the
    /// first `]`, or has text after that `]` that does not start with `:`; when a
    /// port does not parse as a `u16`; or when a value that does not start with
    /// `[` has a single `:` and no such port.
    #[inline]
    pub fn configured_with_default_port(
        protocol: KdcProtocol,
        value: &str,
        default_port: u16,
    ) -> Result<Self, Error> {
        let (host, port) = parse_kdc_endpoint(value, default_port)?;
        Ok(Self {
            protocol,
            host,
            port,
            source: KdcEndpointSource::Config,
        })
    }

    #[must_use]
    /// Return `host:port`, with the host in brackets (`[host]:port`) when it
    /// contains a `:` and does not start with `[`.
    #[inline]
    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Tokio-backed KDC and kpasswd transport, with endpoint discovery.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tokio {
    /// Explicit DNS server for DNS discovery; otherwise use the system resolver.
    dns_server: Option<(IpAddr, u16)>,
    /// Timeout applied to each KDC exchange.
    timeout: Duration,
    /// Maximum accepted UDP response size.
    udp_response_limit: usize,
    /// Maximum accepted TCP response body size.
    tcp_response_limit: usize,
}

#[cfg(feature = "tokio")]
impl Default for Tokio {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "tokio")]
impl Tokio {
    #[must_use]
    /// Create a transport with the system resolver, a 5-second timeout, a UDP
    /// response limit of 65,508 bytes and a TCP response body limit of 16 MiB.
    #[inline]
    pub const fn new() -> Self {
        Self {
            dns_server: None,
            timeout: DEFAULT_KDC_TIMEOUT,
            udp_response_limit: MAX_UDP_DATAGRAM + 1,
            tcp_response_limit: DEFAULT_TCP_RESPONSE_LIMIT,
        }
    }

    #[must_use]
    /// Override the timeout applied to each KDC exchange.
    ///
    /// Password mutations deliberately use separate preparation and send/reply
    /// budgets, each of this duration, so one attempt can take up to twice it.
    /// With [`KdcProtocol::Auto`] and an explicit address the name is also
    /// resolved under a budget of its own and a definite TCP failure can be
    /// followed by a UDP attempt, so a call can take up to four times it.
    #[inline]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Select an explicit DNS server using an IP literal and optional port.
    ///
    /// `value` is trimmed with `str::trim`; an empty result selects the system
    /// resolver. Otherwise a value that parses as a `core::net::SocketAddr`
    /// (IPv4 `address:port`, IPv6 `[address]:port`, for example
    /// `[fd00::1]:5353`) gives the server's address and port, and a value that
    /// parses as a `core::net::IpAddr` gives its address with port 53. An
    /// explicit IPv6 port therefore requires brackets: bare `fd00::1:5353` is an
    /// IPv6 address using port 53, and `[fd00::1]` without a port is refused.
    /// In `[address]:port` a zone id may follow an IPv6 address: a `%` and
    /// ASCII digits whose value fits in a `u32`, as in `[fe80::1%2]:5353`. The
    /// zone id is dropped, so that value selects `fe80::1` port 5353 with no
    /// zone; any other zone id, and a zone id in a value without brackets
    /// (`fe80::1%2`), is refused.
    ///
    /// The server is used only for DNS discovery: configured host names and the
    /// host names of explicit addresses are looked up by the system in either
    /// mode. The mode decides when the target names of DNS SRV records are
    /// resolved. With an explicit server, discovery also resolves each target
    /// name with it (the system hosts file is read first, and an IP literal
    /// target is kept as it is) and the endpoints carry the addresses found: a
    /// target that does not resolve gives no endpoint, and the discovery errors
    /// documented for a record set none of whose targets resolves arise only in
    /// this mode. With the system resolver (the default),
    /// discovery keeps the target names as endpoint hosts, and each name is
    /// looked up like any host name when its endpoint is contacted: a name that
    /// does not resolve then fails that endpoint before anything is sent to it,
    /// the call goes on to the next endpoint as it does after any failure before
    /// a request is sent, and [`Error::KdcEndpointFailures`] lists it as that
    /// endpoint's entry when it reports that pass.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DnsResolverConfig`] when the trimmed `value` is not empty
    /// and parses as neither a `core::net::SocketAddr` nor a `core::net::IpAddr`.
    #[inline]
    pub fn with_dns_server(mut self, value: &str) -> Result<Self, Error> {
        self.dns_server = if value.trim().is_empty() {
            None
        } else {
            Some(parse_dns_server(value).map_err(Error::DnsResolverConfig)?)
        };
        Ok(self)
    }

    #[must_use]
    /// Override the maximum accepted UDP response size.
    #[inline]
    pub const fn with_udp_response_limit(mut self, udp_response_limit: usize) -> Self {
        self.udp_response_limit = udp_response_limit;
        self
    }

    #[must_use]
    /// Override the maximum accepted TCP response body size.
    #[inline]
    pub const fn with_tcp_response_limit(mut self, tcp_response_limit: usize) -> Self {
        self.tcp_response_limit = tcp_response_limit;
        self
    }

    /// Send an encoded KDC request over UDP.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UdpRequestTooLarge`] when `request` is longer than 65,507
    /// bytes (the largest UDP payload over IPv4), [`Error::UdpResponseTooLarge`]
    /// when a reply exceeds the configured receive cap (including Windows
    /// WSAEMSGSIZE), [`Error::Io`] when the address lookup or the socket fails,
    /// [`Error::TransportTimeout`] when the exchange exceeds the transport
    /// timeout, and [`Error::EmptyKdcResponse`] for an empty reply.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    #[inline]
    pub async fn send_udp<A>(&self, addr: A, request: &[u8]) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs,
    {
        if request.len() > MAX_UDP_DATAGRAM {
            return Err(Error::UdpRequestTooLarge {
                actual: request.len(),
                limit: MAX_UDP_DATAGRAM,
            });
        }

        self.with_transport_timeout(async {
            let socket = udp::connect(addr).await?;
            let _: usize = socket.send(request).await?;
            udp::receive(&socket, self.udp_response_limit).await
        })
        .await
        .and_then(non_empty_kdc_response)
    }

    /// Send an encoded KDC request over RFC 4120 TCP framing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the address lookup, the connection or the
    /// stream fails,
    /// [`Error::TcpReservedBitSet`] when the reply record's reserved high bit is set,
    /// [`Error::TransportTimeout`] when the exchange exceeds the transport
    /// timeout, [`Error::TcpRequestTooLarge`] or [`Error::TcpResponseTooLarge`]
    /// when a message exceeds its limit, and [`Error::EmptyKdcResponse`] for an
    /// empty reply.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    #[inline]
    pub async fn send_tcp<A>(&self, addr: A, request: &[u8]) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs,
    {
        self.send_tcp_pinned(addr, request)
            .await
            .map(|(response, _)| response)
    }

    /// Perform a TCP exchange and keep the stream open for a follow-up request.
    ///
    /// RFC 4120 section 7.2.2 permits the KDC to leave the stream open when it
    /// expects a follow-up, which lets a two-phase AS exchange avoid a second
    /// connect.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the address lookup, the connection or the
    /// stream fails,
    /// [`Error::TransportTimeout`] when the exchange exceeds the transport
    /// timeout, and the framing errors of [`Self::exchange_tcp`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    async fn send_tcp_pinned<A>(
        &self,
        addr: A,
        request: &[u8],
    ) -> Result<(Vec<u8>, TcpStream), Error>
    where
        A: ToSocketAddrs,
    {
        self.with_transport_timeout(async {
            let mut stream = Self::connect_tcp(addr).await?;
            let response = self.exchange_tcp(&mut stream, request).await?;
            Ok((response, stream))
        })
        .await
    }

    /// Open a KDC stream with Nagle disabled.
    ///
    /// Applies no timeout of its own; callers wrap this in
    /// [`Self::with_transport_timeout`] together with the exchanges they intend
    /// to perform, so one logical request keeps one timeout budget.
    /// Password mutation is the exception: connection preparation and the
    /// send/reply phase each receive the full timeout, so one attempt can take
    /// up to twice it; `password_delivery::send` states the bound for a whole
    /// call. Post-send expiry is outcome-unknown.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the connection or `TCP_NODELAY` cannot be
    /// set up.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: dropping the future drops the half-open socket and changes no
    /// state.
    async fn connect_tcp<A>(addr: A) -> Result<TcpStream, Error>
    where
        A: ToSocketAddrs,
    {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// Perform one RFC 4120 framed request/response exchange on an open stream.
    ///
    /// The record mark and the request body are written as a single segment:
    /// splitting them leaves the body waiting on the peer's delayed-ACK timer
    /// before Nagle will release it. Applies no timeout of its own; see
    /// [`Self::connect_tcp`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::TcpRequestTooLarge`] when `request` does not fit a record
    /// mark, [`Error::Io`] when the stream fails, [`Error::TcpReservedBitSet`]
    /// when the reply record's reserved high bit is set,
    /// [`Error::TcpResponseTooLarge`] when the reply exceeds the configured
    /// limit, and [`Error::EmptyKdcResponse`] for an empty reply.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe for `stream`: dropping the future mid-exchange can leave a
    /// partial record written to or unread from the stream. Discard the stream
    /// then instead of reusing it.
    async fn exchange_tcp(&self, stream: &mut TcpStream, request: &[u8]) -> Result<Vec<u8>, Error> {
        self.exchange_tcp_framed(stream, request, TcpFraming::Kdc)
            .await
    }

    /// Exchange one bounded TCP record using the service's length rules.
    ///
    /// The record built from `request` is erased when this function returns or
    /// its future is dropped.
    ///
    /// # Errors
    /// Returns I/O, length, reserved-bit or empty-response errors.
    ///
    /// # Cancel safety
    /// NOT cancel-safe for the stream: discard it after a cancelled exchange.
    async fn exchange_tcp_framed(
        &self,
        stream: &mut TcpStream,
        request: &[u8],
        framing: TcpFraming,
    ) -> Result<Vec<u8>, Error> {
        let request_len = tcp_request_length(request.len(), framing)?;
        // Nothing that can fail runs between filling the frame and handing it to its owner.
        let framed = SecretDer::new(
            tcp_record_frame(request_len.to_be_bytes(), request),
            "tcp request frame",
        );
        stream.write_all(&framed).await?;

        let mut header = [0; TCP_RECORD_MARK_LEN];
        let _: usize = stream.read_exact(&mut header).await?;
        let response_len_usize =
            framing::response_length(header, framing, self.tcp_response_limit)?;

        let mut response = vec![0; response_len_usize];
        let _: usize = stream.read_exact(&mut response).await?;
        non_empty_kdc_response(response)
    }

    /// Send an encoded KDC request and keep a TCP stream open for a follow-up.
    ///
    /// Returns no stream for [`KdcProtocol::Udp`], which has none. For
    /// [`KdcProtocol::Auto`] a stream exists exactly when the request fell back
    /// to TCP, so a follow-up reuses the connection that answered instead of
    /// probing UDP again and opening a second connection.
    ///
    /// # Errors
    ///
    /// Returns the errors of the transport that carried the request: those of
    /// [`Self::send_udp`] for [`KdcProtocol::Udp`], and those of the TCP exchange
    /// for [`KdcProtocol::Tcp`] and for an [`KdcProtocol::Auto`] fallback.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    async fn send_pinned<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &[u8],
    ) -> Result<(Vec<u8>, Option<TcpStream>), Error>
    where
        A: ToSocketAddrs + Clone,
    {
        match protocol {
            KdcProtocol::Tcp => self
                .send_tcp_pinned(addr, request)
                .await
                .map(|(response, stream)| (response, Some(stream))),
            KdcProtocol::Udp => self
                .send_udp(addr, request)
                .await
                .map(|response| (response, None)),
            KdcProtocol::Auto => match self.send_udp(addr.clone(), request).await {
                Ok(response) if kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) => self
                    .send_tcp_pinned(addr, request)
                    .await
                    .map(|(tcp_response, stream)| (tcp_response, Some(stream))),
                Ok(response) => Ok((response, None)),
                Err(_) => self
                    .send_tcp_pinned(addr, request)
                    .await
                    .map(|(response, stream)| (response, Some(stream))),
            },
        }
    }

    /// Send a follow-up request on a stream pinned by an earlier exchange.
    ///
    /// Returns `Ok(None)` when there is no pinned stream, or when the exchange on
    /// it fails with an I/O error, as when the KDC closed it: RFC 4120 section
    /// 7.2.2 permits the KDC to close the stream at any time after a response
    /// and requires that closure not be treated as fatal, so the caller retries
    /// on a fresh connection. Protocol errors would recur on a new connection,
    /// so they propagate instead of spending another round trip.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TransportTimeout`] when the follow-up exceeds the
    /// transport timeout, and the framing errors of [`Self::exchange_tcp`]; an
    /// I/O error, a closed stream among them, is `Ok(None)` instead.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe for the pinned stream: dropping the future mid-exchange can leave a
    /// partial record written to or unread from the stream. Discard the stream
    /// then instead of reusing it.
    pub(super) async fn send_follow_up(
        &self,
        pinned: Option<&mut TcpStream>,
        request: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        let Some(stream) = pinned else {
            return Ok(None);
        };
        match self
            .with_transport_timeout(self.exchange_tcp(stream, request))
            .await
        {
            Ok(response) => Ok(Some(response)),
            Err(Error::Io(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Send an encoded KDC request over the selected protocol.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::send_udp`] for [`KdcProtocol::Udp`] and of
    /// [`Self::send_tcp`] for [`KdcProtocol::Tcp`]. [`KdcProtocol::Auto`] retries
    /// over TCP after a failed or `KRB_ERR_RESPONSE_TOO_BIG` UDP attempt and
    /// returns the TCP errors.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    #[inline]
    pub async fn send<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &[u8],
    ) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        match protocol {
            KdcProtocol::Udp => self.send_udp(addr, request).await,
            KdcProtocol::Tcp => self.send_tcp(addr, request).await,
            KdcProtocol::Auto => {
                let udp = self.send_udp(addr.clone(), request).await;
                match udp {
                    Ok(response) if kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) => {
                        self.send_tcp(addr, request).await
                    }
                    Ok(response) => Ok(response),
                    Err(_) => self.send_tcp(addr, request).await,
                }
            }
        }
    }

    /// Discover KDC endpoints for a realm using `krb5.conf` semantics.
    ///
    /// Configured `[realms]` KDCs are preferred. DNS SRV lookup is attempted
    /// only when no KDCs are configured and `dns_lookup_kdc = true`.
    /// Whole-configuration restrictions are admitted before endpoint selection or DNS.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for an unsupported or malformed configuration restriction,
    /// [`Error::InvalidKdcEndpoint`] for a malformed configured KDC
    /// entry, [`Error::DnsResolverConfig`] or [`Error::DnsSrvLookup`] when DNS SRV
    /// discovery fails, [`Error::DnsServiceUnavailable`] for a root SRV target,
    /// [`Error::NoKdcEndpoints`] when the realm is configured
    /// without KDCs or DNS finds none, and a configuration error when the realm is
    /// unknown and DNS lookup is disabled.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and only reads `config` and DNS. Dropping
    /// the future abandons the lookup and changes no state.
    #[inline]
    pub async fn discover_kdcs(
        &self,
        config: &Config,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        restrictions::config(config)?;
        if let Some(realm_entry) = config.realm(realm)
            && !realm_entry.kdc.is_empty()
        {
            return realm_entry
                .kdc
                .iter()
                .map(|value| KdcEndpoint::configured(protocol, value))
                .collect();
        }

        if config.libdefaults.dns_lookup_kdc.is_enabled() {
            return self.discover_kdcs_with_dns(realm, protocol).await;
        }

        if config.realm(realm).is_some() {
            Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            })
        } else {
            Err(ConfigError::NoRealm(realm.to_owned()).into())
        }
    }

    /// Discover kpasswd endpoints for a realm.
    ///
    /// Configured `[realms]` kpasswd servers are preferred. DNS SRV lookup is
    /// attempted only when no password-change servers are configured and
    /// `dns_lookup_kdc = true`. It discovers for the one `protocol` given;
    /// [`Self::send_to_kpasswd_realm`] with [`KdcProtocol::Auto`] discovers once
    /// for both protocols instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for an unsupported or malformed configuration
    /// restriction, [`Error::InvalidKdcEndpoint`] for a malformed server entry,
    /// [`Error::DnsServiceUnavailable`] for a root SRV target,
    /// [`Error::KdcEndpointFailures`] when, with [`Self::with_dns_server`], the
    /// published `_kpasswd` set of the protocol has no target that resolves (the
    /// system resolver keeps target names, see there), [`Error::DnsResolverConfig`],
    /// [`Error::DnsSrvLookup`] or [`Error::NoKdcEndpoints`] when DNS SRV
    /// discovery fails or finds nothing, and a configuration error when no
    /// kpasswd server can be derived from the realm's configuration.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and only reads `config` and DNS. Dropping
    /// the future abandons the lookup and changes no state.
    #[inline]
    pub async fn discover_kpasswd_servers(
        &self,
        config: &Config,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        password_discovery::discover(self, config, realm, protocol).await
    }

    /// Send an encoded request to the first reachable KDC discovered from config.
    ///
    /// # Errors
    ///
    /// Returns the discovery errors of [`Self::discover_kdcs`],
    /// [`Error::NoKdcEndpoints`] when no endpoint is available, and
    /// [`Error::KdcEndpointFailures`] when every endpoint fails.
    /// [`KdcProtocol::Auto`] tries UDP first when the request is no longer than
    /// the effective `udp_preference_limit` (1465 when the setting is negative,
    /// otherwise the setting capped at 32700) and TCP first otherwise, retries
    /// over the other protocol after a failure of the first (or, from UDP, after
    /// `KRB_ERR_RESPONSE_TOO_BIG`) and returns the errors of that retry only:
    /// [`Error::KdcEndpointFailures`], [`Error::NoKdcEndpoints`] and
    /// [`Error::DnsSrvLookup`] then carry the protocol of the second pass (`Tcp`
    /// after UDP first, `Udp` after TCP first), and `failures` lists only its
    /// endpoints; the first pass's errors are dropped.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    #[inline]
    pub async fn send_to_realm(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.send_to_realm_pinned(config, protocol, realm, request)
            .await
            .map(|(response, _)| response)
    }

    /// Send to a realm's KDC and keep a TCP stream open for a follow-up request.
    ///
    /// Discovery runs once here rather than once per request, so a two-phase AS
    /// exchange no longer repeats the DNS SRV lookup.
    ///
    /// # Errors
    ///
    /// Returns the discovery errors of [`Self::discover_kdcs`] and the errors of
    /// [`Self::send_to_endpoints_pinned`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    pub(super) async fn send_to_realm_pinned(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<(Vec<u8>, Option<TcpStream>), Error> {
        if protocol == KdcProtocol::Auto {
            return self.send_to_realm_auto(config, realm, request).await;
        }
        let endpoints = self.discover_kdcs(config, realm, protocol).await?;
        self.send_to_endpoints_pinned(realm, protocol, endpoints, request)
            .await
    }

    /// Send to password endpoints with RFC 3244 framing.
    ///
    /// # Errors
    /// Returns endpoint failures when no exchange succeeds.
    ///
    /// # Cancel safety
    /// NOT cancel-safe: a delivered password request may already have committed.
    async fn send_to_password_endpoints(
        &self,
        realm: &str,
        protocol: KdcProtocol,
        endpoints: Vec<KdcEndpoint>,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        password_delivery::send_to_endpoints(self, realm, protocol, endpoints, request).await
    }

    /// Send one password mutation, reporting uncertainty after possible delivery.
    ///
    /// An uncertain outcome returns immediately; the mutation is never retried.
    ///
    /// # Errors
    /// Returns preparation errors before a send, or `KpasswdOutcomeUnknown` afterward.
    ///
    /// # Cancel safety
    /// NOT cancel-safe: a cancelled send or reply wait may already have committed.
    async fn send_password_once<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &[u8],
    ) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs,
    {
        password_delivery::send(self, protocol, addr, request).await
    }

    /// Send to configured KDC endpoints using KDC framing.
    ///
    /// # Errors
    /// Returns discovery errors or failures from all endpoints.
    ///
    /// # Cancel safety
    /// cancel-safe: no client state is changed and sockets close on cancellation.
    async fn send_to_realm_explicit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let endpoints = self.discover_kdcs(config, realm, protocol).await?;
        self.send_to_endpoints(realm, protocol, endpoints, request)
            .await
    }

    /// Send an encoded kpasswd request to the first reachable kpasswd server
    /// discovered for `realm`.
    ///
    /// # Errors
    ///
    /// Returns the discovery errors of [`Self::discover_kpasswd_servers`],
    /// [`Error::NoKdcEndpoints`] when no endpoint is available, and
    /// [`Error::KdcEndpointFailures`] when every endpoint fails.
    /// Failover is permitted only before possible delivery. Later failures return
    /// [`Error::KpasswdOutcomeUnknown`] without resending the mutation.
    ///
    /// With [`KdcProtocol::Auto`] the servers are discovered once for both
    /// protocols, as MIT's `changepw.c` does: `_kpasswd._udp` and
    /// `_kpasswd._tcp` are both queried and form one list, a root SRV target
    /// adds no server and the other records of its set are kept, and the
    /// `_kerberos-adm._tcp` hosts (port 464, both protocols) are used only when
    /// neither set held a record. A published set none of whose targets
    /// resolves counts as published, and when, with [`Self::with_dns_server`], no
    /// endpoint is left the call fails with [`Error::KdcEndpointFailures`] naming
    /// every such set; the system resolver keeps target names, so such a set
    /// gives endpoints that fail when they are contacted (see there). Every TCP
    /// endpoint is then tried before any UDP endpoint, and
    /// `udp_preference_limit` does not apply. UDP is tried only after a definite
    /// TCP failure; a UDP refusal
    /// (`ConnectionRefused`, or `ConnectionReset` where Windows reports an ICMP
    /// port-unreachable that way) while the single reply is awaited is a
    /// definite endpoint failure, not [`Error::KpasswdOutcomeUnknown`].
    ///
    /// With [`KdcProtocol::Auto`] the endpoint failures are those of the last
    /// pass that ran: [`Error::KdcEndpointFailures`] carries `protocol` `Udp` and
    /// lists only the UDP endpoints (the TCP failures that preceded them are not
    /// in the list), or `protocol` `Tcp` and the TCP endpoints when the
    /// discovered list holds no UDP endpoint. A discovery failure keeps
    /// `protocol` `Auto` in [`Error::KdcEndpointFailures`] and
    /// [`Error::NoKdcEndpoints`].
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn send_to_kpasswd_realm(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if protocol == KdcProtocol::Auto {
            return self
                .send_to_kpasswd_realm_auto(config, realm, request)
                .await;
        }
        self.send_to_kpasswd_realm_explicit(config, protocol, realm, request)
            .await
    }

    /// Send an encoded kpasswd request over one explicit protocol to the first
    /// reachable configured server.
    ///
    /// # Errors
    ///
    /// Returns the discovery errors of [`Self::discover_kpasswd_servers`],
    /// [`Error::NoKdcEndpoints`] when no endpoint is available, and
    /// [`Error::KdcEndpointFailures`] when every endpoint fails.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    async fn send_to_kpasswd_realm_explicit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let endpoints = self
            .discover_kpasswd_servers(config, realm, protocol)
            .await?;
        self.send_to_password_endpoints(realm, protocol, endpoints, request)
            .await
    }

    /// Send a framed kpasswd request through Tokio transport and parse the reply.
    ///
    /// # Security
    /// This raw API does not authenticate AP-REP or validate protected reply
    /// controls. Use [`Self::exchange_kpasswd_result`] for a checked outcome.
    /// An unsigned result is diagnostic data, never confirmation of rejection.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be encoded, the errors of
    /// the password transport, and [`Error::KpasswdOutcomeUnknown`] wrapping
    /// [`Error::Kadmin`] when a delivered request receives a malformed reply.
    ///
    /// With [`KdcProtocol::Auto`] and an explicit address the request goes over
    /// TCP first and over UDP (one datagram, no retransmit) only after a definite
    /// TCP failure; an uncertain TCP outcome is returned and UDP is never
    /// tried. A UDP refusal (`ConnectionRefused`, or `ConnectionReset` where
    /// Windows reports an ICMP port-unreachable that way) while the reply is
    /// awaited is the plain I/O error, not [`Error::KpasswdOutcomeUnknown`].
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn exchange_kpasswd_request<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &kadmin::Request,
    ) -> Result<kadmin::Reply, Error>
    where
        A: ToSocketAddrs,
    {
        let frame = SecretDer::new(request.encode()?, "kpasswd request frame");
        let response = self.send_password_once(protocol, addr, &frame).await?;
        kadmin::Reply::parse(&response)
            .map_err(|source| Error::KpasswdOutcomeUnknown(Box::new(Error::from(source))))
    }

    /// Send a framed kpasswd request to a kpasswd server discovered for `realm`
    /// and parse the reply.
    ///
    /// # Security
    /// This raw API only parses the response. Use
    /// [`Self::exchange_kpasswd_result_with_config`] to authenticate its context
    /// before treating its result as a confirmed password-change outcome.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be encoded, the errors of
    /// [`Self::send_to_kpasswd_realm`], and [`Error::KpasswdOutcomeUnknown`]
    /// wrapping [`Error::Kadmin`] when a delivered request receives a malformed reply.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn exchange_kpasswd_request_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &kadmin::Request,
    ) -> Result<kadmin::Reply, Error> {
        restrictions::config(config)?;
        let frame = SecretDer::new(request.encode()?, "kpasswd request frame");
        let response = self
            .send_to_kpasswd_realm(config, protocol, realm, &frame)
            .await?;
        kadmin::Reply::parse(&response)
            .map_err(|source| Error::KpasswdOutcomeUnknown(Box::new(Error::from(source))))
    }

    /// Send a framed kpasswd request and return a checked password-change result.
    ///
    /// # Errors
    ///
    /// Before any I/O it returns [`Error::Crypto`] carrying the typed policy
    /// refusal when the crypto policy does not permit an encryption type of the
    /// request's keys. Then returns the pre-delivery errors of
    /// [`Self::exchange_kpasswd_request`].
    /// After possible delivery, decryption, AP-REP, freshness, sequence,
    /// address, reflection and unsigned-result failures are wrapped exactly
    /// once in [`Error::KpasswdOutcomeUnknown`]. Only an authenticated,
    /// contextually valid rejection returns `Kadmin::PasswordChangeFailed`.
    /// Server-selected AP-REP subkeys are honored.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn exchange_kpasswd_result<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &BuiltKpasswdRequest,
        options: &RequestOptions,
    ) -> Result<kadmin::ChangePasswordResult, Error>
    where
        A: ToSocketAddrs,
    {
        password_result::outgoing(request, request.crypto_policy())?;
        let reply = self
            .exchange_kpasswd_request(protocol, addr, request.request())
            .await?;
        password_result::checked(&reply, request, options, request.crypto_policy())
    }

    /// Send a framed kpasswd request to a kpasswd server discovered for `realm`
    /// and return a checked result.
    ///
    /// # Errors
    ///
    /// Before any I/O it returns [`Error::Config`] when the configuration is
    /// refused or a request list names an enctype outside the permitted list
    /// ([`crate::error::Config::EnctypeNotPermitted`]) and [`Error::Crypto`]
    /// carrying the typed policy refusal when the crypto policy does not permit
    /// an encryption type of the request's keys. Then returns the pre-delivery
    /// errors of [`Self::exchange_kpasswd_request_with_config`]
    /// and the same authenticated outcome classification as
    /// [`Self::exchange_kpasswd_result`]. Invalid or unauthenticated replies
    /// after delivery return exactly one [`Error::KpasswdOutcomeUnknown`];
    /// only a contextually valid authenticated rejection is definite.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn exchange_kpasswd_result_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &BuiltKpasswdRequest,
        options: &RequestOptions,
    ) -> Result<kadmin::ChangePasswordResult, Error> {
        restrictions::config(config)?;
        let policy = super::crypto_policy::configured_requests(&config.libdefaults)?;
        password_result::outgoing(request, &policy)?;
        let reply = self
            .exchange_kpasswd_request_with_config(config, protocol, realm, request.request())
            .await?;
        password_result::checked(&reply, request, options, &policy)
    }

    /// Send an AS-REQ through Tokio transport and process the returned AS-REP.
    ///
    /// # Errors
    ///
    /// Before any I/O it returns [`Error::Encode`] when the request DER does not
    /// encode the message it carries or a PA-DATA entry is a known unsupported PA
    /// type, a peer-only enctype hint or the embedding wrapper
    /// PA-GET-FROM-TYPED-DATA (type 22), [`Error::Decode`] when a PA-DATA value does
    /// not decode, and [`Error::Crypto`] carrying the typed policy refusal when the
    /// crypto policy does not permit an encryption type that the request or the reply
    /// key uses or a PA-DATA entry has a permanently rejected type (draft-9 PKINIT,
    /// types 14 and 15).
    ///
    /// Returns the errors of [`Self::send`], [`Error::Kdc`] when the KDC answers
    /// with a KRB-ERROR, and an error when the AS-REP cannot be decoded,
    /// decrypted with `reply_key` or matched to `request`.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn exchange_as_req<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &BuiltAsReq,
        reply_key: &EncryptionKey,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        super::crypto_policy::wire_message(&request.message, &request.der, "AS-REQ")?;
        super::crypto_policy::before_exchange(
            &request.crypto_policy,
            &request.message.0,
            reply_key,
        )?;
        let response = self.send(protocol, addr, &request.der).await?;
        process_as_rep(request, &response, reply_key)
    }

    /// Send an AS-REQ through a config-discovered KDC and process the AS-REP.
    ///
    /// # Errors
    ///
    /// Before any I/O it returns [`Error::Config`] when the configuration is refused
    /// for a reason other than a permanently rejected `[libdefaults]` choice (for
    /// example an unknown enctype name, an RC4 or DES3 name without `allow_rc4` or
    /// `allow_des3`, an unsupported relation, or a removed protocol mode in a
    /// `[realms]` relation, whose typed cause stays inside the configuration error)
    /// or a request list names an enctype outside the permitted list
    /// ([`crate::error::Config::EnctypeNotPermitted`]), [`Error::Encode`] when the
    /// request DER does not encode the message it carries or a PA-DATA entry is a
    /// known unsupported PA type, a peer-only enctype hint or the embedding wrapper
    /// PA-GET-FROM-TYPED-DATA (type 22), [`Error::Decode`] when a PA-DATA value does
    /// not decode, and [`Error::Crypto`] carrying the typed policy refusal when the
    /// crypto policy does not permit an encryption type that the request or the reply
    /// key uses, `[libdefaults]` makes a choice the policy permanently rejects (a
    /// removed enctype such as `des-cbc-crc` in an enctype list, `allow_weak_crypto`,
    /// or an unkeyed `safe_checksum_type`) or a PA-DATA entry has a permanently
    /// rejected type (draft-9 PKINIT, types 14 and 15).
    ///
    /// Returns the errors of [`Self::send_to_realm`], [`Error::Kdc`] when the KDC
    /// answers with a KRB-ERROR, an error when the AS-REP cannot be decoded,
    /// decrypted with `reply_key` or matched to `request`, and
    /// [`Error::EnctypeNotPermitted`] when an explicit `permitted_enctypes`
    /// excludes the session-key enctype.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn exchange_as_req_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        request: &BuiltAsReq,
        reply_key: &EncryptionKey,
    ) -> Result<AsRepSession, Error> {
        restrictions::config(config)?;
        let policy = super::crypto_policy::configured(&config.libdefaults)?;
        super::crypto_policy::wire_message(&request.message, &request.der, "AS-REQ")?;
        super::crypto_policy::before_exchange(&policy, &request.message.0, reply_key)?;
        let mut bound = request.clone();
        bound.crypto_policy = policy;
        let response = self
            .send_to_realm(config, protocol, &request.client.realm, &request.der)
            .await?;
        let session = process_as_rep(&bound, &response, reply_key)?;
        if config.libdefaults.permitted_enctypes_explicit.is_enabled() {
            super::ensure_permitted_enctype(
                &config.libdefaults.permitted_enctype_ids(),
                session.session_key().etype(),
            )?;
        }
        Ok(session)
    }

    /// Send a TGS-REQ through Tokio transport and process the returned TGS-REP.
    ///
    /// # Errors
    ///
    /// Before any I/O it returns [`Error::Encode`] when the request DER does not
    /// encode the message it carries or a PA-DATA entry is a known unsupported PA
    /// type, a peer-only enctype hint or the embedding wrapper
    /// PA-GET-FROM-TYPED-DATA (type 22), [`Error::Decode`] when a PA-DATA value does
    /// not decode, and [`Error::Crypto`] carrying the typed policy refusal when the
    /// crypto policy does not permit an encryption type that the request or the reply
    /// key uses or a PA-DATA entry has a permanently rejected type (draft-9 PKINIT,
    /// types 14 and 15).
    ///
    /// Returns the errors of [`Self::send`], [`Error::Kdc`] when the KDC answers
    /// with a KRB-ERROR, and an error when the TGS-REP cannot be decoded,
    /// decrypted with `tgs_session_key` or matched to `request`.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn exchange_tgs_req<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &BuiltTgsReq,
        tgs_session_key: &EncryptionKey,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        super::crypto_policy::wire_message(&request.message, &request.der, "TGS-REQ")?;
        super::crypto_policy::before_exchange(
            &request.crypto_policy,
            &request.message.0,
            tgs_session_key,
        )?;
        let response = self.send(protocol, addr, &request.der).await?;
        process_tgs_rep(request, &response, tgs_session_key)
    }

    /// Send a TGS-REQ through a config-discovered KDC and process the TGS-REP.
    ///
    /// # Errors
    ///
    /// Before any I/O it returns [`Error::Config`] when the configuration is refused
    /// for a reason other than a permanently rejected `[libdefaults]` choice (for
    /// example an unknown enctype name, an RC4 or DES3 name without `allow_rc4` or
    /// `allow_des3`, an unsupported relation, or a removed protocol mode in a
    /// `[realms]` relation, whose typed cause stays inside the configuration error)
    /// or a request list names an enctype outside the permitted list
    /// ([`crate::error::Config::EnctypeNotPermitted`]), [`Error::Encode`] when the
    /// request DER does not encode the message it carries or a PA-DATA entry is a
    /// known unsupported PA type, a peer-only enctype hint or the embedding wrapper
    /// PA-GET-FROM-TYPED-DATA (type 22), [`Error::Decode`] when a PA-DATA value does
    /// not decode, and [`Error::Crypto`] carrying the typed policy refusal when the
    /// crypto policy does not permit an encryption type that the request or the reply
    /// key uses, `[libdefaults]` makes a choice the policy permanently rejects (a
    /// removed enctype such as `des-cbc-crc` in an enctype list, `allow_weak_crypto`,
    /// or an unkeyed `safe_checksum_type`) or a PA-DATA entry has a permanently
    /// rejected type (draft-9 PKINIT, types 14 and 15).
    ///
    /// Returns the errors of [`Self::send_to_realm`], [`Error::Kdc`] when the KDC
    /// answers with a KRB-ERROR, an error when the TGS-REP cannot be decoded,
    /// decrypted with `tgs_session_key` or matched to `request`, and
    /// [`Error::EnctypeNotPermitted`] when an explicit `permitted_enctypes`
    /// excludes the session-key enctype.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn exchange_tgs_req_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        request: &BuiltTgsReq,
        tgs_session_key: &EncryptionKey,
    ) -> Result<TgsRepSession, Error> {
        let policy = super::crypto_policy::configured(&config.libdefaults)?;
        super::crypto_policy::wire_message(&request.message, &request.der, "TGS-REQ")?;
        super::crypto_policy::before_exchange(&policy, &request.message.0, tgs_session_key)?;
        let mut bound = request.clone();
        bound.crypto_policy = policy;
        let response = self
            .send_to_realm(config, protocol, &request.kdc_realm, &request.der)
            .await?;
        let session = process_tgs_rep(&bound, &response, tgs_session_key)?;
        if config.libdefaults.permitted_enctypes_explicit.is_enabled() {
            super::ensure_permitted_enctype(
                &config.libdefaults.permitted_enctype_ids(),
                session.session_key().etype(),
            )?;
        }
        Ok(session)
    }

    /// Perform `S4U2Self` through an explicit KDC endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the `S4U2Self` TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn s4u2self<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        service_tgt: &AsRepSession,
        user: Principal,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_s4u2self_req(service_tgt, user, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &service_tgt.session_key)
            .await
    }

    /// Perform `S4U2Self` through a config-discovered KDC.
    ///
    /// # Errors
    ///
    /// Returns an error when the `S4U2Self` TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req_with_config`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn s4u2self_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        service_tgt: &AsRepSession,
        user: Principal,
        mut options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        options.set_crypto_policy(Ok(super::crypto_policy::configured(&config.libdefaults)?));
        let request = build_s4u2self_req(service_tgt, user, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &service_tgt.session_key)
            .await
    }

    /// Perform `S4U2Proxy` through an explicit KDC endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the `S4U2Proxy` TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn s4u2proxy<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        service_tgt: &AsRepSession,
        evidence_ticket: &TgsRepSession,
        target_service: Principal,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_s4u2proxy_req(service_tgt, evidence_ticket, target_service, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &service_tgt.session_key)
            .await
    }

    /// Perform `S4U2Proxy` through a config-discovered KDC.
    ///
    /// # Errors
    ///
    /// Returns an error when the `S4U2Proxy` TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req_with_config`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn s4u2proxy_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        service_tgt: &AsRepSession,
        evidence_ticket: &TgsRepSession,
        target_service: Principal,
        mut options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        options.set_crypto_policy(Ok(super::crypto_policy::configured(&config.libdefaults)?));
        let request = build_s4u2proxy_req(service_tgt, evidence_ticket, target_service, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &service_tgt.session_key)
            .await
    }

    /// Renew an existing TGT through an explicit KDC endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the renewal TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn renew_tgt<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        tgt: &AsRepSession,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_tgt_renewal_req(tgt, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &tgt.session_key)
            .await
    }

    /// Renew an existing TGT through a config-discovered KDC.
    ///
    /// # Errors
    ///
    /// Returns an error when the renewal TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req_with_config`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn renew_tgt_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        mut options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        options.set_crypto_policy(Ok(super::crypto_policy::configured(&config.libdefaults)?));
        let request = build_tgt_renewal_req(tgt, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &tgt.session_key)
            .await
    }

    /// Renew an existing service ticket through an explicit KDC endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the renewal TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn renew_ticket<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        ticket: &AsRepSession,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_ticket_renewal_req(ticket, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &ticket.session_key)
            .await
    }

    /// Renew an existing service ticket through a config-discovered KDC.
    ///
    /// # Errors
    ///
    /// Returns an error when the renewal TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req_with_config`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn renew_ticket_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        ticket: &AsRepSession,
        mut options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        options.set_crypto_policy(Ok(super::crypto_policy::configured(&config.libdefaults)?));
        let request = build_ticket_renewal_req(ticket, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &ticket.session_key)
            .await
    }

    /// Acquire a service ticket, following cross-realm TGS referrals.
    ///
    /// The supplied `tgt` is used as the starting TGT. If the service belongs
    /// to a different realm, this first obtains referral TGTs until it can ask
    /// the target realm for the final service ticket.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::get_service_ticket_with_referral_trace_limit`]
    /// with a limit of 5 referrals.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn get_service_ticket_with_referrals(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        service: Principal,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        Ok(self
            .get_service_ticket_with_referral_trace(config, protocol, tgt, service, options)
            .await?
            .ticket)
    }

    /// Acquire a service ticket and return intermediate referral TGTs.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::get_service_ticket_with_referral_trace_limit`]
    /// with a limit of 5 referrals.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn get_service_ticket_with_referral_trace(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        service: Principal,
        options: TgsReq,
    ) -> Result<ReferralTgsResult, Error> {
        self.get_service_ticket_with_referral_trace_limit(
            config,
            protocol,
            tgt,
            service,
            options,
            DEFAULT_MAX_REFERRALS,
        )
        .await
    }

    /// Acquire a service ticket with an explicit referral limit.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::get_service_ticket_with_referral_trace_limit`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn get_service_ticket_with_referrals_limit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        service: Principal,
        options: TgsReq,
        max_referrals: usize,
    ) -> Result<TgsRepSession, Error> {
        Ok(self
            .get_service_ticket_with_referral_trace_limit(
                config,
                protocol,
                tgt,
                service,
                options,
                max_referrals,
            )
            .await?
            .ticket)
    }

    /// Acquire a service ticket with an explicit referral limit, returning the referral trace.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] or [`Error::Crypto`] when the crypto policy
    /// refuses the `[libdefaults]` of `config`, [`Error::InvalidReferralTicket`]
    /// when `tgt` is not a TGT or a returned TGT is for the realm of the KDC that
    /// returned it, [`Error::ServicePrincipalMismatch`] when the KDC returns
    /// neither the requested ticket nor a referral, [`Error::MaxReferralDepth`]
    /// when more referrals are needed than allowed, and the errors of building
    /// each TGS-REQ, of [`Self::send_to_realm`] and of processing each TGS-REP.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn get_service_ticket_with_referral_trace_limit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        mut service: Principal,
        mut options: TgsReq,
        max_referrals: usize,
    ) -> Result<ReferralTgsResult, Error> {
        options.set_crypto_policy(Ok(super::crypto_policy::configured(&config.libdefaults)?));
        let current_realm = tgt_realm(tgt).ok_or_else(|| Error::InvalidReferralTicket {
            service: tgt.service.name(),
        })?;
        if service.realm.is_empty() {
            service.realm = service_realm(config, &service).unwrap_or(current_realm);
        }
        let mut exchange = TicketCreds::new(
            tgt.clone(),
            service,
            TicketOptions::new(options).with_max_referrals(max_referrals),
        )?;
        let ticket = drive_tokio(self, (config, protocol), &mut exchange, &mut NoResponder).await?;
        Ok(ReferralTgsResult::new(
            ticket,
            exchange.referral_tgts().to_vec(),
        ))
    }

    /// Perform a TGT AS login using password credentials and KDC preauth hints.
    ///
    /// # Security
    /// The caller owns and must erase the borrowed password and any caller-made
    /// copies. Borrow from a `zeroize::Zeroizing<Vec<u8>>` to erase input on drop;
    /// internal erasure does not erase the supplied allocation.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the password, the
    /// errors of [`Self::send`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the password-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_tgt_with_password<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        password: &[u8],
        options: AsReq,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_password(protocol, addr, client, service, password, options)
            .await
    }

    /// Perform an AS login for an explicit service using password credentials and KDC preauth hints.
    ///
    /// # Security
    /// The caller owns and must erase the borrowed password and any caller-made
    /// copies. Borrow from a `zeroize::Zeroizing<Vec<u8>>` to erase input on drop;
    /// internal erasure does not erase the supplied allocation.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the password, the
    /// errors of [`Self::send`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the password-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_as_service_with_password<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        service: Principal,
        password: &[u8],
        options: AsReq,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let initial_request =
            password_initial_as_req(client.clone(), service.clone(), password, options.clone())?;
        let (mut initial_response, mut pinned) = self
            .send_pinned(protocol, addr.clone(), &initial_request.der)
            .await?;
        if let Some(session) =
            password_initial_as_rep_session(&initial_request, &initial_response, &client, password)?
        {
            return Ok(session);
        }
        if let Some(probe) =
            super::preauth::discovery_request(&initial_request, &options, &initial_response)?
        {
            initial_response =
                if let Some(response) = self.send_follow_up(pinned.as_mut(), &probe.der).await? {
                    response
                } else {
                    let (response, connection) =
                        self.send_pinned(protocol, addr.clone(), &probe.der).await?;
                    pinned = connection;
                    response
                };
            super::preauth::validate_discovery(&initial_response, &options)?;
        }
        let (request, reply_key) =
            password_preauth_request(client, service, password, options, &initial_response)?;
        let response = match self.send_follow_up(pinned.as_mut(), &request.der).await? {
            Some(response) => response,
            None => self.send(protocol, addr, &request.der).await?,
        };
        process_as_rep(&request, &response, &reply_key)
    }

    /// Perform a password TGT AS login using KDCs discovered from `krb5.conf`.
    ///
    /// # Security
    /// The caller owns and must erase the borrowed password and any caller-made
    /// copies. Borrow from a `zeroize::Zeroizing<Vec<u8>>` to erase input on drop;
    /// internal erasure does not erase the supplied allocation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] or [`Error::Crypto`] when the crypto policy
    /// refuses the `[libdefaults]` of `config`, an error when the AS-REQ cannot
    /// be built from the password, the errors of [`Self::send_to_realm`],
    /// [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the password-derived
    /// key or matched to the request.
    ///
    /// When an exchange ran over TCP, the next request goes first over the
    /// stream it kept: an I/O failure there (a closed stream, for example)
    /// sends the request again as [`Self::send_to_realm`] does, and any other
    /// failure there is returned, as one of the errors of [`Self::send_tcp`]
    /// other than [`Error::Io`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_tgt_with_password_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        password: &[u8],
        options: AsReq,
    ) -> Result<AsRepSession, Error> {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_password_config(
            config, protocol, client, service, password, options,
        )
        .await
    }

    /// Perform a password AS login for an explicit service using KDCs discovered from `krb5.conf`.
    ///
    /// # Security
    /// The caller owns and must erase the borrowed password and any caller-made
    /// copies. Borrow from a `zeroize::Zeroizing<Vec<u8>>` to erase input on drop;
    /// internal erasure does not erase the supplied allocation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] or [`Error::Crypto`] when the crypto policy
    /// refuses the `[libdefaults]` of `config`, an error when the AS-REQ cannot
    /// be built from the password, the errors of [`Self::send_to_realm`],
    /// [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the password-derived
    /// key or matched to the request.
    ///
    /// When an exchange ran over TCP, the next request goes first over the
    /// stream it kept: an I/O failure there (a closed stream, for example)
    /// sends the request again as [`Self::send_to_realm`] does, and any other
    /// failure there is returned, as one of the errors of [`Self::send_tcp`]
    /// other than [`Error::Io`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_as_service_with_password_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        service: Principal,
        password: &[u8],
        mut options: AsReq,
    ) -> Result<AsRepSession, Error> {
        restrictions::config(config)?;
        options.set_crypto_policy(Ok(super::crypto_policy::configured(&config.libdefaults)?));
        let engine_options = InitCredsOptions::new(options).with_service(service);
        let owned = Password::from_vec(password.to_vec());
        let mut exchange = InitCreds::with_password(client, Some(owned), engine_options);
        drive_tokio(self, (config, protocol), &mut exchange, &mut NoResponder).await
    }

    /// Perform a TGT AS login using keytab credentials and KDC preauth hints.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the keytab, the
    /// errors of [`Self::send`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the keytab-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_tgt_with_keytab<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        keytab: &Keytab,
        options: AsReq,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_keytab(protocol, addr, client, service, keytab, options)
            .await
    }

    /// Perform an AS login for an explicit service using keytab credentials and KDC preauth hints.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the keytab, the
    /// errors of [`Self::send`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the keytab-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_as_service_with_keytab<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        service: Principal,
        keytab: &Keytab,
        options: AsReq,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let initial_request =
            keytab_initial_as_req(client.clone(), service.clone(), keytab, options.clone())?;
        let (mut initial_response, mut pinned) = self
            .send_pinned(protocol, addr.clone(), &initial_request.der)
            .await?;
        if let Some(session) =
            keytab_initial_as_rep_session(&initial_request, &initial_response, &client, keytab)?
        {
            return Ok(session);
        }
        if let Some(probe) =
            super::preauth::discovery_request(&initial_request, &options, &initial_response)?
        {
            initial_response =
                if let Some(response) = self.send_follow_up(pinned.as_mut(), &probe.der).await? {
                    response
                } else {
                    let (response, connection) =
                        self.send_pinned(protocol, addr.clone(), &probe.der).await?;
                    pinned = connection;
                    response
                };
            super::preauth::validate_discovery(&initial_response, &options)?;
        }
        let (request, reply_key) =
            keytab_preauth_request(client, service, keytab, options, &initial_response)?;
        let response = match self.send_follow_up(pinned.as_mut(), &request.der).await? {
            Some(response) => response,
            None => self.send(protocol, addr, &request.der).await?,
        };
        process_as_rep(&request, &response, &reply_key)
    }

    /// Perform a keytab TGT AS login using KDCs discovered from `krb5.conf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] or [`Error::Crypto`] when the crypto policy
    /// refuses the `[libdefaults]` of `config`, an error when the AS-REQ cannot
    /// be built from the keytab, the errors of [`Self::send_to_realm`],
    /// [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the keytab-derived
    /// key or matched to the request.
    ///
    /// When an exchange ran over TCP, the next request goes first over the
    /// stream it kept: an I/O failure there (a closed stream, for example)
    /// sends the request again as [`Self::send_to_realm`] does, and any other
    /// failure there is returned, as one of the errors of [`Self::send_tcp`]
    /// other than [`Error::Io`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_tgt_with_keytab_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        keytab: &Keytab,
        options: AsReq,
    ) -> Result<AsRepSession, Error> {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_keytab_config(config, protocol, client, service, keytab, options)
            .await
    }

    /// Perform a keytab AS login for an explicit service using KDCs discovered from `krb5.conf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] or [`Error::Crypto`] when the crypto policy
    /// refuses the `[libdefaults]` of `config`, an error when the AS-REQ cannot
    /// be built from the keytab, the errors of [`Self::send_to_realm`],
    /// [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the keytab-derived
    /// key or matched to the request.
    ///
    /// When an exchange ran over TCP, the next request goes first over the
    /// stream it kept: an I/O failure there (a closed stream, for example)
    /// sends the request again as [`Self::send_to_realm`] does, and any other
    /// failure there is returned, as one of the errors of [`Self::send_tcp`]
    /// other than [`Error::Io`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_as_service_with_keytab_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        service: Principal,
        keytab: &Keytab,
        mut options: AsReq,
    ) -> Result<AsRepSession, Error> {
        restrictions::config(config)?;
        options.set_crypto_policy(Ok(super::crypto_policy::configured(&config.libdefaults)?));
        let engine_options = InitCredsOptions::new(options).with_service(service);
        let mut exchange = InitCreds::with_keytab(client, keytab.clone(), engine_options);
        drive_tokio(self, (config, protocol), &mut exchange, &mut NoResponder).await
    }

    /// Discover KDC endpoints through `_kerberos` DNS SRV records.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DnsResolverConfig`] or [`Error::DnsSrvLookup`] when the
    /// lookup fails, and [`Error::NoKdcEndpoints`] when it finds no KDC.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state. Dropping the future abandons
    /// the lookup, which the caller can repeat.
    async fn discover_kdcs_with_dns(
        &self,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        let endpoints = self
            .discover_srv_endpoints("_kerberos", realm, protocol)
            .await?;
        if endpoints.is_empty() {
            Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            })
        } else {
            Ok(endpoints)
        }
    }

    /// Discover kpasswd endpoints through `_kpasswd` DNS SRV records, falling
    /// back to `_kerberos-adm._tcp` on ordinary lookup failure or no records.
    ///
    /// A root SRV target means service unavailable and stops discovery without
    /// fallback. A published set none of whose targets resolves stops it without
    /// fallback too, with an error only with an explicit DNS server: the system
    /// resolver keeps the target names as endpoints ([`Self::with_dns_server`]).
    /// This discovers for one protocol; `KdcProtocol::Auto` of
    /// [`Self::send_to_kpasswd_realm`] uses `password_dns::discover_auto` instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DnsResolverConfig`] when the resolver cannot be built,
    /// [`Error::DnsServiceUnavailable`] for a root SRV target of `_kpasswd` or of
    /// the `_kerberos-adm` fallback, [`Error::KdcEndpointFailures`] when, with an
    /// explicit DNS server, the published `_kpasswd` set of `protocol` has no
    /// target that resolves, [`Error::DnsSrvLookup`] when the `_kerberos-adm`
    /// fallback lookup fails, and [`Error::NoKdcEndpoints`] when it finds no
    /// server.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state. Dropping the future abandons
    /// the lookup, which the caller can repeat.
    async fn discover_kpasswd_servers_with_dns(
        &self,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        password_dns::discover(self, realm, protocol).await
    }

    /// Look up the `<service>._udp` or `._tcp` SRV records of `realm` and order
    /// them by priority, then weighted selection without replacement.
    ///
    /// With an explicit DNS server set, each target is also resolved
    /// to an IP address through the same resolver.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DnsResolverConfig`] when the resolver or the
    /// DNS server option is invalid, and [`Error::DnsSrvLookup`] when
    /// the SRV lookup fails or, with an explicit DNS server, no selected target
    /// resolves. Returns
    /// [`Error::DnsServiceUnavailable`] when an SRV target is the root name.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state. Dropping the future abandons
    /// the lookup, which the caller can repeat.
    async fn discover_srv_endpoints(
        &self,
        service: &str,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        let resolver = dns_resolver(self.dns_server)?;
        let answer = self.srv_answer(&resolver, service, realm, protocol).await?;
        if answer.root {
            return Err(Error::DnsServiceUnavailable {
                service: service.to_owned(),
                realm: realm.to_owned(),
            });
        }
        srv_targets::resolve(
            &resolver,
            realm,
            protocol,
            answer.records,
            self.dns_server.is_some(),
        )
        .await
    }

    /// Look up one SRV name and order its non-root records as
    /// [`Self::discover_srv_endpoints`] does, without resolving their targets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DnsSrvLookup`] when the SRV lookup fails.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a DNS lookup changes no state. Dropping the future
    /// abandons it, which the caller can repeat.
    async fn srv_answer(
        &self,
        resolver: &TokioResolver,
        service: &str,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<srv_targets::SrvAnswer, Error> {
        let transport = match protocol {
            KdcProtocol::Udp | KdcProtocol::Auto => "_udp",
            KdcProtocol::Tcp => "_tcp",
        };
        let query = format!("{service}.{transport}.{realm}.");
        let lookup = resolver
            .srv_lookup(query.as_str())
            .await
            .map_err(|source| Error::DnsSrvLookup {
                realm: realm.to_owned(),
                protocol,
                message: source.to_string(),
            })?;

        let root = lookup
            .answers()
            .iter()
            .any(|record| matches!(&record.data, rr::RData::SRV(srv) if srv.target.is_root()));
        let mut records = lookup
            .answers()
            .iter()
            .filter_map(|record| {
                if let rr::RData::SRV(srv) = &record.data {
                    Some(srv)
                } else {
                    None
                }
            })
            .map(|srv| {
                (
                    srv.priority,
                    srv.weight,
                    srv.target.to_utf8().trim_end_matches('.').to_owned(),
                    srv.port,
                )
            })
            .filter(|(_, _, target, _)| !target.is_empty() && target != ".")
            .collect::<Vec<_>>();
        order_srv_records(&mut records, srv_draw)?;
        Ok(srv_targets::SrvAnswer {
            published: root || !records.is_empty(),
            root,
            records,
        })
    }

    /// Try each endpoint in turn and return the first response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoKdcEndpoints`] when `endpoints` is empty, and
    /// [`Error::KdcEndpointFailures`] when every endpoint fails.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    async fn send_to_endpoints(
        &self,
        realm: &str,
        protocol: KdcProtocol,
        endpoints: Vec<KdcEndpoint>,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.send_to_endpoints_pinned(realm, protocol, endpoints, request)
            .await
            .map(|(response, _)| response)
    }

    /// Try each endpoint in turn, keeping the winning TCP stream open.
    ///
    /// Failover still triggers on a failed exchange rather than on a failed
    /// connect, so the endpoint that answers is the one that gets pinned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoKdcEndpoints`] when `endpoints` is empty, and
    /// [`Error::KdcEndpointFailures`] when every endpoint fails.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    async fn send_to_endpoints_pinned(
        &self,
        realm: &str,
        protocol: KdcProtocol,
        endpoints: Vec<KdcEndpoint>,
        request: &[u8],
    ) -> Result<(Vec<u8>, Option<TcpStream>), Error> {
        if endpoints.is_empty() {
            return Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            });
        }

        let mut failures = Vec::new();
        for endpoint in endpoints {
            match self
                .send_pinned(
                    endpoint.protocol,
                    (endpoint.host.as_str(), endpoint.port),
                    request,
                )
                .await
            {
                Ok(outcome) => return Ok(outcome),
                Err(error) => failures.push(format!("{}: {error}", endpoint.authority())),
            }
        }

        Err(Error::KdcEndpointFailures {
            realm: realm.to_owned(),
            protocol,
            failures,
        })
    }

    /// Send to a realm's KDCs over the protocol `udp_preference_limit` selects,
    /// retrying over the other one after a failure or, from UDP, after
    /// `KRB_ERR_RESPONSE_TOO_BIG`.
    ///
    /// # Errors
    ///
    /// Returns the errors of the retry over the second protocol, those of
    /// [`Self::send_to_realm_explicit`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    async fn send_to_realm_auto(
        &self,
        config: &Config,
        realm: &str,
        request: &[u8],
    ) -> Result<(Vec<u8>, Option<TcpStream>), Error> {
        realm_auto::send(self, config, realm, request).await
    }

    /// Send to a realm's kpasswd servers over TCP, then over UDP, after one discovery.
    ///
    /// This is the MIT shape of `changepw.c`: discovery runs once and builds one
    /// list of TCP and UDP entries; every TCP entry is tried before any UDP
    /// entry, and `udp_preference_limit` does not apply. UDP is tried only
    /// after TCP failed definitely; an uncertain TCP outcome stops the exchange.
    ///
    /// # Errors
    ///
    /// Returns the discovery errors (see [`Self::send_to_kpasswd_realm`]), the
    /// uncertain TCP outcome, or the endpoint failures of the last pass that
    /// ran.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    async fn send_to_kpasswd_realm_auto(
        &self,
        config: &Config,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        password_auto::send(self, config, realm, request).await
    }

    /// Run `operation` under the transport timeout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TransportTimeout`] when `operation` does not finish within
    /// the timeout, and otherwise the error of `operation`.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe exactly when `operation` is: dropping the future drops
    /// `operation` and the timer and changes no state of its own.
    async fn with_transport_timeout<F, T>(&self, operation: F) -> Result<T, Error>
    where
        F: Future<Output = Result<T, Error>>,
    {
        match timeout(self.timeout, operation).await {
            Ok(result) => result,
            Err(_elapsed) => Err(Error::TransportTimeout(self.timeout)),
        }
    }
}

/// Select without replacement within ascending priorities using RFC 2782 draws.
///
/// # Errors
/// Returns the draw error or a transport error for an invalid draw.
fn order_srv_records<F>(records: &mut [(u16, u16, String, u16)], mut draw: F) -> Result<(), Error>
where
    F: FnMut(u64) -> Result<u64, Error>,
{
    records.sort_by_key(|record| record.0);
    for offset in 0..records.len() {
        let remaining = records
            .get_mut(offset..)
            .ok_or_else(|| Error::Transport("SRV selection offset".to_owned()))?;
        let Some(first) = remaining.first() else {
            break;
        };
        let priority = first.0;
        let count = remaining
            .iter()
            .take_while(|record| record.0 == priority)
            .count();
        let group = remaining
            .get_mut(..count)
            .ok_or_else(|| Error::Transport("SRV priority group".to_owned()))?;
        group.sort_by_key(|record| record.1 != 0);
        let total = group.iter().map(|record| u64::from(record.1)).sum::<u64>();
        let selected = if total == 0 {
            usize::try_from(draw(
                u64::try_from(count.saturating_sub(1))
                    .map_err(|error| Error::Transport(error.to_string()))?,
            )?)
            .map_err(|error| Error::Transport(error.to_string()))?
        } else {
            let ticket = draw(total)?;
            let mut cumulative = 0_u64;
            group
                .iter()
                .position(|record| {
                    cumulative = cumulative.saturating_add(u64::from(record.1));
                    cumulative >= ticket
                })
                .ok_or_else(|| Error::Transport("SRV draw outside weight range".to_owned()))?
        };
        group
            .get_mut(..=selected)
            .ok_or_else(|| Error::Transport("SRV draw outside group".to_owned()))?
            .rotate_right(1);
    }
    Ok(())
}

/// Draw uniformly from the inclusive range, rejecting the biased remainder.
///
/// # Errors
/// Returns a transport error if entropy acquisition or range construction fails.
fn srv_draw(maximum: u64) -> Result<u64, Error> {
    let range = maximum
        .checked_add(1)
        .ok_or_else(|| Error::Transport("SRV weight overflow".to_owned()))?;
    let threshold = range
        .wrapping_neg()
        .checked_rem(range)
        .ok_or_else(|| Error::Transport("empty SRV range".to_owned()))?;
    loop {
        let value = getrandom::u64()?;
        if value >= threshold {
            return value
                .checked_rem(range)
                .ok_or_else(|| Error::Transport("empty SRV range".to_owned()));
        }
    }
}

/// Reject an empty KDC reply.
///
/// # Errors
///
/// Returns [`Error::EmptyKdcResponse`] when `response` is empty.
#[cfg(feature = "tokio")]
fn non_empty_kdc_response(response: Vec<u8>) -> Result<Vec<u8>, Error> {
    if response.is_empty() {
        return Err(Error::EmptyKdcResponse);
    }
    Ok(response)
}

/// Split a `host[:port]` KDC entry into host and port, by the rule that
/// [`KdcEndpoint::configured_with_default_port`] documents.
///
/// # Errors
///
/// Returns [`Error::InvalidKdcEndpoint`] in the cases that
/// [`KdcEndpoint::configured_with_default_port`] documents.
#[cfg(feature = "tokio")]
fn parse_kdc_endpoint(value: &str, default_port: u16) -> Result<(String, u16), Error> {
    let endpoint = value.trim();
    if endpoint.is_empty() {
        return Err(Error::InvalidKdcEndpoint(endpoint.to_owned()));
    }

    if endpoint.parse::<IpAddr>().is_ok() {
        return Ok((endpoint.to_owned(), default_port));
    }

    if let Some(rest) = endpoint.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return Err(Error::InvalidKdcEndpoint(endpoint.to_owned()));
        };
        if host.is_empty() {
            return Err(Error::InvalidKdcEndpoint(endpoint.to_owned()));
        }
        let port = if let Some(port) = suffix.strip_prefix(':') {
            parse_kdc_port(endpoint, port)?
        } else if suffix.is_empty() {
            default_port
        } else {
            return Err(Error::InvalidKdcEndpoint(endpoint.to_owned()));
        };
        return Ok((host.to_owned(), port));
    }

    if let Some((host, port)) = endpoint.rsplit_once(':')
        && !host.is_empty()
        && !port.is_empty()
        && port.chars().all(|ch| ch.is_ascii_digit())
        && !host.ends_with(':')
    {
        return Ok((host.to_owned(), parse_kdc_port(endpoint, port)?));
    }

    if endpoint.matches(':').count() == 1 {
        return Err(Error::InvalidKdcEndpoint(endpoint.to_owned()));
    }

    Ok((endpoint.to_owned(), default_port))
}

/// Parse a KDC port, quoting `endpoint` in the error.
///
/// # Errors
///
/// Returns [`Error::InvalidKdcEndpoint`] for `endpoint` when `port` is not a
/// `u16`.
#[cfg(feature = "tokio")]
fn parse_kdc_port(endpoint: &str, port: &str) -> Result<u16, Error> {
    port.parse::<u16>()
        .ok()
        .ok_or_else(|| Error::InvalidKdcEndpoint(endpoint.to_owned()))
}

/// Build the DNS resolver using the explicitly selected server, if any.
///
/// # Errors
///
/// Returns [`Error::DnsResolverConfig`] when the override is invalid or the
/// resolver cannot be built.
#[cfg(feature = "tokio")]
fn dns_resolver(server: Option<(IpAddr, u16)>) -> Result<TokioResolver, Error> {
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

/// Resolve every address of an SRV target; IP literals pass through.
///
/// # Errors
///
/// Returns [`Error::DnsSrvLookup`] when the address lookup fails or finds no
/// address record.
///
/// # Cancel safety
///
/// cancel-safe: DNS lookups change no state. Dropping the future abandons
/// the lookup, which the caller can repeat.
#[cfg(feature = "tokio")]
async fn resolve_dns_endpoint_host(
    resolver: &TokioResolver,
    realm: &str,
    protocol: KdcProtocol,
    target: &str,
) -> Result<Vec<String>, Error> {
    if target.parse::<IpAddr>().is_ok() {
        return Ok(vec![target.to_owned()]);
    }

    let lookup_name = if target.ends_with('.') {
        target.to_owned()
    } else {
        format!("{target}.")
    };
    let lookup = resolver
        .lookup_ip(lookup_name.as_str())
        .await
        .map_err(|source| Error::DnsSrvLookup {
            realm: realm.to_owned(),
            protocol,
            message: format!("target {target}: {source}"),
        })?;
    let hosts: Vec<_> = lookup.iter().map(|ip| ip.to_string()).collect();
    if hosts.is_empty() {
        return Err(Error::DnsSrvLookup {
            realm: realm.to_owned(),
            protocol,
            message: format!("target {target}: no address records found"),
        });
    }
    Ok(hosts)
}

/// Parse a DNS server literal by the rule that [`Tokio::with_dns_server`]
/// documents, after trimming `value` with `str::trim`.
///
/// A `core::net::SocketAddr` gives its address and port, without its zone
/// id; else a `core::net::IpAddr` gives its address with port 53.
///
/// # Errors
///
/// Returns a description of the problem when the trimmed `value` is empty or
/// parses as neither a `core::net::SocketAddr` nor a `core::net::IpAddr`.
#[cfg(feature = "tokio")]
fn parse_dns_server(value: &str) -> Result<(IpAddr, u16), String> {
    let server = value.trim();
    if server.is_empty() {
        return Err("empty DNS server override".to_owned());
    }

    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok((addr.ip(), addr.port()));
    }

    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok((ip, 53));
    }

    Err(format!("expected IP literal or IP:port, got {server:?}"))
}

/// The KRB-ERROR code of `bytes`, if they decode as a KRB-ERROR.
#[cfg(feature = "tokio")]
fn kdc_error_code(bytes: &[u8]) -> Option<i32> {
    decode_krb_error(bytes).ok().map(|error| error.error_code)
}

/// Whether [`KdcProtocol::Auto`] tries UDP first for a request of
/// `request_len` bytes under `udp_preference_limit`.
#[cfg(feature = "tokio")]
fn auto_uses_udp_first(config: &Config, request_len: usize) -> bool {
    let configured = config.libdefaults.udp_preference_limit;
    let limit: i32 = if configured < 0_i32 {
        1465_i32
    } else {
        configured.min(32_700_i32)
    };
    usize::try_from(limit).is_ok_and(|max| request_len <= max)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error as StdError, net::IpAddr, time::Duration};
    use std::{sync::mpsc::channel, thread};

    use chrono::DateTime;
    use rasn::der;
    use rasn_kerberos::{KerberosString, KerberosTime, KrbError, PrincipalName};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::UdpSocket,
    };

    use self::loopback_pair::bind_tcp_and_udp_pair;
    use super::{TCP_RECORD_MARK_LEN, parse_dns_server, tcp_record_frame};

    /// Loopback TCP and UDP port pairs for the tests of this module.
    mod loopback_pair;

    /// The frame is the mark then the request, in one allocation sized for exactly that.
    ///
    /// `Vec::with_capacity(n)` requests exactly `n` bytes from the allocator, and `capacity()` is
    /// documented as at least `n` and not more than the allocation, never as exactly `n`. A frame
    /// that was grown instead ends with the capacity of a growth step, which no request of this
    /// test reaches.
    #[test]
    fn tcp_record_frame_reserves_exactly_the_frame() -> Result<(), super::Error> {
        // Given requests short enough that a frame grown by doubling would end larger than the frame.
        for request in [&[1_u8][..], &[1, 2], &[1, 2, 3]] {
            // When the frame is built with the record mark of the request.
            let mark =
                super::tcp_request_length(request.len(), super::TcpFraming::Kdc)?.to_be_bytes();
            let frame = tcp_record_frame(mark, request);
            // Then it is the mark followed by the request.
            assert_eq!(frame.get(..TCP_RECORD_MARK_LEN), Some(mark.as_slice()));
            assert_eq!(frame.get(TCP_RECORD_MARK_LEN..), Some(request));
            // And it holds at least the frame, with the capacity that an exact request of the
            // frame's size gives, so that no reallocation grew it.
            let reserved = TCP_RECORD_MARK_LEN.saturating_add(request.len());
            assert!(frame.capacity() >= reserved, "capacity below the frame");
            assert_eq!(
                frame.capacity(),
                Vec::<u8>::with_capacity(reserved).capacity(),
                "reallocated for a request of {} bytes",
                request.len()
            );
        }
        Ok(())
    }

    /// Parsed UDP limits reach Auto transport with MIT fallback, cap and boundary.
    #[test]
    fn profile_udp_preference_boundaries() -> Result<(), super::ConfigError> {
        for (limit, size, expected) in [
            (-1_i32, 1465_usize, true),
            (0_i32, 1_usize, false),
            (-1_i32, 1466_usize, false),
            (1_i32, 1_usize, true),
            (1_i32, 2_usize, false),
            (32_701_i32, 32_701_usize, false),
            (32_701_i32, 32_700_usize, true),
        ] {
            let config =
                super::Config::parse(&format!("[libdefaults]\n udp_preference_limit = {limit}\n"))?;
            assert_eq!(super::auto_uses_udp_first(&config, size), expected);
        }
        Ok(())
    }

    /// Invalid entropy ranges are errors rather than a fabricated zero draw.
    #[test]
    fn srv_draw_rejects_overflowing_range() {
        assert!(matches!(
            super::srv_draw(u64::MAX),
            Err(super::Error::Transport(_))
        ));
    }

    /// A singleton entropy range returns its sole index without rejecting every draw.
    #[test]
    fn srv_draw_singleton_terminates() -> Result<(), Box<dyn StdError>> {
        let (sender, receiver) = channel();
        let worker = thread::spawn(move || sender.send(super::srv_draw(0)));
        let draw = receiver.recv_timeout(Duration::from_secs(10))??;
        worker
            .join()
            .map_err(|_panic| "SRV draw worker panicked")??;
        assert_eq!(draw, 0);
        Ok(())
    }

    /// Default transport configuration retains the documented 16 MiB TCP cap.
    #[test]
    fn default_tcp_response_limit_is_sixteen_mib() {
        assert_eq!(super::Tokio::new().tcp_response_limit, 0x0100_0000);
    }

    /// Endpoint syntax preserves explicit ports, default ports and malformed-host handling.
    #[test]
    fn endpoint_port_boundaries() -> Result<(), super::Error> {
        for (input, host, port) in [
            ("kdc:89", "kdc", 89),
            ("host::89", "host::89", 88),
            ("[::1]:65535", "::1", 0xFFFF),
        ] {
            assert_eq!(
                super::parse_kdc_endpoint(input, 88)?,
                (host.to_owned(), port)
            );
        }
        for input in ["", ":88", "host:", "[::1]:65536"] {
            assert!(matches!(
                super::parse_kdc_endpoint(input, 88),
                Err(super::Error::InvalidKdcEndpoint(_))
            ));
        }
        Ok(())
    }

    /// Pinned Auto preserves an ordinary UDP response instead of opening TCP.
    #[tokio::test]
    async fn pinned_auto_preserves_ordinary_udp_reply() -> Result<(), Box<dyn StdError>> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let transport = super::Tokio::new();
        let peer = async {
            let mut request = [0; 32];
            let (_, client) =
                super::timeout(Duration::from_secs(10), socket.recv_from(&mut request)).await??;
            let _: usize = socket.send_to(b"ordinary", client).await?;
            Ok::<_, Box<dyn StdError>>(())
        };
        let (sent, result) = tokio::join!(
            peer,
            transport.send_pinned(super::KdcProtocol::Auto, address, b"request")
        );
        sent?;
        let (response, stream) = result?;
        assert_eq!(response, b"ordinary");
        assert!(
            stream.is_none(),
            "UDP must not fabricate a TCP conversation"
        );
        Ok(())
    }

    /// Pinned Auto retries a UDP response-too-big error on a retained TCP stream.
    #[tokio::test]
    async fn pinned_auto_retries_response_too_big() -> Result<(), Box<dyn StdError>> {
        let (listener, socket) = bind_tcp_and_udp_pair().await?;
        let address = listener.local_addr()?;
        let response = der::encode(&KrbError {
            pvno: 5_i32.into(),
            msg_type: 30_i32.into(),
            ctime: None,
            cusec: None,
            stime: KerberosTime(
                DateTime::from_timestamp(1_893_553_440, 0)
                    .ok_or("time")?
                    .fixed_offset(),
            ),
            susec: 0_i32.into(),
            error_code: super::KRB_ERR_RESPONSE_TOO_BIG,
            crealm: None,
            cname: None,
            realm: KerberosString::try_from("TEST.GOKRB5")?,
            sname: PrincipalName {
                r#type: 2_i32,
                string: vec![KerberosString::try_from("krbtgt")?],
            },
            e_text: None,
            e_data: None,
        })?;
        let transport = super::Tokio::new();
        let peer = async {
            let mut request = [0; 32];
            let (_, client) =
                super::timeout(Duration::from_secs(10), socket.recv_from(&mut request)).await??;
            let _: usize = socket.send_to(&response, client).await?;
            let (mut stream, _) =
                super::timeout(Duration::from_secs(10), listener.accept()).await??;
            let mut framed = [0; 11];
            let _: usize =
                super::timeout(Duration::from_secs(10), stream.read_exact(&mut framed)).await??;
            stream.write_all(&[0, 0, 0, 1, 42]).await?;
            Ok::<_, Box<dyn StdError>>(stream)
        };
        let (sent, result) = tokio::join!(
            peer,
            transport.send_pinned(super::KdcProtocol::Auto, address, b"request")
        );
        let connection = sent?;
        let (reply, stream) = result?;
        assert_eq!(reply, [42]);
        assert!(stream.is_some(), "TCP fallback retains its connection");
        drop(connection);
        Ok(())
    }

    /// Numeric framing boundaries are tested without allocating multi-gigabyte requests.
    #[test]
    fn tcp_lengths_are_service_specific() -> Result<(), super::Error> {
        assert_eq!(
            super::tcp_request_length(0x7FFF_FFFF, super::TcpFraming::Kdc)?,
            0x7FFF_FFFF
        );
        assert!(
            super::tcp_request_length(0x8000_0000, super::TcpFraming::Kdc)
                .err()
                .is_some()
        );
        assert_eq!(
            super::tcp_request_length(0x8000_0000, super::TcpFraming::Kpasswd)?,
            0x8000_0000
        );
        super::validate_tcp_length(u32::MAX, super::TcpFraming::Kpasswd)?;
        Ok(())
    }

    /// A zero draw selects zero-weight records before weighted peers at equal priority.
    #[test]
    fn srv_zero_draw_selects_zero_weight() -> Result<(), super::Error> {
        let mut records = vec![
            (1, 3, "heavy".to_owned(), 88),
            (1, 0, "zero".to_owned(), 88),
            (2, 8, "later".to_owned(), 88),
        ];
        super::order_srv_records(&mut records, |_| Ok(0))?;
        assert_eq!(
            records.first().map(|record| record.2.as_str()),
            Some("zero")
        );
        assert_eq!(
            records.last().map(|record| record.2.as_str()),
            Some("later")
        );
        Ok(())
    }

    /// Inclusive draws cover both weighted boundaries without replacing selected records.
    #[test]
    fn srv_weight_boundaries_select_each_peer() -> Result<(), super::Error> {
        for (ticket, expected) in [(0, "light"), (1, "light"), (2, "heavy"), (4, "heavy")] {
            let mut records = vec![
                (1, 1, "light".to_owned(), 88),
                (1, 3, "heavy".to_owned(), 88),
            ];
            let mut first = true;
            super::order_srv_records(&mut records, |_| {
                let value = if first { ticket } else { 0 };
                first = false;
                Ok(value)
            })?;
            assert_eq!(
                records.first().map(|record| record.2.as_str()),
                Some(expected)
            );
            assert_ne!(records.first(), records.last());
        }
        Ok(())
    }

    /// All-zero groups use the injected index draw rather than a fixed ordering.
    #[test]
    fn srv_all_zero_weights_use_uniform_index() -> Result<(), super::Error> {
        let mut records = vec![
            (1, 0, "first".to_owned(), 88),
            (1, 0, "second".to_owned(), 88),
        ];
        super::order_srv_records(&mut records, Ok)?;
        assert_eq!(
            records.first().map(|record| record.2.as_str()),
            Some("second")
        );
        Ok(())
    }

    /// A bare IP literal selects the standard DNS port 53.
    #[test]
    fn parses_dns_server_override_ip_and_default_port() -> Result<(), String> {
        assert_eq!(
            parse_dns_server("127.0.0.1")?,
            (IpAddr::from([127, 0, 0, 1]), 53),
            "a bare IP literal must use port 53"
        );
        Ok(())
    }

    /// An `ip:port` literal keeps its explicit port.
    #[test]
    fn parses_dns_server_override_ip_and_explicit_port() -> Result<(), String> {
        assert_eq!(
            parse_dns_server("127.0.88.53:5353")?,
            (IpAddr::from([127, 0, 88, 53]), 5353),
            "an explicit port must be kept"
        );
        Ok(())
    }

    /// A host name is rejected: the override must be an IP literal.
    #[test]
    fn rejects_dns_server_override_hostname() -> Result<(), String> {
        let Err(error) = parse_dns_server("dns.test.gokrb5:53") else {
            return Err("a host name must be rejected".to_owned());
        };
        assert!(
            error.contains("expected IP literal"),
            "unexpected error message: {error}"
        );
        Ok(())
    }
}
