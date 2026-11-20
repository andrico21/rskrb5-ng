//! MIT's `krb5srv:flags:transport:host` URI record target.
//!
//! The data of a `_kerberos`, `_kerberos-adm` or `_kpasswd` DNS URI record is
//! `krb5srv:<flags>:<udp|tcp|kkdcp>:<host[:port] or URL>` (MIT
//! `src/lib/krb5/os/locate_kdc.c:552-601`, `parse_uri_fields`). Only the flag
//! `m` (any letter case) is defined: the server is a primary KDC.

/// The longest record target accepted, in bytes; a longer one is ignored.
pub const MAX_TARGET_BYTES: usize = 1024;
/// The longest realm name a TXT record may name.
const MAX_REALM_BYTES: usize = 255;

/// The transport a URI record names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Transport {
    /// Datagrams.
    Udp,
    /// A stream.
    Tcp,
    /// MS-KKDCP over HTTPS; the host field is an `https://` URL.
    Kkdcp,
}

/// A parsed URI record target.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Target {
    /// The transport.
    pub transport: Transport,
    /// The `m` flag was present: a primary KDC.
    pub primary: bool,
    /// The text after the transport field: `host[:port]` or a URL.
    pub spec: String,
}

/// Parse one URI record target, or `None` for a record to ignore.
///
/// A record is ignored when the scheme is not `krb5srv` (any letter case), the
/// flags field is missing or not terminated by `:`, the transport is none of
/// `udp`, `tcp` and `kkdcp` (any letter case, then `:`), or the target is
/// longer than [`MAX_TARGET_BYTES`] or not valid UTF-8 text.
#[must_use]
#[inline]
pub fn parse(record: &[u8]) -> Option<Target> {
    let text = str::from_utf8(record).ok()?;
    let fields = strip_prefix_ignore_case(text, "krb5srv")?.strip_prefix(':')?;
    let (flags, tail_fields) = fields.split_once(':')?;
    if tail_fields.len() > MAX_TARGET_BYTES {
        return None;
    }
    let primary = flags.bytes().any(|flag| flag.eq_ignore_ascii_case(&b'm'));
    let (transport, tail) = if let Some(tail) = strip_prefix_ignore_case(tail_fields, "udp") {
        (Transport::Udp, tail)
    } else if let Some(tail) = strip_prefix_ignore_case(tail_fields, "tcp") {
        (Transport::Tcp, tail)
    } else {
        (
            Transport::Kkdcp,
            strip_prefix_ignore_case(tail_fields, "kkdcp")?,
        )
    };
    let target = tail.strip_prefix(':')?;
    Some(Target {
        transport,
        primary,
        spec: target.to_owned(),
    })
}

/// Split the data of a DNS URI record into its priority and target text (RFC 7553
/// section 4.5: priority, weight, target), or `None` when it is shorter than the
/// four-byte header.
///
/// MIT keeps the weight unused and the target as the rest of the data
/// (`src/lib/krb5/os/dnssrv.c:214-259`).
#[must_use]
#[inline]
pub fn split_rdata(rdata: &[u8]) -> Option<(u16, &[u8])> {
    let (priority, body) = rdata.split_first_chunk::<2>()?;
    let (_weight, target) = body.split_first_chunk::<2>()?;
    Some((u16::from_be_bytes(*priority), target))
}

/// The realm that the first string of a DNS TXT record names, or `None`.
///
/// MIT removes one trailing dot (`src/lib/krb5/os/dnsglue.c:486-489`). The text is
/// untrusted: it must be 1 to 255 printable ASCII bytes without `@`, `/`, `\` and `:`,
/// and must not end in a dot after that one is removed.
#[must_use]
#[inline]
pub fn realm_from_txt(data: &[u8]) -> Option<String> {
    let raw = str::from_utf8(data).ok()?;
    let name = raw.strip_suffix('.').unwrap_or(raw);
    let valid = !name.is_empty()
        && !name.ends_with('.')
        && name.len() <= MAX_REALM_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'@' | b'/' | b'\\' | b':'));
    valid.then(|| name.to_owned())
}

/// `text` without a prefix equal to `prefix` in ASCII letter case.
fn strip_prefix_ignore_case<'text>(text: &'text str, prefix: &str) -> Option<&'text str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| text.get(prefix.len()..))
        .flatten()
}

/// Split `host[:port]` as MIT's `k5_parse_host_string` does.
///
/// The port rule is that of
/// [`KdcEndpoint::configured`](crate::client::transport::KdcEndpoint::configured):
/// ASCII digits only (MIT takes `strtoul`, which also accepts a sign,
/// `src/lib/krb5/krb/parse_host_string.c:106`).
///
/// `[host]` and `[host]:port` bracket an IPv6 address; a bare number is a port
/// without a host, which a server record cannot use, so it gives `None`, as an
/// empty text, a leading `:`, a nested `[` and a non-numeric port do.
#[must_use]
#[inline]
pub fn host_port(spec: &str, default_port: u16) -> Option<(String, u16)> {
    if spec.is_empty() || spec.starts_with(':') || spec.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let (host, tail) = if let Some(rest) = spec.strip_prefix('[') {
        rest.split_once(']')?
    } else {
        spec.split_at(spec.find([' ', '\t', ':']).unwrap_or(spec.len()))
    };
    if host.is_empty() || host.contains('[') {
        return None;
    }
    let port = if tail.is_empty() {
        default_port
    } else {
        let digits = tail.strip_prefix(':')?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        digits.parse::<u16>().ok()?
    };
    Some((host.to_owned(), port))
}
