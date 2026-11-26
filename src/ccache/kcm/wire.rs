//! The KCM wire format: requests, replies and framing, without any I/O (MIT
//! 1.22.2 `src/include/kcm.h` and `src/lib/krb5/ccache/cc_kcm.c`).
//!
//! A request is `major (1) minor (1) opcode (2, big-endian)` followed by its
//! parameters; a frame prefixes it with its length as four big-endian bytes
//! (`cc_kcm.c:345-380`). A reply frame is `length (4)`, a transport status
//! `code (4)`, then `length` bytes that begin with the daemon's own status
//! `code (4)` and carry the payload (`cc_kcm.c:384-421`, `cc_kcm.c:451-480`);
//! SSSD 2.10 answers an unsupported opcode with the transport code and an
//! empty body, and everything else with the in-body status. Flags, lengths
//! and offsets are 32-bit big-endian integers, names are zero-terminated
//! strings, principals and credentials use the version 4 `FILE` ccache
//! encoding, and UUIDs are 16 bytes (`kcm.h:46-65`).
//!
//! # Security
//!
//! Requests and replies carry session keys and tickets: both live in
//! zeroizing buffers, and their `Debug` output shows lengths only. The reply
//! length is checked against [`MAX_REPLY_SIZE`] before any byte is allocated
//! or read for the body.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::Kcm as Error;

pub mod calls;
mod decode;
pub mod shape;
pub mod status;

/// The protocol major version a request carries (`kcm.h:36`).
pub const PROTOCOL_VERSION_MAJOR: u8 = 2;
/// The protocol minor version a request carries (`kcm.h:37`).
pub const PROTOCOL_VERSION_MINOR: u8 = 0;
/// The largest reply a client accepts, in bytes (`cc_kcm.c:54`).
pub const MAX_REPLY_SIZE: usize = 10_usize * 1024 * 1024;
/// The largest request a client sends, in bytes.
pub const MAX_REQUEST_SIZE: usize = 10_usize * 1024 * 1024;
/// The length of a UUID (`kcm.h:39`).
pub const UUID_LENGTH: usize = 16;
/// The longest cache name a client sends or accepts, in bytes.
pub const MAX_NAME_LENGTH: usize = 4096;
/// The default socket of Heimdal's `kcm` daemon (`kcm.h:43`).
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/.heim_org.h5l.kcm-socket";
/// MIT's default `kcm_mach_service` (`DEFAULT_KCM_MACH_SERVICE`, `kcm.h:44`).
pub const DEFAULT_MACH_SERVICE: &str = "org.h5l.kcm";

/// A KCM operation (`kcm_opcode`, `kcm.h:82-117`); only the ones this client
/// sends.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Opcode {
    /// `KCM_OP_GEN_NEW`: `() -> (name)`.
    GenNew,
    /// `KCM_OP_INITIALIZE`: `(name, princ) -> ()`.
    Initialize,
    /// `KCM_OP_DESTROY`: `(name) -> ()`.
    Destroy,
    /// `KCM_OP_STORE`: `(name, cred) -> ()`.
    Store,
    /// `KCM_OP_GET_PRINCIPAL`: `(name) -> (princ)`.
    GetPrincipal,
    /// `KCM_OP_GET_CRED_UUID_LIST`: `(name) -> (uuid, ...)`.
    GetCredUuidList,
    /// `KCM_OP_GET_CRED_BY_UUID`: `(name, uuid) -> (cred)`.
    GetCredByUuid,
    /// `KCM_OP_GET_CACHE_UUID_LIST`: `() -> (uuid, ...)`.
    GetCacheUuidList,
    /// `KCM_OP_GET_CACHE_BY_UUID`: `(uuid) -> (name)`.
    GetCacheByUuid,
    /// `KCM_OP_GET_DEFAULT_CACHE`: `() -> (name)`.
    GetDefaultCache,
    /// `KCM_OP_SET_DEFAULT_CACHE`: `(name) -> ()`.
    SetDefaultCache,
    /// `KCM_OP_GET_KDC_OFFSET`: `(name) -> (offset)`.
    GetKdcOffset,
    /// `KCM_OP_SET_KDC_OFFSET`: `(name, offset) -> ()`.
    SetKdcOffset,
    /// `KCM_OP_GET_CRED_LIST` (MIT extension): `(name) -> (count, count*{len, cred})`.
    GetCredList,
    /// `KCM_OP_REPLACE` (MIT extension): `(name, offset, princ, count, count*{len, cred}) -> ()`.
    Replace,
}

impl Opcode {
    /// The 16-bit opcode number (`kcm.h:82-117`; the MIT extensions start at
    /// 13000).
    #[must_use]
    #[inline]
    pub const fn code(self) -> u16 {
        match self {
            Self::GenNew => 3,
            Self::Initialize => 4,
            Self::Destroy => 5,
            Self::Store => 6,
            Self::GetPrincipal => 8,
            Self::GetCredUuidList => 9,
            Self::GetCredByUuid => 10,
            Self::GetCacheUuidList => 18,
            Self::GetCacheByUuid => 19,
            Self::GetDefaultCache => 20,
            Self::SetDefaultCache => 21,
            Self::GetKdcOffset => 22,
            Self::SetKdcOffset => 23,
            Self::GetCredList => 13_001,
            Self::Replace => 13_002,
        }
    }

    /// Whether the operation changes the daemon's state; when its reply is
    /// lost, the outcome is unknown.
    #[must_use]
    #[inline]
    pub const fn mutates(self) -> bool {
        match self {
            Self::GenNew
            | Self::Initialize
            | Self::Destroy
            | Self::Store
            | Self::SetDefaultCache
            | Self::SetKdcOffset
            | Self::Replace => true,
            Self::GetPrincipal
            | Self::GetCredUuidList
            | Self::GetCredByUuid
            | Self::GetCacheUuidList
            | Self::GetCacheByUuid
            | Self::GetDefaultCache
            | Self::GetKdcOffset
            | Self::GetCredList => false,
        }
    }
}

/// Whether `error` can mean the daemon does not implement the opcode: Heimdal
/// answers `KRB5_FCC_INTERNAL`, SSSD `KRB5_CC_NOSUPP` or `KRB5_CC_IO`
/// (`cc_kcm.c:147-158`); callers then fall back to older opcodes.
#[must_use]
#[inline]
pub const fn is_unsupported(error: &Error) -> bool {
    matches!(
        error,
        Error::Daemon {
            code: status::FCC_INTERNAL | status::CC_IO | status::CC_NOSUPP,
            opcode: _,
        }
    )
}

/// Whether `error` says the cache or the entry does not exist (`KRB5_FCC_NOFILE`
/// and, from SSSD, `KRB5_CC_NOTFOUND` and `KRB5_CC_END`; `cc_kcm.c:933-955` and
/// `cc_kcm.c:1241-1245`).
#[must_use]
#[inline]
pub const fn is_missing(error: &Error) -> bool {
    matches!(
        error,
        Error::Daemon {
            code: status::FCC_NOFILE | status::CC_NOTFOUND | status::CC_END,
            opcode: _,
        }
    )
}

/// A UUID the daemon assigned to a cache or a credential.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Uuid([u8; UUID_LENGTH]);

impl Uuid {
    /// A UUID from its 16 bytes.
    #[must_use]
    #[inline]
    pub const fn new(bytes: [u8; UUID_LENGTH]) -> Self {
        Self(bytes)
    }

    /// The 16 bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; UUID_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for Uuid {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Uuid(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// The residual of a KCM cache name as the daemon knows it: the part after
/// `KCM:` (`KCM:<uid>:<name>` gives `<uid>:<name>`).
///
/// The text goes to the daemon as a zero-terminated string, so it holds no
/// NUL byte and at most [`MAX_NAME_LENGTH`] bytes; the daemon decides which
/// names it accepts.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Residual(String);

impl Residual {
    /// A residual from text.
    ///
    /// `None` for text with a NUL byte or longer than [`MAX_NAME_LENGTH`].
    #[must_use]
    #[inline]
    pub fn new(text: &str) -> Option<Self> {
        (text.len() <= MAX_NAME_LENGTH && !text.contains('\0')).then(|| Self(text.to_owned()))
    }

    /// The text.
    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A request, marshalled and ready to frame.
///
/// Requests are built by the functions of [`calls`].
pub struct Request {
    /// The operation.
    opcode: Opcode,
    /// Version bytes, opcode and parameters, in a zeroizing buffer.
    bytes: Zeroizing<Vec<u8>>,
}

impl Request {
    /// A request header for `opcode`, with room for `parameters` more bytes
    /// (no reallocation, so no unerased copy of a key is left behind).
    pub(crate) fn new(opcode: Opcode, parameters: usize) -> Self {
        let mut bytes = Zeroizing::new(Vec::with_capacity(parameters.saturating_add(4)));
        bytes.push(PROTOCOL_VERSION_MAJOR);
        bytes.push(PROTOCOL_VERSION_MINOR);
        bytes.extend_from_slice(&opcode.code().to_be_bytes());
        Self { opcode, bytes }
    }

    /// The operation.
    #[must_use]
    #[inline]
    pub const fn opcode(&self) -> Opcode {
        self.opcode
    }

    /// The marshalled request, without the frame length.
    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Make room for `additional` more bytes before secrets are appended, so
    /// that no later growth copies them into an unerased allocation.
    pub(crate) fn reserve(&mut self, additional: usize) {
        self.bytes.reserve_exact(additional);
    }

    /// Append a zero-terminated name.
    pub(crate) fn put_name(&mut self, name: &Residual) {
        self.bytes.extend_from_slice(name.as_str().as_bytes());
        self.bytes.push(0);
    }

    /// Append a 32-bit big-endian integer.
    pub(crate) fn put_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Append raw bytes.
    pub(crate) fn put_bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    /// The buffer, for the version 4 encoders of principals and credentials.
    pub(crate) fn buffer(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    /// The request as a frame: its length (four big-endian bytes), then the
    /// request itself.
    ///
    /// # Errors
    ///
    /// [`Error::RequestTooBig`] past [`MAX_REQUEST_SIZE`].
    #[inline]
    pub fn frame(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let length = self.bytes.len();
        let prefix = u32::try_from(length)
            .ok()
            .filter(|_| length <= MAX_REQUEST_SIZE)
            .ok_or(Error::RequestTooBig { length })?;
        let mut frame = Zeroizing::new(Vec::with_capacity(length.saturating_add(4)));
        frame.extend_from_slice(&prefix.to_be_bytes());
        frame.extend_from_slice(&self.bytes);
        Ok(frame)
    }
}

impl fmt::Debug for Request {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("opcode", &self.opcode)
            .field("length", &self.bytes.len())
            .finish()
    }
}

/// A successful reply: the payload after the daemon's status code.
pub struct Reply {
    /// The operation it answers.
    opcode: Opcode,
    /// The payload, in a zeroizing buffer.
    payload: Zeroizing<Vec<u8>>,
}

impl Reply {
    /// The operation the reply answers.
    #[must_use]
    #[inline]
    pub const fn opcode(&self) -> Opcode {
        self.opcode
    }

    /// The payload.
    #[must_use]
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// A reply from the parts of a frame already read: the transport status
    /// code and the body (`cc_kcm.c:384-421` and `cc_kcm.c:451-480`).
    ///
    /// # Errors
    ///
    /// [`Error::Daemon`] for a nonzero transport or body status and
    /// [`Error::MalformedReply`] for a body without a status.
    #[inline]
    pub fn from_frame(
        opcode: Opcode,
        transport_code: i32,
        mut body: Zeroizing<Vec<u8>>,
    ) -> Result<Self, Error> {
        let daemon = |code| Error::Daemon {
            opcode: opcode.code(),
            code,
        };
        if transport_code != 0_i32 {
            return Err(daemon(transport_code));
        }
        let status = body
            .get(..4)
            .and_then(|head| <[u8; 4]>::try_from(head).ok())
            .map(i32::from_be_bytes)
            .ok_or_else(|| Error::MalformedReply {
                opcode: opcode.code(),
                what: "no status code",
            })?;
        if status != 0_i32 {
            return Err(daemon(status));
        }
        drop(body.drain(..4));
        Ok(Self {
            opcode,
            payload: body,
        })
    }
}

impl fmt::Debug for Reply {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("opcode", &self.opcode)
            .field("length", &self.payload.len())
            .finish()
    }
}

/// The length of a reply body from the four length bytes of its frame,
/// checked against `limit` before anything is allocated or read for it
/// (`cc_kcm.c:399-400`).
///
/// # Errors
///
/// [`Error::ReplyTooBig`] when the announced length exceeds `limit`.
#[inline]
pub fn reply_length(header: [u8; 4], limit: usize) -> Result<usize, Error> {
    let announced = u32::from_be_bytes(header);
    usize::try_from(announced)
        .ok()
        .filter(|length| *length <= limit)
        .ok_or(Error::ReplyTooBig {
            length: announced,
            limit,
        })
}
