//! Value types of the adapter client: errors, handles and the step requests.

use core::{error::Error, fmt};
use std::io;

use super::cred::Name;

/// A client-side failure or an error the adapter reported.
#[derive(Debug)]
pub(crate) enum PeerError {
    /// The stream failed or ended inside a frame.
    Io(io::Error),
    /// A GSS call failed in the adapter: major status, minor status, MIT's text.
    Gss {
        /// `OM_uint32` major status.
        major: u32,
        /// Mechanism minor status.
        minor: u32,
        /// MIT's status text.
        text: String,
    },
    /// The adapter refused the frame or the command (status 3).
    Protocol(String),
    /// A reply does not have the documented shape.
    Malformed(&'static str),
    /// A request would exceed a documented bound.
    Limit(&'static str),
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(cause) => write!(f, "adapter stream: {cause}"),
            Self::Gss { major, minor, text } => {
                write!(
                    f,
                    "adapter GSS error (major {major:#x}, minor {minor}): {text}"
                )
            }
            Self::Protocol(text) => write!(f, "adapter protocol error: {text}"),
            Self::Malformed(what) => write!(f, "malformed adapter reply: {what}"),
            Self::Limit(what) => write!(f, "request exceeds a protocol bound: {what}"),
        }
    }
}

impl Error for PeerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(cause) => Some(cause),
            Self::Gss {
                major: _,
                minor: _,
                text: _,
            }
            | Self::Protocol(_)
            | Self::Malformed(_)
            | Self::Limit(_) => None,
        }
    }
}

/// A context handle of the adapter (1 to 16).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContextHandle(u32);

impl ContextHandle {
    /// Wraps the number the adapter returned.
    pub(crate) const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The wire form of the handle.
    pub(crate) const fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

/// A credential handle of the adapter (1 to 16).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CredHandle(u32);

impl CredHandle {
    /// Wraps the number the adapter returned.
    pub(crate) const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The wire form of the handle.
    pub(crate) const fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

/// One `gss_init_sec_context` step.
#[derive(Clone, Debug)]
pub(crate) struct InitRequest {
    /// The context to continue; `None` starts one.
    context: Option<ContextHandle>,
    /// The credential; `None` is the default.
    cred: Option<CredHandle>,
    /// The target name.
    target: Name,
    /// Dotted mechanism OID; `None` is the default mechanism.
    mech: Option<String>,
    /// Request flags (`GSS_C_*`).
    flags: u32,
    /// Channel-binding application data.
    bindings: Option<Vec<u8>>,
    /// The acceptor's token; empty on the first step.
    token: Vec<u8>,
}

impl InitRequest {
    /// The first step towards `target`.
    pub(crate) const fn new(target: Name) -> Self {
        Self {
            context: None,
            cred: None,
            target,
            mech: None,
            flags: 0,
            bindings: None,
            token: Vec::new(),
        }
    }

    /// Uses the credential `cred`.
    #[must_use]
    pub(crate) const fn with_cred(mut self, cred: CredHandle) -> Self {
        self.cred = Some(cred);
        self
    }

    /// Requests the mechanism with the dotted OID `oid`.
    #[must_use]
    pub(crate) fn with_mech(mut self, oid: &str) -> Self {
        self.mech = Some(oid.to_owned());
        self
    }

    /// Sets the request flags.
    #[must_use]
    pub(crate) const fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Supplies channel-binding application data.
    #[must_use]
    pub(crate) fn with_bindings(mut self, data: &[u8]) -> Self {
        self.bindings = Some(data.to_vec());
        self
    }

    /// Continues `context` with the acceptor's `token`.
    #[must_use]
    pub(crate) fn continuing(mut self, context: ContextHandle, token: &[u8]) -> Self {
        self.context = Some(context);
        self.token = token.to_vec();
        self
    }

    /// The nine request fields.
    pub(crate) fn fields(&self) -> Vec<Vec<u8>> {
        let (kind, text) = self.target.fields();
        vec![
            self.context
                .map_or_else(|| vec![0; 4], |handle| handle.to_bytes().to_vec()),
            self.cred
                .map_or_else(|| vec![0; 4], |handle| handle.to_bytes().to_vec()),
            kind.to_vec(),
            text.to_vec(),
            self.mech.clone().unwrap_or_default().into_bytes(),
            self.flags.to_be_bytes().to_vec(),
            vec![u8::from(self.bindings.is_some())],
            self.bindings.clone().unwrap_or_default(),
            self.token.clone(),
        ]
    }
}

/// One `gss_accept_sec_context` step.
#[derive(Clone, Debug)]
pub(crate) struct AcceptRequest {
    /// The context to continue; `None` starts one.
    context: Option<ContextHandle>,
    /// The credential; `None` is the default.
    cred: Option<CredHandle>,
    /// Channel-binding application data.
    bindings: Option<Vec<u8>>,
    /// The initiator's token.
    token: Vec<u8>,
}

impl AcceptRequest {
    /// The first step for the initiator's `token`.
    pub(crate) fn new(token: &[u8]) -> Self {
        Self {
            context: None,
            cred: None,
            bindings: None,
            token: token.to_vec(),
        }
    }

    /// Uses the credential `cred`.
    #[must_use]
    pub(crate) const fn with_cred(mut self, cred: CredHandle) -> Self {
        self.cred = Some(cred);
        self
    }

    /// Supplies channel-binding application data.
    #[must_use]
    pub(crate) fn with_bindings(mut self, data: &[u8]) -> Self {
        self.bindings = Some(data.to_vec());
        self
    }

    /// Continues `context`.
    #[must_use]
    pub(crate) const fn continuing(mut self, context: ContextHandle) -> Self {
        self.context = Some(context);
        self
    }

    /// This request for the next step: `context` (none starts one) and the initiator's `token`.
    #[must_use]
    pub(crate) fn stepping(&self, context: Option<ContextHandle>, token: &[u8]) -> Self {
        Self {
            context,
            token: token.to_vec(),
            ..self.clone()
        }
    }

    /// The five request fields.
    pub(crate) fn fields(&self) -> Vec<Vec<u8>> {
        vec![
            self.context
                .map_or_else(|| vec![0; 4], |handle| handle.to_bytes().to_vec()),
            self.cred
                .map_or_else(|| vec![0; 4], |handle| handle.to_bytes().to_vec()),
            vec![u8::from(self.bindings.is_some())],
            self.bindings.clone().unwrap_or_default(),
            self.token.clone(),
        ]
    }
}
