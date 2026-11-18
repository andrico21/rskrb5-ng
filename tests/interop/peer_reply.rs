//! Reply types of the adapter client.

use super::{
    frame::Fields,
    types::{ContextHandle, PeerError},
};

/// The adapter's limits and version, from a `ping`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ping {
    /// The protocol identifier, `rskrb5-peer/1`.
    version: String,
    /// The frame payload limit the adapter enforces.
    max_frame: u32,
    /// The field limit of one request.
    max_fields: u32,
    /// The handle limit per connection.
    max_handles: u32,
}

impl Ping {
    /// Reads the four fields of a ping reply.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when the fields differ from the documented ones.
    pub(crate) fn read(mut fields: Fields) -> Result<Self, PeerError> {
        let ping = Self {
            version: fields.text()?,
            max_frame: fields.number()?,
            max_fields: fields.number()?,
            max_handles: fields.number()?,
        };
        fields.finish()?;
        Ok(ping)
    }

    /// The protocol identifier.
    pub(crate) fn version(&self) -> &str {
        &self.version
    }

    /// The limits `(frame bytes, fields, handles)`.
    pub(crate) const fn limits(&self) -> (u32, u32, u32) {
        (self.max_frame, self.max_fields, self.max_handles)
    }
}

/// The result of one init or accept step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Step {
    /// Whether another step is needed (`GSS_S_CONTINUE_NEEDED`).
    continue_needed: bool,
    /// The context handle.
    context: ContextHandle,
    /// The output token, possibly empty.
    token: Vec<u8>,
    /// The `ret_flags` of the step.
    flags: u32,
    /// The mechanism OID the call reported, dotted.
    mech: String,
    /// The authenticated source name (accept steps; empty before completion).
    source: String,
}

impl Step {
    /// Reads an init reply (handle, token, flags, mechanism).
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when the fields differ from the documented ones.
    pub(crate) fn read_init(continue_needed: bool, mut fields: Fields) -> Result<Self, PeerError> {
        let step = Self {
            continue_needed,
            context: ContextHandle::new(fields.number()?),
            token: fields.bytes()?,
            flags: fields.number()?,
            mech: fields.text()?,
            source: String::new(),
        };
        fields.finish()?;
        Ok(step)
    }

    /// Reads an accept reply (handle, token, flags, mechanism, source, delegated cred).
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when the fields differ from the documented ones.
    pub(crate) fn read_accept(
        continue_needed: bool,
        mut fields: Fields,
    ) -> Result<Self, PeerError> {
        let step = Self {
            continue_needed,
            context: ContextHandle::new(fields.number()?),
            token: fields.bytes()?,
            flags: fields.number()?,
            mech: fields.text()?,
            source: fields.text()?,
        };
        let delegated = fields.number()?;
        fields.finish()?;
        if delegated != 0 {
            return Err(PeerError::Malformed(
                "the adapter reported a delegated credential",
            ));
        }
        Ok(step)
    }

    /// Whether another step is needed.
    pub(crate) const fn continue_needed(&self) -> bool {
        self.continue_needed
    }

    /// The context handle.
    pub(crate) const fn context(&self) -> ContextHandle {
        self.context
    }

    /// The output token.
    pub(crate) fn token(&self) -> &[u8] {
        &self.token
    }

    /// The `ret_flags`.
    pub(crate) const fn flags(&self) -> u32 {
        self.flags
    }

    /// The mechanism OID, dotted.
    pub(crate) fn mech(&self) -> &str {
        &self.mech
    }

    /// The authenticated source name of an accept step.
    pub(crate) fn source(&self) -> &str {
        &self.source
    }
}

/// What `gss_inquire_context` reports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContextInfo {
    /// The initiator's name.
    source: String,
    /// The acceptor's name.
    target: String,
    /// Remaining lifetime in seconds.
    lifetime: u32,
    /// The mechanism OID, dotted (the underlying one for SPNEGO).
    mech: String,
    /// The context flags.
    flags: u32,
    /// Whether this side initiated.
    initiated: bool,
    /// Whether the context is fully established.
    open: bool,
}

impl ContextInfo {
    /// Reads an inquire reply.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when the fields differ from the documented ones.
    pub(crate) fn read(mut fields: Fields) -> Result<Self, PeerError> {
        let info = Self {
            source: fields.text()?,
            target: fields.text()?,
            lifetime: fields.number()?,
            mech: fields.text()?,
            flags: fields.number()?,
            initiated: fields.flag()?,
            open: fields.flag()?,
        };
        fields.finish()?;
        Ok(info)
    }

    /// The initiator's name.
    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    /// The acceptor's name.
    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    /// Remaining lifetime in seconds.
    pub(crate) const fn lifetime(&self) -> u32 {
        self.lifetime
    }

    /// The mechanism OID, dotted.
    pub(crate) fn mech(&self) -> &str {
        &self.mech
    }

    /// The context flags.
    pub(crate) const fn flags(&self) -> u32 {
        self.flags
    }

    /// Whether this side initiated the context.
    pub(crate) const fn initiated(&self) -> bool {
        self.initiated
    }

    /// Whether the context is established.
    pub(crate) const fn open(&self) -> bool {
        self.open
    }
}

/// Confidentiality request and quality of protection of a wrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Protection {
    /// Request encryption (`conf_req_flag`).
    confidential: bool,
    /// The QOP (0 is the default).
    qop: u32,
}

impl Protection {
    /// Default QOP, encrypted when `confidential`.
    pub(crate) const fn new(confidential: bool) -> Self {
        Self {
            confidential,
            qop: 0,
        }
    }

    /// The two request fields: flag and QOP.
    pub(crate) fn fields(self) -> [Vec<u8>; 2] {
        [
            vec![u8::from(self.confidential)],
            self.qop.to_be_bytes().to_vec(),
        ]
    }
}

/// A wrapped message: whether it was encrypted and the token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sealed {
    /// Whether the message was encrypted.
    confidential: bool,
    /// The wrap token.
    token: Vec<u8>,
}

impl Sealed {
    /// Reads `conf_state` and the token.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when the fields differ from the documented ones.
    pub(crate) fn read(mut fields: Fields) -> Result<Self, PeerError> {
        let sealed = Self {
            confidential: fields.flag()?,
            token: fields.bytes()?,
        };
        fields.finish()?;
        Ok(sealed)
    }

    /// Whether the message was encrypted.
    pub(crate) const fn confidential(&self) -> bool {
        self.confidential
    }

    /// The wrap token.
    pub(crate) fn token(&self) -> &[u8] {
        &self.token
    }
}

/// An unwrapped message with the protection it carried.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Unsealed {
    /// Whether the message was encrypted.
    confidential: bool,
    /// The QOP the token carried.
    qop: u32,
    /// The message.
    message: Vec<u8>,
}

impl Unsealed {
    /// Reads `conf_state`, QOP and message.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when the fields differ from the documented ones.
    pub(crate) fn read(mut fields: Fields) -> Result<Self, PeerError> {
        let unsealed = Self {
            confidential: fields.flag()?,
            qop: fields.number()?,
            message: fields.bytes()?,
        };
        fields.finish()?;
        Ok(unsealed)
    }

    /// Whether the message was encrypted.
    pub(crate) const fn confidential(&self) -> bool {
        self.confidential
    }

    /// The QOP.
    pub(crate) const fn qop(&self) -> u32 {
        self.qop
    }

    /// The message.
    pub(crate) fn message(&self) -> &[u8] {
        &self.message
    }
}

/// A message wrapped as IOV buffers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IovSealed {
    /// Whether the data was encrypted.
    confidential: bool,
    /// The HEADER buffer.
    header: Vec<u8>,
    /// The DATA buffer (encrypted in place when confidential).
    data: Vec<u8>,
    /// The PADDING buffer.
    padding: Vec<u8>,
    /// The TRAILER buffer.
    trailer: Vec<u8>,
}

impl IovSealed {
    /// Reads `conf_state` and the four buffers.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when the fields differ from the documented ones.
    pub(crate) fn read(mut fields: Fields) -> Result<Self, PeerError> {
        let sealed = Self {
            confidential: fields.flag()?,
            header: fields.bytes()?,
            data: fields.bytes()?,
            padding: fields.bytes()?,
            trailer: fields.bytes()?,
        };
        fields.finish()?;
        Ok(sealed)
    }

    /// Whether the data was encrypted.
    pub(crate) const fn confidential(&self) -> bool {
        self.confidential
    }

    /// The four buffers `(header, data, padding, trailer)`.
    pub(crate) fn buffers(&self) -> (&[u8], &[u8], &[u8], &[u8]) {
        (&self.header, &self.data, &self.padding, &self.trailer)
    }
}
