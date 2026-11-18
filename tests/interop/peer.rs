//! Typed client of the external-peer adapter of the `mit-peer` fixture.
//!
//! The adapter (`scripts/interop/peer-mit/peer/`) is a C program linked against
//! MIT krb5 1.22.2 inside the fixture image. It runs GSS-API steps on request
//! over length-prefixed frames, so a Rust test can drive an MIT initiator or
//! acceptor of the mechanisms krb5, SPNEGO, IAKERB and NegoEx (with the
//! `negoextest` mechanism) and compare the result with the crate. The frame
//! protocol is documented at the top of `peer.c`; [`frame`] mirrors it.
//! Later todos (18 to 21) include this module through
//! `#[path = "interop/peer.rs"] mod peer;`.

use std::io::{Read, Write};

/// Names and credential requests.
#[path = "peer_cred.rs"]
pub(crate) mod cred;

/// Frame codec.
#[path = "peer_frame.rs"]
pub(crate) mod frame;

/// Reply types.
#[path = "peer_reply.rs"]
pub(crate) mod reply;

/// Request types, handles and errors.
#[path = "peer_types.rs"]
pub(crate) mod types;

/// Codec and command regressions against a scripted stream.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "peer_tests.rs"]
mod tests;

use self::{
    cred::CredRequest,
    frame::{Fields, borrowed, encode_request, map_status, read_reply},
    reply::{ContextInfo, IovSealed, Ping, Protection, Sealed, Step, Unsealed},
    types::{AcceptRequest, ContextHandle, CredHandle, InitRequest, PeerError},
};

/// Which part of the key `gss_pseudo_random` uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrfKey {
    /// `GSS_C_PRF_KEY_FULL`.
    Full,
    /// `GSS_C_PRF_KEY_PARTIAL`.
    Partial,
}

/// A connection to an adapter; every command is one request and one reply.
#[derive(Debug)]
pub(crate) struct Peer<S> {
    /// The byte stream to the adapter.
    stream: S,
}

impl<S> Peer<S>
where
    S: Read + Write,
{
    /// Wraps an open stream to an adapter.
    pub(crate) const fn new(stream: S) -> Self {
        Self { stream }
    }

    /// The underlying stream (to half-close it in a framing test).
    pub(crate) const fn stream(&self) -> &S {
        &self.stream
    }

    /// Writes `bytes` unframed (a framing test sends malformed frames).
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Io`] when the write fails.
    pub(crate) fn send_raw(&mut self, bytes: &[u8]) -> Result<(), PeerError> {
        self.stream.write_all(bytes).map_err(PeerError::Io)?;
        self.stream.flush().map_err(PeerError::Io)
    }

    /// Reads one reply: `(status, bytes after it)`.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Io`] or [`PeerError::Malformed`] when no well-formed reply arrives.
    pub(crate) fn read_raw(&mut self) -> Result<(u8, Vec<u8>), PeerError> {
        read_reply(&mut self.stream)
    }

    /// Writes `bytes` unframed and reads one reply.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Io`] or [`PeerError::Malformed`] when no well-formed reply arrives.
    pub(crate) fn exchange_raw(&mut self, bytes: &[u8]) -> Result<(u8, Vec<u8>), PeerError> {
        self.send_raw(bytes)?;
        self.read_raw()
    }

    /// Sends one command and maps the reply status.
    ///
    /// # Errors
    ///
    /// Returns the exchange's or the status's [`PeerError`].
    fn call(&mut self, command: u8, fields: &[&[u8]]) -> Result<(bool, Fields), PeerError> {
        let (status, rest) = self.exchange_raw(&encode_request(command, fields)?)?;
        map_status(status, &rest)
    }

    /// Sends one command whose reply must be a plain success.
    ///
    /// # Errors
    ///
    /// Returns the exchange's [`PeerError`], or [`PeerError::Malformed`] for a CONTINUE status.
    fn call_ok(&mut self, command: u8, fields: &[&[u8]]) -> Result<Fields, PeerError> {
        match self.call(command, fields)? {
            (false, fields_back) => Ok(fields_back),
            (true, _fields) => Err(PeerError::Malformed(
                "CONTINUE for a command that has no steps",
            )),
        }
    }

    /// `P`: the adapter's version and limits.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the exchange fails.
    pub(crate) fn ping(&mut self) -> Result<Ping, PeerError> {
        Ping::read(self.call_ok(b'P', &[])?)
    }

    /// `M`: the dotted OIDs of the mechanisms the adapter's GSS library offers.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the exchange fails.
    pub(crate) fn mechs(&mut self) -> Result<Vec<String>, PeerError> {
        let mut fields = self.call_ok(b'M', &[])?;
        let mut oids = Vec::new();
        while fields.remaining() != 0 {
            oids.push(fields.text()?);
        }
        Ok(oids)
    }

    /// `E`: sets an allow-listed environment variable of this connection (the
    /// negoextest knobs, or `GSS_MECH_CONFIG` with the value `negoextest`);
    /// refused once a GSS command ran.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the adapter refuses the name or value.
    pub(crate) fn set_env(&mut self, name: &str, value: &str) -> Result<(), PeerError> {
        self.call_ok(b'E', &[name.as_bytes(), value.as_bytes()])?
            .finish()
    }

    /// `T`: the tail of this connection's `KRB5_TRACE` file.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the exchange fails.
    pub(crate) fn trace(&mut self) -> Result<String, PeerError> {
        let mut fields = self.call_ok(b'T', &[])?;
        Ok(String::from_utf8_lossy(&fields.bytes()?).into_owned())
    }

    /// `A`: acquires a credential; returns its handle and display name.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the credential cannot be acquired.
    pub(crate) fn acquire(
        &mut self,
        request: &CredRequest,
    ) -> Result<(CredHandle, String), PeerError> {
        let owned = request.fields();
        let mut fields = self.call_ok(b'A', &borrowed(&owned))?;
        Ok((CredHandle::new(fields.number()?), fields.text()?))
    }

    /// `S`: restricts the mechanisms an SPNEGO credential offers (`gss_set_neg_mechs`).
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the adapter refuses.
    pub(crate) fn set_neg_mechs(
        &mut self,
        cred: CredHandle,
        mechs: &[&str],
    ) -> Result<(), PeerError> {
        let list = mechs.join(",");
        self.call_ok(b'S', &[&cred.to_bytes(), list.as_bytes()])?
            .finish()
    }

    /// `R`: releases a credential.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] for an unknown handle.
    pub(crate) fn release_cred(&mut self, cred: CredHandle) -> Result<(), PeerError> {
        self.call_ok(b'R', &[b"c", &cred.to_bytes()])?.finish()
    }

    /// `R`: deletes a context.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] for an unknown handle.
    pub(crate) fn release_context(&mut self, context: ContextHandle) -> Result<(), PeerError> {
        self.call_ok(b'R', &[b"x", &context.to_bytes()])?.finish()
    }

    /// `I`: one `gss_init_sec_context` step.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`], [`PeerError::Gss`] for a GSS failure.
    pub(crate) fn init_step(&mut self, request: &InitRequest) -> Result<Step, PeerError> {
        let owned = request.fields();
        let (continue_needed, fields) = self.call(b'I', &borrowed(&owned))?;
        Step::read_init(continue_needed, fields)
    }

    /// `C`: one `gss_accept_sec_context` step.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`], [`PeerError::Gss`] for a GSS failure.
    pub(crate) fn accept_step(&mut self, request: &AcceptRequest) -> Result<Step, PeerError> {
        let owned = request.fields();
        let (continue_needed, fields) = self.call(b'C', &borrowed(&owned))?;
        Step::read_accept(continue_needed, fields)
    }

    /// `Q`: `gss_inquire_context`.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] for an unknown handle.
    pub(crate) fn inquire(&mut self, context: ContextHandle) -> Result<ContextInfo, PeerError> {
        ContextInfo::read(self.call_ok(b'Q', &[&context.to_bytes()])?)
    }

    /// `m`: `gss_get_mic` with the default QOP.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the adapter's call fails.
    pub(crate) fn get_mic(
        &mut self,
        context: ContextHandle,
        message: &[u8],
    ) -> Result<Vec<u8>, PeerError> {
        let mut fields = self.call_ok(b'm', &[&context.to_bytes(), &[0; 4], message])?;
        let token = fields.bytes()?;
        fields.finish()?;
        Ok(token)
    }

    /// `v`: `gss_verify_mic`; returns the QOP the token carried.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Gss`] when the token does not verify.
    pub(crate) fn verify_mic(
        &mut self,
        context: ContextHandle,
        message: &[u8],
        token: &[u8],
    ) -> Result<u32, PeerError> {
        let mut fields = self.call_ok(b'v', &[&context.to_bytes(), message, token])?;
        let qop = fields.number()?;
        fields.finish()?;
        Ok(qop)
    }

    /// `w`: `gss_wrap`.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the adapter's call fails.
    pub(crate) fn wrap(
        &mut self,
        context: ContextHandle,
        protection: Protection,
        message: &[u8],
    ) -> Result<Sealed, PeerError> {
        let [conf, qop] = protection.fields();
        Sealed::read(self.call_ok(b'w', &[&context.to_bytes(), &conf, &qop, message])?)
    }

    /// `u`: `gss_unwrap`.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Gss`] when the token does not unwrap.
    pub(crate) fn unwrap(
        &mut self,
        context: ContextHandle,
        token: &[u8],
    ) -> Result<Unsealed, PeerError> {
        Unsealed::read(self.call_ok(b'u', &[&context.to_bytes(), token])?)
    }

    /// `W`: `gss_wrap_iov` of `data` with `sign_only` data (layout HEADER,
    /// `SIGN_ONLY` when non-empty, DATA, PADDING, TRAILER).
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the adapter's call fails.
    pub(crate) fn wrap_iov(
        &mut self,
        context: ContextHandle,
        protection: Protection,
        buffers: (&[u8], &[u8]),
    ) -> Result<IovSealed, PeerError> {
        let [conf, qop] = protection.fields();
        let (data, sign_only) = buffers;
        IovSealed::read(self.call_ok(b'W', &[&context.to_bytes(), &conf, &qop, data, sign_only])?)
    }

    /// `U`: `gss_unwrap_iov`; `sign_only` must be what the wrapper passed.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Gss`] when the buffers do not unwrap.
    pub(crate) fn unwrap_iov(
        &mut self,
        context: ContextHandle,
        sealed: &IovSealed,
        sign_only: &[u8],
    ) -> Result<Unsealed, PeerError> {
        let (header, data, padding, trailer) = sealed.buffers();
        Unsealed::read(self.call_ok(
            b'U',
            &[
                &context.to_bytes(),
                header,
                sign_only,
                data,
                padding,
                trailer,
            ],
        )?)
    }

    /// `a`: `gss_wrap_aead` with `assoc` as associated data.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the adapter's call fails.
    pub(crate) fn wrap_aead(
        &mut self,
        context: ContextHandle,
        protection: Protection,
        data: (&[u8], &[u8]),
    ) -> Result<Sealed, PeerError> {
        let [conf, qop] = protection.fields();
        let (assoc, message) = data;
        Sealed::read(self.call_ok(b'a', &[&context.to_bytes(), &conf, &qop, assoc, message])?)
    }

    /// `b`: `gss_unwrap_aead`.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Gss`] when the token or the associated data does not verify.
    pub(crate) fn unwrap_aead(
        &mut self,
        context: ContextHandle,
        assoc: &[u8],
        token: &[u8],
    ) -> Result<Unsealed, PeerError> {
        Unsealed::read(self.call_ok(b'b', &[&context.to_bytes(), assoc, token])?)
    }

    /// `p`: `gss_pseudo_random` of `input`, `length` bytes (1 to 65536).
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the adapter's call fails.
    pub(crate) fn pseudo_random(
        &mut self,
        context: ContextHandle,
        key: PrfKey,
        request: (&[u8], u32),
    ) -> Result<Vec<u8>, PeerError> {
        let kind = match key {
            PrfKey::Full => 0_u32,
            PrfKey::Partial => 1_u32,
        };
        let (input, length) = request;
        let mut fields = self.call_ok(
            b'p',
            &[
                &context.to_bytes(),
                &kind.to_be_bytes(),
                input,
                &length.to_be_bytes(),
            ],
        )?;
        let output = fields.bytes()?;
        fields.finish()?;
        Ok(output)
    }

    /// `x`: exports the context (it is consumed) and returns the token.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the context cannot be exported.
    pub(crate) fn export_context(&mut self, context: ContextHandle) -> Result<Vec<u8>, PeerError> {
        let mut fields = self.call_ok(b'x', &[&context.to_bytes()])?;
        let token = fields.bytes()?;
        fields.finish()?;
        Ok(token)
    }

    /// `y`: imports an exported context.
    ///
    /// # Errors
    ///
    /// Returns a [`PeerError`] when the token does not import.
    pub(crate) fn import_context(&mut self, token: &[u8]) -> Result<ContextHandle, PeerError> {
        let mut fields = self.call_ok(b'y', &[token])?;
        let handle = ContextHandle::new(fields.number()?);
        fields.finish()?;
        Ok(handle)
    }
}
