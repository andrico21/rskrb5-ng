//! IOV and AEAD per-message tokens.
//!
//! `gss_wrap_iov`, `gss_wrap_iov_length`, `gss_unwrap_iov`, `gss_get_mic_iov`,
//! `gss_verify_mic_iov`, `gss_wrap_aead` and `gss_unwrap_aead` with the RFC 4121
//! section 4.2 token layout and MIT 1.22.2's buffer semantics
//! (`k5sealv3iov.c:32-308` for wrapping, `k5sealv3iov.c:310-468` and
//! `k5unsealiov.c:275-600` for unwrapping, `util_crypt.c:418-524` for the
//! crypto layout, `util_cksum.c:159-239` for the checksum layout,
//! `mechglue/g_wrap_aead.c` and `g_unwrap_aead.c` for AEAD).
//!
//! A sealed token is `HEADER = token header | E(confounder)`, the data buffers
//! sealed in place, and `TRAILER = E(filler | token header) | tag`; without a
//! trailer buffer the trailer is rotated into the header (RRC). `SIGN_ONLY`
//! buffers are covered by the tag in their array position and never sealed.

use core::iter;

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use zeroize::Zeroizing;

use super::{
    ContextFlags, EncryptionKey, Error, EstablishedContext, IovBuffer, IovKind, Unwrapped,
};
use crate::{
    crypto::{AesSha2Etype, KerberosEtype},
    spnego::{GSS_TOKEN_FLAG_SEALED, GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR},
};

/// The RFC 4121 per-message token header length.
const HEADER_LEN: usize = 16;
/// The token ID of a Wrap token.
const TOK_WRAP: [u8; 2] = [0x05, 0x04];
/// The token ID of a MIC token.
const TOK_MIC: [u8; 2] = [0x04, 0x04];
/// The AES and Camellia cipher block, the DCE-style filler.
const DCE_FILLER: usize = 16;
/// The longest IOV array this module takes.
const MAX_BUFFERS: usize = 64;

/// The positions of the framing buffers in an IOV array.
struct Layout {
    /// The HEADER (or `MIC_TOKEN`) buffer.
    header: usize,
    /// The TRAILER buffer.
    trailer: Option<usize>,
    /// The PADDING buffer.
    padding: Option<usize>,
}

/// The one buffer of `kind`, refusing a duplicate (MIT's `kg_locate_iov`
/// treats a duplicate as absent; this module refuses it).
///
/// # Errors
///
/// Returns [`Error::BadIov`] for a second buffer of `kind`.
fn locate(buffers: &[IovBuffer], kind: IovKind) -> Result<Option<usize>, Error> {
    let mut found = None;
    for (index, buffer) in buffers.iter().enumerate() {
        if buffer.kind == kind {
            if found.is_some() {
                return Err(Error::BadIov("a framing buffer appears twice"));
            }
            found = Some(index);
        }
    }
    Ok(found)
}

/// The framing of an array whose header buffer is of `header`.
///
/// # Errors
///
/// Returns [`Error::BadIov`] for an oversized array, a missing header, a
/// duplicated framing buffer or a STREAM buffer.
fn layout(buffers: &[IovBuffer], header: IovKind) -> Result<Layout, Error> {
    if buffers.len() > MAX_BUFFERS {
        return Err(Error::BadIov("too many buffers"));
    }
    if locate(buffers, IovKind::Stream)?.is_some() {
        return Err(Error::BadIov("a STREAM buffer outside unwrap"));
    }
    let other = if header == IovKind::MicToken {
        IovKind::Header
    } else {
        IovKind::MicToken
    };
    if locate(buffers, other)?.is_some() {
        return Err(Error::BadIov("a header buffer of the other token type"));
    }
    Ok(Layout {
        header: locate(buffers, header)?.ok_or(Error::BadIov("no header buffer"))?,
        trailer: locate(buffers, IovKind::Trailer)?,
        padding: locate(buffers, IovKind::Padding)?,
    })
}

/// Whether a buffer of `kind` is covered by the integrity tag.
const fn signed(kind: IovKind) -> bool {
    matches!(kind, IovKind::Data | IovKind::SignOnly | IovKind::Padding)
}

/// The DATA and `SIGN_ONLY` bytes in array order, then `header`.
fn checksum_input(buffers: &[IovBuffer], header: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut data = Zeroizing::new(Vec::new());
    for buffer in buffers.iter().filter(|buffer| signed(buffer.kind)) {
        data.extend_from_slice(&buffer.value);
    }
    data.extend_from_slice(header);
    data
}

/// Whether the array has a DATA buffer; one without is only signed (MIT
/// `kg_integ_only_iov`, `util_crypt.c:775-790`).
fn has_data(buffers: &[IovBuffer]) -> bool {
    buffers.iter().any(|buffer| buffer.kind == IovKind::Data)
}

/// Whether any `SIGN_ONLY` buffer holds bytes.
fn has_sign_only(buffers: &[IovBuffer]) -> bool {
    buffers
        .iter()
        .any(|buffer| buffer.kind == IovKind::SignOnly && !buffer.value.is_empty())
}

/// The enctype of a context key.
///
/// # Errors
///
/// Returns [`Error::LegacyTokenFormat`] for an unknown enctype.
fn etype_of(key: &EncryptionKey) -> Result<KerberosEtype, Error> {
    KerberosEtype::from_etype_id(key.etype()).ok_or(Error::LegacyTokenFormat(key.etype()))
}

/// The 16-byte token header.
fn header_bytes(token: [u8; 2], flags: u8, counts: [u16; 2], sequence: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&token);
    header.extend_from_slice(&[flags, 0xff]);
    for count in counts {
        header.extend_from_slice(&count.to_be_bytes());
    }
    header.extend_from_slice(&sequence.to_be_bytes());
    header
}

/// A big-endian 16-bit field of a token header.
fn field(header: &[u8], at: usize) -> u16 {
    header
        .get(at..at.saturating_add(2))
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map_or(0, u16::from_be_bytes)
}

/// The sequence number of a token header.
fn sequence_of(header: &[u8]) -> u64 {
    header
        .get(8..HEADER_LEN)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map_or(0, u64::from_be_bytes)
}

/// The usage label of an RFC 3961 key derivation.
fn label(usage: u32, suffix: u8) -> [u8; 5] {
    let mut out = [suffix; 5];
    out.iter_mut()
        .zip(usage.to_be_bytes())
        .for_each(|(slot, byte)| *slot = byte);
    out
}

/// The derived encryption and integrity keys of one usage.
type KeyPair = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// The encryption and integrity keys of `usage`.
///
/// # Errors
///
/// Returns [`Error::NotNegotiated`] for an enctype without `SIGN_ONLY` support
/// in sealed tokens and the derivation errors.
fn split_keys(etype: KerberosEtype, key: &EncryptionKey, usage: u32) -> Result<KeyPair, Error> {
    let derive = |suffix: u8| -> Result<Zeroizing<Vec<u8>>, Error> {
        Ok(Zeroizing::new(match etype {
            KerberosEtype::Sha1(family) => family.derive_key(key.value(), &label(usage, suffix))?,
            KerberosEtype::Sha2(family) => family.derive_key(key.value(), &label(usage, suffix))?,
            KerberosEtype::Camellia(_)
            | KerberosEtype::Des3CbcSha1Kd(_)
            | KerberosEtype::Rc4Hmac(_) => {
                return Err(Error::NotNegotiated(
                    "SIGN_ONLY buffers in a sealed token of this enctype",
                ));
            }
        }))
    };
    Ok((derive(0xaa)?, derive(0x55)?))
}

/// The truncated HMAC of `parts` under `integrity`, or, with `expected`, its
/// constant-time verification (an empty vector).
///
/// # Errors
///
/// Returns [`Error::BadSignature`] when `expected` does not verify.
fn keyed<M>(
    integrity: &[u8],
    parts: &[&[u8]],
    length: usize,
    expected: Option<&[u8]>,
) -> Result<Vec<u8>, Error>
where
    M: Mac + KeyInit,
{
    let mut mac = <M as KeyInit>::new_from_slice(integrity)
        .map_err(|_length| Error::NotNegotiated("an integrity key of the wrong length"))?;
    for part in parts {
        mac.update(part);
    }
    match expected {
        Some(received) if received.len() == length => mac
            .verify_truncated_left(received)
            .map(|()| Vec::new())
            .map_err(|_mismatch| Error::BadSignature),
        Some(_) => Err(Error::BadSignature),
        None => Ok(mac
            .finalize()
            .into_bytes()
            .iter()
            .copied()
            .take(length)
            .collect()),
    }
}

/// The integrity tag over `parts`, HMAC-SHA1-96 over the plaintext (RFC 3962)
/// or the RFC 8009 HMAC over a zero IV and the ciphertext; with `expected`,
/// its verification.
///
/// # Errors
///
/// Returns [`Error::NotNegotiated`] for another enctype and
/// [`Error::BadSignature`] for a tag that does not verify.
fn tag(
    etype: KerberosEtype,
    integrity: &[u8],
    parts: &[&[u8]],
    expected: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let zero_iv: &[u8] = &[0; 16];
    let with_iv: Vec<&[u8]> = iter::once(zero_iv).chain(parts.iter().copied()).collect();
    match etype {
        KerberosEtype::Sha1(_) => keyed::<Hmac<Sha1>>(integrity, parts, 12, expected),
        KerberosEtype::Sha2(AesSha2Etype::Aes128) => {
            keyed::<Hmac<Sha256>>(integrity, &with_iv, 16, expected)
        }
        KerberosEtype::Sha2(AesSha2Etype::Aes256) => {
            keyed::<Hmac<Sha384>>(integrity, &with_iv, 24, expected)
        }
        KerberosEtype::Camellia(_)
        | KerberosEtype::Des3CbcSha1Kd(_)
        | KerberosEtype::Rc4Hmac(_) => Err(Error::NotNegotiated(
            "SIGN_ONLY buffers in a sealed token of this enctype",
        )),
    }
}

/// Whether the integrity tag is computed over the ciphertext (RFC 8009).
const fn encrypt_then_mac(etype: KerberosEtype) -> bool {
    matches!(etype, KerberosEtype::Sha2(_))
}

/// AES-CTS with a zero IV under the derived encryption key.
///
/// # Errors
///
/// Returns the cipher errors.
fn cts(etype: KerberosEtype, key: &[u8], input: &[u8], seal: bool) -> Result<Vec<u8>, Error> {
    Ok(match (etype, seal) {
        (KerberosEtype::Sha1(family), true) => family.encrypt_data(key, input)?.1,
        (KerberosEtype::Sha1(family), false) => family.decrypt_data(key, input)?,
        (KerberosEtype::Sha2(family), true) => family.encrypt_data(key, input)?.1,
        (KerberosEtype::Sha2(family), false) => family.decrypt_data(key, input)?,
        (
            KerberosEtype::Camellia(_)
            | KerberosEtype::Des3CbcSha1Kd(_)
            | KerberosEtype::Rc4Hmac(_),
            _,
        ) => {
            return Err(Error::NotNegotiated(
                "SIGN_ONLY buffers in a sealed token of this enctype",
            ));
        }
    })
}

/// The parts of the tag input in array order: `first`, the signed buffers
/// (each DATA buffer replaced by `data[i]`), then `last`.
fn sign_parts<'part>(
    buffers: &'part [IovBuffer],
    first: &'part [u8],
    data: &'part [Zeroizing<Vec<u8>>],
    last: &'part [u8],
) -> Vec<&'part [u8]> {
    let mut parts = vec![first];
    let mut next = data.iter();
    for buffer in buffers.iter().filter(|buffer| signed(buffer.kind)) {
        if buffer.kind == IovKind::Data {
            parts.push(next.next().map_or(&[][..], |piece| piece.as_slice()));
        } else {
            parts.push(&buffer.value);
        }
    }
    parts.push(last);
    parts
}

/// Seal `plain` (confounder, data buffers, filler and header copy) with the
/// `SIGN_ONLY` buffers in the tag; returns the ciphertext and the tag.
///
/// # Errors
///
/// Returns the key and cipher errors.
fn seal_signed(
    etype: KerberosEtype,
    key: &EncryptionKey,
    usage: u32,
    buffers: &[IovBuffer],
    plain: &Pieces,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (encryption, integrity) = split_keys(etype, key, usage)?;
    let joined = plain.joined();
    let cipher = cts(etype, &encryption, &joined, true)?;
    let pieces = plain.split(&cipher);
    let source = if encrypt_then_mac(etype) {
        &pieces
    } else {
        plain
    };
    let mac = tag(
        etype,
        &integrity,
        &sign_parts(buffers, &source.confounder, &source.data, &source.trailer),
        None,
    )?;
    Ok((cipher, mac))
}

/// A sealed stream cut at the IOV boundaries.
struct Pieces {
    /// The confounder.
    confounder: Zeroizing<Vec<u8>>,
    /// Each DATA buffer.
    data: Vec<Zeroizing<Vec<u8>>>,
    /// The filler and the header copy.
    trailer: Zeroizing<Vec<u8>>,
}

impl Pieces {
    /// The concatenated stream.
    fn joined(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(self.confounder.to_vec());
        for piece in &self.data {
            out.extend_from_slice(piece);
        }
        out.extend_from_slice(&self.trailer);
        out
    }

    /// `stream`, of this stream's length, cut at the same boundaries.
    fn split(&self, stream: &[u8]) -> Self {
        let mut rest = stream;
        let mut take = |length: usize| {
            let (head, tail) = rest.split_at(length.min(rest.len()));
            rest = tail;
            Zeroizing::new(head.to_vec())
        };
        Self {
            confounder: take(self.confounder.len()),
            data: self.data.iter().map(|piece| take(piece.len())).collect(),
            trailer: take(self.trailer.len()),
        }
    }
}

/// Open `cipher` (confounder, data buffers, filler and header copy) whose tag
/// covers the `SIGN_ONLY` buffers too; returns the plaintext pieces.
///
/// # Errors
///
/// Returns [`Error::BadSignature`] for a tag that does not verify, and the key
/// and cipher errors.
fn open_signed(
    etype: KerberosEtype,
    key: &EncryptionKey,
    usage: u32,
    buffers: &[IovBuffer],
    cipher: &Pieces,
    mac: &[u8],
) -> Result<Pieces, Error> {
    let (encryption, integrity) = split_keys(etype, key, usage)?;
    let check = |source: &Pieces| {
        tag(
            etype,
            &integrity,
            &sign_parts(buffers, &source.confounder, &source.data, &source.trailer),
            Some(mac),
        )
    };
    if encrypt_then_mac(etype) {
        let _verified: Vec<u8> = check(cipher)?;
    }
    let plain = cipher.split(&Zeroizing::new(cts(
        etype,
        &encryption,
        &cipher.joined(),
        false,
    )?));
    if !encrypt_then_mac(etype) {
        let _verified: Vec<u8> = check(&plain)?;
    }
    Ok(plain)
}

/// The lengths of a token's framing (`k5sealv3iov.c:77-113`).
struct Framing {
    /// The Kerberos confounder in the header.
    confounder: usize,
    /// The trailer: filler, encrypted header copy and tag, or the checksum.
    trailer: usize,
    /// The EC field: the filler, or the checksum length.
    ec: usize,
    /// The RRC field.
    rrc: usize,
}

/// The framing of a token of `etype`.
const fn framing(etype: KerberosEtype, confidential: bool, dce: bool, detached: bool) -> Framing {
    if confidential {
        let ec = if dce { DCE_FILLER } else { 0 };
        let trailer = ec
            .saturating_add(HEADER_LEN)
            .saturating_add(etype.hmac_len());
        let rrc = match (detached, dce) {
            (true, _) => 0,
            (false, true) => trailer.saturating_sub(ec),
            (false, false) => trailer,
        };
        Framing {
            confounder: etype.confounder_len(),
            trailer,
            ec,
            rrc,
        }
    } else {
        let trailer = etype.hmac_len();
        Framing {
            confounder: 0,
            trailer,
            ec: trailer,
            rrc: if detached { 0 } else { trailer },
        }
    }
}

/// A 16-bit header field.
///
/// # Errors
///
/// Returns [`Error::BadIov`] above 65535.
fn count(value: usize) -> Result<u16, Error> {
    u16::try_from(value).map_err(|_overflow| Error::BadIov("a count above 65535"))
}

/// Refuse an array whose bytes exceed the per-message bound.
///
/// # Errors
///
/// Returns [`Error::TokenTooLarge`].
fn bounded(buffers: &[IovBuffer]) -> Result<(), Error> {
    let actual = buffers.iter().fold(0_usize, |total, buffer| {
        total.saturating_add(buffer.value.len())
    });
    if actual > super::context::MAX_TOKEN_LEN {
        return Err(Error::TokenTooLarge {
            maximum: super::context::MAX_TOKEN_LEN,
            actual,
        });
    }
    Ok(())
}

/// Copies of the DATA buffers in array order.
fn data_of(buffers: &[IovBuffer]) -> Vec<Zeroizing<Vec<u8>>> {
    buffers
        .iter()
        .filter(|buffer| buffer.kind == IovKind::Data)
        .map(|buffer| buffer.value.clone())
        .collect()
}

/// Replace the DATA buffers, in array order, with `data`.
fn scatter(buffers: &mut [IovBuffer], data: Vec<Zeroizing<Vec<u8>>>) {
    let mut next = data.into_iter();
    for buffer in buffers
        .iter_mut()
        .filter(|buffer| buffer.kind == IovKind::Data)
    {
        if let Some(value) = next.next() {
            buffer.value = value;
        }
    }
}

/// Set the value of the buffer at `index`.
fn set(buffers: &mut [IovBuffer], index: usize, value: Vec<u8>) {
    if let Some(buffer) = buffers.get_mut(index) {
        buffer.value = Zeroizing::new(value);
    }
}

/// The value of the buffer at `index`.
fn get(buffers: &[IovBuffer], index: usize) -> &[u8] {
    buffers.get(index).map_or(&[][..], |buffer| &buffer.value)
}

/// `gss_wrap_iov_length`: size the header, trailer and padding buffers.
///
/// # Errors
///
/// Returns the errors of [`wrap`] that do not depend on the data.
pub(super) fn wrap_length(
    context: &EstablishedContext,
    buffers: &mut [IovBuffer],
    confidential: bool,
) -> Result<bool, Error> {
    let layout = layout(buffers, IovKind::Header)?;
    let etype = etype_of(super::context::usable(context)?)?;
    let sealed = confidential && has_data(buffers);
    let dce = context.flags.contains(ContextFlags::DCE_STYLE);
    let frame = framing(etype, sealed, dce, layout.trailer.is_some());
    let mut header = HEADER_LEN.saturating_add(frame.confounder);
    match layout.trailer {
        Some(index) => set(buffers, index, vec![0; frame.trailer]),
        None => header = header.saturating_add(frame.trailer),
    }
    set(buffers, layout.header, vec![0; header]);
    if let Some(index) = layout.padding {
        set(buffers, index, Vec::new());
    }
    Ok(sealed)
}

/// `gss_wrap_iov`.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::wrap_iov`].
pub(super) fn wrap(
    context: &mut EstablishedContext,
    buffers: &mut [IovBuffer],
    confidential: bool,
) -> Result<bool, Error> {
    let layout = layout(buffers, IovKind::Header)?;
    bounded(buffers)?;
    let key = super::context::usable(context)?.clone();
    let etype = etype_of(&key)?;
    let sealed = confidential && has_data(buffers);
    let dce = context.flags.contains(ContextFlags::DCE_STYLE);
    let frame = framing(etype, sealed, dce, layout.trailer.is_some());
    let (_, seal) = super::context::usages(context.initiated);
    let sequence = context.send_sequence;
    let mut flags = super::context::sent_flags(context);
    if let Some(index) = layout.padding {
        set(buffers, index, Vec::new());
    }
    let (header, trailer) = if sealed {
        flags |= GSS_TOKEN_FLAG_SEALED;
        let ec = count(frame.ec)?;
        let copy = header_bytes(TOK_WRAP, flags, [ec, 0], sequence);
        let mut confounder = Zeroizing::new(vec![0; frame.confounder]);
        getrandom::fill(&mut confounder).map_err(Error::Random)?;
        let plain = Pieces {
            confounder,
            data: data_of(buffers),
            trailer: Zeroizing::new([vec![0xff; frame.ec], copy].concat()),
        };
        let (cipher, mac) = if has_sign_only(buffers) {
            seal_signed(etype, &key, seal, buffers, &plain)?
        } else {
            let joined = plain.joined();
            let message = joined.get(frame.confounder..).unwrap_or_default();
            let mut out = etype.encrypt_message_with_confounder(
                key.value(),
                message,
                seal,
                &plain.confounder,
            )?;
            let mac = out.split_off(out.len().saturating_sub(etype.hmac_len()));
            (out, mac)
        };
        let pieces = plain.split(&cipher);
        let token = header_bytes(TOK_WRAP, flags, [ec, count(frame.rrc)?], sequence);
        let tail = [pieces.trailer.as_slice(), &mac].concat();
        let header = match layout.trailer {
            Some(_) => [token.as_slice(), &pieces.confounder].concat(),
            None => [token.as_slice(), &tail, &pieces.confounder].concat(),
        };
        scatter(buffers, pieces.data);
        (header, tail)
    } else {
        let zero = header_bytes(TOK_WRAP, flags, [0, 0], sequence);
        let checksum = etype.checksum(key.value(), &checksum_input(buffers, &zero), seal)?;
        let ec = count(checksum.len())?;
        let rrc = if layout.trailer.is_some() { 0 } else { ec };
        let token = header_bytes(TOK_WRAP, flags, [ec, rrc], sequence);
        match layout.trailer {
            Some(_) => (token, checksum),
            None => ([token, checksum].concat(), Vec::new()),
        }
    };
    set(buffers, layout.header, header);
    if let Some(index) = layout.trailer {
        set(buffers, index, trailer);
    }
    context.send_sequence = sequence.wrapping_add(1);
    Ok(sealed)
}

/// The checked header of a received Wrap or MIC token, and its key.
///
/// # Errors
///
/// Returns [`Error::DefectiveToken`] for a short header, another token ID, a
/// token from this end or a bad filler, and the key errors.
fn received(
    context: &EstablishedContext,
    header: &[u8],
    token: [u8; 2],
) -> Result<(EncryptionKey, KerberosEtype), Error> {
    let defective = Error::DefectiveToken;
    let id = header
        .get(..2)
        .ok_or_else(|| defective("a token shorter than its header"))?;
    if header.len() < HEADER_LEN || id != token {
        return Err(defective("not a token of the expected type"));
    }
    let flags = header.get(2).copied().unwrap_or_default();
    let from_acceptor = flags & GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR != 0;
    if from_acceptor != context.initiated {
        return Err(defective("a token from this end of the context"));
    }
    let filler = if token == TOK_MIC { 3..8 } else { 3..4 };
    if header
        .get(filler)
        .is_none_or(|bytes| bytes.iter().any(|byte| *byte != 0xff))
    {
        return Err(defective("a bad filler"));
    }
    let key = super::context::received_key(context, flags)?;
    let etype = etype_of(&key)?;
    Ok((key, etype))
}

/// Open the framing of a received Wrap token.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::unwrap_iov`].
fn open(
    context: &mut EstablishedContext,
    buffers: &mut [IovBuffer],
    layout: &Layout,
) -> Result<bool, Error> {
    let _usable: &EncryptionKey = super::context::usable(context)?;
    if layout
        .padding
        .is_some_and(|index| !get(buffers, index).is_empty())
    {
        return Err(Error::DefectiveToken(
            "a PADDING buffer in an RFC 4121 token",
        ));
    }
    let header = get(buffers, layout.header).to_vec();
    let (key, etype) = received(context, &header, TOK_WRAP)?;
    let (_, seal) = super::context::usages(!context.initiated);
    let flags = header.get(2).copied().unwrap_or_default();
    let (ec, rrc) = (
        usize::from(field(&header, 4)),
        usize::from(field(&header, 6)),
    );
    let dce = context.flags.contains(ContextFlags::DCE_STYLE);
    let detached = layout.trailer.map(|index| get(buffers, index).to_vec());
    let bad_length = Error::BadIov("a header or trailer of the wrong length");
    let confidential = flags & GSS_TOKEN_FLAG_SEALED != 0;
    if !confidential {
        let length = etype.hmac_len();
        let checksum = match &detached {
            _ if ec != length => {
                return Err(Error::DefectiveToken("EC is not the checksum length"));
            }
            None if rrc == length && header.len() == HEADER_LEN.saturating_add(length) => {
                header.get(HEADER_LEN..).unwrap_or_default().to_vec()
            }
            Some(trailer) if rrc == 0 && trailer.len() == length && header.len() == HEADER_LEN => {
                trailer.clone()
            }
            _ => return Err(bad_length),
        };
        let mut zero = header.get(..HEADER_LEN).unwrap_or_default().to_vec();
        zero.iter_mut().skip(4).take(4).for_each(|byte| *byte = 0);
        if !etype.verify_checksum(
            key.value(),
            &checksum_input(buffers, &zero),
            &checksum,
            seal,
        ) {
            return Err(Error::BadSignature);
        }
        context.window.admit(sequence_of(&header))?;
        return Ok(false);
    }
    let trailer_len = ec
        .saturating_add(HEADER_LEN)
        .saturating_add(etype.hmac_len());
    let confounder = etype.confounder_len();
    if detached.is_some() && rrc != 0 {
        return Err(Error::DefectiveToken("an RRC beside a TRAILER buffer"));
    }
    if detached.is_none() && rrc != trailer_len.saturating_sub(if dce { ec } else { 0 }) {
        return Err(Error::DefectiveToken(
            "an RRC that does not rotate the trailer",
        ));
    }
    let expected = Framing {
        confounder,
        trailer: trailer_len,
        ec,
        rrc,
    };
    let (front, tail) = sealed_parts(&header, detached.as_deref(), &expected)?;
    let (sealed_tail, mac) = tail.split_at(ec.saturating_add(HEADER_LEN));
    let cipher = Pieces {
        confounder: Zeroizing::new(front),
        data: data_of(buffers),
        trailer: Zeroizing::new(sealed_tail.to_vec()),
    };
    let plain = if has_sign_only(buffers) {
        open_signed(etype, &key, seal, buffers, &cipher, mac)?
    } else {
        let joined = [cipher.joined().as_slice(), mac].concat();
        let message = Zeroizing::new(
            etype
                .decrypt_message(key.value(), &joined, seal)
                .map_err(|_failure| Error::BadSignature)?,
        );
        cipher.split(&[vec![0; confounder].as_slice(), &message].concat())
    };
    let copy = plain.trailer.get(ec..).unwrap_or_default();
    let same = copy.get(..4) == header.get(..4)
        && copy.get(4..6) == header.get(4..6)
        && copy.get(8..HEADER_LEN) == header.get(8..HEADER_LEN);
    if !same {
        return Err(Error::DefectiveToken("the sealed header copy differs"));
    }
    context.window.admit(sequence_of(&header))?;
    scatter(buffers, plain.data.clone());
    Ok(true)
}

/// The confounder and the trailer of a received sealed token whose RRC was
/// checked: rotated into its HEADER buffer, or in its TRAILER buffer.
///
/// # Errors
///
/// Returns [`Error::BadIov`] for a header or trailer of the wrong length.
fn sealed_parts(
    header: &[u8],
    detached: Option<&[u8]>,
    expected: &Framing,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let bad_length = Error::BadIov("a header or trailer of the wrong length");
    let rest = header.get(HEADER_LEN..).unwrap_or_default();
    match detached {
        None => {
            if rest.len() != expected.trailer.saturating_add(expected.confounder) {
                return Err(bad_length);
            }
            let (tail, front) = rest.split_at(expected.trailer);
            Ok((front.to_vec(), tail.to_vec()))
        }
        Some(trailer) => {
            if trailer.len() != expected.trailer || rest.len() != expected.confounder {
                return Err(bad_length);
            }
            Ok((rest.to_vec(), trailer.to_vec()))
        }
    }
}

/// Unwrap a STREAM buffer into the one DATA buffer (`k5unsealiov.c:356-570`).
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::unwrap_iov`].
fn open_stream(
    context: &mut EstablishedContext,
    buffers: &mut [IovBuffer],
    stream: usize,
) -> Result<bool, Error> {
    if context.flags.contains(ContextFlags::DCE_STYLE) {
        return Err(Error::BadIov("a STREAM buffer in a DCE-style context"));
    }
    for kind in [
        IovKind::Header,
        IovKind::Trailer,
        IovKind::Padding,
        IovKind::MicToken,
    ] {
        if locate(buffers, kind)?.is_some() {
            return Err(Error::BadIov("a framing buffer beside a STREAM buffer"));
        }
    }
    let mut data_slots = buffers
        .iter()
        .enumerate()
        .filter(|(_, buffer)| buffer.kind == IovKind::Data)
        .map(|(index, _)| index);
    let (Some(slot), None) = (data_slots.next(), data_slots.next()) else {
        return Err(Error::BadIov(
            "a STREAM unwrap needs exactly one DATA buffer",
        ));
    };
    let token = Zeroizing::new(get(buffers, stream).to_vec());
    let (header, body) = token
        .split_at_checked(HEADER_LEN)
        .ok_or(Error::DefectiveToken("a stream shorter than its header"))?;
    let (_, etype) = received(context, header, TOK_WRAP)?;
    let confidential = header
        .get(2)
        .is_some_and(|flags| flags & GSS_TOKEN_FLAG_SEALED != 0);
    let ec = if confidential {
        usize::from(field(header, 4))
    } else {
        0
    };
    let rrc = usize::from(field(header, 6));
    let mut rotated = Zeroizing::new(body.to_vec());
    if let Some(shift) = rrc.checked_rem(rotated.len()) {
        rotated.rotate_left(shift);
    }
    let unrotated = rotated;
    let (confounder, trailer) = if confidential {
        (
            etype.confounder_len(),
            ec.saturating_add(HEADER_LEN)
                .saturating_add(etype.hmac_len()),
        )
    } else {
        (0, etype.hmac_len())
    };
    let data_end = unrotated
        .len()
        .checked_sub(trailer)
        .filter(|end| *end >= confounder)
        .ok_or(Error::DefectiveToken("a stream shorter than its framing"))?;
    let mut fixed = header.to_vec();
    fixed.iter_mut().skip(6).take(2).for_each(|byte| *byte = 0);
    fixed.extend_from_slice(unrotated.get(..confounder).unwrap_or_default());
    let mut inner = vec![IovBuffer::new(IovKind::Header, fixed)];
    for buffer in buffers.iter() {
        match buffer.kind {
            IovKind::Data => inner.push(IovBuffer::new(
                IovKind::Data,
                unrotated
                    .get(confounder..data_end)
                    .unwrap_or_default()
                    .to_vec(),
            )),
            IovKind::SignOnly => inner.push(buffer.clone()),
            IovKind::Empty
            | IovKind::Header
            | IovKind::MechParams
            | IovKind::Trailer
            | IovKind::Padding
            | IovKind::Stream
            | IovKind::MicToken => {}
        }
    }
    inner.push(IovBuffer::new(
        IovKind::Trailer,
        unrotated.get(data_end..).unwrap_or_default().to_vec(),
    ));
    let trailer_at = inner.len().saturating_sub(1);
    let layout = Layout {
        header: 0,
        trailer: Some(trailer_at),
        padding: None,
    };
    let opened = open(context, &mut inner, &layout)?;
    if let Some(data) = inner
        .into_iter()
        .find(|buffer| buffer.kind == IovKind::Data)
    {
        set(buffers, slot, data.value.to_vec());
    }
    Ok(opened)
}

/// `gss_unwrap_iov`.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::unwrap_iov`].
pub(super) fn unwrap(
    context: &mut EstablishedContext,
    buffers: &mut [IovBuffer],
) -> Result<bool, Error> {
    if buffers.len() > MAX_BUFFERS {
        return Err(Error::BadIov("too many buffers"));
    }
    bounded(buffers)?;
    if let Some(stream) = locate(buffers, IovKind::Stream)? {
        return open_stream(context, buffers, stream);
    }
    let layout = layout(buffers, IovKind::Header)?;
    open(context, buffers, &layout)
}

/// `gss_get_mic_iov`.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::get_mic_iov`].
pub(super) fn get_mic(
    context: &mut EstablishedContext,
    buffers: &mut [IovBuffer],
) -> Result<(), Error> {
    let layout = layout(buffers, IovKind::MicToken)?;
    bounded(buffers)?;
    let key = super::context::usable(context)?.clone();
    let etype = etype_of(&key)?;
    let (sign, _) = super::context::usages(context.initiated);
    let sequence = context.send_sequence;
    let header = header_bytes(
        TOK_MIC,
        super::context::sent_flags(context),
        [0xffff, 0xffff],
        sequence,
    );
    let checksum = etype.checksum(key.value(), &checksum_input(buffers, &header), sign)?;
    set(buffers, layout.header, [header, checksum].concat());
    context.send_sequence = sequence.wrapping_add(1);
    Ok(())
}

/// `gss_verify_mic_iov`.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::verify_mic_iov`].
pub(super) fn verify_mic(
    context: &mut EstablishedContext,
    buffers: &[IovBuffer],
) -> Result<(), Error> {
    let layout = layout(buffers, IovKind::MicToken)?;
    bounded(buffers)?;
    let _usable: &EncryptionKey = super::context::usable(context)?;
    let token = get(buffers, layout.header);
    let (key, etype) = received(context, token, TOK_MIC)?;
    if token
        .get(2)
        .is_some_and(|flags| flags & GSS_TOKEN_FLAG_SEALED != 0)
    {
        return Err(Error::DefectiveToken("a MIC token cannot be sealed"));
    }
    let (sign, _) = super::context::usages(!context.initiated);
    let (header, checksum) = token.split_at(HEADER_LEN);
    if checksum.len() != etype.hmac_len() {
        return Err(Error::BadIov("a MIC token of the wrong length"));
    }
    if !etype.verify_checksum(
        key.value(),
        &checksum_input(buffers, header),
        checksum,
        sign,
    ) {
        return Err(Error::BadSignature);
    }
    context.window.admit(sequence_of(header))
}

/// `gss_wrap_aead`: HEADER | `SIGN_ONLY` | DATA | PADDING | TRAILER, sent as
/// header, data, padding and trailer (`g_wrap_aead.c:76-160`).
///
/// # Errors
///
/// Returns the errors of [`wrap`].
pub(super) fn wrap_aead(
    context: &mut EstablishedContext,
    associated: &[u8],
    message: &[u8],
    confidential: bool,
) -> Result<Vec<u8>, Error> {
    let mut buffers = [
        IovBuffer::empty(IovKind::Header),
        IovBuffer::new(IovKind::SignOnly, associated.to_vec()),
        IovBuffer::new(IovKind::Data, message.to_vec()),
        IovBuffer::empty(IovKind::Padding),
        IovBuffer::empty(IovKind::Trailer),
    ];
    let _sealed: bool = wrap(context, &mut buffers, confidential)?;
    Ok(buffers
        .iter()
        .filter(|buffer| buffer.kind != IovKind::SignOnly)
        .flat_map(|buffer| buffer.value.iter().copied())
        .collect())
}

/// `gss_unwrap_aead`: STREAM | `SIGN_ONLY` | DATA (`g_unwrap_aead.c:75-110`).
///
/// # Errors
///
/// Returns the errors of [`unwrap`].
pub(super) fn unwrap_aead(
    context: &mut EstablishedContext,
    token: &[u8],
    associated: &[u8],
) -> Result<Unwrapped, Error> {
    let mut buffers = [
        IovBuffer::new(IovKind::Stream, token.to_vec()),
        IovBuffer::new(IovKind::SignOnly, associated.to_vec()),
        IovBuffer::empty(IovKind::Data),
    ];
    let confidential = unwrap(context, &mut buffers)?;
    let [_, _, data] = buffers;
    Ok(Unwrapped {
        message: data.value,
        confidential,
    })
}
