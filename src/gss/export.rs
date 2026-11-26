//! Context and credential transfer.
//!
//! `gss_export_sec_context`, `gss_import_sec_context`, `gss_export_cred` and
//! `gss_import_cred` (MIT 1.22.2 `export_sec_context.c:28-95`,
//! `import_sec_context.c:28-93`, `ser_sctx.c`, `export_cred.c`,
//! `import_cred.c`) under the transfer contract of this crate: the exported
//! object is consumed, the blob is sealed under a caller-supplied 256-bit key,
//! and a [`TransferLedger`] refuses a transfer id it has consumed.
//!
//! # Format (version 1)
//!
//! ```text
//! blob      = header | ciphertext
//! header    = "GSSX" | version (1 byte, 1) | kind (1 byte: 1 context, 2 credential)
//!           | transfer id (16 random bytes) | export time (8 bytes, big-endian POSIX seconds)
//! ciphertext = aes256-cts-hmac-sha384-192 (RFC 8009) encryption of header | payload
//!              under the transfer key, key usage 0x47535831
//! ```
//!
//! The payload is this module's private serialization of the object; the
//! header is authenticated because it is encrypted with the payload and
//! compared after decryption. MIT's export format is not used: it carries the
//! keys in the clear.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::{
    CCache, ContextFlags, Credential, CredentialUsage, EncryptionKey, Error, EstablishedContext,
    Keytab, Name, NameKind, NameType, Principal, TransferBlob, TransferKey, TransferLedger,
    context::Mechanism, pac, seq,
};
use crate::crypto::{AesSha2Etype, CryptoPolicy};

/// The magic of a transfer blob.
const MAGIC: [u8; 4] = *b"GSSX";
/// The format version.
const VERSION: u8 = 1;
/// The kind byte of a security context.
const KIND_CONTEXT: u8 = 1;
/// The kind byte of a credential.
const KIND_CREDENTIAL: u8 = 2;
/// The length of the clear header.
const HEADER_LEN: usize = 30;
/// The key usage of the RFC 8009 encryption ("GSX1").
const USAGE: u32 = 0x4753_5831;
/// The longest blob, in bytes.
pub(super) const MAX_BLOB: usize = 0x10_0000;
/// The profile that seals blobs.
const PROFILE: AesSha2Etype = AesSha2Etype::Aes256;
/// Every name type, in the order of its transfer code.
const NAME_TYPES: [NameType; 10] = [
    NameType::HostbasedService,
    NameType::User,
    NameType::MachineUid,
    NameType::StringUid,
    NameType::Anonymous,
    NameType::Export,
    NameType::CompositeExport,
    NameType::Principal,
    NameType::Enterprise,
    NameType::X509Cert,
];

/// A malformed payload; only reachable for a blob sealed by another writer
/// under the same key.
const MALFORMED: Error = Error::TransferRejected("a malformed transfer payload");

/// The payload writer.
#[derive(Default)]
struct Writer {
    /// The bytes written.
    out: Zeroizing<Vec<u8>>,
}

impl Writer {
    /// Append one byte.
    fn byte(&mut self, value: u8) {
        self.out.push(value);
    }

    /// Append a boolean.
    fn flag(&mut self, value: bool) {
        self.byte(u8::from(value));
    }

    /// Append a big-endian `u32`.
    fn word(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    /// Append a big-endian `u64`.
    fn long(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    /// Append length-prefixed bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TokenTooLarge`] above 4 GiB.
    fn bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        let length = u32::try_from(value.len()).map_err(|_overflow| Error::TokenTooLarge {
            maximum: MAX_BLOB,
            actual: value.len(),
        })?;
        self.word(length);
        self.out.extend_from_slice(value);
        Ok(())
    }

    /// Append optional length-prefixed bytes.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::bytes`].
    fn optional(&mut self, value: Option<&[u8]>) -> Result<(), Error> {
        self.flag(value.is_some());
        value.map_or(Ok(()), |bytes| self.bytes(bytes))
    }

    /// Append a key.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::bytes`].
    fn key(&mut self, key: Option<&EncryptionKey>) -> Result<(), Error> {
        self.flag(key.is_some());
        if let Some(value) = key {
            self.word(value.etype().cast_unsigned());
            self.bytes(value.value())?;
        }
        Ok(())
    }

    /// Append a name.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::bytes`].
    fn name(&mut self, name: &Name) -> Result<(), Error> {
        let principal = &name.principal;
        self.bytes(principal.realm.as_bytes())?;
        self.word(principal.name_type.cast_unsigned());
        self.bytes(
            &u32::try_from(principal.components.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        )?;
        for component in &principal.components {
            self.bytes(component.as_bytes())?;
        }
        let code = NAME_TYPES
            .iter()
            .position(|kind| *kind == name.imported_as)
            .and_then(|index| u8::try_from(index).ok())
            .unwrap_or(u8::MAX);
        self.byte(code);
        match &name.kind {
            NameKind::Principal => self.byte(0),
            NameKind::Hostbased => self.byte(1),
            NameKind::Certificate(bytes) => {
                self.byte(2);
                self.bytes(bytes)?;
            }
        }
        self.optional(name.attributes.as_deref())
    }

    /// Append an optional name.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::bytes`].
    fn optional_name(&mut self, name: Option<&Name>) -> Result<(), Error> {
        self.flag(name.is_some());
        name.map_or(Ok(()), |value| self.name(value))
    }
}

/// The payload reader.
struct Reader<'bytes> {
    /// The bytes not read yet.
    rest: &'bytes [u8],
}

impl<'bytes> Reader<'bytes> {
    /// `count` bytes.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error past the end.
    fn take(&mut self, count: usize) -> Result<&'bytes [u8], Error> {
        let (head, tail) = self.rest.split_at_checked(count).ok_or(MALFORMED)?;
        self.rest = tail;
        Ok(head)
    }

    /// One byte.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error past the end.
    fn byte(&mut self) -> Result<u8, Error> {
        self.take(1)?.first().copied().ok_or(MALFORMED)
    }

    /// A boolean.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error past the end or for another byte.
    fn flag(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MALFORMED),
        }
    }

    /// A big-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error past the end.
    fn word(&mut self) -> Result<u32, Error> {
        let bytes = <[u8; 4]>::try_from(self.take(4)?).map_err(|_length| MALFORMED)?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// A big-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error past the end.
    fn long(&mut self) -> Result<u64, Error> {
        let bytes = <[u8; 8]>::try_from(self.take(8)?).map_err(|_length| MALFORMED)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Length-prefixed bytes.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error past the end.
    fn bytes(&mut self) -> Result<&'bytes [u8], Error> {
        let length = usize::try_from(self.word()?).map_err(|_range| MALFORMED)?;
        self.take(length)
    }

    /// Optional length-prefixed bytes.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error past the end.
    fn optional(&mut self) -> Result<Option<&'bytes [u8]>, Error> {
        if self.flag()? {
            Ok(Some(self.bytes()?))
        } else {
            Ok(None)
        }
    }

    /// A UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error past the end or for invalid UTF-8.
    fn string(&mut self) -> Result<String, Error> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_invalid| MALFORMED)
    }

    /// A key.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error past the end.
    fn key(&mut self) -> Result<Option<EncryptionKey>, Error> {
        if !self.flag()? {
            return Ok(None);
        }
        let etype = self.word()?.cast_signed();
        Ok(Some(EncryptionKey::new(etype, self.bytes()?.to_vec())))
    }

    /// A name.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error for a malformed name.
    fn name(&mut self) -> Result<Name, Error> {
        let realm = self.string()?;
        let name_type = self.word()?.cast_signed();
        let count =
            u32::from_be_bytes(<[u8; 4]>::try_from(self.bytes()?).map_err(|_length| MALFORMED)?);
        let mut components = Vec::new();
        for _ in 0..count {
            components.push(self.string()?);
        }
        let imported_as = NAME_TYPES
            .get(usize::from(self.byte()?))
            .copied()
            .ok_or(MALFORMED)?;
        let kind = match self.byte()? {
            0 => NameKind::Principal,
            1 => NameKind::Hostbased,
            2 => NameKind::Certificate(self.bytes()?.to_vec()),
            _ => return Err(MALFORMED),
        };
        let attributes = self.optional()?.map(<[u8]>::to_vec);
        Ok(Name {
            principal: Principal::new(realm, name_type, components),
            imported_as,
            kind,
            attributes,
        })
    }

    /// An optional name.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error for a malformed name.
    fn optional_name(&mut self) -> Result<Option<Name>, Error> {
        if self.flag()? {
            Ok(Some(self.name()?))
        } else {
            Ok(None)
        }
    }

    /// Refuse bytes after the payload.
    ///
    /// # Errors
    ///
    /// Returns the malformed-payload error for trailing bytes.
    const fn finish(&self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(MALFORMED)
        }
    }
}

/// The code of a credential usage.
const fn usage_code(usage: CredentialUsage) -> u8 {
    match usage {
        CredentialUsage::Initiate => 1,
        CredentialUsage::Accept => 2,
        CredentialUsage::Both => 3,
    }
}

/// Serialize a credential.
///
/// # Errors
///
/// Returns [`Error::NotNegotiated`] for a credential with a replay cache (any
/// `rcache` store key), whose replay evidence the blob cannot carry, and the
/// cache and keytab errors.
fn put_credential(writer: &mut Writer, credential: &Credential) -> Result<(), Error> {
    if credential.replay.is_some() {
        return Err(Error::NotNegotiated(
            "a credential with a replay cache cannot be transferred",
        ));
    }
    writer.optional_name(credential.name.as_ref())?;
    writer.byte(usage_code(credential.usage));
    let cache = credential
        .cache
        .as_ref()
        .map(CCache::to_bytes)
        .transpose()?
        .map(Zeroizing::new);
    writer.optional(cache.as_deref().map(Vec::as_slice))?;
    for keytab in [&credential.client_keytab, &credential.keytab] {
        let bytes = keytab
            .as_ref()
            .map(Keytab::to_bytes)
            .transpose()?
            .map(Zeroizing::new);
        writer.optional(bytes.as_deref().map(Vec::as_slice))?;
    }
    writer.optional(credential.password.as_deref().map(Vec::as_slice))?;
    writer.flag(credential.verify_keytab.is_some());
    if let Some(host_keys) = &credential.verify_keytab {
        writer.bytes(&Zeroizing::new(host_keys.to_bytes()?))?;
        let server = credential.verify_server.as_ref().map(Name::from_principal);
        writer.optional_name(server.as_ref())?;
    }
    let impersonator = match &credential.impersonator {
        Some(inner) => {
            let mut nested = Writer::default();
            put_credential(&mut nested, inner)?;
            Some(nested.out)
        }
        None => None,
    };
    writer.optional(impersonator.as_deref().map(Vec::as_slice))
}

/// Deserialize a credential.
///
/// # Errors
///
/// Returns the malformed-payload error and the cache and keytab errors.
fn get_credential(reader: &mut Reader<'_>) -> Result<Credential, Error> {
    let name = reader.optional_name()?;
    let usage = match reader.byte()? {
        1 => CredentialUsage::Initiate,
        2 => CredentialUsage::Accept,
        3 => CredentialUsage::Both,
        _ => return Err(MALFORMED),
    };
    let cache = reader.optional()?.map(CCache::parse).transpose()?;
    let client_keytab = reader.optional()?.map(Keytab::parse).transpose()?;
    let keytab = reader.optional()?.map(Keytab::parse).transpose()?;
    let password = reader
        .optional()?
        .map(|bytes| Zeroizing::new(bytes.to_vec()));
    let (verify_keytab, verify_server) = if reader.flag()? {
        let host_keys = Keytab::parse(reader.bytes()?)?;
        let server = reader
            .optional_name()?
            .map(|verify_name| verify_name.principal().clone());
        (Some(host_keys), server)
    } else {
        (None, None)
    };
    let impersonator = match reader.optional()? {
        Some(bytes) => {
            let mut nested = Reader { rest: bytes };
            let inner = get_credential(&mut nested)?;
            nested.finish()?;
            Some(Box::new(inner))
        }
        None => None,
    };
    Ok(Credential {
        name,
        usage,
        cache,
        client_keytab,
        password,
        keytab,
        replay: None,
        verify_keytab,
        verify_server,
        impersonator,
    })
}

/// Whole POSIX seconds and nanoseconds of `at`.
fn instant(at: SystemTime) -> (u64, u32) {
    at.duration_since(UNIX_EPOCH)
        .map_or((0, 0), |since| (since.as_secs(), since.subsec_nanos()))
}

/// Serialize a context.
///
/// # Errors
///
/// Returns the errors of [`put_credential`] for a delegated credential and of
/// the payload writer.
fn put_context(writer: &mut Writer, context: &EstablishedContext) -> Result<(), Error> {
    writer.flag(context.initiated);
    writer.flag(context.open);
    writer.word(context.flags.bits());
    writer.name(&context.source)?;
    writer.name(&context.target)?;
    writer.key(Some(&context.session_key))?;
    writer.key(context.initiator_subkey.as_ref())?;
    writer.key(context.acceptor_subkey.as_ref())?;
    writer.long(context.send_sequence);
    let (replay, sequence, state) = context.window.parts();
    writer.flag(replay);
    writer.flag(sequence);
    for value in state {
        writer.long(value);
    }
    let (seconds, nanos) = instant(context.expires);
    writer.long(seconds);
    writer.word(nanos);
    let delegated = match &context.delegated {
        Some(credential) => {
            let mut inner = Writer::default();
            put_credential(&mut inner, credential)?;
            Some(inner.out)
        }
        None => None,
    };
    writer.optional(delegated.as_deref().map(Vec::as_slice))?;
    writer.flag(context.pac.is_some());
    if let Some(verified) = &context.pac {
        writer.bytes(verified.pac().data())?;
        let checks = verified.checks();
        for passed in [
            checks.server(),
            checks.kdc(),
            checks.ticket(),
            checks.full(),
            checks.client(),
        ] {
            writer.flag(passed);
        }
    }
    writer.word(u32::try_from(context.auth_indicators.len()).map_err(|_count| MALFORMED)?);
    for indicator in &context.auth_indicators {
        writer.bytes(indicator.as_bytes())?;
    }
    writer.byte(match context.mechanism {
        Mechanism::Krb5 => 1,
        Mechanism::Iakerb => 2,
    });
    Ok(())
}

/// Deserialize a context; it takes the default enctype policy.
///
/// # Errors
///
/// Returns the malformed-payload error and the PAC and credential errors.
fn get_context(reader: &mut Reader<'_>) -> Result<EstablishedContext, Error> {
    let initiated = reader.flag()?;
    let open = reader.flag()?;
    let flags = ContextFlags::from_bits(reader.word()?);
    let source = reader.name()?;
    let target = reader.name()?;
    let session_key = reader.key()?.ok_or(MALFORMED)?;
    let initiator_subkey = reader.key()?;
    let acceptor_subkey = reader.key()?;
    let send_sequence = reader.long()?;
    let replay = reader.flag()?;
    let sequence = reader.flag()?;
    let state = [reader.long()?, reader.long()?, reader.long()?];
    let seconds = reader.long()?;
    let nanos = reader.word()?;
    let expires = UNIX_EPOCH
        .checked_add(Duration::new(seconds, nanos.min(999_999_999)))
        .ok_or(MALFORMED)?;
    let delegated = match reader.optional()? {
        Some(bytes) => {
            let mut inner = Reader { rest: bytes };
            let credential = get_credential(&mut inner)?;
            inner.finish()?;
            Some(Box::new(credential))
        }
        None => None,
    };
    let verified = if reader.flag()? {
        let data = reader.bytes()?;
        let mut results = [false; 5];
        for slot in &mut results {
            *slot = reader.flag()?;
        }
        let parsed = pac::Pac::parse_and_process(data).map_err(|_invalid| MALFORMED)?;
        Some(pac::Verified::restored(parsed, results))
    } else {
        None
    };
    let mut auth_indicators = Vec::new();
    for _ in 0..reader.word()? {
        auth_indicators.push(reader.string()?);
    }
    let mechanism = match reader.byte()? {
        1 => Mechanism::Krb5,
        2 => Mechanism::Iakerb,
        _ => return Err(MALFORMED),
    };
    Ok(EstablishedContext {
        initiated,
        source,
        target,
        flags,
        session_key,
        initiator_subkey,
        acceptor_subkey,
        send_sequence,
        window: seq::Window::from_parts(replay, sequence, state),
        expires,
        crypto_policy: CryptoPolicy::default(),
        delegated,
        pac: verified,
        auth_indicators,
        open,
        mechanism,
    })
}

/// Seal `payload` of `kind` under `key`.
///
/// # Errors
///
/// Returns the random-source and encryption errors.
fn seal(kind: u8, payload: &[u8], key: &TransferKey) -> Result<TransferBlob, Error> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(Error::Random)?;
    let (seconds, _) = instant(SystemTime::now());
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&[VERSION, kind]);
    header.extend_from_slice(&id);
    header.extend_from_slice(&seconds.to_be_bytes());
    let plaintext = Zeroizing::new([header.as_slice(), payload].concat());
    let mut confounder = Zeroizing::new([0; 16]);
    getrandom::fill(confounder.as_mut_slice()).map_err(Error::Random)?;
    let ciphertext = PROFILE.encrypt_message_with_confounder(
        key.bytes(),
        &plaintext,
        USAGE,
        confounder.as_slice(),
    )?;
    Ok(TransferBlob {
        bytes: [header, ciphertext].concat(),
    })
}

/// Open a blob of `kind` and consume its transfer id in `ledger`.
///
/// # Errors
///
/// Returns [`Error::TokenTooLarge`] above 1 MiB, [`Error::TransferRejected`]
/// for another format, version or kind, or a blob that does not authenticate
/// under `key`, [`Error::TransferReplayed`] for a consumed transfer id, and
/// the ledger's errors.
fn open(
    kind: u8,
    blob: &TransferBlob,
    key: &TransferKey,
    ledger: &mut dyn TransferLedger,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let bytes = blob.bytes.as_slice();
    if bytes.len() > MAX_BLOB {
        return Err(Error::TokenTooLarge {
            maximum: MAX_BLOB,
            actual: bytes.len(),
        });
    }
    let (header, ciphertext) = bytes
        .split_at_checked(HEADER_LEN)
        .ok_or(Error::TransferRejected("a blob shorter than its header"))?;
    if header.get(..4) != Some(&MAGIC[..]) || header.get(4..6) != Some(&[VERSION, kind][..]) {
        return Err(Error::TransferRejected(
            "not a transfer blob of this version and kind",
        ));
    }
    let plaintext = Zeroizing::new(
        PROFILE
            .decrypt_message(key.bytes(), ciphertext, USAGE)
            .map_err(|_failure| {
                Error::TransferRejected("the blob does not authenticate under the key")
            })?,
    );
    let (inner, payload) = plaintext
        .split_at_checked(HEADER_LEN)
        .ok_or(Error::TransferRejected("a sealed header that is too short"))?;
    if inner != header {
        return Err(Error::TransferRejected("the sealed header differs"));
    }
    let id =
        <[u8; 16]>::try_from(header.get(6..22).unwrap_or_default()).map_err(|_length| MALFORMED)?;
    let seconds = <[u8; 8]>::try_from(header.get(22..HEADER_LEN).unwrap_or_default())
        .map(u64::from_be_bytes)
        .map_err(|_length| MALFORMED)?;
    let exported = UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or(MALFORMED)?;
    if !ledger.consume(id, exported)? {
        return Err(Error::TransferReplayed);
    }
    Ok(Zeroizing::new(payload.to_vec()))
}

/// `gss_export_sec_context` under the transfer contract.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::export`].
pub(super) fn export_context(
    context: EstablishedContext,
    key: &TransferKey,
) -> Result<TransferBlob, Error> {
    let mut writer = Writer::default();
    put_context(&mut writer, &context)?;
    drop(context);
    seal(KIND_CONTEXT, &writer.out, key)
}

/// `gss_import_sec_context` under the transfer contract.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::import`].
pub(super) fn import_context(
    blob: &TransferBlob,
    key: &TransferKey,
    ledger: &mut dyn TransferLedger,
) -> Result<EstablishedContext, Error> {
    let payload = open(KIND_CONTEXT, blob, key, ledger)?;
    let mut reader = Reader { rest: &payload };
    let context = get_context(&mut reader)?;
    reader.finish()?;
    Ok(context)
}

/// `gss_export_cred` under the transfer contract.
///
/// # Errors
///
/// Returns the errors of [`super::Credential::export`].
pub(super) fn export_credential(
    credential: Credential,
    key: &TransferKey,
) -> Result<TransferBlob, Error> {
    let mut writer = Writer::default();
    put_credential(&mut writer, &credential)?;
    drop(credential);
    seal(KIND_CREDENTIAL, &writer.out, key)
}

/// `gss_import_cred` under the transfer contract.
///
/// # Errors
///
/// Returns the errors of [`super::Credential::import`].
pub(super) fn import_credential(
    blob: &TransferBlob,
    key: &TransferKey,
    ledger: &mut dyn TransferLedger,
) -> Result<Credential, Error> {
    let payload = open(KIND_CREDENTIAL, blob, key, ledger)?;
    let mut reader = Reader { rest: &payload };
    let credential = get_credential(&mut reader)?;
    reader.finish()?;
    Ok(credential)
}
