//! Request buffers of the Kerberos package messages `MSLSA:` uses.
//!
//! The structures are those of `NTSecAPI.h`, built as bytes for the
//! caller's pointer width. Strings
//! follow the fixed structure in the same buffer, and their `Buffer`
//! pointers are `base` (the buffer's address) plus their offset, as MIT
//! 1.22.2 `src/lib/krb5/ccache/cc_mslsa.c` lays out its requests
//! (`PurgeTicketEx` :647-728, `GetMSCacheTicketFromCacheInfoEx2` :1361-1420).

#[cfg(test)]
use rskrb5_ng::ccache::Credential;

/// Parsing of the response buffers.
pub(crate) mod parse;

/// The pointer width of the target.
pub(crate) const POINTER: usize = size_of::<usize>();
/// `KerbPurgeTicketCacheMessage`.
const PURGE: u32 = 6;
/// `KerbRetrieveEncodedTicketMessage`.
const RETRIEVE_ENCODED: u32 = 8;
/// `KerbPurgeTicketCacheExMessage`.
const PURGE_EX: u32 = 15;
/// `KerbQueryTicketCacheEx2Message`.
const QUERY_EX2: u32 = 20;
/// `KerbSubmitTicketMessage`.
const SUBMIT: u32 = 21;
/// `KERB_RETRIEVE_TICKET_USE_CACHE_ONLY`: never ask a KDC.
const USE_CACHE_ONLY: u32 = 2;
/// The size of `KERB_SUBMIT_TKT_REQUEST`.
const SUBMIT_SIZE: usize = 36;

/// `offset` rounded up to a multiple of `to` (a power of two).
pub(crate) const fn align(offset: usize, to: usize) -> usize {
    offset.saturating_add(to.saturating_sub(1)) & !to.saturating_sub(1)
}

/// The size of `UNICODE_STRING`: two lengths, then a pointer.
pub(crate) const USTRING: usize = align(4, POINTER) + POINTER;
/// The offset of `TargetName` in `KERB_RETRIEVE_TKT_REQUEST`.
const RETRIEVE_TARGET: usize = align(12, POINTER);
/// The size of `KERB_RETRIEVE_TKT_REQUEST` (`CredentialsHandle` is two
/// pointer-sized words).
const RETRIEVE_SIZE: usize = align(RETRIEVE_TARGET + USTRING + 12, POINTER) + 2 * POINTER;
/// The size of `KERB_PURGE_TKT_CACHE_REQUEST`.
const PURGE_SIZE: usize = align(RETRIEVE_TARGET + 2 * USTRING, POINTER);
/// The offset of `TicketTemplate` in `KERB_PURGE_TKT_CACHE_EX_REQUEST`.
const TEMPLATE: usize = 16;
/// The size of `KERB_PURGE_TKT_CACHE_EX_REQUEST`.
const PURGE_EX_SIZE: usize = align(TEMPLATE + 4 * USTRING + 24 + 8, 8);

/// One entry of `KerbQueryTicketCacheEx2Message`: the identity of a cached
/// ticket, also the template of `KerbPurgeTicketCacheExMessage`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CacheInfo {
    /// Client name, components joined by `/`.
    client_name: String,
    /// Client realm.
    client_realm: String,
    /// Server name, components joined by `/`.
    server_name: String,
    /// Server realm.
    server_realm: String,
    /// The session-key type (MIT purges with the keyblock enctype).
    session_key_type: i32,
}

impl CacheInfo {
    /// The entry of a credential, as the LSA would list it.
    #[cfg(test)]
    pub(crate) fn of(credential: &Credential) -> Self {
        Self {
            client_name: credential.client().components.join("/"),
            client_realm: credential.client().realm.clone(),
            server_name: credential.server().components.join("/"),
            server_realm: credential.server().realm.clone(),
            session_key_type: credential.key().etype(),
        }
    }

    /// The client name, components joined by `/`.
    pub(crate) fn client_name(&self) -> &str {
        &self.client_name
    }

    /// The client realm.
    pub(crate) fn client_realm(&self) -> &str {
        &self.client_realm
    }

    /// The name `KerbRetrieveEncodedTicketMessage` retrieves: `server@realm`.
    pub(crate) fn target(&self) -> String {
        format!("{}@{}", self.server_name, self.server_realm)
    }

    /// Whether the ticket is for `components` in `realm`.
    pub(crate) fn is_for(&self, realm: &str, components: &[String]) -> bool {
        self.server_realm == realm && self.server_name == components.join("/")
    }
}

/// A request under construction: fixed bytes, then string data.
struct Builder {
    /// The bytes.
    out: Vec<u8>,
    /// The address the buffer will have.
    base: u64,
}

impl Builder {
    /// A zeroed fixed part of `size` bytes whose first field is `message`.
    fn new(size: usize, message: u32, base: u64) -> Self {
        let mut out = vec![0; size];
        put(&mut out, 0, &message.to_le_bytes());
        Self { out, base }
    }

    /// Append `text` as UTF-16 and point the `UNICODE_STRING` at `at` to it.
    fn string(&mut self, at: usize, text: &str) {
        let start = self.out.len();
        self.out
            .extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        let bytes = self.out.len().saturating_sub(start);
        let length = u16::try_from(bytes).unwrap_or(u16::MAX).to_le_bytes();
        put(&mut self.out, at, &length);
        put(&mut self.out, at.saturating_add(2), &length);
        let address = self
            .base
            .saturating_add(u64::try_from(start).unwrap_or(u64::MAX));
        let pointer = address.to_le_bytes();
        put(
            &mut self.out,
            at.saturating_add(align(4, POINTER)),
            pointer.get(..POINTER).unwrap_or_default(),
        );
    }
}

/// Copy `bytes` into `out` at `at`; the callers' offsets are within it.
fn put(out: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(target) = out.get_mut(at..at.saturating_add(bytes.len())) {
        target.copy_from_slice(bytes);
    }
}

/// `KERB_QUERY_TKT_CACHE_REQUEST` for `KerbQueryTicketCacheEx2Message` in
/// the caller's logon session (MIT `GetQueryTktCacheResponseEx2`).
pub(crate) fn query_cache() -> Vec<u8> {
    Builder::new(12, QUERY_EX2, 0).out
}

/// `KERB_RETRIEVE_TKT_REQUEST` for the cached ticket of `target`
/// (`name@realm`), never asking a KDC.
pub(crate) fn retrieve(base: u64, target: &str) -> Vec<u8> {
    let mut request = Builder::new(RETRIEVE_SIZE, RETRIEVE_ENCODED, base);
    put(
        &mut request.out,
        RETRIEVE_TARGET.saturating_add(USTRING).saturating_add(4),
        &USE_CACHE_ONLY.to_le_bytes(),
    );
    request.string(RETRIEVE_TARGET, target);
    request.out
}

/// `KERB_PURGE_TKT_CACHE_REQUEST` with empty names: every ticket of the
/// caller's logon session (MIT `PurgeAllTickets`, `cc_mslsa.c:618-645`).
pub(crate) fn purge_all() -> Vec<u8> {
    Builder::new(PURGE_SIZE, PURGE, 0).out
}

/// `KERB_PURGE_TKT_CACHE_EX_REQUEST` for one ticket (MIT `PurgeTicketEx`).
pub(crate) fn purge(base: u64, template: &CacheInfo) -> Vec<u8> {
    let mut request = Builder::new(PURGE_EX_SIZE, PURGE_EX, base);
    let etype_at = TEMPLATE.saturating_add(4 * USTRING).saturating_add(24);
    put(
        &mut request.out,
        etype_at,
        &template.session_key_type.to_le_bytes(),
    );
    for (index, text) in [
        &template.client_name,
        &template.client_realm,
        &template.server_name,
        &template.server_realm,
    ]
    .into_iter()
    .enumerate()
    {
        request.string(TEMPLATE.saturating_add(index.saturating_mul(USTRING)), text);
    }
    request.out
}

/// `KERB_SUBMIT_TKT_REQUEST` followed by the KRB-CRED and the key that
/// encrypts its `enc-part` (MIT `KerbSubmitTicket`, `cc_mslsa.c:730-843`).
/// Returns `None` when a length does not fit 32 bits.
pub(crate) fn submit(krb_cred: &[u8], key_type: i32, key: &[u8]) -> Option<Vec<u8>> {
    let cred_size = u32::try_from(krb_cred.len()).ok()?;
    let key_size = u32::try_from(key.len()).ok()?;
    let key_offset = u32::try_from(SUBMIT_SIZE.checked_add(krb_cred.len())?).ok()?;
    let mut request = Builder::new(SUBMIT_SIZE, SUBMIT, 0);
    for (at, value) in [
        (16, key_type.to_le_bytes()),
        (20, key_size.to_le_bytes()),
        (24, key_offset.to_le_bytes()),
        (28, cred_size.to_le_bytes()),
        (32, 36_u32.to_le_bytes()),
    ] {
        put(&mut request.out, at, &value);
    }
    request.out.extend_from_slice(krb_cred);
    request.out.extend_from_slice(key);
    Some(request.out)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::{
        CacheInfo, POINTER, PURGE_EX_SIZE, PURGE_SIZE, RETRIEVE_SIZE, purge, purge_all,
        query_cache, retrieve, submit,
    };

    /// The fixed sizes equal the SDK's `sizeof` values.
    #[test]
    fn sizes_match_the_sdk() {
        // Given the 64-bit layout (Miri and the Windows CI job run x64).
        // When the sizes are compared with the SDK's sizeof values.
        // Then they agree.
        if POINTER == 8 {
            assert_eq!((RETRIEVE_SIZE, PURGE_SIZE, PURGE_EX_SIZE), (64, 48, 112));
        } else {
            assert_eq!((RETRIEVE_SIZE, PURGE_SIZE, PURGE_EX_SIZE), (40, 28, 80));
        }
    }

    /// Requests carry their message type and self-relative strings.
    #[test]
    fn request_layouts() -> Result<(), &'static str> {
        // Given a buffer address and a ticket identity.
        let base = 0x1000_u64;
        let template = CacheInfo {
            client_name: "u".to_owned(),
            client_realm: "R".to_owned(),
            server_name: "s/h".to_owned(),
            server_realm: "R".to_owned(),
            session_key_type: 18,
        };
        assert_eq!(template.target(), "s/h@R");
        assert_eq!(template.client_realm(), "R");
        assert!(
            template.is_for("R", &["s".to_owned(), "h".to_owned()]),
            "server match"
        );
        assert!(!template.is_for("R", &["s".to_owned()]), "other server");
        // When the requests are built.
        let retrieve = retrieve(base, "s@R");
        let purge = purge(base, &template);
        let submit = submit(&[0x76, 0], 18, &[1; 32]).ok_or("submit")?;
        // Then types, lengths and pointers sit where the SDK puts them.
        assert_eq!(query_cache(), [20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(purge_all().get(..4), Some(&[6, 0, 0, 0][..]));
        assert_eq!(retrieve.len(), RETRIEVE_SIZE + 6);
        assert_eq!(retrieve.get(..4), Some(&[8, 0, 0, 0][..]));
        if POINTER == 8 {
            assert_eq!(retrieve.get(16..20), Some(&[6, 0, 6, 0][..]));
            assert_eq!(retrieve.get(24..32), Some(&0x1040_u64.to_le_bytes()[..]));
            assert_eq!(retrieve.get(36..40), Some(&[2, 0, 0, 0][..]));
            assert_eq!(retrieve.get(64..), Some(&[b's', 0, b'@', 0, b'R', 0][..]));
            assert_eq!(purge.get(..4), Some(&[15, 0, 0, 0][..]));
            assert_eq!(purge.get(16..20), Some(&[2, 0, 2, 0][..]));
            assert_eq!(purge.get(24..32), Some(&0x1070_u64.to_le_bytes()[..]));
            assert_eq!(purge.get(104..108), Some(&[18, 0, 0, 0][..]));
            assert_eq!(purge.len(), 112 + 2 + 2 + 6 + 2);
        }
        assert_eq!(
            submit.get(..36),
            Some(
                &[
                    21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 32, 0, 0, 0, 38,
                    0, 0, 0, 2, 0, 0, 0, 36, 0, 0, 0
                ][..]
            )
        );
        assert_eq!(submit.get(36..38), Some(&[0x76, 0][..]));
        assert_eq!(submit.len(), 36 + 2 + 32);
        Ok(())
    }
}
