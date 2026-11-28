//! Parsing of the response buffers of the Kerberos package.
//!
//! The structures are those of `NTSecAPI.h`; credentials are converted as
//! MIT 1.22.2 `src/lib/krb5/ccache/cc_mslsa.c` `MSCredToMITCred` (:318-349)
//! does.
//!
//! The package returns one buffer whose embedded pointers point into
//! itself. Every pointer is translated to an offset in that buffer and
//! bounds-checked; one that points elsewhere is a malformed reply, so a
//! parse never reads memory outside the buffer.

use rskrb5_ng::ccache::{Credential, CredentialTimes, EncryptionKey, Principal};

use super::{CacheInfo, POINTER, USTRING, align};
use crate::{Secret, error::Platform};

/// The size of `KERB_TICKET_CACHE_INFO_EX2`.
const INFO_SIZE: usize = 4 * USTRING + 24 + 16;
/// The most tickets or name components a reply may list.
const MAX_ITEMS: usize = 1024;
/// Seconds between 1601-01-01 and 1970-01-01 (`FileTimeToUnixTime`).
const EPOCH_DELTA: i64 = 11_644_473_600;
/// FILETIME ticks per second.
const TICKS: i64 = 10_000_000;

/// A malformed-reply failure.
const fn malformed(reason: &'static str) -> Platform {
    Platform::MalformedReply {
        cache_type: "MSLSA",
        reason,
    }
}

/// A response buffer and the address it was returned at.
#[derive(Clone, Copy, Debug)]
pub(crate) struct View<'buffer> {
    /// The bytes.
    bytes: &'buffer [u8],
    /// The address of the first byte.
    base: u64,
}

impl<'buffer> View<'buffer> {
    /// The buffer `bytes` the system returned at address `base`.
    pub(crate) const fn new(bytes: &'buffer [u8], base: u64) -> Self {
        Self { bytes, base }
    }

    /// `length` bytes at offset `at`.
    /// # Errors
    /// Returns [`Platform::MalformedReply`] outside the buffer or for a bad shape.
    fn at(self, at: usize, length: usize) -> Result<&'buffer [u8], Platform> {
        self.bytes
            .get(at..at.saturating_add(length))
            .ok_or_else(|| malformed("field outside the buffer"))
    }

    /// An `N`-byte little-endian field at `at`.
    /// # Errors
    /// Returns [`Platform::MalformedReply`] outside the buffer or for a bad shape.
    fn array<const N: usize>(self, at: usize) -> Result<[u8; N], Platform> {
        <[u8; N]>::try_from(self.at(at, N)?).map_err(|_size| malformed("field size"))
    }

    /// A 32-bit field.
    /// # Errors
    /// Returns [`Platform::MalformedReply`] outside the buffer or for a bad shape.
    fn u32(self, at: usize) -> Result<u32, Platform> {
        self.array::<4>(at).map(u32::from_le_bytes)
    }

    /// A `LARGE_INTEGER` field.
    /// # Errors
    /// Returns [`Platform::MalformedReply`] outside the buffer or for a bad shape.
    fn i64(self, at: usize) -> Result<i64, Platform> {
        self.array::<8>(at).map(i64::from_le_bytes)
    }

    /// The buffer offset a pointer field at `at` holds, or `None` for null.
    /// # Errors
    /// Returns [`Platform::MalformedReply`] outside the buffer or for a bad shape.
    fn pointer(self, at: usize) -> Result<Option<usize>, Platform> {
        let mut raw = [0_u8; 8];
        raw.get_mut(..POINTER)
            .ok_or_else(|| malformed("pointer width"))?
            .copy_from_slice(self.at(at, POINTER)?);
        match u64::from_le_bytes(raw) {
            0 => Ok(None),
            address => address
                .checked_sub(self.base)
                .and_then(|offset| usize::try_from(offset).ok())
                .map(Some)
                .ok_or_else(|| malformed("pointer outside the buffer")),
        }
    }

    /// `length` bytes a pointer field at `at` points to.
    /// # Errors
    /// Returns [`Platform::MalformedReply`] outside the buffer or for a bad shape.
    fn pointed(self, at: usize, length: usize) -> Result<&'buffer [u8], Platform> {
        match self.pointer(at)? {
            Some(offset) => self.at(offset, length),
            None if length == 0 => Ok(&[]),
            None => Err(malformed("null pointer with a length")),
        }
    }

    /// The `UNICODE_STRING` at `at`.
    /// # Errors
    /// Returns [`Platform::MalformedReply`] outside the buffer or for a bad shape.
    fn string(self, at: usize) -> Result<String, Platform> {
        let length = usize::from(u16::from_le_bytes(self.array::<2>(at)?));
        let bytes = self.pointed(at.saturating_add(align(4, POINTER)), length)?;
        let (units, odd) = bytes.as_chunks::<2>();
        if !odd.is_empty() {
            return Err(malformed("odd UTF-16 length"));
        }
        String::from_utf16(
            &units
                .iter()
                .map(|unit| u16::from_le_bytes(*unit))
                .collect::<Vec<_>>(),
        )
        .map_err(|_utf16| malformed("name is not UTF-16"))
    }

    /// The `KERB_EXTERNAL_NAME` a pointer at `at` points to, in `realm`.
    /// # Errors
    /// Returns [`Platform::MalformedReply`] outside the buffer or for a bad shape.
    fn name(self, at: usize, realm: &str) -> Result<Principal, Platform> {
        let offset = self.pointer(at)?.ok_or_else(|| malformed("null name"))?;
        let name_type = i16::from_le_bytes(self.array::<2>(offset)?);
        let count = usize::from(u16::from_le_bytes(
            self.array::<2>(offset.saturating_add(2))?,
        ));
        if count == 0 || count > MAX_ITEMS {
            return Err(malformed("name component count"));
        }
        let first = offset.saturating_add(align(4, POINTER));
        let components = (0..count)
            .map(|index| self.string(first.saturating_add(index.saturating_mul(USTRING))))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Principal::new(realm, i32::from(name_type), components))
    }
}

/// The entries of a `KERB_QUERY_TKT_CACHE_EX2_RESPONSE`.
/// # Errors
/// Returns [`Platform::MalformedReply`] for a buffer the count does not fit.
pub(crate) fn cache_entries(view: View<'_>) -> Result<Vec<CacheInfo>, Platform> {
    let count = usize::try_from(view.u32(4)?).map_err(|_count| malformed("ticket count"))?;
    if count > MAX_ITEMS {
        return Err(malformed("ticket count"));
    }
    let first = align(8, POINTER);
    (0..count)
        .map(|index| {
            let at = first.saturating_add(index.saturating_mul(INFO_SIZE));
            let key = view.u32(at.saturating_add(4 * USTRING + 32))?;
            Ok(CacheInfo {
                client_name: view.string(at)?,
                client_realm: view.string(at.saturating_add(USTRING))?,
                server_name: view.string(at.saturating_add(2 * USTRING))?,
                server_realm: view.string(at.saturating_add(3 * USTRING))?,
                session_key_type: i32::from_le_bytes(key.to_le_bytes()),
            })
        })
        .collect()
}

/// A FILETIME as a ccache time: seconds since 1970, saturated to 32 bits.
fn unix_time(filetime: i64) -> u32 {
    let seconds = filetime.div_euclid(TICKS).saturating_sub(EPOCH_DELTA);
    u32::try_from(seconds.max(0)).unwrap_or(u32::MAX)
}

/// Convert the `KERB_EXTERNAL_TICKET` of a `KERB_RETRIEVE_TKT_RESPONSE` to a
/// credential of `client_realm`. Returns `None` for a null session key,
/// which MIT skips (`IsMSSessionKeyNull`, `cc_mslsa.c:275-289`).
/// # Errors
/// Returns [`Platform::MalformedReply`] for a malformed ticket.
pub(crate) fn credential(
    view: View<'_>,
    client_realm: &str,
) -> Result<Option<Credential>, Platform> {
    let strings = 3 * POINTER;
    let key_at = strings.saturating_add(3 * USTRING);
    let flags_at = key_at.saturating_add(align(8 + POINTER, POINTER));
    let times_at = align(flags_at.saturating_add(8), 8);
    let size_at = times_at.saturating_add(40);
    let server_realm = view.string(strings)?;
    let key_type = i32::from_le_bytes(view.u32(key_at)?.to_le_bytes());
    let key_length = usize::try_from(view.u32(key_at.saturating_add(4))?)
        .map_err(|_length| malformed("key length"))?;
    let key = Secret::from(view.pointed(key_at.saturating_add(8), key_length)?.to_vec());
    if key_type == 0_i32 || key.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    let ticket_length =
        usize::try_from(view.u32(size_at)?).map_err(|_length| malformed("ticket length"))?;
    let ticket = view
        .pointed(align(size_at.saturating_add(4), POINTER), ticket_length)?
        .to_vec();
    let mut times = CredentialTimes::default();
    times.start_time = unix_time(view.i64(times_at.saturating_add(8))?);
    times.end_time = unix_time(view.i64(times_at.saturating_add(16))?);
    times.renew_till = unix_time(view.i64(times_at.saturating_add(24))?);
    Ok(Some(Credential::new(
        view.name(2 * POINTER, client_realm)?,
        view.name(0, &server_realm)?,
        EncryptionKey::new(key_type, key.to_vec()),
        times,
        view.u32(flags_at)?.to_be_bytes(),
        ticket.into(),
    )))
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::{CacheInfo, POINTER, Platform, USTRING, View, align, cache_entries, credential};

    /// The address the synthetic buffers claim.
    const BASE: u64 = 0x7f00_0000;
    /// The offset of the session key in `KERB_EXTERNAL_TICKET`.
    const KEY_AT: usize = 3 * POINTER + 3 * USTRING;
    /// The offset of the ticket flags.
    const FLAGS_AT: usize = KEY_AT + align(8 + POINTER, POINTER);
    /// The offset of the times.
    const TIMES_AT: usize = align(FLAGS_AT + 8, 8);
    /// The size of `KERB_EXTERNAL_TICKET`.
    const TICKET_SIZE: usize = align(TIMES_AT + 44, POINTER) + POINTER;

    /// A response buffer under construction.
    struct Buffer(Vec<u8>);

    impl Buffer {
        /// Write `bytes` at `at`, growing the buffer.
        fn put(&mut self, at: usize, bytes: &[u8]) {
            let end = at.saturating_add(bytes.len());
            if self.0.len() < end {
                self.0.resize(end, 0);
            }
            if let Some(target) = self.0.get_mut(at..end) {
                target.copy_from_slice(bytes);
            }
        }

        /// Write a pointer to `offset` at `at`.
        fn pointer(&mut self, at: usize, offset: usize) {
            let address = BASE.saturating_add(u64::try_from(offset).unwrap_or_default());
            self.put(at, address.to_le_bytes().get(..POINTER).unwrap_or_default());
        }

        /// Append `bytes` and return their offset.
        fn data(&mut self, bytes: &[u8]) -> usize {
            let at = self.0.len();
            self.0.extend_from_slice(bytes);
            at
        }

        /// Write a `UNICODE_STRING` of `text` at `at`.
        fn string(&mut self, at: usize, text: &str) {
            let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let length = u16::try_from(units.len()).unwrap_or_default().to_le_bytes();
            self.put(at, &length);
            self.put(at.saturating_add(2), &length);
            let offset = self.data(&units);
            self.pointer(at.saturating_add(align(4, POINTER)), offset);
        }

        /// Append a `KERB_EXTERNAL_NAME` and return its offset.
        fn name(&mut self, name_type: i16, components: &[&str]) -> usize {
            let at = self.0.len();
            let first = at.saturating_add(align(4, POINTER));
            let count = u16::try_from(components.len()).unwrap_or_default();
            self.put(at, &name_type.to_le_bytes());
            self.put(at.saturating_add(2), &count.to_le_bytes());
            let slots = components.len().saturating_mul(USTRING);
            self.put(first, &vec![0; slots]);
            for (index, component) in components.iter().enumerate() {
                self.string(
                    first.saturating_add(index.saturating_mul(USTRING)),
                    component,
                );
            }
            at
        }
    }

    /// A `KERB_EXTERNAL_TICKET` for `HTTP/web@R`, client `alice`, with `key`.
    fn ticket(key: &[u8]) -> Buffer {
        let mut buffer = Buffer(vec![0; TICKET_SIZE]);
        let service = buffer.name(2, &["HTTP", "web"]);
        buffer.pointer(0, service);
        let client = buffer.name(1, &["alice"]);
        buffer.pointer(2 * POINTER, client);
        buffer.string(3 * POINTER, "R");
        buffer.put(KEY_AT, &18_i32.to_le_bytes());
        let key_length = u32::try_from(key.len()).unwrap_or_default();
        buffer.put(KEY_AT + 4, &key_length.to_le_bytes());
        let key_data = buffer.data(key);
        buffer.pointer(KEY_AT + 8, key_data);
        buffer.put(FLAGS_AT, &0x40e1_0000_u32.to_le_bytes());
        for (slot, seconds) in [(8_usize, 1000_i64), (16, 1001), (24, 1002)] {
            let ticks = seconds
                .saturating_add(11_644_473_600)
                .saturating_mul(10_000_000);
            buffer.put(TIMES_AT.saturating_add(slot), &ticks.to_le_bytes());
        }
        buffer.put(TIMES_AT + 40, &3_u32.to_le_bytes());
        let encoded = buffer.data(&[0x61, 1, 0]);
        buffer.pointer(align(TIMES_AT + 44, POINTER), encoded);
        buffer
    }

    /// A retrieved ticket converts as `MSCredToMITCred` of MIT does.
    #[test]
    fn external_ticket_converts() -> Result<(), Platform> {
        // Given a retrieved ticket with a session key.
        let buffer = ticket(&[5; 32]);
        // When it is converted for the client realm R.
        let value =
            credential(View::new(&buffer.0, BASE), "R")?.ok_or(Platform::MalformedReply {
                cache_type: "MSLSA",
                reason: "no credential",
            })?;
        // Then names, realms, key, times, flags and ticket are carried over.
        assert_eq!(value.client().components, ["alice"]);
        assert_eq!(value.server().components, ["HTTP", "web"]);
        assert_eq!(
            (value.server().realm.as_str(), value.server().name_type),
            ("R", 2_i32)
        );
        assert_eq!(value.key().etype(), 18_i32);
        assert_eq!(
            (
                value.times().start_time,
                value.times().end_time,
                value.times().renew_till
            ),
            (1000, 1001, 1002)
        );
        assert_eq!(value.ticket_flags(), [0x40, 0xe1, 0, 0]);
        assert_eq!(value.ticket().as_slice(), [0x61, 1, 0]);
        Ok(())
    }

    /// Null keys are skipped; stray pointers and truncation are refused.
    #[test]
    fn null_keys_and_stray_pointers() -> Result<(), Platform> {
        // Given a ticket with an all-zero key, one with a stray pointer and a truncated one.
        let empty = ticket(&[0; 16]);
        let mut stray = ticket(&[5; 32]);
        stray.put(0, &BASE.saturating_sub(8).to_le_bytes());
        let whole = ticket(&[5; 32]);
        let truncated = whole.0.get(..20).unwrap_or_default();
        // When they are converted.
        // Then the first is skipped and the others refused.
        assert!(
            credential(View::new(&empty.0, BASE), "R")?.is_none(),
            "null key"
        );
        assert!(
            credential(View::new(&stray.0, BASE), "R").is_err(),
            "stray pointer"
        );
        assert!(
            credential(View::new(truncated, BASE), "R").is_err(),
            "truncated"
        );
        Ok(())
    }

    /// The query response lists its entries; an oversized count is refused.
    #[test]
    fn cache_query_entries() -> Result<(), Platform> {
        // Given a query response with one entry.
        let mut buffer = Buffer(vec![0; 8 + 4 * USTRING + 40]);
        buffer.put(0, &20_u32.to_le_bytes());
        buffer.put(4, &1_u32.to_le_bytes());
        for (index, text) in ["alice", "R", "krbtgt/R", "R"].iter().enumerate() {
            buffer.string(index.saturating_mul(USTRING).saturating_add(8), text);
        }
        buffer.put(8 + 4 * USTRING + 32, &18_u32.to_le_bytes());
        // When it is parsed, and again with a count beyond the buffer.
        let entries = cache_entries(View::new(&buffer.0, BASE))?;
        buffer.put(4, &1000_u32.to_le_bytes());
        // Then the entry is read and the overrun refused.
        let expected = CacheInfo {
            client_name: "alice".to_owned(),
            client_realm: "R".to_owned(),
            server_name: "krbtgt/R".to_owned(),
            server_realm: "R".to_owned(),
            session_key_type: 18,
        };
        assert_eq!(entries, [expected]);
        assert!(
            cache_entries(View::new(&buffer.0, BASE)).is_err(),
            "overrun"
        );
        Ok(())
    }
}
