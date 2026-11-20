//! CCAPI caches and the conversion of their credentials.
//!
//! The conversion follows MIT 1.22.2 `src/lib/krb5/ccache/ccapi_util.c`
//! (`k5_ccapi_to_krb5_creds`, `k5_krb5_to_ccapi_creds`).

use alloc::ffi::CString;
use core::{
    ffi::{CStr, c_char, c_void},
    mem::ManuallyDrop,
    ptr::{self, NonNull},
    slice,
};

use rskrb5_ng::ccache::{
    AuthorizationDataEntry, Credential, CredentialTimes, EncryptionKey, HostAddress, Principal,
};

use super::{
    CREDENTIALS_V5, Cache, CredentialsObject, CredentialsUnion, CredentialsV5, Data,
    IteratorFunctions, MAX_LIST, Owned, Release, check, failure, next, owned, take_string,
};
use crate::{Secret, error::Platform, principal_text};

/// The bytes of a `cc_data`.
/// # Errors
/// Returns [`Platform::Ccapi`] for a null pointer with a length.
fn data_bytes(value: Data) -> Result<Secret, Platform> {
    let length = usize::try_from(value.length).map_err(|_length| failure(-1))?;
    match NonNull::new(value.bytes.cast::<u8>()) {
        _ if length == 0 => Ok(Secret::from(Vec::new())),
        Some(pointer) => {
            // SAFETY: CCAPI owns `length` readable bytes at `data` for as
            // long as the credentials object they belong to is alive.
            #[expect(unsafe_code, reason = "reading CCAPI credential data")]
            let slice = unsafe { slice::from_raw_parts(pointer.as_ptr(), length) };
            Ok(Secret::from(slice.to_vec()))
        }
        None => Err(failure(-1)),
    }
}

/// Kinds and bytes of list entries.
type Entries = Vec<(u32, Secret)>;

/// The entries of a NULL-terminated `cc_data` list.
/// # Errors
/// Returns [`Platform::Ccapi`] for a list longer than [`MAX_LIST`].
fn data_list(list: *mut *mut Data) -> Result<Entries, Platform> {
    let mut out = Vec::new();
    if list.is_null() {
        return Ok(out);
    }
    for index in 0..MAX_LIST {
        let slot = list.wrapping_add(index);
        // SAFETY: the list is NULL-terminated and every slot before the
        // terminator is readable; the loop stops at the terminator.
        #[expect(unsafe_code, reason = "reading a CCAPI list")]
        let entry = unsafe { slot.read() };
        let Some(item) = NonNull::new(entry) else {
            return Ok(out);
        };
        // SAFETY: a non-null slot points to a live `cc_data`.
        #[expect(unsafe_code, reason = "reading a CCAPI list entry")]
        let value = unsafe { item.as_ptr().read_unaligned() };
        out.push((value.kind, data_bytes(value)?));
    }
    Err(failure(-1))
}

/// A principal from its CCAPI text.
/// # Errors
/// Returns [`Platform::Ccapi`] for a null or malformed name.
fn principal(text: *mut c_char) -> Result<Principal, Platform> {
    let pointer = NonNull::new(text).ok_or(failure(-1))?;
    // SAFETY: CCAPI principal texts are NUL-terminated and live as long as
    // their credentials object.
    #[expect(unsafe_code, reason = "reading a CCAPI string")]
    let value = unsafe { CStr::from_ptr(pointer.as_ptr()) };
    value
        .to_str()
        .ok()
        .and_then(principal_text::parse)
        .ok_or(failure(-1))
}

/// Convert CCAPI v5 credentials.
/// # Errors
/// Returns [`Platform::Ccapi`] for a field out of range.
fn convert(value: CredentialsV5) -> Result<Credential, Platform> {
    let key_type = i32::try_from(value.keyblock.kind).map_err(|_kind| failure(-1))?;
    let mut times = CredentialTimes::default();
    times.auth_time = value.authtime;
    times.start_time = value.starttime;
    times.end_time = value.endtime;
    times.renew_till = value.renew_till;
    let addresses = data_list(value.addresses)?
        .into_iter()
        .map(|(kind, bytes)| {
            let address_type = i16::try_from(kind).map_err(|_kind| failure(-1))?;
            Ok(HostAddress::new(address_type, bytes.to_vec()))
        })
        .collect::<Result<Vec<_>, Platform>>()?;
    let authdata = data_list(value.authdata)?
        .into_iter()
        .map(|(kind, bytes)| {
            let ad_type = i32::try_from(kind).map_err(|_kind| failure(-1))?;
            Ok(AuthorizationDataEntry::new(ad_type, bytes.to_vec().into()))
        })
        .collect::<Result<Vec<_>, Platform>>()?;
    Ok(Credential::new(
        principal(value.client)?,
        principal(value.server)?,
        EncryptionKey::new(key_type, data_bytes(value.keyblock)?.to_vec()),
        times,
        value.ticket_flags.to_be_bytes(),
        data_bytes(value.ticket)?.to_vec().into(),
    )
    .with_is_skey(value.is_skey != 0)
    .with_addresses(addresses)
    .with_auth_data(authdata)
    .with_second_ticket(data_bytes(value.second_ticket)?.to_vec().into()))
}

/// One `cc_credentials_t`, released on drop.
#[derive(Debug)]
pub(crate) struct Credentials(NonNull<CredentialsObject>);

impl Credentials {
    /// The converted credential.
    /// # Errors
    /// Returns [`Platform::Ccapi`] for malformed credentials.
    fn credential(&self) -> Result<Credential, Platform> {
        // SAFETY: the object is live; `data` is its first field.
        #[expect(unsafe_code, reason = "reading a CCAPI object")]
        let data = unsafe { (*self.0.as_ptr()).data };
        let wrapped = NonNull::new(data.cast_mut()).ok_or(failure(-1))?;
        // SAFETY: `data` points to the object's live credentials wrapped.
        #[expect(unsafe_code, reason = "reading CCAPI credentials")]
        let header = unsafe { wrapped.as_ptr().read_unaligned() };
        let v5 = NonNull::new(header.credentials_v5)
            .filter(|_| header.version == CREDENTIALS_V5)
            .ok_or(failure(-1))?;
        // SAFETY: a version-5 wrapped points to live v5 credentials.
        #[expect(unsafe_code, reason = "reading CCAPI credentials")]
        let value = unsafe { v5.as_ptr().read_unaligned() };
        convert(value)
    }
}

// Drop audit: one CCAPI release call; it never blocks on I/O and its result is ignored.
impl Drop for Credentials {
    fn drop(&mut self) {
        // SAFETY: the object is live; `functions` is its second field.
        #[expect(unsafe_code, reason = "reading a CCAPI object")]
        let functions = unsafe { (*self.0.as_ptr()).functions };
        // SAFETY: CCAPI function tables are static data of the framework.
        #[expect(unsafe_code, reason = "reading a CCAPI function table")]
        let release: Option<Release<CredentialsObject>> = unsafe { functions.as_ref() }.copied();
        if let Some(function) = release.flatten() {
            // SAFETY: the object is owned and released exactly once.
            #[expect(unsafe_code, reason = "FFI call")]
            let _ignored: i32 = unsafe { function(self.0.as_ptr()) };
        }
    }
}

/// The C form of one credential, alive while CCAPI copies it.
struct Outgoing {
    /// Client text.
    client: CString,
    /// Server text.
    server: CString,
    /// Key, ticket and second ticket bytes.
    bytes: [Secret; 3],
    /// Address and authorization-data entries.
    entries: [Vec<Data>; 2],
}

/// A `cc_data` that points into `bytes`.
/// # Errors
/// Returns [`Platform::Ccapi`] for more than 4 GiB.
fn data(kind: u32, bytes: &[u8]) -> Result<Data, Platform> {
    Ok(Data {
        kind,
        length: u32::try_from(bytes.len()).map_err(|_length| failure(-1))?,
        bytes: bytes.as_ptr().cast_mut().cast::<c_void>(),
    })
}

/// Store `credential` with `function` through its CCAPI wrapped
/// (`k5_krb5_to_ccapi_creds`).
/// # Errors
/// Returns [`Platform::Ccapi`] for a field out of range and `function`'s failure.
pub(crate) fn to_union<F>(credential: &Credential, function: F) -> Result<(), Platform>
where
    F: FnOnce(&CredentialsUnion) -> Result<(), Platform>,
{
    let text = |value| CString::new(principal_text::unparse(value)).map_err(|_nul| failure(-1));
    let outgoing = Outgoing {
        client: text(credential.client())?,
        server: text(credential.server())?,
        bytes: [
            Secret::from(credential.key().value().to_vec()),
            Secret::from(credential.ticket().clone()),
            Secret::from(credential.second_ticket().to_vec()),
        ],
        entries: [
            credential
                .addresses()
                .iter()
                .map(|address| {
                    data(
                        u32::try_from(address.addr_type).unwrap_or_default(),
                        &address.address,
                    )
                })
                .collect::<Result<_, _>>()?,
            credential
                .auth_data()
                .iter()
                .map(|entry| {
                    data(
                        u32::try_from(entry.ad_type()).unwrap_or_default(),
                        entry.data(),
                    )
                })
                .collect::<Result<_, _>>()?,
        ],
    };
    let [key, ticket, second] = &outgoing.bytes;
    let [addresses, authdata] = &outgoing.entries;
    let mut lists: [Vec<*mut Data>; 2] = [addresses, authdata].map(|entries| {
        entries
            .iter()
            .map(|entry| ptr::from_ref(entry).cast_mut())
            .chain([ptr::null_mut()])
            .collect()
    });
    let [address_list, authdata_list] = &mut lists;
    let mut v5 = CredentialsV5 {
        client: outgoing.client.as_ptr().cast_mut(),
        server: outgoing.server.as_ptr().cast_mut(),
        keyblock: data(
            u32::try_from(credential.key().etype()).map_err(|_etype| failure(-1))?,
            key,
        )?,
        authtime: credential.times().auth_time,
        starttime: credential.times().start_time,
        endtime: credential.times().end_time,
        renew_till: credential.times().renew_till,
        is_skey: u32::from(credential.is_skey()),
        ticket_flags: u32::from_be_bytes(credential.ticket_flags()),
        addresses: address_list.as_mut_ptr(),
        ticket: data(0, ticket)?,
        second_ticket: data(0, second)?,
        authdata: authdata_list.as_mut_ptr(),
    };
    let wrapped = CredentialsUnion {
        version: CREDENTIALS_V5,
        credentials_v5: &raw mut v5,
    };
    function(&wrapped)
}

impl Cache {
    /// The cache name (without the `API:` prefix).
    /// # Errors
    /// Returns the CCAPI failure.
    pub(crate) fn name(&self) -> Result<String, Platform> {
        let function = self.table()?.get_name.ok_or(failure(-1))?;
        let mut name = ptr::null_mut();
        // SAFETY: the cache is live and `name` a valid out pointer.
        #[expect(unsafe_code, reason = "FFI call")]
        let code = unsafe { function(self.raw(), &raw mut name) };
        check(code)?;
        take_string(name)
    }

    /// The default principal text.
    /// # Errors
    /// Returns the CCAPI failure.
    pub(crate) fn principal(&self) -> Result<Principal, Platform> {
        let function = self.table()?.get_principal.ok_or(failure(-1))?;
        let mut name = ptr::null_mut();
        // SAFETY: the cache is live and `name` a valid out pointer.
        #[expect(unsafe_code, reason = "FFI call")]
        let code = unsafe { function(self.raw(), CREDENTIALS_V5, &raw mut name) };
        check(code)?;
        principal_text::parse(&take_string(name)?).ok_or(failure(-1))
    }

    /// Make this the default cache.
    /// # Errors
    /// Returns the CCAPI failure.
    pub(crate) fn set_default(&self) -> Result<(), Platform> {
        let function = self.table()?.set_default.ok_or(failure(-1))?;
        // SAFETY: the cache is live.
        #[expect(unsafe_code, reason = "FFI call")]
        let code = unsafe { function(self.raw()) };
        check(code)
    }

    /// Destroy the cache; CCAPI releases the object itself.
    /// # Errors
    /// Returns the CCAPI failure.
    pub(crate) fn destroy(self) -> Result<(), Platform> {
        let function = self.table()?.destroy.ok_or(failure(-1))?;
        let object = ManuallyDrop::new(self);
        // SAFETY: the cache is live; `destroy` consumes it, so it is not
        // released again.
        #[expect(unsafe_code, reason = "FFI call")]
        let code = unsafe { function(object.raw()) };
        check(code)
    }

    /// Store one credential.
    /// # Errors
    /// Returns the CCAPI failure.
    pub(crate) fn store(&self, credential: &Credential) -> Result<(), Platform> {
        let function = self.table()?.store_credentials.ok_or(failure(-1))?;
        to_union(credential, |wrapped| {
            // SAFETY: the cache is live and `wrapped` with every buffer it
            // points to stays alive for the call; CCAPI copies them.
            #[expect(unsafe_code, reason = "FFI call")]
            let code = unsafe { function(self.raw(), ptr::from_ref(wrapped)) };
            check(code)
        })
    }

    /// Visit every credential; `keep` returns whether to keep it, and the
    /// others are removed. Returns the credentials kept and the count removed.
    /// # Errors
    /// Returns the CCAPI and conversion failures.
    pub(crate) fn credentials<F>(&self, mut keep: F) -> Result<(Vec<Credential>, usize), Platform>
    where
        F: FnMut(&Credential) -> bool,
    {
        let table = self.table()?;
        let start = table.new_credentials_iterator.ok_or(failure(-1))?;
        let mut raw = ptr::null_mut();
        // SAFETY: the cache is live and `raw` a valid out pointer.
        #[expect(unsafe_code, reason = "FFI call")]
        let code = unsafe { start(self.raw(), &raw mut raw) };
        check(code)?;
        let iterator: Owned<IteratorFunctions<CredentialsObject>> = owned(raw)?;
        let (mut kept, mut removed) = (Vec::new(), 0_usize);
        while let Some(item) = next(&iterator)? {
            let object = Credentials(NonNull::new(item).ok_or(failure(-1))?);
            let credential = object.credential()?;
            if keep(&credential) {
                kept.push(credential);
            } else {
                let remove = table.remove_credentials.ok_or(failure(-1))?;
                // SAFETY: the cache and the credentials object are live.
                #[expect(unsafe_code, reason = "FFI call")]
                let removed_code = unsafe { remove(self.raw(), object.0.as_ptr()) };
                check(removed_code)?;
                removed = removed.saturating_add(1);
            }
        }
        Ok((kept, removed))
    }
}
