//! The Kerberos.framework CCAPI version 3 interface.
//!
//! It is the API of `CredentialsCache.h` that MIT 1.22.2
//! `src/lib/krb5/ccache/cc_api_macos.c` uses, with owning wrappers that
//! release every object on drop.
//!
//! Objects are C structs whose first field points to a table of function
//! pointers; the tables are static in the framework. Only the prefixes of
//! the tables up to the last function used are declared. The structures
//! have natural alignment on arm64; on x86_64 the header packs them to 2.

use alloc::ffi::CString;
use core::{
    ffi::{CStr, c_char, c_void},
    ptr::{self, NonNull},
};

use crate::error::Platform;

/// `cc_int32` results.
type Code = i32;
/// `ccapi_version_3`: the oldest API with every function used here.
const API_VERSION: i32 = 3;
/// `cc_credentials_v5`.
pub(crate) const CREDENTIALS_V5: u32 = 2;
/// `ccIteratorEnd`.
const ITERATOR_END: Code = 201;
/// `ccErrCCacheNotFound`.
pub(crate) const CACHE_NOT_FOUND: Code = 224;
/// The most entries of an address or authorization-data list.
const MAX_LIST: usize = 1024;

/// `cc_data`.
#[repr(C)]
#[cfg_attr(target_arch = "x86_64", repr(packed(2)))]
#[derive(Clone, Copy, Debug)]
struct Data {
    /// The enctype, address type or authorization-data type.
    kind: u32,
    /// The length of `data`.
    length: u32,
    /// The bytes.
    bytes: *mut c_void,
}

/// `cc_credentials_v5_t`.
#[repr(C)]
#[cfg_attr(target_arch = "x86_64", repr(packed(2)))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CredentialsV5 {
    /// The client principal text.
    client: *mut c_char,
    /// The server principal text.
    server: *mut c_char,
    /// The session key.
    keyblock: Data,
    /// `authtime`.
    authtime: u32,
    /// `starttime`.
    starttime: u32,
    /// `endtime`.
    endtime: u32,
    /// `renew_till`.
    renew_till: u32,
    /// `is_skey`.
    is_skey: u32,
    /// `ticket_flags`.
    ticket_flags: u32,
    /// A NULL-terminated list of addresses.
    addresses: *mut *mut Data,
    /// The ticket.
    ticket: Data,
    /// The second ticket.
    second_ticket: Data,
    /// A NULL-terminated list of authorization data.
    authdata: *mut *mut Data,
}

/// `cc_credentials_union`.
#[repr(C)]
#[cfg_attr(target_arch = "x86_64", repr(packed(2)))]
#[derive(Debug)]
pub(crate) struct CredentialsUnion {
    /// `cc_credentials_v5`.
    version: u32,
    /// The v5 credentials.
    credentials_v5: *mut CredentialsV5,
}

/// An opaque function slot this crate does not call.
type Unused = Option<unsafe extern "C" fn()>;
/// A `release` function.
pub(crate) type Release<D> = Option<unsafe extern "C" fn(*mut D) -> Code>;

/// `cc_context_f`, up to `new_ccache_iterator`.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct ContextFunctions {
    /// `release`.
    release: Release<ContextObject>,
    /// `get_change_time`.
    get_change_time: Unused,
    /// `get_default_ccache_name`.
    get_default_ccache_name:
        Option<unsafe extern "C" fn(*mut ContextObject, *mut *mut StringObject) -> Code>,
    /// `open_ccache`.
    open_ccache: Option<
        unsafe extern "C" fn(*mut ContextObject, *const c_char, *mut *mut CacheObject) -> Code,
    >,
    /// `open_default_ccache`.
    open_default_ccache: Unused,
    /// `create_ccache`.
    create_ccache: Option<
        unsafe extern "C" fn(
            *mut ContextObject,
            *const c_char,
            u32,
            *const c_char,
            *mut *mut CacheObject,
        ) -> Code,
    >,
    /// `create_default_ccache`.
    create_default_ccache: Unused,
    /// `create_new_ccache`.
    create_new_ccache: Option<
        unsafe extern "C" fn(*mut ContextObject, u32, *const c_char, *mut *mut CacheObject) -> Code,
    >,
    /// `new_ccache_iterator`.
    new_ccache_iterator: Option<
        unsafe extern "C" fn(*mut ContextObject, *mut *mut IteratorObject<CacheObject>) -> Code,
    >,
}

/// `cc_ccache_f`, up to `new_credentials_iterator`.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct CacheFunctions {
    /// `release`.
    release: Release<CacheObject>,
    /// `destroy`.
    destroy: Release<CacheObject>,
    /// `set_default`.
    set_default: Release<CacheObject>,
    /// `get_credentials_version`.
    get_credentials_version: Unused,
    /// `get_name`.
    get_name: Option<unsafe extern "C" fn(*mut CacheObject, *mut *mut StringObject) -> Code>,
    /// `get_principal`.
    get_principal:
        Option<unsafe extern "C" fn(*mut CacheObject, u32, *mut *mut StringObject) -> Code>,
    /// `set_principal`.
    set_principal: Unused,
    /// `store_credentials`.
    store_credentials:
        Option<unsafe extern "C" fn(*mut CacheObject, *const CredentialsUnion) -> Code>,
    /// `remove_credentials`.
    remove_credentials:
        Option<unsafe extern "C" fn(*mut CacheObject, *mut CredentialsObject) -> Code>,
    /// `new_credentials_iterator`.
    new_credentials_iterator: Option<
        unsafe extern "C" fn(*mut CacheObject, *mut *mut IteratorObject<CredentialsObject>) -> Code,
    >,
}

/// `cc_*_iterator_f`.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct IteratorFunctions<T> {
    /// `release`.
    release: Release<IteratorObject<T>>,
    /// `next`.
    next: Option<unsafe extern "C" fn(*mut IteratorObject<T>, *mut *mut T) -> Code>,
}

/// A CCAPI object: its function table, then the vector table on macOS.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct Object<F> {
    /// The function table.
    functions: *const F,
    /// The vector function table (unused).
    vector_functions: *const F,
}

/// `cc_context_d`.
pub(crate) type ContextObject = Object<ContextFunctions>;
/// `cc_ccache_d`.
pub(crate) type CacheObject = Object<CacheFunctions>;
/// `cc_*_iterator_d`.
pub(crate) type IteratorObject<T> = Object<IteratorFunctions<T>>;

/// `cc_string_d`.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct StringObject {
    /// The text.
    data: *const c_char,
    /// The function table: only `release`.
    functions: *const Release<Self>,
}

/// `cc_credentials_d`.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct CredentialsObject {
    /// The credentials.
    data: *const CredentialsUnion,
    /// The function table: `release` first.
    functions: *const Release<Self>,
}

// `cc_initialize` is the exported CCAPI entry point of Kerberos.framework,
// declared with the signature of `CredentialsCache.h`.
#[expect(unsafe_code, reason = "the CCAPI FFI declaration")]
#[link(name = "Kerberos", kind = "framework")]
unsafe extern "C" {
    fn cc_initialize(
        out_context: *mut *mut ContextObject,
        in_version: i32,
        out_supported_version: *mut i32,
        out_vendor: *mut *const c_char,
    ) -> Code;
}

/// A CCAPI failure.
pub(crate) const fn failure(code: Code) -> Platform {
    Platform::Ccapi { code }
}

/// Map a CCAPI result.
/// # Errors
/// Returns [`Platform::Ccapi`] for a nonzero code.
pub(crate) const fn check(code: Code) -> Result<(), Platform> {
    if code == 0 {
        Ok(())
    } else {
        Err(failure(code))
    }
}

/// An owned CCAPI object whose table starts with `release`; released on drop.
#[derive(Debug)]
pub(crate) struct Owned<F>(NonNull<Object<F>>);

/// Wrap a newly returned object.
/// # Errors
/// Returns [`Platform::Ccapi`] for a null pointer.
fn owned<F>(raw: *mut Object<F>) -> Result<Owned<F>, Platform> {
    NonNull::new(raw).map(Owned).ok_or(failure(-1))
}

impl<F> Owned<F> {
    /// The raw pointer, for calls.
    pub(crate) const fn raw(&self) -> *mut Object<F> {
        self.0.as_ptr()
    }

    /// The function table.
    /// # Errors
    /// Returns [`Platform::Ccapi`] for a null table.
    pub(crate) fn table(&self) -> Result<&F, Platform> {
        // SAFETY: the object is live; its first field is the table pointer.
        #[expect(unsafe_code, reason = "reading a CCAPI object")]
        let functions = unsafe { (*self.0.as_ptr()).functions };
        // SAFETY: CCAPI function tables are static data of the framework.
        #[expect(unsafe_code, reason = "reading a CCAPI function table")]
        let table = unsafe { functions.as_ref() };
        table.ok_or(failure(-1))
    }
}

// Drop audit: one CCAPI release call; it never blocks on I/O and its result is ignored.
impl<F> Drop for Owned<F> {
    fn drop(&mut self) {
        let Ok(table) = self.table() else {
            return;
        };
        let slot = ptr::from_ref(table).cast::<Release<Object<F>>>();
        // SAFETY: every table this type wraps is `#[repr(C)]` with the
        // `release` slot as its first field, at offset 0.
        #[expect(unsafe_code, reason = "reading the release slot")]
        let release = unsafe { slot.read() };
        if let Some(function) = release {
            // SAFETY: the object is owned and released exactly once here.
            #[expect(unsafe_code, reason = "FFI call")]
            let _ignored: Code = unsafe { function(self.0.as_ptr()) };
        }
    }
}

/// A CCAPI context.
pub(crate) type Context = Owned<ContextFunctions>;
/// A CCAPI cache.
pub(crate) type Cache = Owned<CacheFunctions>;

/// Open the CCAPI context.
/// # Errors
/// Returns the `cc_initialize` failure.
pub(crate) fn context() -> Result<Context, Platform> {
    let mut raw = ptr::null_mut();
    // SAFETY: `raw` is a valid out pointer; the version and vendor outputs
    // are optional and passed as null.
    #[expect(unsafe_code, reason = "FFI call")]
    let code =
        unsafe { cc_initialize(&raw mut raw, API_VERSION, ptr::null_mut(), ptr::null_mut()) };
    check(code)?;
    owned(raw)
}

/// Take the text of a returned `cc_string_t` and release it.
/// # Errors
/// Returns [`Platform::Ccapi`] for a null or non-UTF-8 string.
pub(crate) fn take_string(raw: *mut StringObject) -> Result<String, Platform> {
    let object = NonNull::new(raw).ok_or(failure(-1))?;
    // SAFETY: `object` is a live `cc_string_d`.
    #[expect(unsafe_code, reason = "reading a CCAPI string")]
    let data = unsafe { (*object.as_ptr()).data };
    let text = NonNull::new(data.cast_mut()).map(|pointer| {
        // SAFETY: `data` is NUL-terminated text that lives until the string
        // is released below.
        #[expect(unsafe_code, reason = "reading a CCAPI string")]
        let value = unsafe { CStr::from_ptr(pointer.as_ptr()) };
        value.to_str().map(str::to_owned)
    });
    // SAFETY: `object` is a live `cc_string_d`.
    #[expect(unsafe_code, reason = "reading a CCAPI string")]
    let functions = unsafe { (*object.as_ptr()).functions };
    // SAFETY: the table of a live string is static data of the framework.
    #[expect(unsafe_code, reason = "reading a CCAPI function table")]
    let release = unsafe { functions.as_ref() }.copied().flatten();
    if let Some(function) = release {
        // SAFETY: the string is owned and released exactly once.
        #[expect(unsafe_code, reason = "FFI call")]
        let _ignored: Code = unsafe { function(object.as_ptr()) };
    }
    text.and_then(Result::ok).ok_or(failure(-1))
}

impl Context {
    /// The default (primary) cache name.
    /// # Errors
    /// Returns the CCAPI failure.
    pub(crate) fn default_name(&self) -> Result<String, Platform> {
        let function = self.table()?.get_default_ccache_name.ok_or(failure(-1))?;
        let mut name = ptr::null_mut();
        // SAFETY: the context is live and `name` a valid out pointer.
        #[expect(unsafe_code, reason = "FFI call")]
        let code = unsafe { function(self.raw(), &raw mut name) };
        check(code)?;
        take_string(name)
    }

    /// Open the cache `name`.
    /// # Errors
    /// Returns the CCAPI failure, [`CACHE_NOT_FOUND`] for a missing cache.
    pub(crate) fn open(&self, name: &str) -> Result<Cache, Platform> {
        let function = self.table()?.open_ccache.ok_or(failure(-1))?;
        let text = CString::new(name).map_err(|_nul| failure(-1))?;
        let mut cache = ptr::null_mut();
        // SAFETY: the context is live, `text` NUL-terminated and alive for
        // the call, and `cache` a valid out pointer.
        #[expect(unsafe_code, reason = "FFI call")]
        let code = unsafe { function(self.raw(), text.as_ptr(), &raw mut cache) };
        check(code)?;
        owned(cache)
    }

    /// Create (or empty) the cache `name` with default principal `principal`.
    /// # Errors
    /// Returns the CCAPI failure.
    pub(crate) fn create(&self, name: &str, principal: &str) -> Result<Cache, Platform> {
        let function = self.table()?.create_ccache.ok_or(failure(-1))?;
        let text = CString::new(name).map_err(|_nul| failure(-1))?;
        let owner = CString::new(principal).map_err(|_nul| failure(-1))?;
        let mut cache = ptr::null_mut();
        // SAFETY: the context is live, both strings NUL-terminated and alive
        // for the call, and `cache` a valid out pointer.
        #[expect(unsafe_code, reason = "FFI call")]
        let code = unsafe {
            function(
                self.raw(),
                text.as_ptr(),
                CREDENTIALS_V5,
                owner.as_ptr(),
                &raw mut cache,
            )
        };
        check(code)?;
        owned(cache)
    }

    /// Create a cache with a unique name (`api_macos_gen_new`).
    /// # Errors
    /// Returns the CCAPI failure.
    pub(crate) fn create_new(&self) -> Result<Cache, Platform> {
        let function = self.table()?.create_new_ccache.ok_or(failure(-1))?;
        let mut cache = ptr::null_mut();
        // SAFETY: the context is live, the principal is the empty string as
        // MIT passes it, and `cache` a valid out pointer.
        #[expect(unsafe_code, reason = "FFI call")]
        let code = unsafe { function(self.raw(), CREDENTIALS_V5, c"".as_ptr(), &raw mut cache) };
        check(code)?;
        owned(cache)
    }

    /// The names of every cache.
    /// # Errors
    /// Returns the CCAPI failure.
    pub(crate) fn names(&self) -> Result<Vec<String>, Platform> {
        let function = self.table()?.new_ccache_iterator.ok_or(failure(-1))?;
        let mut raw = ptr::null_mut();
        // SAFETY: the context is live and `raw` a valid out pointer.
        #[expect(unsafe_code, reason = "FFI call")]
        let code = unsafe { function(self.raw(), &raw mut raw) };
        check(code)?;
        let iterator: Owned<IteratorFunctions<CacheObject>> = owned(raw)?;
        let mut names = Vec::new();
        while let Some(cache) = next(&iterator)? {
            let opened: Cache = owned(cache)?;
            names.push(opened.name()?);
        }
        Ok(names)
    }
}

/// The next element of an iterator, or `None` at its end.
/// # Errors
/// Returns the CCAPI failure.
pub(crate) fn next<T>(iterator: &Owned<IteratorFunctions<T>>) -> Result<Option<*mut T>, Platform> {
    let function = iterator.table()?.next.ok_or(failure(-1))?;
    let mut item = ptr::null_mut();
    // SAFETY: the iterator is live and `item` a valid out pointer.
    #[expect(unsafe_code, reason = "FFI call")]
    let code = unsafe { function(iterator.raw(), &raw mut item) };
    match code {
        0 => Ok(Some(item)),
        ITERATOR_END => Ok(None),
        other => Err(failure(other)),
    }
}

/// Caches and their credentials.
pub(crate) mod cache;
