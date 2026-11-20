//! The requests of the KCM opcodes this client sends, each paired with the
//! decoder of its reply (`cc_kcm.c:164-180`, the `kcm_*` operations from
//! `cc_kcm.c:741-1340`).

use core::{fmt, marker::PhantomData};

use super::{
    Opcode, Request, Residual, Uuid,
    shape::{Credentials, DefaultPrincipal, Empty, KdcOffset, Name, OneCredential, Uuids},
};
use crate::{
    ccache::{CCache, Credential, Endian, Principal},
    error::Kcm as Error,
};

/// The version of the principal and credential encodings in KCM payloads.
const FILE_VERSION: u8 = 4;
/// The tag of the KDC time offset field of a version 4 cache header.
const KDC_OFFSET_TAG: u16 = 1;

/// A request and the shape of its reply.
pub struct Call<S> {
    /// The request.
    request: Request,
    /// The shape of the reply.
    shape: PhantomData<S>,
}

impl<S> Call<S> {
    /// The request to send.
    #[must_use]
    #[inline]
    pub const fn request(&self) -> &Request {
        &self.request
    }
}

impl<S> fmt::Debug for Call<S> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// A call from its request.
const fn call<S>(request: Request) -> Call<S> {
    Call {
        request,
        shape: PhantomData,
    }
}

/// A call whose request is an opcode and a name.
fn named<S>(opcode: Opcode, name: &Residual) -> Call<S> {
    let mut request = Request::new(opcode, name.as_str().len().saturating_add(1));
    request.put_name(name);
    call(request)
}

/// Append a principal in the version 4 encoding.
///
/// # Errors
///
/// [`Error::Unencodable`] when a length does not fit its field.
fn put_principal(request: &mut Request, principal: &Principal) -> Result<(), Error> {
    principal
        .write_to(request.buffer(), FILE_VERSION, Endian::Big)
        .map_err(|_encode| Error::Unencodable)
}

/// Append a credential in the version 4 encoding.
///
/// # Errors
///
/// [`Error::Unencodable`] when a length does not fit its field.
fn put_credential(request: &mut Request, credential: &Credential) -> Result<(), Error> {
    credential
        .write_to(request.buffer(), FILE_VERSION, Endian::Big)
        .map_err(|_encode| Error::Unencodable)
}

/// `GET_DEFAULT_CACHE`: the name of the primary cache (`get_primary_name`,
/// `cc_kcm.c:726-738`).
#[must_use]
#[inline]
pub fn get_default_cache() -> Call<Name> {
    call(Request::new(Opcode::GetDefaultCache, 0))
}

/// `SET_DEFAULT_CACHE`: make `name` the primary cache (`kcm_switch_to`,
/// `cc_kcm.c:1331-1340`).
#[must_use]
#[inline]
pub fn set_default_cache(name: &Residual) -> Call<Empty> {
    named(Opcode::SetDefaultCache, name)
}

/// `GEN_NEW`: the name of a new, uninitialized cache (`kcm_gen_new`,
/// `cc_kcm.c:796-822`).
#[must_use]
#[inline]
pub fn gen_new() -> Call<Name> {
    call(Request::new(Opcode::GenNew, 0))
}

/// `INITIALIZE`: empty the cache `name` and set its default principal
/// (`kcm_initialize`, `cc_kcm.c:825-836`).
///
/// # Errors
///
/// [`Error::Unencodable`] for a principal that does not fit the encoding.
#[inline]
pub fn initialize(name: &Residual, principal: &Principal) -> Result<Call<Empty>, Error> {
    let mut call = named(Opcode::Initialize, name);
    call.request.reserve(principal.encoded_len(FILE_VERSION));
    put_principal(&mut call.request, principal)?;
    Ok(call)
}

/// `DESTROY`: delete the cache `name` (`kcm_destroy`, `cc_kcm.c:852-862`).
#[must_use]
#[inline]
pub fn destroy(name: &Residual) -> Call<Empty> {
    named(Opcode::Destroy, name)
}

/// `STORE`: add a credential to the cache `name` (`kcm_store`,
/// `cc_kcm.c:865-875`).
///
/// # Errors
///
/// [`Error::Unencodable`] for a credential that does not fit the encoding.
#[inline]
pub fn store(name: &Residual, credential: &Credential) -> Result<Call<Empty>, Error> {
    let mut call = named(Opcode::Store, name);
    call.request.reserve(credential.encoded_len(FILE_VERSION));
    put_credential(&mut call.request, credential)?;
    Ok(call)
}

/// `GET_PRINCIPAL`: the default principal of the cache `name`; `None` when the
/// daemon answers with no principal (`kcm_get_princ`, `cc_kcm.c:933-955`).
#[must_use]
#[inline]
pub fn get_principal(name: &Residual) -> Call<DefaultPrincipal> {
    named(Opcode::GetPrincipal, name)
}

/// `GET_CRED_LIST` (MIT extension): every credential of the cache `name`
/// (`kcm_start_seq_get`, `cc_kcm.c:957-1005`).
#[must_use]
#[inline]
pub fn get_cred_list(name: &Residual) -> Call<Credentials> {
    named(Opcode::GetCredList, name)
}

/// `GET_CRED_UUID_LIST`: the credential UUIDs of the cache `name`, for
/// daemons without [`get_cred_list`] (`cc_kcm.c:985-995`).
#[must_use]
#[inline]
pub fn get_cred_uuid_list(name: &Residual) -> Call<Uuids> {
    named(Opcode::GetCredUuidList, name)
}

/// `GET_CRED_BY_UUID`: one credential of the cache `name` (`next_cred_by_uuid`,
/// `cc_kcm.c:1008-1028`).
#[must_use]
#[inline]
pub fn get_cred_by_uuid(name: &Residual, uuid: Uuid) -> Call<OneCredential> {
    let mut call = named(Opcode::GetCredByUuid, name);
    call.request.put_bytes(uuid.as_bytes());
    call
}

/// `GET_CACHE_UUID_LIST`: the UUIDs of the caches the daemon lets this user
/// see (`kcm_ptcursor_new`, `cc_kcm.c:1139-1195`).
#[must_use]
#[inline]
pub fn get_cache_uuid_list() -> Call<Uuids> {
    call(Request::new(Opcode::GetCacheUuidList, 0))
}

/// `GET_CACHE_BY_UUID`: the name of the cache with `uuid` (`kcm_ptcursor_next`,
/// `cc_kcm.c:1211-1264`).
#[must_use]
#[inline]
pub fn get_cache_by_uuid(uuid: Uuid) -> Call<Name> {
    let mut request = Request::new(Opcode::GetCacheByUuid, 16);
    request.put_bytes(uuid.as_bytes());
    call(request)
}

/// `GET_KDC_OFFSET`: the KDC time offset of the cache `name` in seconds
/// (`get_kdc_offset`, `cc_kcm.c:683-702`); `None` when the daemon keeps none.
#[must_use]
#[inline]
pub fn get_kdc_offset(name: &Residual) -> Call<KdcOffset> {
    named(Opcode::GetKdcOffset, name)
}

/// `SET_KDC_OFFSET`: set the KDC time offset of the cache `name` (`set_kdc_offset`,
/// `cc_kcm.c:705-715`).
#[must_use]
#[inline]
pub fn set_kdc_offset(name: &Residual, offset: i32) -> Call<Empty> {
    let mut call = named(Opcode::SetKdcOffset, name);
    call.request.put_bytes(&offset.to_be_bytes());
    call
}

/// The KDC time offset of a cache's version 4 header, 0 without one.
fn header_offset(cache: &CCache) -> i32 {
    cache
        .header()
        .fields
        .iter()
        .find(|field| field.tag == KDC_OFFSET_TAG)
        .and_then(|field| field.value.get(..4))
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map_or(0, i32::from_be_bytes)
}

/// `REPLACE` (MIT extension): replace the cache `name` with `cache` at once
/// (`kcm_replace`, `cc_kcm.c:1280-1314`).
///
/// # Errors
///
/// [`Error::Unencodable`] for a cache that does not fit the encoding.
#[inline]
pub fn replace(name: &Residual, cache: &CCache) -> Result<Call<Empty>, Error> {
    let mut call = named(Opcode::Replace, name);
    let body = cache.credentials().iter().fold(
        cache.default_principal().encoded_len(FILE_VERSION),
        |sum, credential| {
            sum.saturating_add(4)
                .saturating_add(credential.encoded_len(FILE_VERSION))
        },
    );
    call.request.reserve(body.saturating_add(8));
    call.request.put_bytes(&header_offset(cache).to_be_bytes());
    put_principal(&mut call.request, cache.default_principal())?;
    let count = u32::try_from(cache.credentials().len()).map_err(|_count| Error::Unencodable)?;
    call.request.put_u32(count);
    for credential in cache.credentials() {
        let start = call.request.buffer().len();
        call.request.put_u32(0);
        put_credential(&mut call.request, credential)?;
        let length = call
            .request
            .buffer()
            .len()
            .checked_sub(start.saturating_add(4))
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(Error::Unencodable)?;
        call.request
            .buffer()
            .get_mut(start..start.saturating_add(4))
            .ok_or(Error::Unencodable)?
            .copy_from_slice(&length.to_be_bytes());
    }
    Ok(call)
}
