//! The shapes of KCM replies: which payload an opcode returns and how it
//! decodes.
//!
//! A [`Call`](super::calls::Call) carries its shape as a type, so that
//! decoding a reply gives the right Rust type without a function pointer.

use super::{Reply, Residual, Uuid, decode};
use crate::{
    ccache::{Credential, Principal},
    error::Kcm as Error,
};

/// How the payload of a reply decodes.
pub trait Shape: Send + Sync {
    /// What the payload decodes to.
    type Output;

    /// Decode `reply`.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedReply`] for a payload that is not this shape.
    fn decode(reply: &Reply) -> Result<Self::Output, Error>;
}

/// A cache name (`GEN_NEW`, `GET_DEFAULT_CACHE`, `GET_CACHE_BY_UUID`).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Name;

/// A list of UUIDs (`GET_CACHE_UUID_LIST`, `GET_CRED_UUID_LIST`).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Uuids;

/// A default principal, or none (`GET_PRINCIPAL`).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct DefaultPrincipal;

/// One credential (`GET_CRED_BY_UUID`).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct OneCredential;

/// A counted credential list (`GET_CRED_LIST`).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Credentials;

/// A KDC time offset, or none (`GET_KDC_OFFSET`).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct KdcOffset;

/// No payload.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Empty;

impl Shape for Name {
    type Output = Residual;

    #[inline]
    fn decode(reply: &Reply) -> Result<Residual, Error> {
        decode::name(reply)
    }
}

impl Shape for Uuids {
    type Output = Vec<Uuid>;

    #[inline]
    fn decode(reply: &Reply) -> Result<Vec<Uuid>, Error> {
        decode::uuids(reply)
    }
}

impl Shape for DefaultPrincipal {
    type Output = Option<Principal>;

    #[inline]
    fn decode(reply: &Reply) -> Result<Option<Principal>, Error> {
        decode::principal(reply)
    }
}

impl Shape for OneCredential {
    type Output = Credential;

    #[inline]
    fn decode(reply: &Reply) -> Result<Credential, Error> {
        decode::credential(reply)
    }
}

impl Shape for Credentials {
    type Output = Vec<Credential>;

    #[inline]
    fn decode(reply: &Reply) -> Result<Vec<Credential>, Error> {
        decode::credentials(reply)
    }
}

impl Shape for KdcOffset {
    type Output = Option<i32>;

    #[inline]
    fn decode(reply: &Reply) -> Result<Option<i32>, Error> {
        decode::kdc_offset(reply)
    }
}

impl Shape for Empty {
    type Output = ();

    #[inline]
    fn decode(reply: &Reply) -> Result<(), Error> {
        decode::unit(reply)
    }
}
