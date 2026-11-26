//! The conversions into the IAKERB error that `?` applies to the exchange,
//! AP-REQ and random-source errors.
//!
//! The variants are built in free functions: inside an `impl` the strict
//! `use_self` lint wants `Self::Client`, which the error-construction audit
//! (`scripts/check-error-constructions.py`) does not count.

use super::{Error, finished::Fault};
use crate::error::{ApRep, ApReq, Client, Service};

/// The IAKERB error of a refused `IAKERB-FINISHED`.
const fn finished(fault: Fault) -> Error {
    match fault {
        Fault::Unexpected => Error::UnexpectedFinished,
        Fault::Missing => Error::MissingFinished,
        Fault::Bad => Error::BadFinished,
    }
}

impl From<Fault> for Error {
    #[inline]
    fn from(fault: Fault) -> Self {
        finished(fault)
    }
}

/// Wraps an exchange failure.
const fn client(failure: Client) -> Error {
    Error::Client(failure)
}

/// Wraps a service-side failure.
const fn service(failure: Service) -> Error {
    Error::Service(failure)
}

/// Wraps an AP-REQ failure.
const fn ap_req(failure: ApReq) -> Error {
    Error::ApReq(failure)
}

/// Wraps an AP-REP failure.
const fn ap_rep(failure: ApRep) -> Error {
    Error::ApRep(failure)
}

/// Wraps a random-source failure.
const fn random(failure: getrandom::Error) -> Error {
    Error::Random(failure)
}

impl From<Client> for Error {
    #[inline]
    fn from(failure: Client) -> Self {
        client(failure)
    }
}

impl From<Service> for Error {
    #[inline]
    fn from(failure: Service) -> Self {
        service(failure)
    }
}

impl From<ApReq> for Error {
    #[inline]
    fn from(failure: ApReq) -> Self {
        ap_req(failure)
    }
}

impl From<ApRep> for Error {
    #[inline]
    fn from(failure: ApRep) -> Self {
        ap_rep(failure)
    }
}

impl From<getrandom::Error> for Error {
    #[inline]
    fn from(failure: getrandom::Error) -> Self {
        random(failure)
    }
}
