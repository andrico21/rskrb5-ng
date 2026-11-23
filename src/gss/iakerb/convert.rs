//! The conversions into the IAKERB error that `?` applies to the exchange,
//! AP-REQ and random-source errors.

use super::Error;
use crate::error::{ApRep, ApReq, Client, Service};

impl From<Client> for Error {
    #[inline]
    fn from(failure: Client) -> Self {
        Self::Client(failure)
    }
}

impl From<Service> for Error {
    #[inline]
    fn from(failure: Service) -> Self {
        Self::Service(failure)
    }
}

impl From<ApReq> for Error {
    #[inline]
    fn from(failure: ApReq) -> Self {
        Self::ApReq(failure)
    }
}

impl From<ApRep> for Error {
    #[inline]
    fn from(failure: ApRep) -> Self {
        Self::ApRep(failure)
    }
}

impl From<getrandom::Error> for Error {
    #[inline]
    fn from(failure: getrandom::Error) -> Self {
        Self::Random(failure)
    }
}
