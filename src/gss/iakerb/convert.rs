//! The conversions into the IAKERB error that `?` applies to the exchange,
//! AP-REQ and random-source errors.

use super::Error;
use crate::error::{ApRep, ApReq, Client, Service};

impl From<Client> for Error {
    #[inline]
    fn from(failure: Client) -> Self {
        Error::Client(failure)
    }
}

impl From<Service> for Error {
    #[inline]
    fn from(failure: Service) -> Self {
        Error::Service(failure)
    }
}

impl From<ApReq> for Error {
    #[inline]
    fn from(failure: ApReq) -> Self {
        Error::ApReq(failure)
    }
}

impl From<ApRep> for Error {
    #[inline]
    fn from(failure: ApRep) -> Self {
        Error::ApRep(failure)
    }
}

impl From<getrandom::Error> for Error {
    #[inline]
    fn from(failure: getrandom::Error) -> Self {
        Error::Random(failure)
    }
}
