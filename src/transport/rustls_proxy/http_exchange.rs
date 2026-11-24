//! The built-in HTTPS [`HttpExchange`] of the `kkdcp-rustls` leaf.

use crate::{
    error::HttpExchange as Error,
    http::wire::{ExchangeFuture, HttpExchange},
    transport::rustls_proxy::RustlsTransport,
};

impl HttpExchange for RustlsTransport {
    #[inline]
    fn exchange(&self, _request: http_types::Request<Vec<u8>>) -> ExchangeFuture<'_> {
        Box::pin(async {
            Err(Error::InvalidRequest {
                reason: "not implemented",
            })
        })
    }
}
