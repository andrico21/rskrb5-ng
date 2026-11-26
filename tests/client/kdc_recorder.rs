//! A KDC behind an `https://` proxy entry that records each request.

use std::sync::{Mutex, PoisonError};

use rskrb5_ng::{
    error::KdcProxy,
    transport::{
        kkdcp::ProxyMessage,
        proxy::{KdcProxyTransport, PostFuture, Request},
    },
};

/// A KDC proxy that records each Kerberos message and refuses delivery.
#[derive(Debug)]
pub(crate) struct Recorder(Mutex<Vec<Vec<u8>>>);

impl Recorder {
    /// A recorder that has seen nothing.
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    /// The messages seen so far.
    pub(crate) fn seen(&self) -> Vec<Vec<u8>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether `message` holds the bytes of `text` anywhere.
    pub(crate) fn names(message: &[u8], text: &str) -> bool {
        message
            .windows(text.len())
            .any(|window| window == text.as_bytes())
    }
}

impl KdcProxyTransport for Recorder {
    fn post<'request>(&'request self, request: Request<'request>) -> PostFuture<'request> {
        let message = ProxyMessage::decode(request.body).map_or_else(
            |_error| Vec::new(),
            |decoded| decoded.kerb_message().to_vec(),
        );
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(message);
        Box::pin(async { Err(KdcProxy::NotDelivered("recorded".into())) })
    }
}
