//! Trace events of the KDC and kpasswd transport (FU-TRC-P01).
//!
//! The guard of a traced call lives in a task-local slot, because the transport is a
//! `Copy` value that cannot own one. Every event carries a step, a protocol, a size
//! and one [`Identity`] (a realm or an endpoint), never request or reply bytes.

use super::{KdcEndpoint, KdcProtocol};
use crate::trace::{Event, Guard, Identity, TransportStep, TransportWire};

tokio::task_local! {
    /// The guard of the traced call running on this task.
    static GUARD: Guard;
}

/// Run `future` with `guard` receiving the transport events it causes.
///
/// # Cancel safety
///
/// cancel-safe exactly when `future` is.
pub(super) async fn scope<F>(guard: Guard, future: F) -> F::Output
where
    F: Future,
{
    GUARD.scope(guard, future).await
}

/// Hand one event to the guard of the current task; nothing without one.
///
/// `target` runs only when a guard is set, so an untraced call formats nothing.
fn emit<T>(step: TransportStep, wire: TransportWire, target: T, size: usize)
where
    T: FnOnce() -> String,
{
    GUARD
        .try_with(|guard| {
            let name = target();
            guard.emit(&Event::Transport {
                step,
                wire,
                target: Identity::new(&name),
                size,
            });
        })
        .unwrap_or_default();
}

/// The trace protocol of a request protocol.
const fn wire(protocol: KdcProtocol) -> TransportWire {
    match protocol {
        KdcProtocol::Udp => TransportWire::Udp,
        KdcProtocol::Tcp => TransportWire::Tcp,
        KdcProtocol::Auto => TransportWire::Auto,
    }
}

/// Discovery found `count` endpoints of `protocol` for `realm`.
pub(super) fn located(realm: &str, protocol: KdcProtocol, count: usize) {
    emit(
        TransportStep::Located,
        wire(protocol),
        || realm.to_owned(),
        count,
    );
}

/// The realm is tried again over `protocol`.
pub(super) fn switched(realm: &str, protocol: KdcProtocol) {
    emit(
        TransportStep::Switched,
        wire(protocol),
        || realm.to_owned(),
        0,
    );
}

/// `step` happened at `endpoint`, with `size` bytes sent or received.
pub(super) fn at(step: TransportStep, endpoint: &KdcEndpoint, size: usize) {
    emit(step, wire(endpoint.protocol), || endpoint.authority(), size);
}
