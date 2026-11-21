//! Trace events of the KDC and kpasswd transport (FU-TRC-P01).
//!
//! The guard of a traced call sits in a per-thread slot while the call's future is
//! polled, because the transport is a `Copy` value that cannot own one (the
//! semantics of a Tokio task-local, without its item macro, which the secret-Debug
//! audit cannot read through). Every event carries a step, a protocol, a size and one
//! [`Identity`] (a realm or an endpoint), never request or reply bytes.

use core::future::poll_fn;
use std::{
    sync::{Mutex, MutexGuard, PoisonError},
    thread::{self, ThreadId},
};

use super::{KdcEndpoint, KdcProtocol};
use crate::trace::{Event, Guard, Identity, TransportStep, TransportWire};

/// The guard of the traced poll running on each thread, at most one per thread.
static ACTIVE: Mutex<Vec<(ThreadId, Guard)>> = Mutex::new(Vec::new());

/// The slots; a panic while they were held left them consistent, so poison is ignored.
fn slots() -> MutexGuard<'static, Vec<(ThreadId, Guard)>> {
    ACTIVE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Put `next` in this thread's slot and return the guard it held.
fn install(next: Option<Guard>) -> Option<Guard> {
    let thread = thread::current().id();
    let mut slots = slots();
    let previous = slots
        .iter()
        .position(|(owner, _)| *owner == thread)
        .map(|index| slots.swap_remove(index).1);
    if let Some(guard) = next {
        slots.push((thread, guard));
    }
    previous
}

/// A guard installed for one poll; dropping it, also by unwinding, takes it back
/// into `held` and reinstalls the guard it displaced.
struct Installed<'held> {
    /// The guard this poll displaced.
    outer: Option<Guard>,
    /// Where the scope keeps its guard between polls.
    held: &'held mut Option<Guard>,
}

// Drop audit: a short std mutex section with no I/O and no panic (poison is ignored).
impl Drop for Installed<'_> {
    fn drop(&mut self) {
        *self.held = install(self.outer.take());
    }
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
    let mut held = Some(guard);
    let mut pinned = Box::pin(future);
    poll_fn(|context| {
        let _installed = Installed {
            outer: install(held.take()),
            held: &mut held,
        };
        pinned.as_mut().poll(context)
    })
    .await
}

/// Hand one event to the guard of the current poll; nothing without one.
///
/// `target` runs only when a guard is set, so an untraced call formats nothing. The
/// guard leaves its slot while its sink runs, so a sink never runs under the lock.
fn emit<T>(step: TransportStep, wire: TransportWire, target: T, size: usize)
where
    T: FnOnce() -> String,
{
    let Some(guard) = install(None) else {
        return;
    };
    let name = target();
    guard.emit(&Event::Transport {
        step,
        wire,
        target: Identity::new(&name),
        size,
    });
    drop(install(Some(guard)));
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
    let protocol = if endpoint.proxy.is_some() {
        TransportWire::Https
    } else {
        wire(endpoint.protocol)
    };
    emit(step, protocol, || endpoint.target(), size);
}
