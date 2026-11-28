//! Mach RPC to a KCM service.
//!
//! It is `bootstrap_look_up` and one `mach_msg` send-and-receive per request, with the messages of [`crate::mig`]
//! (MIT 1.22.2 `kcmio_mach_connect` and `kcmio_mach_call`,
//! `src/lib/krb5/ccache/cc_kcm.c:189-281`).
//!
//! Each call allocates its own reply port and destroys it afterwards, so a
//! timed-out call never leaves a late reply for the next one, and both the
//! send and the receive are bounded by [`TIMEOUT_MS`] (MIT waits forever).

use alloc::ffi::CString;
use core::{ffi::c_char, ptr, slice};
use std::io;

use rskrb5_ng::{
    ccache::kcm::seam::KcmTransport,
    error::{Kcm, KcmStage},
};

use crate::{Secret, error::Platform, mig};

/// A Mach port name.
type Port = u32;
/// `kern_return_t`.
type Kern = i32;

/// `MACH_SEND_MSG | MACH_RCV_MSG | MACH_SEND_TIMEOUT | MACH_RCV_TIMEOUT`.
const CALL: i32 = 0x1 | 0x2 | 0x10 | 0x100;
/// `MACH_RCV_MSG | MACH_RCV_TIMEOUT`.
#[cfg(test)]
const RECEIVE: i32 = 0x2 | 0x100;
/// `MACH_SEND_MSG | MACH_SEND_TIMEOUT`.
#[cfg(test)]
const SEND: i32 = 0x1 | 0x10;
/// The code of a local refusal (`KERN_INVALID_ARGUMENT`).
const INVALID: Kern = 4;
/// `MACH_PORT_RIGHT_RECEIVE`.
const RIGHT_RECEIVE: u32 = 1;
/// The bound on each send and receive, in milliseconds.
pub(crate) const TIMEOUT_MS: u32 = 30_000;
/// The receive buffer in words: a full reply (`REPLY_FIXED` 64 + 2048
/// in-band bytes) and the largest trailer (68 bytes).
const WORDS: usize = 545;
/// The largest out-of-line reply accepted, in bytes.
const OUTBAND_MAX: u32 = 0x0100_0000;

// These are the libSystem declarations of `<mach/mach.h>`,
// `<mach/message.h>`, `<mach/vm_map.h>` and `<servers/bootstrap.h>` with
// their C types (`mach_port_t` and `mach_msg_size_t` are `u32`,
// `kern_return_t` is `i32`, `vm_address_t`/`vm_size_t` are `usize`). The
// two statics are written once by libSystem before `main` and only read
// here, so reading them is safe; the port functions only take port names,
// which the kernel validates, so they are declared safe.
#[expect(unsafe_code, reason = "the Mach FFI declarations")]
unsafe extern "C" {
    safe static mach_task_self_: Port;
    safe static bootstrap_port: Port;
    fn bootstrap_look_up(bp: Port, service_name: *const c_char, sp: *mut Port) -> Kern;
    #[cfg(test)]
    fn bootstrap_check_in(bp: Port, service_name: *const c_char, sp: *mut Port) -> Kern;
    fn mach_port_allocate(task: Port, right: u32, name: *mut Port) -> Kern;
    safe fn mach_port_mod_refs(task: Port, name: Port, right: u32, delta: i32) -> Kern;
    safe fn mach_port_deallocate(task: Port, name: Port) -> Kern;
    fn mach_msg(
        msg: *mut u32,
        option: i32,
        send_size: u32,
        rcv_size: u32,
        rcv_name: Port,
        timeout: u32,
        notify: Port,
    ) -> Kern;
    fn mach_msg_destroy(msg: *mut u32);
    fn vm_deallocate(task: Port, address: usize, size: usize) -> Kern;
}

/// A send right to a service; deallocated on drop.
#[derive(Debug)]
struct SendRight(Port);

// Drop audit: one port-right release (a Mach trap); it never blocks.
impl Drop for SendRight {
    fn drop(&mut self) {
        let _ignored: Kern = mach_port_deallocate(mach_task_self_, self.0);
    }
}

/// A receive right; destroyed on drop.
#[derive(Debug)]
struct ReceiveRight(Port);

// Drop audit: one port-right release (a Mach trap); it never blocks.
impl Drop for ReceiveRight {
    fn drop(&mut self) {
        let _ignored: Kern = mach_port_mod_refs(mach_task_self_, self.0, RIGHT_RECEIVE, -1);
    }
}

/// `service` as a C string.
/// # Errors
/// Returns [`Platform::NoServer`] for a name with a NUL byte.
fn c_name(service: &str) -> Result<CString, Platform> {
    CString::new(service).map_err(|_nul| Platform::NoServer { code: INVALID })
}

/// Look `service` up in the bootstrap namespace.
/// # Errors
/// Returns [`Platform::NoServer`] when it is not registered.
fn look_up(service: &str) -> Result<SendRight, Platform> {
    let name = c_name(service)?;
    let mut port: Port = 0;
    // SAFETY: `name` is a NUL-terminated string that outlives the call and
    // `port` is a valid, writable `mach_port_t`.
    #[expect(unsafe_code, reason = "FFI call")]
    let code = unsafe { bootstrap_look_up(bootstrap_port, name.as_ptr(), &raw mut port) };
    if code == 0 {
        Ok(SendRight(port))
    } else {
        Err(Platform::NoServer { code })
    }
}

/// A new receive right.
/// # Errors
/// Returns [`Platform::MachRpc`] when the kernel refuses.
fn receive_right() -> Result<ReceiveRight, Platform> {
    let mut port: Port = 0;
    // SAFETY: `port` is a valid, writable `mach_port_name_t`.
    #[expect(unsafe_code, reason = "FFI call")]
    let code = unsafe { mach_port_allocate(mach_task_self_, RIGHT_RECEIVE, &raw mut port) };
    if code == 0 {
        Ok(ReceiveRight(port))
    } else {
        Err(Platform::MachRpc { code })
    }
}

/// Words of `bytes` (a whole number of words) in a receive-sized buffer.
fn words(bytes: &[u8]) -> Vec<u32> {
    let mut buffer = vec![0_u32; WORDS];
    for (word, chunk) in buffer.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    buffer
}

/// The bytes of a received buffer.
fn bytes(buffer: &[u32]) -> Secret {
    Secret::from(
        buffer
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<u8>>(),
    )
}

/// Send `message` and, when `receive` is set, wait for a message on it.
/// # Errors
/// Returns [`Platform::MachRpc`] with the `mach_msg` result.
fn message(
    buffer: &mut [u32],
    send: Option<usize>,
    receive: Option<&ReceiveRight>,
) -> Result<(), Platform> {
    let option = match (send, receive) {
        (Some(_), Some(_)) => CALL,
        #[cfg(test)]
        (Some(_), None) => SEND,
        #[cfg(test)]
        (None, Some(_)) => RECEIVE,
        (_, _) => return Err(Platform::MachRpc { code: INVALID }),
    };
    let send_size = u32::try_from(send.unwrap_or_default())
        .map_err(|_size| Platform::MachRpc { code: INVALID })?;
    let receive_size = u32::try_from(buffer.len().saturating_mul(4))
        .map_err(|_size| Platform::MachRpc { code: INVALID })?;
    let name = receive.map_or(0, |right| right.0);
    // SAFETY: `buffer` is a writable, 4-aligned buffer of `receive_size`
    // bytes that holds `send_size` bytes of a well-formed message whose
    // out-of-line region (if any) the caller keeps mapped; the kernel writes
    // at most `receive_size` bytes back into it.
    #[expect(unsafe_code, reason = "FFI call")]
    let code = unsafe {
        mach_msg(
            buffer.as_mut_ptr(),
            option,
            send_size,
            receive_size,
            name,
            TIMEOUT_MS,
            0,
        )
    };
    if code == 0 {
        Ok(())
    } else {
        Err(Platform::MachRpc { code })
    }
}

/// Copy and unmap the out-of-line region the kernel mapped for a received
/// message.
/// # Errors
/// Returns [`Platform::TooLarge`] above [`OUTBAND_MAX`] (unmapped, not copied).
fn take_region(region: mig::Region) -> Result<Secret, Platform> {
    let (address, length) = region;
    if length == 0 {
        return Ok(Secret::from(Vec::new()));
    }
    let start = usize::try_from(address).map_err(|_address| Platform::MachRpc { code: INVALID })?;
    let size = usize::try_from(length).map_err(|_size| Platform::MachRpc { code: INVALID })?;
    let copied = (length <= OUTBAND_MAX).then(|| {
        let pointer = ptr::with_exposed_provenance::<u8>(start);
        // SAFETY: the kernel mapped `size` readable bytes at `start` for the
        // received out-of-line descriptor; they stay mapped until the
        // `vm_deallocate` below, and nothing else aliases them.
        #[expect(unsafe_code, reason = "reading kernel-mapped message memory")]
        let slice = unsafe { slice::from_raw_parts(pointer, size) };
        Secret::from(slice.to_vec())
    });
    // SAFETY: `start..start + size` is the region the kernel mapped for this
    // message, owned by this task and no longer borrowed.
    #[expect(unsafe_code, reason = "FFI call")]
    let unmapped = unsafe { vm_deallocate(mach_task_self_, start, size) };
    match (copied, unmapped) {
        (Some(data), 0) => Ok(data),
        (Some(_), code) => Err(Platform::MachRpc { code }),
        (None, _) => Err(Platform::TooLarge {
            cache_type: "KCM",
            length: size,
        }),
    }
}

/// Release the rights and memory of a received message that failed checks.
fn destroy(buffer: &mut [u32]) {
    // SAFETY: `buffer` holds a message the kernel delivered; destroying it
    // releases the rights and out-of-line memory it carries exactly once.
    #[expect(unsafe_code, reason = "FFI call")]
    unsafe {
        mach_msg_destroy(buffer.as_mut_ptr());
    }
}

/// One `call` RPC to `service`: the reply's status-framed KCM body.
/// # Errors
/// Returns the lookup, Mach and MIG failures, and [`Platform::Kcm`] for a
/// nonzero `returnvalue`.
fn call(service: &str, request: &[u8]) -> Result<Secret, Platform> {
    let server = look_up(service)?;
    let reply = receive_right()?;
    let address = u64::try_from(request.as_ptr().expose_provenance()).unwrap_or_default();
    let encoded = mig::request((server.0, reply.0), request, address)?;
    let mut buffer = words(&encoded);
    message(&mut buffer, Some(encoded.len()), Some(&reply))?;
    let received = bytes(&buffer);
    let (code, (inband, region)) = match mig::decode_reply(&received) {
        Ok(decoded) => decoded,
        Err(error) => {
            destroy(&mut buffer);
            return Err(error);
        }
    };
    let outband = take_region(region)?;
    if code != 0_i32 {
        return Err(Platform::Kcm { code });
    }
    Ok(if region.1 == 0 {
        Secret::from(inband)
    } else {
        outband
    })
}

/// The KCM transport over Mach RPC to a named service (`kcm_mach_service`,
/// MIT 1.22.2 `kcmio_mach_connect` and `kcmio_mach_call`, `cc_kcm.c:189-281`).
///
/// It is the transport the factory of [`crate::install_kcm_transport`] makes
/// for the built-in `KCM:` store; the main crate disables Mach for `-` and
/// never asks for it. A service that is not registered is
/// [`Kcm::NoServer`], so the store falls back to the socket as MIT does.
///
/// # Security
///
/// The reply leaves the zeroizing buffer as the transport signature's
/// `Vec<u8>` and is wrapped again by its caller before it is parsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MachTransport(String);

impl MachTransport {
    /// The transport to `service`.
    pub(crate) const fn new(service: String) -> Self {
        Self(service)
    }
}

/// The opcode of a KCM request, `0` for one too short to carry it.
fn opcode(request: &[u8]) -> u16 {
    request
        .get(2..4)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map_or(0, u16::from_be_bytes)
}

/// `failure` of a call with `request` as the transport error the seam
/// classifies: no service, the service's own failure code, or a lost call.
fn kcm_error(failure: Platform, request: &[u8]) -> Kcm {
    match failure {
        Platform::NoServer { code: _ } => Kcm::NoServer,
        Platform::Kcm { code } => Kcm::Daemon {
            opcode: opcode(request),
            code,
        },
        Platform::MutationNotAuthorized { cache_type: _ }
        | Platform::UnsupportedOperation {
            cache_type: _,
            operation: _,
        }
        | Platform::MalformedReply {
            cache_type: _,
            reason: _,
        }
        | Platform::TooLarge {
            cache_type: _,
            length: _,
        }
        | Platform::MachRpc { code: _ }
        | Platform::Ccapi { code: _ }
        | Platform::Lsa {
            status: _,
            sub_status: _,
        } => Kcm::Io {
            stage: KcmStage::Read,
            source: io::Error::other(failure),
        },
    }
}

impl KcmTransport for MachTransport {
    fn call(&self, request: &[u8]) -> Result<Vec<u8>, Kcm> {
        call(&self.0, request)
            .map(|reply| reply.to_vec())
            .map_err(|failure| kcm_error(failure, request))
    }
}

/// A test KCM service: a receive right checked in under a name.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct Service(ReceiveRight);

#[cfg(test)]
impl Service {
    /// Check `name` in with the bootstrap server.
    /// # Errors
    /// Returns [`Platform::NoServer`] when it is refused.
    pub(crate) fn check_in(name: &str) -> Result<Self, Platform> {
        let text = c_name(name)?;
        let mut port: Port = 0;
        // SAFETY: `name` is NUL-terminated and outlives the call; `port` is a
        // valid, writable `mach_port_t`.
        #[expect(unsafe_code, reason = "FFI call")]
        let code = unsafe { bootstrap_check_in(bootstrap_port, text.as_ptr(), &raw mut port) };
        if code == 0 {
            Ok(Self(ReceiveRight(port)))
        } else {
            Err(Platform::NoServer { code })
        }
    }

    /// Receive one request, answer it with `handler` (a status-framed KCM
    /// reply, sent with `returnvalue` 0 as Heimdal's `kcm` does), and send it.
    /// # Errors
    /// Returns the Mach and MIG failures.
    pub(crate) fn serve_one<F>(&self, handler: F) -> Result<(), Platform>
    where
        F: FnOnce(&[u8]) -> Secret,
    {
        let mut buffer = vec![0_u32; WORDS];
        message(&mut buffer, None, Some(&self.0))?;
        let received = bytes(&buffer);
        let (reply_port, (inband, region)) = mig::decode_request(&received)?;
        let request = if region.1 == 0 {
            Secret::from(inband)
        } else {
            take_region(region)?
        };
        let answer = handler(&request);
        let address = u64::try_from(answer.as_ptr().expose_provenance()).unwrap_or_default();
        let encoded = mig::reply(reply_port, 0, &answer, address)?;
        let mut out = words(&encoded);
        message(&mut out, Some(encoded.len()), None)
    }
}
