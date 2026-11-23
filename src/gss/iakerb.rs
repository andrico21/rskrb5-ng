//! IAKERB: Kerberos through an application-mediated KDC relay.
//!
//! IAKERB is the GSS-API mechanism `1.3.6.1.5.2.5` of MIT krb5 1.22.2
//! (`iakerb.c`), which implements `draft-ietf-krb-wg-iakerb-02` (MIT
//! `doc/mitK5features.rst:99`). The initiator has no route to a KDC: its AS and
//! TGS requests travel inside GSS context tokens to the acceptor, which sends
//! them to a KDC of the named realm and returns the replies, before the normal
//! AP exchange. It is not anonymous Kerberos (RFC 6112).
//!
//! # Security
//!
//! - The acceptor relays only through a caller-supplied [`KdcRelay`], never
//!   through a socket of its own, and only for the realms, rounds and bytes
//!   its [`RelayPolicy`] allows; a request for another realm, or one that is
//!   not a well-formed AS-REQ or TGS-REQ for the realm in its header, is refused.
//! - Every IAKERB token of the exchange is appended to a transcript; the
//!   AP-REQ carries an `IAKERB-FINISHED` checksum of that transcript under
//!   the initiator's subkey, which the acceptor verifies (MIT `iakerb.c:125-181`).
//! - Tokens are bounded before they are parsed; a malformed or reordered token
//!   is an error, never a panic.

use core::fmt;

use super::{Accepted, Acceptor, Config, Credential, EstablishedContext, InitStep};
use crate::{error::Iakerb as Error, spnego::oid::ObjectIdentifier};

include!("iakerb/token.rs");
include!("iakerb/relay.rs");
include!("iakerb/context.rs");
