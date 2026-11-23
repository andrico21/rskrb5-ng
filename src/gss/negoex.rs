//! `NegoEx` (MS-NEGOEX): mechanism negotiation framed in SPNEGO mechanism tokens.
//!
//! The message framework follows MIT krb5 1.22.2 (`lib/gssapi/spnego/negoex_*.c`):
//! `INITIATOR_NEGO` and `ACCEPTOR_NEGO` list the authentication schemes, the
//! meta-data messages let each scheme prune the list, `AP_REQUEST` and `CHALLENGE`
//! carry the selected mechanism's tokens, and `VERIFY` messages bind the whole
//! exchange with an RFC 3961 checksum under the mechanism's keys.
//!
//! # Security
//!
//! - Tokens are bounded in bytes, messages, schemes, extensions and alerts
//!   before they are used, and every length, offset and count is checked against
//!   its message; a malformed token is refused and changes no state.
//! - A header shorter than its message type needs is refused (MIT 1.22.2 reads
//!   past the token there, `negoex_util.c:325-340`), and so is an extension vector
//!   that leaves its message (MIT dereferences NULL, `negoex_util.c:213-221`).
//! - No mechanism is built in and none is added by default: the application
//!   names the mechanisms, each must be a registered
//!   [`GssMechanism`](crate::extensions::GssMechanism), and NTLM is refused by name.

use alloc::sync::Arc;
use core::{error::Error as StdError, fmt, mem};

use zeroize::Zeroizing;

use super::{ChannelBindings, ContextFlags, Name};
use crate::{
    crypto::{CryptoPolicy, KerberosEtype, checked::Etype},
    error::{Crypto, Negoex},
    extensions::Registry,
    keytab::EncryptionKey,
    spnego::oid::ObjectIdentifier,
};

include!("negoex/guid.rs");
include!("negoex/message.rs");
include!("negoex/conversation.rs");
include!("negoex/codec.rs");
include!("negoex/mechanism.rs");
include!("negoex/entry.rs");
include!("negoex/context.rs");
include!("negoex/metadata.rs");
include!("negoex/steps.rs");
include!("negoex/checksum.rs");
