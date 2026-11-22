//! Cross-realm routing (WP-11): realm paths from `[capaths]` and the realm
//! hierarchy, the DOMAIN-X500-COMPRESS transited encoding, and the certificate
//! identity of certificate `S4U2Self`.
//!
//! Everything here is always compiled and uses no dependency. The paths read
//! the typed `[capaths]` section (`Config::capaths`): the client walks
//! [`RealmPath::client`] when it asks for cross-realm TGTs, an acceptor checks a
//! decoded [`transited`] list against [`RealmPath::walk`] (the service's
//! `CapathsTransit` does), and a certificate `S4U2Self` request carries a
//! [`CertificateIdentity`].
//!
//! # Security
//!
//! Paths, transited encodings and certificates are bounded before they are
//! used: a path holds at most [`RealmPath::MAX_REALMS`] realms and no realm
//! twice, an encoding at most [`transited::MAX_ENCODED_BYTES`] bytes naming at
//! most [`transited::MAX_REALMS`] realms of at most
//! [`transited::MAX_REALM_BYTES`] bytes each, and a certificate at most
//! [`CertificateIdentity::MAX_CERTIFICATE_BYTES`] bytes. Nothing here reads
//! the environment.

use core::fmt;

use crate::{
    config::section_values::{Capaths, Route},
    error::Routing as Error,
    extensions::ProviderError,
};

#[cfg(feature = "tokio")]
pub mod impersonation;
#[cfg(feature = "tokio")]
pub mod init_creds;
#[cfg(feature = "messages")]
pub mod s4u;
pub mod transited;

include!("routing/path.rs");
include!("routing/certificate.rs");
