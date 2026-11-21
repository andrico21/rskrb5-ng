//! The MS-KKDCP KDC proxy (MS-KKDCP; MIT 1.22.2 "HTTPS proxy support").
//!
//! A realm reaches its KDC or kpasswd server through an HTTPS proxy when its profile
//! names the server as a URL, `kdc = https://proxy.example.com/KdcProxy` (MIT
//! `locate_kdc.c:216-231`, `docs/admin/https.rst`). This module holds the
//! `KDC-PROXY-MESSAGE` codec ([`kkdcp`]) and, with the `tokio` feature, the transport
//! trait the Tokio client posts through (`proxy`) and the built-in rustls transport
//! (`rustls_proxy`, feature `kkdcp-rustls`).
//!
//! # Security
//!
//! A proxy is trusted only after TLS verifies its certificate chain against the
//! realm's `http_anchors` (or roots the application configures) and the URL's host
//! name; an unset `http_anchors` with no configured roots is an error, never an
//! implicit system trust store. The proxy only relays: every reply is checked by its
//! Kerberos keys as a reply over UDP or TCP is.

pub mod kkdcp;
#[cfg(feature = "tokio")]
pub mod proxy;
#[cfg(feature = "tokio")]
pub mod rustls_proxy;
