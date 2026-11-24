# shellcheck shell=bash
# Plan 2 todo 19 (WP-12b, GSS-API II): the `gss-ext` suite. The directory name
# `suite-gss-ext` sorts after every fixture directory, so mit-kdc and mit-peer
# are registered already. No port, principal, drop-in or secret is added: the
# suite reuses the peer adapter's services (mit/provision.d/70-peer.sh),
# testuser1 and the adapter's `D` command (peer-mit/peer/peer_deleg.c).
#
#   gss-ext      interop_gss_ext: IOV and AEAD tokens both ways, byte-identical
#                gss_pseudo_random output on both context roles, DCE-style
#                three-leg establishment with MIT as either end, Rust and MIT
#                context transfer in mid-conversation, and a TGT delegated from
#                Rust to MIT and on from MIT back to Rust
interop_suite gss-ext interop_gss_ext mit-kdc mit-peer
