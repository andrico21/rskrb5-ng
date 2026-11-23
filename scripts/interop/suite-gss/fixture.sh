# shellcheck shell=bash
# Plan 2 todo 18 (WP-12a, GSS-API I): the `gss` suites. The directory name
# `suite-gss` sorts after every fixture directory, so mit-kdc, mit-peer and the
# Samba fixtures are registered already. No port, principal or secret is added:
# the suite reuses the peer adapter's services (mit/provision.d/70-peer.sh),
# testuser1 and its client keytab (mit/fixture.sh).
#
#   gss          interop_gss: Rust GSS initiators against MIT's acceptor and
#                MIT initiators against the Rust GSS and SPNEGO acceptors, with
#                and without channel bindings (a mismatch refused both ways, an
#                acceptor requiring bindings refuses a token without them, MIT
#                enforcing KERB_AP_OPTIONS_CBT), the password and client keytab
#                credential stores, a TGT delegated to the Rust acceptor that
#                reaches MIT as the user, and per-message tokens both ways
#   gss-samba    interop_gss_samba: Samba's LDAP enforces TLS channel bindings
#                on a GSSAPI SASL bind of the Rust GSS initiator over LDAPS.
#                Registered with the Samba fixtures, which INTEROP_SAMBA=0
#                leaves out.
interop_suite gss interop_gss mit-kdc mit-peer
if [[ "${INTEROP_SAMBA:-1}" != 0 ]]; then
  interop_suite gss-samba interop_gss_samba samba-user
fi
