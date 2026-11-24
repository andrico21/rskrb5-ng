# shellcheck shell=bash
# Plan 2 todo 21 (WP-13b, NegoEx): the `negoex` suite. The directory name
# `suite-negoex` sorts after every fixture directory, so mit-kdc and mit-peer
# are registered already. No port, principal or secret is added: the suite
# reuses the peer adapter's `negoextest` mechanisms (peer-mit/gss-mech.negoextest,
# loaded per connection by the adapter's `E GSS_MECH_CONFIG negoextest`).
#
#   negoex       interop_negoex: the crate's NegoEx under SPNEGO against MIT's
#                NegoEx, both ways (Rust initiator against MIT's acceptor, MIT's
#                initiator against the Rust acceptor), one to three hops of the
#                negoextest mechanism, the mechanism pinned to the first
#                negoextest OID; a VERIFY message with a wrong checksum fails
#                the context in each direction.
interop_suite negoex interop_negoex mit-kdc mit-peer
