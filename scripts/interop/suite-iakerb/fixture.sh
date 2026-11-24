# shellcheck shell=bash
# Plan 2 todo 20 (WP-13a, IAKERB): the `iakerb` suite. The directory name
# `suite-iakerb` sorts after every fixture directory, so mit-kdc and the two
# mit-peer containers are registered already. No port, principal, secret or
# drop-in is added (the PP 80 and ports 19700-19709 of the todo stay unused):
# the suite reuses the peer adapter's two containers, one with a route to the KDC
# and one without (peer-mit/fixture.sh), peeruser and the services of
# mit/provision.d/70-peer.sh.
#
#   iakerb   interop_iakerb: a Rust IAKERB initiator completes a context against
#            MIT's IAKERB acceptor while its own direct path to the KDC is
#            blocked (a direct AS exchange of the same profile fails), a Rust
#            IAKERB acceptor relays the AS and TGS exchanges of an MIT initiator
#            in the container that cannot reach the KDC (the application's
#            relay, a plain TCP client of the KDC, is the only path), and the
#            acceptor refuses a relay request for a realm its policy does not
#            name. The AS exchange of the Rust initiator is pinned to the
#            encrypted timestamp (an empty spake_preauth_groups), the realm
#            offering SPAKE realm-wide.
interop_suite iakerb interop_iakerb mit-kdc mit-peer mit-peer-iso
