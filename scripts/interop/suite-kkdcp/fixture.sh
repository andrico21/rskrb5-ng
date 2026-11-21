# shellcheck shell=bash
# Plan 2 todo 16 (WP-10b, MS-KKDCP): the `kkdcp` suite. It drives the built-in
# rustls KDC proxy transport (the `kkdcp-rustls` leaf) through the `kdcproxy`
# fixture (lane 1D-b: scripts/interop/net-kdcproxy, its per-run CA, the wrong CA
# and the disposable account proxypwuser of mit/provision.d/51-net-services.sh)
# to the MIT realm; it adds no drop-in, port or secret. The protocol check of the
# proxy stays callable as net_kdcproxy_self_check (net-kdcproxy/fixture.sh). The
# directory name `suite-kkdcp` sorts after every fixture directory, so mit-kdc and
# kdcproxy are registered already.
interop_suite kkdcp interop_kkdcp mit-kdc kdcproxy
