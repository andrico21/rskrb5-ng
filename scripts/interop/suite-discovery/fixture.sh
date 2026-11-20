# shellcheck shell=bash
# Plan 2 todo 15 (WP-10a, discovery and canonicalization): the `discovery`
# suite. It reuses the `dns` fixture (CoreDNS with the URI, SRV, TXT, site and
# AAAA records of TEST.RSKRB5 in the host view, scripts/interop/net-zone) and
# the TEST.RSKRB5 KDC; it adds no drop-in, port or secret (todo 15's reserved
# MIT drop-in prefix 65 and host ports 19650-19659 stay unused). The directory
# name `suite-discovery` sorts after every fixture directory, so mit-kdc and
# dns are registered already.
interop_suite discovery interop_discovery mit-kdc dns
