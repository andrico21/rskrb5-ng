# shellcheck shell=bash
# Plan 2 todo 7 (WP-05, FAST armor and encrypted challenge): the `fast` suite.
# It reuses the mit-kdc principals of lane 1D-a (provision.d/20-fast.sh:
# fastuser, fastrequired/svc.test.rskrb5 with require_auth = fast-ec, and
# kdc.conf.d/20-fast.conf) and testuser1's keytab for the armor TGT; it adds
# no drop-in, port or secret (prefix 57 and ports 19570-19579 stay reserved
# for this todo). The directory name `suite-fast` sorts after every fixture
# directory, so mit-kdc is registered already. Todo 28 (lane E, implicit FAST
# armor of TGS requests) adds mit-other: the cross-realm scenario armors the
# referral hop and the service hop against OTHER.RSKRB5.
interop_suite fast interop_fast mit-kdc mit-other
