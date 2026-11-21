# shellcheck shell=bash
# Plan 2 todo 8 (WP-06, PKINIT and anonymous credentials): the `pkinit` suite.
# It reuses the mit-kdc PKINIT CA, principals and KDC configuration of lane
# 1D-a (provision.d/45-pkinit.sh, provision.d/48-anonymous.sh,
# kdc.conf.d/45-pkinit.conf: pkinituser, pkinitrequired/svc.test.rskrb5 with
# require_auth = pkinit, WELLKNOWN/ANONYMOUS) and the FAST principals of
# provision.d/20-fast.sh for the anonymous armor; it adds no drop-in, port or
# secret (prefix 58 and ports 19580-19589 stay reserved for this todo). The
# directory name `suite-pkinit` sorts after every fixture directory, so mit-kdc
# is registered already.
interop_suite pkinit interop_pkinit mit-kdc
