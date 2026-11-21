# shellcheck shell=bash
# Plan 2 todo 17 (WP-11, routing, capaths transit validation, S4U/RBCD, U2U
# and verify_init_creds): the `routing` suites. The directory name
# `suite-routing` sorts after every fixture directory, so mit-kdc, mit-other,
# samba-user and samba-res are registered already. No drop-in, port or secret
# is added: the routes, principals and keytabs are the fixtures' own
# (mit-other's capaths-only FAR.EXAMPLE, the MIT host and HTTP keytabs, the
# Samba forest trust and its RBCD accounts).
#
#   routing        interop_routing: the non-hierarchical [capaths] route
#                  TEST.RSKRB5 -> OTHER.RSKRB5 -> FAR.EXAMPLE and the transited
#                  path the FAR KDC records, verify_init_creds against the host
#                  keytab and a wrong one, and a user-to-user ticket, against
#                  MIT krb5 1.22.2
#   routing-samba  interop_routing_samba: the unsolicited referral across the
#                  forest trust (FU-IOP-P12), transit validation of the AD
#                  ticket with [capaths] (FU-SVC-08) and resource-based
#                  constrained delegation (FU-IOP-P11), against Samba AD.
#                  Registered with the Samba fixtures, which INTEROP_SAMBA=0
#                  leaves out.
interop_suite routing interop_routing mit-kdc mit-other
if [[ "${INTEROP_SAMBA:-1}" != 0 ]]; then
  interop_suite routing-samba interop_routing_samba samba-user samba-res
fi
