# shellcheck shell=bash
# Plan 2 todo 22 (WP-14, PAC API): the `pac` suites. The directory name
# `suite-pac` sorts after every fixture directory, so mit-kdc, samba-user and
# samba-res are registered already. No port and no secret is added: the MIT
# service pac/svc.test.rskrb5 (a default PAC, not +no_auth_data_required) and
# the exported krbtgt keytab are provisioned by mit/provision.d/82-pac.sh, the
# Samba accounts and keytabs are the fixtures' own.
#
#   pac          interop_pac: the PAC MIT krb5 1.22.2 puts into a service
#                ticket (client info and the four signatures, no
#                KERB_VALIDATION_INFO) is accepted by the acceptor and its
#                signatures verify (FU-SVC-P01), and a PAC verified under the
#                wrong key is refused
#   pac-samba    interop_pac_samba: a Samba PAC with a zero-length client-claims
#                buffer is accepted (FU-IOP-P14) and the Samba PAC attributes
#                and claims read through the verified PAC. Registered with the
#                Samba fixtures, which INTEROP_SAMBA=0 leaves out.
interop_suite pac interop_pac mit-kdc
if [[ "${INTEROP_SAMBA:-1}" != 0 ]]; then
  interop_suite pac-samba interop_pac_samba samba-user samba-res
fi
