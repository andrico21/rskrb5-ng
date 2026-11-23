# shellcheck shell=bash
# Plan 2 todo 24 (WP-15b, remote kadm5 over RPCSEC_GSS): the `kadm5` suite.
# The directory name `suite-kadm5` sorts after every fixture directory, so
# mit-kdc is registered already. No port, principal or secret is added: the
# scenarios reach the fixture's kadmind (`kadmind -nofork`, published as
# INTEROP_MIT_KADMIN) as admin/admin (kadm5.acl `*`) and as testuser1 (no ACL
# entry), create only names under a per-run prefix, delete them before they
# end, and check every effect with MIT's own kadmin.local in the container.
#
#   kadm5   interop_kadm5: principal, policy and key operations, string
#           attributes, an alias, the extract-keys ACL refusal, integrity and
#           privacy, and the ACL refusal of an unprivileged principal against
#           MIT krb5 1.22.2
interop_suite kadm5 interop_kadm5 mit-kdc
