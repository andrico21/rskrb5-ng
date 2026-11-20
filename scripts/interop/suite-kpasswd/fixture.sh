# shellcheck shell=bash
# Plan 2 todo 23 (WP-15a, password expiry and kpasswd completion): the
# `kpasswd` suites. The directory name `suite-kpasswd` sorts after every
# fixture directory, so mit-kdc, samba-user and samba-res are registered
# already. No port and no secret is added: the MIT principals are provisioned
# by mit/provision.d/73-kpasswd.sh (expiredpw, expiredpolicy, expiringpw, with
# passwords the host derives from the admin password) and the Samba accounts
# kpasswdself and setpwtarget by samba/setup-user.sh.
#
#   kpasswd        interop_kpasswd: the expired-password login, the change and
#                  the login again, the password-policy soft error and the
#                  impending expiry against MIT krb5 1.22.2
#   kpasswd-samba  interop_kpasswd_samba: an ordinary user's self change without
#                  RFC 3244 target fields (FU-IOP-P13) and the administrator's
#                  targeted reset, against Samba AD. Registered with the Samba
#                  fixtures, which INTEROP_SAMBA=0 leaves out.
interop_suite kpasswd interop_kpasswd mit-kdc
if [[ "${INTEROP_SAMBA:-1}" != 0 ]]; then
  interop_suite kpasswd-samba interop_kpasswd_samba samba-user samba-res
fi
