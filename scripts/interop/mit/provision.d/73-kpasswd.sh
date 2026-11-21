#!/bin/bash
# Plan 2 todo 23 (WP-15a, password expiry and kpasswd completion): the
# principals of the `kpasswd` suite (extension prefix 73). Idempotent; the
# output names principals only.
#
#   expiredpw      +requires_preauth, password expired yesterday: the login
#                  gets KDC_ERR_KEY_EXP, the change and the login again
#   expiredpolicy  as expiredpw, under the policy kpasswd-policy (minimum
#                  length 20): a short new password is a soft error
#                  (KPASSWD_SOFTERROR), the retry succeeds
#   expiringpw     +requires_preauth, password expires 2037-06-15: the login
#                  succeeds and the KDC reports the expiry (key_exp)
#
# The passwords are derived from the admin password, so the host derives the
# same values (tests/interop_kpasswd.rs): the first 32 hex digits of
# sha256("rskrb5-interop kpasswd <name> v1" + admin password), the way
# 70-peer.sh derives peeruser's. Every account is the suite's alone and
# changed at most once per run: do not give them to another suite.
set -euo pipefail
# shellcheck source=scripts/interop/mit/preauth/kadm.sh
source /opt/interop/mit/preauth/kadm.sh

: "${INTEROP_MIT_ADMIN_PASSWORD:?}"

derive() {
  printf '%s' "rskrb5-interop kpasswd $1 v1${INTEROP_MIT_ADMIN_PASSWORD}" | sha256sum | cut -c1-32
}

if ! kadmin.local -r "$REALM" -q "getpol kpasswd-policy" 2>/dev/null | grep -q '^Policy: '; then
  kadmin.local -r "$REALM" -q "addpol -minlength 20 kpasswd-policy" >/dev/null
  kadmin_query "getpol kpasswd-policy" "Minimum password length: 20"
  printf 'created the policy kpasswd-policy\n'
fi

ensure_principal expiredpw +requires_preauth -pwexpire yesterday -pw "$(derive expiredpw)"
ensure_principal expiredpolicy +requires_preauth -policy kpasswd-policy -pwexpire yesterday \
  -pw "$(derive expiredpolicy)"
ensure_principal expiringpw +requires_preauth -pwexpire 2037-06-15 -pw "$(derive expiringpw)"
