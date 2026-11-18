#!/bin/bash
# Lane 1D-a: OTP preauthentication (RFC 6560 style, MIT otp module) backed by
# the RADIUS fixture `radius` (scripts/interop/radius/).
#
# kdc.conf.d/40-otp.conf overrides the DEFAULT token type of [otp]: server
# radius.test.rskrb5:1812, the shared secret in the FILE written here from the
# per-run secret INTEROP_RADIUS_SHARED_SECRET (tmpfs, mode 0600, never in an
# image), strip_realm, indicator `otp`. The principal's `otp` string attribute
# `[]` means one DEFAULT token (doc/admin/otp.rst). The principal has random
# keys nobody knows, so only the OTP exchange (which requires FAST armor)
# can authenticate it.
#   otpuser                      +requires_preauth, random key, otp = []
#   otprequired/svc.test.rskrb5  require_auth = otp
set -euo pipefail
# shellcheck source=scripts/interop/mit/preauth/kadm.sh
source /opt/interop/mit/preauth/kadm.sh

: "${INTEROP_RADIUS_SHARED_SECRET:?}" "${INTEROP_MIT_OTP_TOKEN:?}"

install -d -m 0700 /run/interop/otp
printf '%s\n' "$INTEROP_RADIUS_SHARED_SECRET" >/run/interop/otp/radius.secret
chmod 0600 /run/interop/otp/radius.secret

ensure_principal otpuser +requires_preauth -randkey
set_principal_string otpuser otp '[]'
ensure_principal otprequired/svc.test.rskrb5 +no_auth_data_required -randkey
set_principal_string otprequired/svc.test.rskrb5 require_auth otp
