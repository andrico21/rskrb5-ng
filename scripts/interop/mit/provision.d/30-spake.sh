#!/bin/bash
# Lane 1D-a: SPAKE preauthentication principals of the MIT interop fixture.
#
# krb5.conf.d/30-spake.conf turns SPAKE on (spake_preauth_groups in
# [libdefaults] is read by KDC and clients); kdc.conf.d/30-spake.conf makes the
# KDC assert the indicator `spake`. MIT 1.22.2 cannot forbid the encrypted
# timestamp fallback per client principal (doc/admin/spake.rst: it is a
# client-side realm relation, disable_encrypted_timestamp), so the "SPAKE
# required" principal is, as for FAST, a SERVER principal whose `require_auth`
# is `spake`: a TGT obtained by timestamp fallback cannot get a ticket for it.
#   spakeuser                      password user, +requires_preauth -allow_svr
#   spakerequired/svc.test.rskrb5  require_auth = spake
set -euo pipefail
# shellcheck source=scripts/interop/mit/preauth/kadm.sh
source /opt/interop/mit/preauth/kadm.sh

: "${INTEROP_MIT_SPAKE_USER_PASSWORD:?}"

ensure_principal spakeuser +requires_preauth -allow_svr -pw "$INTEROP_MIT_SPAKE_USER_PASSWORD"
ensure_principal spakerequired/svc.test.rskrb5 +no_auth_data_required -randkey
set_principal_string spakerequired/svc.test.rskrb5 require_auth spake
