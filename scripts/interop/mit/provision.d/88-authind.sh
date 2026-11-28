#!/bin/bash
# Plan 2 todo 28 (wave 11 lane D, MIT-gss-8; extension prefix 88): the service
# of the authentication-indicator scenario of tests/interop_gss_ext. NOT
# realm-wide: one service principal and its keytab, nothing in kdc.conf or
# krb5.conf. The indicators come from the realm's preauthentication indicators
# (kdc.conf.d/30-spake.conf: spake_preauth_indicator = spake). Idempotent; the
# output names principals only.
#
#   authind/svc.test.rskrb5   a service with the DEFAULT authorization data (not
#                             +no_auth_data_required): MIT copies the TGT's
#                             authentication indicators into an AD-CAMMAC of
#                             every ticket for it, with a service verifier under
#                             its key (src/kdc/kdc_authdata.c:298-336,479-494;
#                             src/kdc/cammac.c:57-127). Keytab
#                             out/authind-svc.keytab.
set -euo pipefail
# shellcheck source=scripts/interop/mit/preauth/kadm.sh
source /opt/interop/mit/preauth/kadm.sh

ensure_principal authind/svc.test.rskrb5 -randkey
rm -f "$OUT/authind-svc.keytab"
kadmin_query "ktadd -k $OUT/authind-svc.keytab -norandkey authind/svc.test.rskrb5" "added to keytab"
printf 'exported authind/svc.test.rskrb5@%s to out/authind-svc.keytab\n' "$REALM"
