#!/bin/bash
# Plan 2 todo 22 (WP-14, PAC API; extension prefix 82). Idempotent; the output
# names principals only.
#
#   pac/svc.test.rskrb5   a service with the DEFAULT authorization data: MIT
#                         1.22.2 puts a PAC into every ticket for it
#                         (src/kdc/kdc_authdata.c:479-494). Unlike HTTP/http and
#                         host/mit-kdc it is NOT +no_auth_data_required. The PAC
#                         MIT builds carries PAC_CLIENT_INFO, the server, KDC,
#                         ticket and full checksums, and no KERB_VALIDATION_INFO
#                         (FU-SVC-P01). Keytab out/pac-svc.keytab.
#   krbtgt/TEST.RSKRB5    its key exported to out/pac-krbtgt.keytab so a test can
#                         verify the KDC, ticket and full signatures of a PAC the
#                         way a KDC does (a service holds only its own key). The
#                         realm is disposable and its keys are generated per run.
set -euo pipefail
# shellcheck source=scripts/interop/mit/preauth/kadm.sh
source /opt/interop/mit/preauth/kadm.sh

export_keytab() {
  local file="$OUT/$1" name="$2"
  rm -f "$file"
  kadmin_query "ktadd -k $file -norandkey $name" "added to keytab"
  printf 'exported %s@%s to out/%s\n' "$name" "$REALM" "$1"
}

ensure_principal pac/svc.test.rskrb5 -randkey
export_keytab pac-svc.keytab pac/svc.test.rskrb5
export_keytab pac-krbtgt.keytab "krbtgt/$REALM"
