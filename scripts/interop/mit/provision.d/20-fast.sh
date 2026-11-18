#!/bin/bash
# Lane 1D-a: FAST (RFC 6113) principals of the MIT interop fixture.
#
# The KDC needs no switch to accept FAST armor (any TGT or anonymous TGT of
# the realm can armor a request). MIT 1.22.2 has no per-client "armor required"
# flag: a policy is attached to the SERVER principal of an AS or TGS request
# through the `require_auth` string attribute (src/kdc/kdc_util.c
# check_indicators, called from do_as_req.c and do_tgs_req.c). Encrypted
# challenge, which only works inside FAST, asserts the indicator `fast-ec`
# (kdc.conf.d/20-fast.conf, encrypted_challenge_indicator), so a ticket for
# fastrequired/svc.test.rskrb5 can only be obtained with a FAST armored
# encrypted-challenge exchange (or from a TGT obtained that way).
#   fastuser                      password user, +requires_preauth
#   fastrequired/svc.test.rskrb5  require_auth = fast-ec
set -euo pipefail
# shellcheck source=scripts/interop/mit/preauth/kadm.sh
source /opt/interop/mit/preauth/kadm.sh

: "${INTEROP_MIT_FAST_USER_PASSWORD:?}"

ensure_principal fastuser +requires_preauth -pw "$INTEROP_MIT_FAST_USER_PASSWORD"
ensure_principal fastrequired/svc.test.rskrb5 +no_auth_data_required -randkey
set_principal_string fastrequired/svc.test.rskrb5 require_auth fast-ec
