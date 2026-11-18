#!/bin/bash
# Lane 1D-a: anonymous Kerberos (RFC 6112). Creating WELLKNOWN/ANONYMOUS turns
# anonymity support on (doc/admin/pkinit.rst "Anonymous PKINIT"); the KDC
# certificate of 45-pkinit.sh serves anonymous PKINIT and clients need only the
# anchor. restrict_anonymous_to_tgt stays at its default (false), so anonymous
# service tickets stay possible for later scenarios (EXECUTOR decision).
set -euo pipefail
# shellcheck source=scripts/interop/mit/preauth/kadm.sh
source /opt/interop/mit/preauth/kadm.sh

ensure_principal WELLKNOWN/ANONYMOUS -randkey
