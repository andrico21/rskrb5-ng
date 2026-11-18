#!/bin/bash
# After the daemons listen: MIT 1.22.2 `kinit` writes a FILE credential cache
# for testuser1 (from its exported keytab) that the Rust tests load
# (INTEROP_MIT_KINIT_CCACHE). The TGT session key enctype follows
# default_tkt_enctypes of the fixture krb5.conf (aes256-cts-hmac-sha384-192).
set -euo pipefail

readonly OUT=/run/interop/out
rm -f "$OUT/kinit.ccache"
kinit -k -t "$OUT/testuser1.keytab" -c "FILE:$OUT/kinit.ccache" testuser1@TEST.RSKRB5
klist -e -c "FILE:$OUT/kinit.ccache" | sed -n '/krbtgt/,+1p'
