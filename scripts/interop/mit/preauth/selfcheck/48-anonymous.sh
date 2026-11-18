#!/bin/bash
# Self-check of the anonymous fixture (lane 1D-a): anonymous PKINIT
# (`kinit -n`, RFC 6112) yields a TGT of WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS,
# and that anonymous TGT works as FAST armor.
set -euo pipefail
SC_NAME=anonymous
# shellcheck source=scripts/interop/mit/preauth/selfcheck/lib.sh
source /opt/interop/mit/preauth/selfcheck/lib.sh
sc_prepare
sc_load_secrets

readonly SVC=fastrequired/svc.test.rskrb5
sc_conf no-spake <<'CONF'
[plugins]
    clpreauth = {
        disable = spake
    }
CONF

# 1. Anonymous PKINIT.
sc_log_mark
sc_run anon env KRB5_CONFIG="/etc/krb5.conf:/opt/interop/mit/preauth/client-pkinit.conf" kinit -n -c "FILE:$SC_DIR/anon.cc"
sc_expect_rc anon zero "kinit -n (anonymous PKINIT)"
sc_expect_trace anon 'Getting initial credentials for WELLKNOWN/ANONYMOUS@TEST.RSKRB5' "the client asked for WELLKNOWN/ANONYMOUS"
sc_expect_trace anon 'PKINIT client making DH request' "the request was a PKINIT request"
sc_expect_trace anon 'PKINIT client matched KDC principal krbtgt/TEST.RSKRB5@TEST.RSKRB5 against id-pkinit-san' "the KDC certificate was verified"
sc_expect_no_trace anon 'PKINIT loading identity' "no client identity (certificate) was used"
sc_expect_kdc_log 'AS_REQ .*ISSUE: .*WELLKNOWN/ANONYMOUS@TEST.RSKRB5 for krbtgt/TEST.RSKRB5@TEST.RSKRB5' "the KDC issued the anonymous TGT"
sc_run anon-klist klist -c "FILE:$SC_DIR/anon.cc"
sc_expect_out anon-klist 'Default principal: WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS' "the ticket client is WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS"

# 2. The anonymous TGT as FAST armor (the encrypted challenge of fastuser).
sc_run anon-armored env KRB5_CONFIG="/etc/krb5.conf:$SC_DIR/no-spake.conf" kinit -T "FILE:$SC_DIR/anon.cc" -S "$SVC" -c "FILE:$SC_DIR/anon-armored.cc" fastuser <<<"$INTEROP_MIT_FAST_USER_PASSWORD"
sc_expect_rc anon-armored zero "an AS-REQ armored by the anonymous TGT succeeds"
sc_expect_trace anon-armored 'FAST armor ccache: FILE:.*anon.cc' "the armor ccache is the anonymous one"
sc_expect_trace anon-armored 'Read config in FILE:.*anon.cc for krbtgt/TEST.RSKRB5@TEST.RSKRB5: fast_avail: yes' "FAST availability came from the anonymous ccache"
sc_expect_trace anon-armored 'Preauth module encrypted_challenge \(138\) \(real\) returned: 0/Success' "the encrypted challenge ran inside the anonymous armor"
sc_say "PASS anonymous: all assertions"
