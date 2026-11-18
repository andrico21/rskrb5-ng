#!/bin/bash
# Self-check of the FAST fixture (lane 1D-a): FAST armor and encrypted
# challenge against the MIT KDC, and the policy that makes FAST mandatory for
# one service principal. SPAKE is switched off in the client profile where the
# check must use the encrypted challenge or the timestamp (the MIT client
# prefers SPAKE, also inside FAST).
set -euo pipefail
SC_NAME=fast
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
conf_no_spake="/etc/krb5.conf:$SC_DIR/no-spake.conf"

sc_armor_tgt armor

# 1. Unarmored request for the FAST-required service: refused.
sc_log_mark
sc_run plain env KRB5_CONFIG="$conf_no_spake" kinit -S "$SVC" -c "FILE:$SC_DIR/plain.cc" fastuser <<<"$INTEROP_MIT_FAST_USER_PASSWORD"
sc_expect_rc plain nonzero "an unarmored AS-REQ for $SVC is refused"
sc_expect_trace plain 'Preauth module encrypted_timestamp \(2\) \(real\) returned: 0/Success' "the unarmored request used the encrypted timestamp"
sc_expect_no_trace plain 'FAST armor' "no FAST armor was used"
sc_expect_kdc_log 'HIGHER_AUTHENTICATION_REQUIRED: fastuser@TEST.RSKRB5 for fastrequired/.*Required auth indicators not present in ticket: fast-ec' \
  "the KDC refused it for the missing fast-ec indicator"

# 2. Armored request (armor from a normal principal's TGT): the encrypted
#    challenge succeeds and satisfies the policy.
sc_log_mark
sc_run armored env KRB5_CONFIG="$conf_no_spake" kinit -T "FILE:$SC_DIR/armor.cc" -S "$SVC" -c "FILE:$SC_DIR/armored.cc" fastuser <<<"$INTEROP_MIT_FAST_USER_PASSWORD"
sc_expect_rc armored zero "an armored AS-REQ for $SVC succeeds"
sc_expect_trace armored 'Using FAST due to armor ccache negotiation result' "FAST was used"
sc_expect_trace armored 'FAST armor ccache: FILE:' "the armor ccache was taken"
sc_expect_trace armored 'Preauth module encrypted_challenge \(138\) \(real\) returned: 0/Success' "the encrypted challenge was the preauth"
sc_expect_trace armored 'FAST reply key: ' "the reply key came from FAST"
sc_expect_no_trace armored 'Encrypted timestamp \(for ' "the encrypted timestamp was not used"
sc_expect_kdc_log "ISSUE: .*fastuser@TEST.RSKRB5 for $SVC@TEST.RSKRB5" "the KDC issued the ticket"

# 3. The same policy on the TGS path: a TGT obtained without FAST cannot get a
#    ticket for the service, a TGT obtained with FAST can.
sc_run tgt-plain env KRB5_CONFIG="$conf_no_spake" kinit -c "FILE:$SC_DIR/tgt-plain.cc" fastuser <<<"$INTEROP_MIT_FAST_USER_PASSWORD"
sc_expect_rc tgt-plain zero "an unarmored TGT is issued"
sc_log_mark
sc_run kvno-plain env KRB5CCNAME="FILE:$SC_DIR/tgt-plain.cc" kvno "$SVC"
sc_expect_rc kvno-plain nonzero "the unarmored TGT cannot get a ticket for $SVC"
sc_expect_kdc_log 'TGS_REQ .*HIGHER_AUTHENTICATION_REQUIRED: .*fastuser@TEST.RSKRB5 for fastrequired/.*fast-ec' "the KDC names the missing fast-ec indicator"
sc_run tgt-fast env KRB5_CONFIG="$conf_no_spake" kinit -T "FILE:$SC_DIR/armor.cc" -c "FILE:$SC_DIR/tgt-fast.cc" fastuser <<<"$INTEROP_MIT_FAST_USER_PASSWORD"
sc_expect_trace tgt-fast 'Preauth module encrypted_challenge \(138\) \(real\) returned: 0/Success' "the FAST TGT used the encrypted challenge"
sc_log_mark
sc_run kvno-fast env KRB5CCNAME="FILE:$SC_DIR/tgt-fast.cc" kvno "$SVC"
sc_expect_rc kvno-fast zero "the FAST TGT gets a ticket for $SVC"
sc_expect_kdc_log "TGS_REQ .*ISSUE: .*fastuser@TEST.RSKRB5 for $SVC@TEST.RSKRB5" "the KDC issued the service ticket on the TGS path"
sc_say "PASS fast: all assertions"
