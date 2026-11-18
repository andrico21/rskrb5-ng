#!/bin/bash
# Self-check of the SPAKE fixture (lane 1D-a): SPAKE preauthentication
# (RFC 8636 style, MIT spake module) with the groups of the KDC, and proof that
# the encrypted timestamp fallback cannot satisfy the SPAKE policy of
# spakerequired/svc.test.rskrb5.
set -euo pipefail
SC_NAME=spake
# shellcheck source=scripts/interop/mit/preauth/selfcheck/lib.sh
source /opt/interop/mit/preauth/selfcheck/lib.sh
sc_prepare
sc_load_secrets

readonly SVC=spakerequired/svc.test.rskrb5
readonly PASSWORD="$INTEROP_MIT_SPAKE_USER_PASSWORD"

# 1. Default client: SPAKE, edwards25519 (group 1, the first group of the KDC).
sc_log_mark
sc_run spake kinit -c "FILE:$SC_DIR/spake.cc" spakeuser <<<"$PASSWORD"
sc_expect_rc spake zero "kinit of spakeuser"
sc_expect_trace spake 'SPAKE challenge received with group 1, pubkey ' "the KDC sent a SPAKE challenge in group 1 (edwards25519)"
sc_expect_trace spake 'Sending SPAKE response' "the client sent the SPAKE response"
sc_expect_trace spake 'Preauth module spake \(151\) \(real\) returned: 0/Success' "the SPAKE module succeeded"
sc_expect_no_trace spake 'Encrypted timestamp \(for ' "the timestamp preauth was NOT used"
sc_expect_kdc_log 'AS_REQ .*ISSUE: .*spakeuser@TEST.RSKRB5 for krbtgt/TEST.RSKRB5@TEST.RSKRB5' "the KDC issued the TGT"
sc_log_mark
sc_run kvno-spake env KRB5CCNAME="FILE:$SC_DIR/spake.cc" kvno "$SVC"
sc_expect_rc kvno-spake zero "the SPAKE TGT gets a ticket for $SVC (indicator spake present)"
sc_expect_kdc_log "TGS_REQ .*ISSUE: .*spakeuser@TEST.RSKRB5 for $SVC@TEST.RSKRB5" "the KDC issued the service ticket"

# 2. A client that supports only P-256: the KDC allows it (group 2).
sc_conf spake-p256 <<'CONF'
[libdefaults]
    spake_preauth_groups = P-256
CONF
sc_run p256 env KRB5_CONFIG="$SC_DIR/spake-p256.conf:/etc/krb5.conf" kinit -c "FILE:$SC_DIR/p256.cc" spakeuser <<<"$PASSWORD"
sc_expect_rc p256 zero "kinit of spakeuser with spake_preauth_groups = P-256"
sc_expect_trace p256 'SPAKE challenge received with group 2, pubkey ' "the KDC used group 2 (P-256)"

# 3. A client without SPAKE falls back to the encrypted timestamp: it gets a
#    TGT, but that TGT cannot get a ticket for the SPAKE-required service.
sc_conf no-spake <<'CONF'
[plugins]
    clpreauth = {
        disable = spake
    }
CONF
conf_no_spake="/etc/krb5.conf:$SC_DIR/no-spake.conf"
sc_run fallback env KRB5_CONFIG="$conf_no_spake" kinit -c "FILE:$SC_DIR/fallback.cc" spakeuser <<<"$PASSWORD"
sc_expect_rc fallback zero "kinit of spakeuser without the SPAKE module"
sc_expect_trace fallback 'Preauth module encrypted_timestamp \(2\) \(real\) returned: 0/Success' "the fallback used the encrypted timestamp"
sc_expect_no_trace fallback 'SPAKE challenge received' "no SPAKE exchange took place"
sc_log_mark
sc_run kvno-fallback env KRB5CCNAME="FILE:$SC_DIR/fallback.cc" kvno "$SVC"
sc_expect_rc kvno-fallback nonzero "the timestamp TGT cannot get a ticket for $SVC"
sc_expect_kdc_log 'TGS_REQ .*HIGHER_AUTHENTICATION_REQUIRED: .*spakeuser@TEST.RSKRB5 for spakerequired/.*spake' "the KDC names the missing spake indicator"

# 4. disable_encrypted_timestamp (the client-side realm switch against a forced
#    fallback, doc/admin/spake.rst) makes the same client fail outright.
sc_conf no-timestamp <<'CONF'
[realms]
    TEST.RSKRB5 = {
        disable_encrypted_timestamp = true
    }
CONF
sc_run no-timestamp env KRB5_CONFIG="$conf_no_spake:$SC_DIR/no-timestamp.conf" kinit -c "FILE:$SC_DIR/no-timestamp.cc" spakeuser <<<"$PASSWORD"
sc_expect_rc no-timestamp nonzero "kinit without SPAKE and with disable_encrypted_timestamp"
sc_expect_trace no-timestamp 'Ignoring encrypted timestamp because it is disabled' "the timestamp factor was refused by the client"
sc_say "PASS spake: all assertions"
