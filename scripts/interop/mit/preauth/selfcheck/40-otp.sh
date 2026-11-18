#!/bin/bash
# Self-check of the OTP fixture (lane 1D-a), run by fixture_radius_up once the
# radius container is up: OTP preauthentication (MIT otp module, RADIUS
# backend) inside FAST armor. The token is the per-run token that radiusd
# accepts for otpuser. MIT 1.22.2 kinit has no `-X OTP=` attribute; the token
# is answered at the "Enter OTP Token Value" prompt, here from stdin.
set -euo pipefail
SC_NAME=otp
# shellcheck source=scripts/interop/mit/preauth/selfcheck/lib.sh
source /opt/interop/mit/preauth/selfcheck/lib.sh
sc_prepare
sc_load_secrets

readonly SVC=otprequired/svc.test.rskrb5
sc_armor_tgt armor

# 1. Right token, FAST armor: accepted through RADIUS; the ticket carries the
#    `otp` indicator.
sc_log_mark
sc_run otp kinit -T "FILE:$SC_DIR/armor.cc" -c "FILE:$SC_DIR/otp.cc" otpuser <<<"$INTEROP_MIT_OTP_TOKEN"
sc_expect_rc otp zero "kinit -T armor of otpuser with the OTP token"
sc_expect_trace otp 'Using FAST due to armor ccache negotiation result' "FAST was used"
sc_expect_trace otp 'Preauth module otp \([0-9]+\) \(real\) returned: 0/Success' "the OTP module succeeded"
sc_expect_out otp 'OTP Token Value' "the client asked for the OTP token value"
sc_expect_no_trace otp 'Encrypted timestamp \(for |Preauth module (spake|encrypted_challenge)' "no password-based preauth was used"
sc_expect_kdc_log 'AS_REQ .*ISSUE: .*otpuser@TEST.RSKRB5 for krbtgt/TEST.RSKRB5@TEST.RSKRB5' "the KDC issued the TGT"
sc_run kvno-otp env KRB5CCNAME="FILE:$SC_DIR/otp.cc" kvno "$SVC"
sc_expect_rc kvno-otp zero "the OTP TGT gets a ticket for $SVC (indicator otp present)"

# 2. Wrong token: RADIUS rejects it, the KDC refuses.
sc_log_mark
sc_run otp-wrong kinit -T "FILE:$SC_DIR/armor.cc" -c "FILE:$SC_DIR/otp-wrong.cc" otpuser <<<"${INTEROP_MIT_OTP_TOKEN}x"
sc_expect_rc otp-wrong nonzero "kinit -T armor of otpuser with a wrong OTP token"
sc_expect_kdc_log 'preauth \(otp\) verify failure' "the KDC's OTP module rejected the token"
sc_expect_kdc_log 'PREAUTH_FAILED: otpuser@TEST.RSKRB5' "the KDC answered PREAUTH_FAILED"

# 3. No FAST armor: the OTP factor is not even offered, the user's keys are
#    random and unknown, nothing can authenticate.
sc_run otp-plain kinit -c "FILE:$SC_DIR/otp-plain.cc" otpuser <<<"$INTEROP_MIT_OTP_TOKEN"
sc_expect_rc otp-plain nonzero "kinit of otpuser without armor"
sc_expect_no_trace otp-plain 'Preauth module otp' "the OTP module was not used without FAST"
sc_say "PASS otp: all assertions"
