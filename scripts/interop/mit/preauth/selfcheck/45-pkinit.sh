#!/bin/bash
# Self-check of the PKINIT fixture (lane 1D-a): certificate authentication
# with the EC P-256 client (EC root) and the RSA client (RSA root), the
# id-pkinit-san mapping, a pkinit_cert_match rule, and the refusals: a root
# that did not sign the KDC certificate, and a certificate of the wrong
# principal. The client profile adds client-pkinit.conf (anchor = EC root).
set -euo pipefail
SC_NAME=pkinit
# shellcheck source=scripts/interop/mit/preauth/selfcheck/lib.sh
source /opt/interop/mit/preauth/selfcheck/lib.sh
sc_prepare

readonly PKI=/run/interop/out/pki
readonly SVC=pkinitrequired/svc.test.rskrb5
export KRB5_CONFIG=/etc/krb5.conf:/opt/interop/mit/preauth/client-pkinit.conf
ec_identity="FILE:$PKI/pkinit-ec.pem,$PKI/pkinit-ec.key"
rsa_identity="FILE:$PKI/pkinit-rsa.pem,$PKI/pkinit-rsa.key"

# pkinit_success LABEL PRINCIPAL IDENTITY ANCHORS CHAIN_CN: asserts a full
# PKINIT exchange (DH, KDC certificate matched by its id-pkinit-san) and that
# the TGT passes the pkinit indicator policy.
pkinit_success() {
  local label="$1" principal="$2" identity="$3" anchors="$4" cn="$5"
  sc_log_mark
  sc_run "$label" kinit -X "X509_anchors=$anchors" -X "X509_user_identity=$identity" -c "FILE:$SC_DIR/$label.cc" "$principal" </dev/null
  sc_expect_rc "$label" zero "kinit of $principal with a certificate"
  sc_expect_trace "$label" "PKINIT loading identity $identity" "the client loaded its certificate identity"
  sc_expect_trace "$label" "PKINIT chain cert #0: /CN=$cn" "the client certificate is /CN=$cn"
  sc_expect_trace "$label" 'PKINIT client verified DH reply' "the client verified the KDC's signed DH reply"
  sc_expect_trace "$label" 'PKINIT client matched KDC principal krbtgt/TEST.RSKRB5@TEST.RSKRB5 against id-pkinit-san' "the KDC certificate's id-pkinit-san matched krbtgt"
  sc_expect_trace "$label" 'Preauth module pkinit \(17\) \(real\) returned: 0/Success' "the PKINIT reply module succeeded"
  sc_expect_no_trace "$label" 'Encrypted timestamp \(for |Preauth module spake' "no password-based preauth was used"
  sc_expect_kdc_log "AS_REQ .*ISSUE: .*$principal@TEST.RSKRB5 for krbtgt/TEST.RSKRB5@TEST.RSKRB5" "the KDC issued the TGT"
  sc_run "$label-kvno" env KRB5CCNAME="FILE:$SC_DIR/$label.cc" kvno "$SVC"
  sc_expect_rc "$label-kvno" zero "the PKINIT TGT gets a ticket for $SVC (indicator pkinit present)"
}

pkinit_success ec pkinituser "$ec_identity" "FILE:$PKI/ca-ec.pem" pkinituser
# MIT verifies the client's own certificate against the anchors too, so the
# RSA-signed client needs the RSA root next to the EC root that signed the KDC.
pkinit_success rsa pkinitrsa "$rsa_identity" "FILE:$PKI/anchors.pem" pkinitrsa

# A root that did not sign the KDC certificate: the client refuses the reply.
sc_run wrong-anchor kinit -X "X509_anchors=FILE:$PKI/ca-rsa.pem" -X "X509_user_identity=$rsa_identity" -c "FILE:$SC_DIR/wrong-anchor.cc" pkinitrsa </dev/null
sc_expect_rc wrong-anchor nonzero "kinit with an anchor that did not sign the KDC certificate"
sc_expect_trace wrong-anchor 'PKINIT OpenSSL error: Failed to verify received certificate \(depth 0\): unable to get local issuer certificate' "the client could not verify the KDC certificate"
sc_expect_trace wrong-anchor 'PKINIT client could not verify DH reply' "the DH reply was not accepted"

# A certificate of another principal: the KDC refuses the name mismatch.
sc_log_mark
sc_run wrong-identity kinit -X "X509_anchors=FILE:$PKI/anchors.pem" -X "X509_user_identity=$rsa_identity" -c "FILE:$SC_DIR/wrong-identity.cc" pkinituser </dev/null
sc_expect_rc wrong-identity nonzero "kinit of pkinituser with the certificate of pkinitrsa"
sc_expect_kdc_log 'PREAUTH_FAILED: pkinituser@TEST.RSKRB5 for krbtgt/.*Client name mismatch' "the KDC refused the certificate (id-pkinit-san names another principal)"

# The pkinit_cert_match rule and the SAN of pkinitrsa both refuse the EC certificate.
sc_log_mark
sc_run ec-for-rsa kinit -X "X509_user_identity=$ec_identity" -c "FILE:$SC_DIR/ec-for-rsa.cc" pkinitrsa </dev/null
sc_expect_rc ec-for-rsa nonzero "kinit of pkinitrsa with the certificate of pkinituser"
sc_expect_kdc_log 'PREAUTH_FAILED: pkinitrsa@TEST.RSKRB5 for krbtgt/.*Client name mismatch' "the KDC refused the EC certificate for pkinitrsa"

# Without a certificate there is nothing to authenticate with (no long-term key).
sc_run no-identity kinit -c "FILE:$SC_DIR/no-identity.cc" pkinituser </dev/null
sc_expect_rc no-identity nonzero "kinit of the key-less pkinituser without a certificate"
sc_say "PASS pkinit: all assertions"
