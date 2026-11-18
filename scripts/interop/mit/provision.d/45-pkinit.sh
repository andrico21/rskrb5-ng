#!/bin/bash
# Lane 1D-a: PKINIT test CA of the MIT interop fixture, generated PER RUN with
# the openssl CLI inside the container (no key or certificate is in an image
# layer; everything is on the tmpfs /run/interop, mode 0700/0600).
#
#   ca-ec        EC P-256 root CA: signs the KDC certificate and the EC client
#   ca-rsa       RSA-3072 root CA: signs the RSA client (RSA-signed chain)
#   kdc          EC P-256 KDC certificate, SAN krbtgt/TEST.RSKRB5@TEST.RSKRB5
#                (id-pkinit-san, name type KRB5-NT-SRV-INST), EKU id-pkinit-KPKdc
#   pkinituser   EC P-256 client, SAN pkinituser@TEST.RSKRB5, EKU id-pkinit-KPClientAuth
#   pkinitrsa    RSA-2048 client, SAN pkinitrsa@TEST.RSKRB5, signed by ca-rsa;
#                its principal also carries a pkinit_cert_match rule on the subject
# Files: /run/interop/pki/ holds the KDC key and certificate and the anchors
# the KDC uses (never exported); /run/interop/out/pki/ holds what the host
# receives (public CA certificates, the client certificates and keys, 0600).
# The CA private keys are deleted as soon as the certificates are signed.
# Principals: pkinituser and pkinitrsa (+requires_preauth, no long-term key, so
# only the certificate can authenticate), pkinitrequired/svc.test.rskrb5
# (require_auth = pkinit, the KDC asserts that indicator for PKINIT tickets).
set -euo pipefail
# shellcheck source=scripts/interop/mit/preauth/kadm.sh
source /opt/interop/mit/preauth/kadm.sh

readonly PKI=/run/interop/pki
readonly PUB="$OUT/pki"
readonly DAYS=30

umask 077
install -d -m 0700 "$PKI" "$PUB"
cd "$PKI"

cat >extensions.cnf <<'EXT'
[kdc_cert]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = 1.3.6.1.5.2.3.5
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name

[kdc_princ_name]
realm = EXP:0,GeneralString:${ENV::REALM}
principal_name = EXP:1,SEQUENCE:kdc_principal_seq

[kdc_principal_seq]
name_type = EXP:0,INTEGER:2
name_string = EXP:1,SEQUENCE:kdc_principals

[kdc_principals]
princ1 = GeneralString:krbtgt
princ2 = GeneralString:${ENV::REALM}

[client_cert]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = 1.3.6.1.5.2.3.4
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name

[princ_name]
realm = EXP:0,GeneralString:${ENV::REALM}
principal_name = EXP:1,SEQUENCE:principal_seq

[principal_seq]
name_type = EXP:0,INTEGER:1
name_string = EXP:1,SEQUENCE:principals

[principals]
princ1 = GeneralString:${ENV::CLIENT}
EXT

# new_root NAME KEYGEN...: self-signed root CA (key NAME.key, certificate NAME.pem).
new_root() {
  local name="$1"
  shift
  "$@" >"$name.key" 2>/dev/null
  openssl req -new -x509 -key "$name.key" -sha256 -days "$DAYS" \
    -subj "/O=RSKRB5 Interop/CN=RSKRB5 Interop $name root" \
    -config /dev/null -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" \
    -out "$name.pem" 2>/dev/null
}

# issue CA CN EXTENSION OUTPEM KEYGEN...: leaf key (OUTPEM with .pem -> .key),
# signed by CA; CLIENT is the principal name in the SAN.
issue() {
  local ca="$1" cn="$2" ext="$3" out="$4"
  shift 4
  local key="${out%.pem}.key"
  "$@" >"$key" 2>/dev/null
  openssl req -new -key "$key" -subj "/CN=$cn" -out "$cn.csr" 2>/dev/null
  env REALM="$REALM" CLIENT="$cn" openssl x509 -req -in "$cn.csr" -CA "$ca.pem" -CAkey "$ca.key" \
    -CAcreateserial -sha256 -days "$DAYS" -extfile extensions.cnf -extensions "$ext" \
    -out "$out" 2>/dev/null
  rm -f "$cn.csr"
}

ec_key() { openssl ecparam -name prime256v1 -genkey -noout; }
rsa_key() { openssl genrsa "$1"; }

new_root ca-ec ec_key
new_root ca-rsa rsa_key 3072
issue ca-ec kdc kdc_cert kdc.pem ec_key
issue ca-ec pkinituser client_cert "$PUB/pkinit-ec.pem" ec_key
issue ca-rsa pkinitrsa client_cert "$PUB/pkinit-rsa.pem" rsa_key 2048
cat ca-ec.pem ca-rsa.pem >anchors.pem
cp ca-ec.pem ca-rsa.pem anchors.pem "$PUB/"
rm -f ca-ec.key ca-rsa.key ./*.srl extensions.cnf
chmod 0600 ./*.pem ./*.key "$PUB"/*
printf 'generated the PKINIT test CA (EC P-256 root, RSA-3072 root, EC KDC certificate, EC and RSA clients)\n'

ensure_principal pkinituser +requires_preauth -nokey
ensure_principal pkinitrsa +requires_preauth -nokey
set_principal_string pkinitrsa pkinit_cert_match '"<SUBJECT>^CN=pkinitrsa$"'
ensure_principal pkinitrequired/svc.test.rskrb5 +no_auth_data_required -randkey
set_principal_string pkinitrequired/svc.test.rskrb5 require_auth pkinit
