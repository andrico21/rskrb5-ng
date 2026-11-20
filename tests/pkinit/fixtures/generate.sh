#!/bin/bash
# Provenance of the PKINIT test fixtures (plan 2 todo 8): generated with the
# OpenSSL CLI, independently of rskrb5-ng, the library MIT krb5 1.22.2's
# PKINIT plugin is built on. Re-running replaces every key and certificate
# (the tests read the files, so they keep passing). Run from this directory:
#   bash generate.sh
# ca-ec        EC P-256 root CA (trusted by the tests)
# ca-rsa       RSA-3072 root CA (trusted): signs kdc-rsachain (an RSA-signed chain)
# ca-other     EC P-256 root CA (never trusted)
# kdc          EC P-256 KDC: SAN krbtgt/TEST.RSKRB5@TEST.RSKRB5, EKU id-pkinit-KPKdc
# kdc-noeku    as kdc without the EKU extension
# kdc-serverauth  EKU id-kp-serverAuth, SAN dNSName kdc.test.rskrb5 only
# kdc-wrongsan SAN krbtgt/OTHER.RSKRB5@OTHER.RSKRB5
# kdc-untrusted  as kdc, signed by ca-other
# kdc-revoked  as kdc, listed in crl-ec.pem
# kdc-expired  as kdc, valid 2020-01-01 to 2021-01-01
# kdc-rsachain as kdc, signed by ca-rsa
# client       EC P-256 client pkinituser@TEST.RSKRB5, EKU id-pkinit-KPClientAuth
#              (client.key SEC1 "EC PRIVATE KEY", client-pkcs8.key PKCS#8)
# client-p384  EC P-384 client, PKCS#8 key
# cms-dhkeydata.der  `openssl cms -sign` SignedData (eContentType
#              id-pkinit-DHKeyData) over dhkeydata.der, signed by the kdc key
# dh-*.der     modp_2048 and P-256 key pairs and their shared secrets
#              (`openssl pkeyutl -derive`), for the key-agreement answers
set -euo pipefail
export LC_ALL=C
DAYS=36500
umask 077

cat >ext.cnf <<'EXT'
[kdc]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = 1.3.6.1.5.2.3.5
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_name
[kdc_noeku]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, keyAgreement
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_name
[kdc_serverauth]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:kdc.test.rskrb5
[kdc_wrongsan]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = 1.3.6.1.5.2.3.5
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:other_name
[client]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = 1.3.6.1.5.2.3.4
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:client_name
[kdc_name]
realm = EXP:0,GeneralString:TEST.RSKRB5
principal_name = EXP:1,SEQUENCE:kdc_seq
[kdc_seq]
name_type = EXP:0,INTEGER:2
name_string = EXP:1,SEQUENCE:kdc_parts
[kdc_parts]
p1 = GeneralString:krbtgt
p2 = GeneralString:TEST.RSKRB5
[other_name]
realm = EXP:0,GeneralString:OTHER.RSKRB5
principal_name = EXP:1,SEQUENCE:other_seq
[other_seq]
name_type = EXP:0,INTEGER:2
name_string = EXP:1,SEQUENCE:other_parts
[other_parts]
p1 = GeneralString:krbtgt
p2 = GeneralString:OTHER.RSKRB5
[client_name]
realm = EXP:0,GeneralString:TEST.RSKRB5
principal_name = EXP:1,SEQUENCE:client_seq
[client_seq]
name_type = EXP:0,INTEGER:1
name_string = EXP:1,SEQUENCE:client_parts
[client_parts]
p1 = GeneralString:pkinituser
EXT

ec() { openssl ecparam -name "${2:-prime256v1}" -genkey -noout -out "$1"; }
root() {
  openssl req -new -x509 -key "$1.key" -sha256 -days "$DAYS" -subj "/O=RSKRB5 Test/CN=$1" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$1.pem"
}
# leaf NAME CA SECTION [extra x509 args...]
leaf() {
  local name=$1 ca=$2 section=$3
  shift 3
  openssl req -new -key "$name.key" -subj "/O=RSKRB5 Test/CN=$name" -out "$name.csr"
  openssl x509 -req -in "$name.csr" -CA "$ca.pem" -CAkey "$ca.key" -CAcreateserial -sha256 \
    -extfile ext.cnf -extensions "$section" -out "$name.pem" "$@"
  rm -f "$name.csr"
}

ec ca-ec.key
root ca-ec
openssl genrsa -out ca-rsa.key 3072
root ca-rsa
ec ca-other.key
root ca-other
for name in kdc kdc-noeku kdc-serverauth kdc-wrongsan kdc-untrusted kdc-revoked kdc-expired kdc-rsachain client; do
  ec "$name.key"
done
ec client-p384.key secp384r1
leaf kdc ca-ec kdc -days "$DAYS"
leaf kdc-noeku ca-ec kdc_noeku -days "$DAYS"
leaf kdc-serverauth ca-ec kdc_serverauth -days "$DAYS"
leaf kdc-wrongsan ca-ec kdc_wrongsan -days "$DAYS"
leaf kdc-untrusted ca-other kdc -days "$DAYS"
leaf kdc-revoked ca-ec kdc -days "$DAYS"
leaf kdc-expired ca-ec kdc -not_before 20200101000000Z -not_after 20210101000000Z
leaf kdc-rsachain ca-rsa kdc -days "$DAYS"
leaf client ca-ec client -days "$DAYS"
leaf client-p384 ca-ec client -days "$DAYS"
openssl pkcs8 -topk8 -nocrypt -in client.key -out client-pkcs8.key
openssl pkcs8 -topk8 -nocrypt -in client-p384.key -out client-p384-pkcs8.key

# CRL of ca-ec revoking kdc-revoked.
mkdir -p crl.d
: >crl.d/index.txt
echo 1000 >crl.d/crlnumber
cat >crl.cnf <<'CRL'
[ca]
default_ca = ca_ec
[ca_ec]
database = crl.d/index.txt
crlnumber = crl.d/crlnumber
default_md = sha256
default_crl_days = 36500
CRL
openssl ca -config crl.cnf -keyfile ca-ec.key -cert ca-ec.pem -revoke kdc-revoked.pem -batch 2>/dev/null
openssl ca -config crl.cnf -keyfile ca-ec.key -cert ca-ec.pem -gencrl -out crl-ec.pem -batch 2>/dev/null
rm -rf crl.d crl.cnf

# An OpenSSL CMS SignedData of id-pkinit-DHKeyData, signed by the kdc key.
printf 'pkinit-dhkeydata-fixture' >dhkeydata.der
openssl cms -sign -binary -nodetach -nosmimecap -md sha256 -econtent_type 1.3.6.1.5.2.3.2 \
  -in dhkeydata.der -signer kdc.pem -inkey kdc.key -outform DER -out cms-dhkeydata.der

# Key-agreement answers: two modp_2048 keys and two P-256 keys, raw private
# values and public values, and the shared secrets OpenSSL derives.
openssl genpkey -genparam -algorithm DH -pkeyopt group:modp_2048 -out dh-params.pem
for side in a b; do
  openssl genpkey -paramfile dh-params.pem -out "dh-$side.pem"
  openssl pkey -in "dh-$side.pem" -pubout -out "dh-$side.pub"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "ec-$side.pem"
  openssl pkey -in "ec-$side.pem" -pubout -out "ec-$side.pub"
done
openssl pkeyutl -derive -inkey dh-a.pem -peerkey dh-b.pub -pkeyopt dh_pad:1 -out dh-shared.bin
openssl pkeyutl -derive -inkey ec-a.pem -peerkey ec-b.pub -out ec-shared.bin
# The raw values in hex: private exponent of a, public value of b.
priv_hex() { openssl pkey -in "$1" -text -noout | awk '/^(private|priv)/{f=1;next} /^(public|pub)/{f=0} f' | tr -d ' :\n'; }
pub_hex() { openssl pkey -in "$1" -text -noout | awk '/^(public|pub)/{f=1;next} /^(P|p):|^ASN1|^NIST|^GROUP|^prime|^generator|^Q:/{f=0} f' | tr -d ' :\n'; }
priv_hex dh-a.pem >dh-a.priv.hex
pub_hex dh-b.pem >dh-b.pub.hex
priv_hex ec-a.pem >ec-a.priv.hex
pub_hex ec-b.pem >ec-b.pub.hex
rm -f dh-a.pem ec-a.pem dh-params.pem dh-a.pub dh-b.pub ec-a.pub ec-b.pub dh-b.pem ec-b.pem ext.cnf ./*.srl
rm -f ca-ec.key ca-rsa.key ca-other.key
chmod 0644 ./*
