#!/bin/sh
# Regenerates the test PKI of tests/kkdcp.rs (provenance of the files in this
# directory). OpenSSL, EC P-256 keys, 36500-day validity; the private keys are
# test-only and protect nothing.
set -eu
cd "$(dirname "$0")"
days=36500
ext=$(mktemp)
trap 'rm -f "$ext" ./*.csr ./*.srl' EXIT
for ca in ca other-ca; do
  openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$ca.key" -out "$ca.pem" -days "$days" -subj "/CN=rskrb5-ng kkdcp test $ca" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
done
leaf() { # name ca subjectAltName
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$1.key" -out "$1.csr" -subj "/CN=$1"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$3" > "$ext"
  openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" -CAcreateserial \
    -out "$1.pem" -days "$days" -extfile "$ext"
  openssl pkcs8 -topk8 -nocrypt -in "$1.key" -out "$1.p8.pem"
  mv "$1.p8.pem" "$1.key"
}
leaf localhost ca 'DNS:localhost,IP:127.0.0.1'
leaf other-host ca 'DNS:other.example'
leaf untrusted other-ca 'DNS:localhost,IP:127.0.0.1'
rm -f ca.key other-ca.key
mkdir -p anchors && cp ca.pem anchors/ca.pem
