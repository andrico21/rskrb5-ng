#!/bin/sh
# Regenerates the RFC 5929 `tls-server-end-point` fixtures of
# tests/http_client/channel.rs (provenance of the files in this directory).
# OpenSSL 3 (generated with 3.5.5) signs one self-signed certificate per
# signature algorithm and computes the expected binding hash independently of
# the crate: RFC 5929 section 4.1 hashes the DER certificate with the hash of
# its signature algorithm, SHA-256 when that hash is MD5 or SHA-1, and defines
# no binding for an algorithm without exactly one hash (Ed25519, an RSASSA-PSS
# signature whose MGF1 hash differs from its message hash). The private keys
# are deleted: the certificates are only parsed and hashed.
# Output: <name>.der and expected.txt (`<name> <hash or none> <hex digest>`).
set -eu
cd "$(dirname "$0")"
days=36500
key=$(mktemp)
trap 'rm -f "$key"' EXIT
rm -f ./*.der expected.txt
cert() { # name keyspec hash(for expected.txt) openssl signing options...
  name=$1 spec=$2 hash=$3
  shift 3
  case "$spec" in
    rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key" 2>/dev/null ;;
    p256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$key" ;;
    p384) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$key" ;;
    ed25519) openssl genpkey -algorithm ED25519 -out "$key" ;;
  esac
  openssl req -x509 -new -key "$key" -days "$days" -subj "/CN=rskrb5-ng cbt $name" \
    -outform DER -out "$name.der" "$@"
  if [ "$hash" = none ]; then
    printf '%s none -\n' "$name" >>expected.txt
  else
    printf '%s %s %s\n' "$name" "$hash" \
      "$(openssl dgst "-$hash" -r "$name.der" | cut -d' ' -f1)" >>expected.txt
  fi
}
cert rsa-md5 rsa sha256 -md5
cert rsa-sha1 rsa sha256 -sha1
cert rsa-sha224 rsa sha224 -sha224
cert rsa-sha256 rsa sha256 -sha256
cert rsa-sha512 rsa sha512 -sha512
cert ecdsa-sha256 p256 sha256 -sha256
cert ecdsa-sha384 p384 sha384 -sha384
cert pss-sha384 rsa sha384 -sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_mgf1_md:sha384
cert pss-sha1 rsa sha256 -sha1 -sigopt rsa_padding_mode:pss -sigopt rsa_mgf1_md:sha1
cert pss-mixed rsa none -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_mgf1_md:sha384
cert ed25519 ed25519 none
