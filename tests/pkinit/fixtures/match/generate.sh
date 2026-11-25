#!/bin/bash
# Provenance of the pkinit_cert_match fixtures (plan 2 todo 28, MIT-config-51):
# generated with the OpenSSL CLI, independently of rskrb5-ng. The expected
# DN renderings in subjects.tsv are what `openssl x509 -nameopt sep_comma_plus`
# prints, which is MIT krb5 1.22.2 `pkinit_crypto_openssl.c:4769-4784`
# (`rfc2253_name`: `X509_NAME_print_ex(b, name, 0, XN_FLAG_SEP_COMMA_PLUS)`).
# Re-running replaces every key and certificate. Run from this directory:
#   bash generate.sh
# Every identity is EC P-256 (a software identity signs with EC keys only) and
# is issued by one of two throwaway CAs whose keys are deleted afterwards.
#   user    MIT t_pkinit.py's p12_identity analog: O=KRBTEST.COM,CN=user, SAN
#           user@KRBTEST.COM, EKU id-pkinit-KPClientAuth, KU digitalSignature + keyEncipherment
#   generic MIT t_pkinit.py's p12_generic_identity analog: O=KRBTEST.COM,CN=user, issuer O=MIT, no PKINIT SAN/EKU
#   alice   O=KRBTEST.COM,CN=alice, SAN alice@TEST.RSKRB5 and UPN alice@upn.test, EKU pkinit, KU ds+ke
#   bob     O=KRBTEST.COM,CN=bob, SAN bob@TEST.RSKRB5, EKU clientAuth + emailProtection, KU ds
#   carol   O=OTHER.COM,CN=carol, issuer O=OTHER CA, no SAN, EKU msScLogin + clientAuth, no KU
#   doe     O=Example,CN=John DoE, SAN john@EXAMPLE.COM, EKU msScLogin + clientAuth, KU ds, issuer O=DoE CA
#   erin    C=CH,O=Zurich, AG\+x,CN=<CJK>+UID=u1,emailAddress=...: multi-valued RDN, a comma and plus, non-ASCII
#   frank   SANs frank/admin@TEST.RSKRB5 and fr@nk@TEST.RSKRB5 (krb5_unparse_name quoting)
set -euo pipefail
export LC_ALL=C
DAYS=36500
umask 077

cat >ext.cnf <<'EXT'
[user]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = 1.3.6.1.5.2.3.4
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:user_name
[generic]
basicConstraints = CA:FALSE
[alice]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = 1.3.6.1.5.2.3.4
subjectAltName = @alice_sans
[bob]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth, emailProtection
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:bob_name
[carol]
basicConstraints = CA:FALSE
extendedKeyUsage = 1.3.6.1.4.1.311.20.2.2, clientAuth
[doe]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = 1.3.6.1.4.1.311.20.2.2, clientAuth
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:doe_name
[erin]
basicConstraints = CA:FALSE
keyUsage = keyEncipherment
[frank]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = 1.3.6.1.5.2.3.4
subjectAltName = @frank_sans
[alice_sans]
otherName.1 = 1.3.6.1.5.2.2;SEQUENCE:alice_name
otherName.2 = 1.3.6.1.4.1.311.20.2.3;UTF8:alice@upn.test
DNS.1 = alice.example.test
[frank_sans]
otherName.1 = 1.3.6.1.5.2.2;SEQUENCE:frank_admin_name
otherName.2 = 1.3.6.1.5.2.2;SEQUENCE:frank_at_name
[user_name]
realm = EXP:0,GeneralString:KRBTEST.COM
principal_name = EXP:1,SEQUENCE:user_seq
[user_seq]
name_type = EXP:0,INTEGER:1
name_string = EXP:1,SEQUENCE:user_parts
[user_parts]
p1 = GeneralString:user
[alice_name]
realm = EXP:0,GeneralString:TEST.RSKRB5
principal_name = EXP:1,SEQUENCE:alice_seq
[alice_seq]
name_type = EXP:0,INTEGER:1
name_string = EXP:1,SEQUENCE:alice_parts
[alice_parts]
p1 = GeneralString:alice
[bob_name]
realm = EXP:0,GeneralString:TEST.RSKRB5
principal_name = EXP:1,SEQUENCE:bob_seq
[bob_seq]
name_type = EXP:0,INTEGER:1
name_string = EXP:1,SEQUENCE:bob_parts
[bob_parts]
p1 = GeneralString:bob
[doe_name]
realm = EXP:0,GeneralString:EXAMPLE.COM
principal_name = EXP:1,SEQUENCE:doe_seq
[doe_seq]
name_type = EXP:0,INTEGER:1
name_string = EXP:1,SEQUENCE:doe_parts
[doe_parts]
p1 = GeneralString:john
[frank_admin_name]
realm = EXP:0,GeneralString:TEST.RSKRB5
principal_name = EXP:1,SEQUENCE:frank_admin_seq
[frank_admin_seq]
name_type = EXP:0,INTEGER:1
name_string = EXP:1,SEQUENCE:frank_admin_parts
[frank_admin_parts]
p1 = GeneralString:frank
p2 = GeneralString:admin
[frank_at_name]
realm = EXP:0,GeneralString:TEST.RSKRB5
principal_name = EXP:1,SEQUENCE:frank_at_seq
[frank_at_seq]
name_type = EXP:0,INTEGER:1
name_string = EXP:1,SEQUENCE:frank_at_parts
[frank_at_parts]
p1 = GeneralString:fr@nk
EXT

ec() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }
ca() { # NAME SUBJECT
  ec "$1.key"
  openssl req -new -x509 -key "$1.key" -sha256 -days "$DAYS" -utf8 -subj "$2" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" -out "$1.pem"
}
# leaf NAME CA SUBJECT SECTION
leaf() {
  ec "$1.key"
  openssl req -new -key "$1.key" -utf8 -subj "$3" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" -CAcreateserial -sha256 \
    -days "$DAYS" -extfile ext.cnf -extensions "$4" -out "$1.pem"
  rm -f "$1.csr"
}

ca ca-mit '/O=MIT/CN=match CA'
ca ca-doe '/O=DoE CA/CN=ca'
ca ca-other '/O=OTHER CA/CN=ca'
leaf user ca-mit '/O=KRBTEST.COM/CN=user' user
leaf generic ca-mit '/O=KRBTEST.COM/CN=user' generic
leaf alice ca-mit '/O=KRBTEST.COM/CN=alice' alice
leaf bob ca-mit '/O=KRBTEST.COM/CN=bob' bob
leaf carol ca-other '/O=OTHER.COM/CN=carol' carol
leaf doe ca-doe '/O=Example/CN=John DoE' doe
leaf erin ca-mit '/C=CH/O=Zurich, AG\+x/CN=中文+UID=u1/emailAddress=erin@example.test' erin
leaf frank ca-mit '/O=KRBTEST.COM/CN=frank' frank
rm -f ext.cnf ca-*.key ca-*.srl ca-*.pem

# The expected DN renderings: what OpenSSL prints for MIT's flags.
: >subjects.tsv
for name in user generic alice bob carol doe erin frank; do
  subject=$(openssl x509 -in "$name.pem" -noout -subject -nameopt sep_comma_plus)
  issuer=$(openssl x509 -in "$name.pem" -noout -issuer -nameopt sep_comma_plus)
  printf '%s\t%s\t%s\n' "$name" "${subject#subject=}" "${issuer#issuer=}" >>subjects.tsv
done
