#!/bin/bash
# Self-check of the Samba AD fixtures, run by fixture.sh inside the
# samba-user container after the trust exists. It proves every fixture
# feature with the MIT reference tools (and OpenLDAP for channel bindings)
# and asserts the mechanism actually used, so a running but misconfigured
# fixture fails here, naming itself:
#   1. password kinit in both domains: encrypted-timestamp pre-authentication
#      (KRB5_TRACE) and an aes256-cts-hmac-sha1-96 TGT (klist -e);
#   2. the trust in both directions: cross-realm TGTs and service tickets;
#   3. a referral of a host-based service name across the forest trust;
#   4. the delegation attributes in sam.ldb (ldbsearch, samba-tool);
#   5. S4U2Self + S4U2Proxy (kvno -U -P): constrained delegation and RBCD
#      allowed for the configured pair, refused by the KDC for another target;
#   6. a kpasswd password change of the disposable account kpasswdcheck;
#   7. LDAP channel-binding enforcement: a GSSAPI bind over LDAPS (no SASL
#      security layer, maxssf=0, as TLS already protects it) succeeds with
#      tls-endpoint channel bindings and is refused with SEC_E_BAD_BINDINGS
#      (0x80090346) without them.
# Output carries principal names and mechanism lines only, never a secret.
set -euo pipefail
# shellcheck source=scripts/interop/samba/lib-dc.sh
source /opt/interop/samba/lib-dc.sh
load_secrets
[[ "$SAMBA_ROLE" == user ]] || fail "selfcheck.sh runs in the samba-user container"

readonly WORK="$RUN_DIR/selfcheck"
rm -rf "$WORK"
mkdir -m 700 "$WORK"

passed() {
  log "self-check: $*"
}

# require FILE REGEX WHAT [LABEL]: fails unless a line of FILE matches REGEX;
# with LABEL, reports the first matching line as "LABEL: <line>".
require() {
  local line
  line="$(grep -m1 -E -- "$2" "$1")" || {
    tail_scrubbed 20 "$1"
    fail "self-check: $3: no line matches /$2/"
  }
  if [[ -n "${4:-}" ]]; then
    passed "$4: $line"
  fi
}

# kinit_password NAME PRINCIPAL PASSWORD_VARIABLE: a TGT in $WORK/NAME.cc,
# the trace in $WORK/NAME.trace.
kinit_password() {
  local name="$1" principal="$2" variable="$3"
  printf '%s\n' "${!variable:?}" |
    KRB5_TRACE="$WORK/$name.trace" KRB5CCNAME="FILE:$WORK/$name.cc" kinit "$principal" >"$WORK/$name.out" 2>&1 || {
    tail_scrubbed 20 "$WORK/$name.trace"
    fail "self-check: kinit $principal failed"
  }
}

# kinit_keytab NAME PRINCIPAL KEYTAB
kinit_keytab() {
  KRB5_TRACE="$WORK/$1.trace" KRB5CCNAME="FILE:$WORK/$1.cc" kinit -k -t "$OUT/$3" "$2" >"$WORK/$1.out" 2>&1 || {
    tail_scrubbed 20 "$WORK/$1.trace"
    fail "self-check: kinit -k $2 failed"
  }
}

# kvno_as CACHE LOG ARGS...: kvno with $WORK/CACHE.cc; trace and output in $WORK/LOG.*
kvno_as() {
  local cache="$1" logname="$2"
  shift 2
  KRB5_TRACE="$WORK/$logname.trace" KRB5CCNAME="FILE:$WORK/$cache.cc" kvno "$@" >"$WORK/$logname.out" 2>&1
}

check_login() {
  local name="$1" principal="$2" variable="$3" realm="${2#*@}"
  kinit_password "$name" "$principal" "$variable"
  require "$WORK/$name.trace" 'Preauth module encrypted_timestamp \(2\) \(real\) returned: 0/Success' "encrypted-timestamp pre-authentication of $principal" "kinit $principal"
  KRB5CCNAME="FILE:$WORK/$name.cc" klist -e >"$WORK/$name.klist" 2>&1
  require "$WORK/$name.klist" "^Default principal: $principal\$" "default principal of $principal"
  require "$WORK/$name.klist" "krbtgt/$realm@$realm\$" "TGT of $principal"
  require "$WORK/$name.klist" 'Etype \(skey, tkt\): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96' "AES256 TGT of $principal" "TGT of $principal"
}

check_trust() {
  local cache="$1" service="$2" crossed="$3"
  kvno_as "$cache" "trust-$cache" "$service" || {
    tail_scrubbed 20 "$WORK/trust-$cache.trace"
    fail "self-check: cross-trust kvno $service failed"
  }
  KRB5CCNAME="FILE:$WORK/$cache.cc" klist -e >"$WORK/trust-$cache.klist" 2>&1
  require "$WORK/trust-$cache.klist" "$crossed" "cross-realm TGT $crossed"
  require "$WORK/trust-$cache.out" "^$service: kvno = [0-9]+" "service ticket $service" "trust via $crossed"
}

check_referral() {
  local profile="$WORK/krb5-no-domain-realm.conf"
  sed '/^\[domain_realm\]/,$d' /etc/krb5.conf >"$profile"
  kinit_password referral testuser1@USER.RSKRB5 INTEROP_SAMBA_USER_USER_PASSWORD
  KRB5_CONFIG="$profile" KRB5_TRACE="$WORK/referral.trace" KRB5CCNAME="FILE:$WORK/referral.cc" \
    kvno -S HTTP host.res.rskrb5 >"$WORK/referral.out" 2>&1 || {
    tail_scrubbed 20 "$WORK/referral.trace"
    fail "self-check: referral of HTTP/host.res.rskrb5 across the trust failed"
  }
  require "$WORK/referral.trace" 'referral.*krbtgt/RES\.RSKRB5@USER\.RSKRB5|krbtgt/RES\.RSKRB5@USER\.RSKRB5.*referral' "referral TGT to RES.RSKRB5" "referral"
  require "$WORK/referral.out" '^HTTP/host\.res\.rskrb5@[A-Z.]*: kvno = [0-9]+' "service ticket after the referral" "referral"
  KRB5CCNAME="FILE:$WORK/referral.cc" klist >"$WORK/referral.klist" 2>&1
  require "$WORK/referral.klist" 'HTTP/host\.res\.rskrb5@RES\.RSKRB5' "RES.RSKRB5 service ticket after the referral" "referral"
}

check_delegation_attributes() {
  ldbsearch -H /var/lib/samba/private/sam.ldb '(sAMAccountName=svc-s4u)' \
    msDS-AllowedToDelegateTo userAccountControl >"$WORK/svc-s4u.ldif" 2>&1
  require "$WORK/svc-s4u.ldif" '^msDS-AllowedToDelegateTo: HTTP/backend\.user\.rskrb5$' "constrained-delegation target of svc-s4u" "ldbsearch svc-s4u"
  local uac
  require "$WORK/svc-s4u.ldif" '^userAccountControl: [0-9]+$' "userAccountControl of svc-s4u"
  uac="$(grep -m1 -E '^userAccountControl: [0-9]+$' "$WORK/svc-s4u.ldif")"
  ((${uac##* } & 0x01000000)) || fail "self-check: svc-s4u lacks UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION ($uac)"
  passed "ldbsearch svc-s4u: $uac (UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION set)"
  ldbsearch -H /var/lib/samba/private/sam.ldb '(sAMAccountName=svc-rbcd)' \
    msDS-AllowedToDelegateTo userAccountControl >"$WORK/svc-rbcd.ldif" 2>&1
  require "$WORK/svc-rbcd.ldif" '^dn: CN=svc-rbcd,' "svc-rbcd entry"
  if grep -q '^msDS-AllowedToDelegateTo:' "$WORK/svc-rbcd.ldif"; then
    fail "self-check: svc-rbcd has msDS-AllowedToDelegateTo, so its check would not isolate RBCD"
  fi
  passed "ldbsearch svc-rbcd: no msDS-AllowedToDelegateTo (only RBCD can let it delegate)"
  samba-tool delegation show svc-backend >"$WORK/svc-backend.delegation" 2>&1
  require "$WORK/svc-backend.delegation" 'svc-rbcd' "RBCD principal of svc-backend" "samba-tool delegation show svc-backend"
}

# check_s4u NAME PRINCIPAL KEYTAB: S4U2Self for s4uclient, then S4U2Proxy to
# HTTP/backend (allowed) and HTTP/denied (refused by the KDC).
check_s4u() {
  local name="$1" principal="$2" keytab="$3"
  kinit_keytab "$name" "$principal" "$keytab"
  kvno_as "$name" "$name-allowed" -U s4uclient -P HTTP/backend.user.rskrb5@USER.RSKRB5 || {
    tail_scrubbed 20 "$WORK/$name-allowed.trace"
    fail "self-check: $name S4U2Proxy to HTTP/backend.user.rskrb5 failed"
  }
  require "$WORK/$name-allowed.trace" "TGS reply is for s4uclient@USER\\.RSKRB5 -> ${principal//./\\.} " \
    "S4U2Self evidence ticket of $name" "$name S4U2Self"
  require "$WORK/$name-allowed.trace" 'TGS reply is for s4uclient@USER\.RSKRB5 -> HTTP/backend\.user\.rskrb5@USER\.RSKRB5 ' \
    "S4U2Proxy reply of $name" "$name S4U2Proxy"
  KRB5CCNAME="FILE:$WORK/$name.cc" klist |
    awk '/ HTTP\/backend\.user\.rskrb5@USER\.RSKRB5$/ { getline; print }' >"$WORK/$name.proxied" 2>&1
  require "$WORK/$name.proxied" 'for client s4uclient@USER\.RSKRB5' "delegated ticket for s4uclient" \
    "$name allowed: HTTP/backend.user.rskrb5@USER.RSKRB5"
  if kvno_as "$name" "$name-denied" -U s4uclient -P HTTP/denied.user.rskrb5@USER.RSKRB5; then
    fail "self-check: $name obtained a delegated ticket for HTTP/denied.user.rskrb5"
  fi
  require "$WORK/$name-denied.trace" "Got cred; -1765328371/KDC can't fulfill requested option" \
    "KDC refusal (KDC_ERR_BADOPTION) of $name to HTTP/denied" "$name denied"
}

check_kpasswd() {
  printf '%s\n%s\n%s\n' "${INTEROP_SAMBA_USER_KPASSWD_CHECK_PASSWORD:?}" \
    "${INTEROP_SAMBA_USER_KPASSWD_CHECK_NEW_PASSWORD:?}" "$INTEROP_SAMBA_USER_KPASSWD_CHECK_NEW_PASSWORD" |
    KRB5_TRACE="$WORK/kpasswd.trace" KRB5CCNAME="FILE:$WORK/kpasswd.cc" kpasswd kpasswdcheck@USER.RSKRB5 >"$WORK/kpasswd.out" 2>&1 || {
    tail_scrubbed 20 "$WORK/kpasswd.trace"
    fail "self-check: kpasswd of kpasswdcheck failed"
  }
  require "$WORK/kpasswd.out" '^Password changed\.$' "kpasswd result" "kpasswd kpasswdcheck"
  require "$WORK/kpasswd.trace" 'kadmin/changepw@USER\.RSKRB5' "kadmin/changepw ticket" "kpasswd kpasswdcheck"
  kinit_password kpasswd-new kpasswdcheck@USER.RSKRB5 INTEROP_SAMBA_USER_KPASSWD_CHECK_NEW_PASSWORD
  passed "kpasswd kpasswdcheck: the new password logs in"
}

check_channel_bindings() {
  local uri=ldaps://dcuser.user.rskrb5 cache="FILE:$WORK/testuser1.cc"
  LDAPTLS_CACERT="$OUT/ldaps-ca.pem" LDAPSASL_CBINDING=tls-endpoint KRB5CCNAME="$cache" \
    ldapwhoami -Q -O maxssf=0 -Y GSSAPI -H "$uri" >"$WORK/cbt-bound.out" 2>&1 || {
    tail_scrubbed 10 "$WORK/cbt-bound.out"
    fail "self-check: GSSAPI bind over LDAPS with tls-endpoint channel bindings failed"
  }
  require "$WORK/cbt-bound.out" '^u:USER\\testuser1$' "LDAP identity" "LDAPS GSSAPI with channel bindings"
  if LDAPTLS_CACERT="$OUT/ldaps-ca.pem" LDAPSASL_CBINDING=none KRB5CCNAME="$cache" \
    ldapwhoami -Q -O maxssf=0 -Y GSSAPI -H "$uri" >"$WORK/cbt-unbound.out" 2>&1; then
    fail "self-check: a GSSAPI bind over LDAPS without channel bindings was accepted"
  fi
  require "$WORK/cbt-unbound.out" '80090346' "LDAP refusal with SEC_E_BAD_BINDINGS (0x80090346)" \
    "LDAPS GSSAPI without channel bindings refused"
}

check_login testuser1 testuser1@USER.RSKRB5 INTEROP_SAMBA_USER_USER_PASSWORD
check_login resuser resuser@RES.RSKRB5 INTEROP_SAMBA_RES_USER_PASSWORD
check_trust testuser1 HTTP/host.res.rskrb5@RES.RSKRB5 'krbtgt/RES\.RSKRB5@USER\.RSKRB5'
check_trust resuser HTTP/user2.user.rskrb5@USER.RSKRB5 'krbtgt/USER\.RSKRB5@RES\.RSKRB5'
check_referral
check_delegation_attributes
check_s4u s4u svc-s4u@USER.RSKRB5 svc-s4u.keytab
check_s4u rbcd svc-rbcd@USER.RSKRB5 svc-rbcd.keytab
check_kpasswd
check_channel_bindings
rm -rf "$WORK"
passed "all checks passed"
