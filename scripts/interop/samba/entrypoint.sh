#!/bin/bash
# Entrypoint of the Samba AD DC interop fixtures `samba-user` (USER.RSKRB5)
# and `samba-res` (RES.RSKRB5); SAMBA_ROLE (user | res) selects the domain.
#
# 1. Waits (bounded) for run.sh to stream the per-run secrets into the tmpfs
#    file /run/interop/secrets (NAME=value lines, values [A-Za-z0-9] only).
# 2. Points the container's resolver at its own Samba DNS server and makes the
#    runtime's DNS server (which knows every container's network alias, e.g.
#    dcres.res.rskrb5) Samba's `dns forwarder`.
# 3. Provisions the domain on tmpfs (/var/lib/samba) with the settings listed
#    in provision_domain, starts `samba` in the foreground, waits (bounded)
#    until its KDC, kpasswd, LDAP, LDAPS and DNS ports accept TCP connections,
#    runs setup-<role>.sh (accounts, SPNs, delegation, claims, keytabs) and
#    writes /run/interop/ready. run.sh waits for that marker; the trust and the
#    self-check run afterwards from fixture.sh (trust.sh, selfcheck.sh).
# 4. Exits non-zero, naming the fixture, as soon as samba exits.
# No secret is ever printed: tool output that may echo one stays on tmpfs and
# only its last lines are shown on failure (run.sh redacts container logs).
set -euo pipefail

# shellcheck source=scripts/interop/samba/lib-dc.sh
source /opt/interop/samba/lib-dc.sh

wait_for_secrets() {
  local limit="${INTEROP_SECRETS_TIMEOUT:-120}" waited=0
  while [[ ! -f "$SECRETS" ]]; do
    ((waited < limit)) || fail "no secrets were delivered to $SECRETS within ${limit}s"
    sleep 1
    waited=$((waited + 1))
  done
}

# Writes the MIT client profile (both realms) and the resolver configuration;
# prints the runtime's DNS server, which becomes Samba's forwarder.
configure_resolver() {
  local forwarder
  forwarder="$(awk '$1 == "nameserver" { print $2; exit }' /etc/resolv.conf)"
  [[ -n "$forwarder" ]] || fail "no nameserver in /etc/resolv.conf"
  sed "s/@DEFAULT_REALM@/$REALM/" /opt/interop/samba/krb5.conf >/etc/krb5.conf
  printf 'search %s\nnameserver 127.0.0.1\n' "$DNS_DOMAIN" >/etc/resolv.conf
  printf '%s' "$forwarder"
}

# Provisions the domain. Settings (each one recorded in fixture.sh):
# - ad dc functional level / --function-level 2016 (FUNCTION_LEVEL in
#   lib-dc.sh): Kerberos claims, authentication policies, compound identity
#   (Samba 4.20+);
# - ldap server require strong auth = yes: LDAP accepts only simple binds and
#   SASL binds with correct TLS channel bindings over TLS, and SASL binds with
#   sign or seal on unencrypted connections (Windows LdapEnforceChannelBinding=2);
# - tls enabled = yes: LDAPS on 636 with the self-signed CA Samba generates in
#   /var/lib/samba/private/tls (exported as ldaps-ca.pem);
# - kdc enable fast = yes: the embedded Heimdal KDC answers FAST (RFC 6113);
# - vfs objects = dfs_samba4 acl_xattr xattr_tdb: NT ACLs are kept in a TDB
#   instead of security.* extended attributes, so no CAP_SYS_ADMIN is needed;
# - dns forwarder: the runtime's DNS server (container aliases).
provision_domain() {
  local forwarder="$1" admin_password="$2" log="$RUN_DIR/provision.log"
  if ! samba-tool domain provision --realm="$REALM" --domain="$NETBIOS" \
    --server-role=dc --dns-backend=SAMBA_INTERNAL --host-name="$DC_NAME" \
    --adminpass="$admin_password" --function-level="$FUNCTION_LEVEL" \
    --option="ad dc functional level = $FUNCTION_LEVEL" \
    --option="ldap server require strong auth = yes" \
    --option="tls enabled = yes" \
    --option="kdc enable fast = yes" \
    --option="vfs objects = dfs_samba4 acl_xattr xattr_tdb" \
    --option="dns forwarder = $forwarder" >"$log" 2>&1; then
    tail_scrubbed 25 "$log"
    fail "samba-tool domain provision failed"
  fi
  log "provisioned $REALM (NetBIOS $NETBIOS, DC $DC_NAME.$DNS_DOMAIN, functional level $FUNCTION_LEVEL, forwarder $forwarder)"
}

wait_for_ports() {
  local limit="${INTEROP_DAEMON_TIMEOUT:-120}" waited=0 port
  for port in 88 464 389 636 53; do
    until tcp_open "$port"; do
      ((waited < limit)) || fail "port $port did not accept connections within ${limit}s"
      kill -0 "$1" 2>/dev/null || fail "samba exited before port $port listened"
      sleep 1
      waited=$((waited + 1))
    done
  done
}

main() {
  umask 077
  mkdir -p "$RUN_DIR/out"
  rm -f "$READY"
  wait_for_secrets
  load_secrets
  local forwarder admin_variable
  forwarder="$(configure_resolver)"
  admin_variable="INTEROP_SAMBA_${ROLE_UPPER}_ADMIN_PASSWORD"
  provision_domain "$forwarder" "${!admin_variable:?}"
  samba --foreground --no-process-group --debug-stdout --debuglevel=1 &
  local samba_pid=$!
  trap 'kill "$samba_pid" 2>/dev/null; exit 143' TERM INT
  wait_for_ports "$samba_pid"
  bash "/opt/interop/samba/setup-$SAMBA_ROLE.sh" || fail "setup-$SAMBA_ROLE.sh failed"
  cp /var/lib/samba/private/tls/ca.pem "$RUN_DIR/out/ldaps-ca.pem"
  : >"$READY"
  log "ready (samba pid $samba_pid)"
  local status=0
  wait "$samba_pid" || status=$?
  fail "samba exited with status $status"
}

main "$@"
