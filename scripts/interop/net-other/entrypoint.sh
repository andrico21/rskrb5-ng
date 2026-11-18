#!/bin/bash
# Entrypoint of the second MIT realm fixture `mit-other` (lane 1D-b). Runs in
# the mit-kdc image (MIT krb5 1.22.2), bind-mounted read-only at
# /opt/interop/net-other with KRB5_CONFIG/KRB5_KDC_PROFILE pointing here.
#
# 1. Waits (bounded) for the per-run secrets in the tmpfs /run/interop/secrets.
# 2. Creates the OTHER.RSKRB5 and FAR.EXAMPLE databases and principals
#    (idempotent) and exports the keytabs to /run/interop/out:
#      OTHER.RSKRB5: otheruser (password), HTTP/http.other.rskrb5 (random,
#        +no_auth_data_required like the TEST services), admin/admin,
#        krbtgt/OTHER.RSKRB5@TEST.RSKRB5 and krbtgt/TEST.RSKRB5@OTHER.RSKRB5
#        (the TEST trust, cross-realm password), krbtgt/FAR.EXAMPLE@OTHER.RSKRB5
#        and krbtgt/OTHER.RSKRB5@FAR.EXAMPLE (the FAR trust).
#      FAR.EXAMPLE: HTTP/http.far.example (random, +no_auth_data_required) and
#        the two FAR trust principals.
# 3. Starts kadmind (OTHER.RSKRB5) and one krb5kdc serving both realms, waits
#    (bounded) for ports 88/464/749, writes /run/interop/ready, and exits
#    non-zero naming the fixture as soon as a daemon exits.
# No secret is printed.
set -euo pipefail

readonly FIXTURE=mit-other
readonly RUN_DIR=/run/interop
readonly SECRETS="$RUN_DIR/secrets"
readonly READY="$RUN_DIR/ready"
readonly OUT="$RUN_DIR/out"
readonly OTHER=OTHER.RSKRB5
readonly FAR=FAR.EXAMPLE
readonly TEST=TEST.RSKRB5

log() {
  printf 'interop[%s]: %s\n' "$FIXTURE" "$*" >&2
}

fail() {
  log "FAILED: $*"
  exit 1
}

wait_for_secrets() {
  local limit="${INTEROP_SECRETS_TIMEOUT:-120}" waited=0
  while [[ ! -f "$SECRETS" ]]; do
    ((waited < limit)) || fail "no secrets were delivered to $SECRETS within ${limit}s"
    sleep 1
    waited=$((waited + 1))
  done
}

load_secrets() {
  local name value
  while IFS='=' read -r name value; do
    [[ "$name" =~ ^INTEROP_[A-Z0-9_]+$ ]] || fail "malformed secret name in $SECRETS"
    [[ "$value" =~ ^[A-Za-z0-9]+$ ]] || fail "secret $name has characters outside [A-Za-z0-9]"
    printf -v "$name" '%s' "$value"
    export "${name?}"
  done <"$SECRETS"
}

# kadmin_query REALM QUERY EXPECT: fails unless the output contains EXPECT.
kadmin_query() {
  local realm="$1" query="$2" expect="$3" output
  output="$(kadmin.local -r "$realm" -q "$query" 2>&1)" || fail "kadmin.local -r $realm failed: ${query%% -pw *}"
  [[ "$output" == *"$expect"* ]] || fail "kadmin.local -r $realm did not report \"$expect\" for: ${query%% -pw *}"
}

# ensure REALM NAME [addprinc options...]: creates NAME (a full principal) once.
ensure() {
  local realm="$1" name="$2"
  shift 2
  if kadmin.local -r "$realm" -q "getprinc $name" 2>/dev/null | grep -q '^Principal: '; then
    return 0
  fi
  kadmin_query "$realm" "addprinc $* $name" "Principal \"$name\" created"
  log "created $name in the $realm database"
}

export_keytab() {
  local realm="$1" file="$OUT/$2" name="$3"
  rm -f "$file"
  kadmin_query "$realm" "ktadd -k $file -norandkey $name" "added to keytab"
  log "exported $name to out/$2"
}

create_database() {
  local realm="$1" stash="/var/lib/krb5kdc/.k5.$1"
  [[ -f "$stash" ]] && return 0
  # The master password protects the stash on this container's tmpfs only.
  kdb5_util -r "$realm" create -s -P "$(head -c 48 /dev/urandom | base64 -w0)" >/dev/null
  log "created the $realm database"
}

provision() {
  : "${INTEROP_MIT_OTHER_USER_PASSWORD:?}" "${INTEROP_MIT_OTHER_ADMIN_PASSWORD:?}"
  : "${INTEROP_MIT_OTHER_CROSS_REALM_SECRET:?}" "${INTEROP_MIT_OTHER_FAR_CROSS_REALM_SECRET:?}"
  create_database "$OTHER"
  create_database "$FAR"
  local realm
  for realm in "$OTHER" "$FAR"; do
    ensure "$realm" "krbtgt/$FAR@$OTHER" -pw "$INTEROP_MIT_OTHER_FAR_CROSS_REALM_SECRET"
    ensure "$realm" "krbtgt/$OTHER@$FAR" -pw "$INTEROP_MIT_OTHER_FAR_CROSS_REALM_SECRET"
  done
  ensure "$OTHER" "krbtgt/$OTHER@$TEST" -pw "$INTEROP_MIT_OTHER_CROSS_REALM_SECRET"
  ensure "$OTHER" "krbtgt/$TEST@$OTHER" -pw "$INTEROP_MIT_OTHER_CROSS_REALM_SECRET"
  ensure "$OTHER" "otheruser@$OTHER" -pw "$INTEROP_MIT_OTHER_USER_PASSWORD"
  ensure "$OTHER" "admin/admin@$OTHER" -pw "$INTEROP_MIT_OTHER_ADMIN_PASSWORD"
  ensure "$OTHER" "HTTP/http.other.rskrb5@$OTHER" +no_auth_data_required -randkey
  ensure "$FAR" "HTTP/http.far.example@$FAR" +no_auth_data_required -randkey
  export_keytab "$OTHER" otheruser.keytab "otheruser@$OTHER"
  export_keytab "$OTHER" http-other.keytab "HTTP/http.other.rskrb5@$OTHER"
  export_keytab "$FAR" http-far.keytab "HTTP/http.far.example@$FAR"
}

tcp_open() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

wait_for_ports() {
  local limit="${INTEROP_DAEMON_TIMEOUT:-60}" waited=0 port
  for port in 88 464 749; do
    until tcp_open "$port"; do
      ((waited < limit)) || fail "port $port did not accept connections within ${limit}s"
      sleep 1
      waited=$((waited + 1))
    done
  done
}

main() {
  umask 077
  mkdir -p "$OUT" /var/log/krb5
  rm -f "$READY"
  wait_for_secrets
  load_secrets
  provision
  kadmind -nofork -r "$OTHER" &
  local kadmind_pid=$!
  krb5kdc -n -r "$OTHER" -r "$FAR" &
  local kdc_pid=$!
  trap 'kill "$kadmind_pid" "$kdc_pid" 2>/dev/null; exit 143' TERM INT
  wait_for_ports
  : >"$READY"
  log "ready (krb5kdc pid $kdc_pid for $OTHER and $FAR, kadmind pid $kadmind_pid)"
  local status=0
  wait -n "$kadmind_pid" "$kdc_pid" || status=$?
  fail "a daemon exited with status $status"
}

main "$@"
