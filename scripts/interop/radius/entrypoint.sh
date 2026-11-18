#!/bin/sh
# Entrypoint of the FreeRADIUS interop fixture `radius` (lane 1D-a).
#
# 1. Waits (bounded) for run.sh to stream the per-run secrets into the tmpfs
#    file /run/interop/secrets (NAME=value lines, values [A-Za-z0-9] only):
#    INTEROP_RADIUS_SHARED_SECRET (the RADIUS shared secret of the KDC) and
#    INTEROP_MIT_OTP_TOKEN (the password of the user otpuser).
# 2. Builds a private copy of raddb on the tmpfs with one client (any address
#    of the interop network, that secret) and one user, and logs every
#    authentication result (never a password) to stdout.
# 3. Starts radiusd, waits (bounded) until it answers an Access-Request, then
#    writes /run/interop/ready. Exits non-zero, naming the fixture, as soon as
#    radiusd exits. No secret is ever printed.
set -eu

FIXTURE=radius
RUN_DIR=/run/interop
SECRETS="$RUN_DIR/secrets"
READY="$RUN_DIR/ready"
CONF="$RUN_DIR/raddb"
RADCLIENT=/opt/bin/radclient

log() {
  printf 'interop[%s]: %s\n' "$FIXTURE" "$*" >&2
}

fail() {
  log "FAILED: $*"
  exit 1
}

wait_for_secrets() {
  limit="${INTEROP_SECRETS_TIMEOUT:-120}"
  waited=0
  while [ ! -f "$SECRETS" ]; do
    [ "$waited" -lt "$limit" ] || fail "no secrets were delivered to $SECRETS within ${limit}s"
    sleep 1
    waited=$((waited + 1))
  done
}

# Reads the two secrets; names and values are validated, never evaluated.
load_secrets() {
  shared=""
  token=""
  while IFS='=' read -r name value; do
    case "$value" in
      "" | *[!A-Za-z0-9]*) fail "secret $name is empty or has characters outside [A-Za-z0-9]" ;;
    esac
    case "$name" in
      INTEROP_RADIUS_SHARED_SECRET) shared="$value" ;;
      INTEROP_MIT_OTP_TOKEN) token="$value" ;;
      *) fail "unexpected secret name $name" ;;
    esac
  done <"$SECRETS"
  if [ -z "$shared" ] || [ -z "$token" ]; then
    fail "the shared secret or the OTP token is missing"
  fi
}

write_config() {
  cp -a /opt/etc/raddb "$CONF"
  cat >"$CONF/clients.conf" <<CLIENTS
client interop {
	ipaddr = 0.0.0.0/0
	secret = $shared
	shortname = interop
}
CLIENTS
  cat >"$CONF/mods-config/files/authorize" <<USERS
otpuser Cleartext-Password := "$token"
USERS
  # Log accepted and rejected logins (user name only, never the password).
  sed -i -e 's/^\([[:space:]]*\)auth = no/\1auth = yes/' \
    -e 's/^\([[:space:]]*\)auth_badpass = .*/\1auth_badpass = no/' \
    -e 's/^\([[:space:]]*\)auth_goodpass = .*/\1auth_goodpass = no/' "$CONF/radiusd.conf"
  chmod -R go-rwx "$CONF"
}

wait_until_answering() {
  limit="${INTEROP_DAEMON_TIMEOUT:-60}"
  waited=0
  while ! printf 'User-Name = readiness-probe\nUser-Password = x\n' |
    "$RADCLIENT" -t 1 -r 1 127.0.0.1:1812 auth "$shared" 2>&1 | grep -q 'Received Access-Reject'; do
    kill -0 "$radiusd_pid" 2>/dev/null || fail "radiusd exited before it answered"
    [ "$waited" -lt "$limit" ] || fail "radiusd did not answer within ${limit}s"
    waited=$((waited + 1))
  done
}

main() {
  umask 077
  rm -f "$READY"
  wait_for_secrets
  load_secrets
  write_config
  /opt/sbin/radiusd -f -d "$CONF" -l stdout &
  radiusd_pid=$!
  trap 'kill "$radiusd_pid" 2>/dev/null; exit 143' TERM INT
  wait_until_answering
  : >"$READY"
  log "ready (radiusd pid $radiusd_pid)"
  status=0
  wait "$radiusd_pid" || status=$?
  fail "radiusd exited with status $status"
}

main "$@"
