# shellcheck shell=bash
# Host side of the MS-KKDCP KDC proxy fixture `kdcproxy` (lane 1D-b, plan 2
# todo 1 step 2), sourced by scripts/interop/run.sh. Layout contract:
# scripts/interop/lib.sh; shared helpers: scripts/interop/net-common/net.sh.
#
# Container rskrb5-interop-kdcproxy (hostname and network alias
# kdcproxy.test.rskrb5): latchset kdcproxy 1.1.0 under gunicorn, HTTPS on 443
# with a per-run test CA generated into its tmpfs (net-kdcproxy/entrypoint.sh),
# forwarding TEST.RSKRB5 KDC and kpasswd requests to kdc.test.rskrb5 (fixture
# mit-kdc) over TCP, then UDP. Published on 127.0.0.1:
#   INTEROP_KDCPROXY_PORT (default 19143) -> 443.
# The server certificate names kdcproxy.test.rskrb5, localhost and 127.0.0.1,
# so host clients verify https://localhost:<port>/KdcProxy against
# INTEROP_KDCPROXY_CA; INTEROP_KDCPROXY_WRONG_CA is an unrelated CA for
# negative tests. No extra capability and no --privileged.
#
# Self-check (MIT 1.22.2 in a throwaway mit-kdc image container, KRB5_TRACE):
# kinit with `kdc = https://kdcproxy.test.rskrb5/KdcProxy` and `http_anchors`
# = the test CA succeeds over HTTPS with the certificate name matched; the
# same kinit anchored on the wrong CA fails with a TLS certificate error; and
# kpasswd through `kpasswd_server = https://...` changes proxypwuser's password
# (mit/provision.d/51-net-services.sh) over HTTPS.

# shellcheck source=scripts/interop/net-common/net.sh
source "$INTEROP_ROOT/scripts/interop/net-common/net.sh"

interop_fixture kdcproxy

# Client profile of the self-check: TEST.RSKRB5 only through the proxy,
# anchored on the CA file $1 (a path inside the check container).
net_kdcproxy_client_conf() {
  cat <<EOF
[libdefaults]
    default_realm = TEST.RSKRB5
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    TEST.RSKRB5 = {
        kdc = https://kdcproxy.test.rskrb5/KdcProxy
        kpasswd_server = https://kdcproxy.test.rskrb5/KdcProxy
        http_anchors = FILE:$1
    }
EOF
}

# net_kdcproxy_check NAME CA COMMAND [stdin]: runs COMMAND (MIT tools, traced)
# with the proxy profile anchored on CA (ca.pem or wrong-ca.pem); output to
# $INTEROP_STATE_DIR/kdcproxy/NAME.log; returns COMMAND's status.
net_kdcproxy_check() {
  local name="$1" ca="$2" command="$3" input="${4:-}" log
  log="$INTEROP_STATE_DIR/kdcproxy/$name.log"
  printf '%s\n' "$input" | net_check_run "kdcproxy-$name" "$INTEROP_MIT_IMAGE" -i \
    -v "$INTEROP_STATE_DIR/mit:/in/mit:ro" -v "$INTEROP_STATE_DIR/kdcproxy:/in/kdcproxy:ro" \
    -e KRB5_CONFIG=/tmp/krb5.conf -e KRB5CCNAME=FILE:/tmp/cc -e KRB5_TRACE=/dev/stderr -- \
    "set -e; printf '%s\n' \"\$0\" >/tmp/krb5.conf; $command" \
    "$(net_kdcproxy_client_conf "/in/kdcproxy/$ca")" >"$log"
}

fixture_kdcproxy_up() {
  local fixture=kdcproxy container dir out host=127.0.0.1 old new
  local port
  port="$(interop_port INTEROP_KDCPROXY_PORT 19143)" || return 1
  container="$(interop_container_name "$fixture")"
  dir="$INTEROP_ROOT/scripts/interop/net-kdcproxy"
  out="$INTEROP_STATE_DIR/kdcproxy"
  net_require_mit "$fixture" || return 1

  local image
  image="$(interop_build_image kdcproxy "$dir")" || return 1
  interop_env INTEROP_KDCPROXY_IMAGE "$image"
  interop_run_container "$fixture" "$image" \
    --hostname kdcproxy.test.rskrb5 --network-alias kdcproxy.test.rskrb5 \
    --tmpfs /run/kdcproxy:rw,mode=0700 \
    -p "$host:$port:443/tcp" || interop_die "fixture $fixture: container $container did not start" || return 1
  interop_wait_ready "$fixture" || return 1
  interop_wait_tcp "$fixture" "$host" "$port" || return 1

  interop_prepare_private_dir "$out" || return 1
  interop_copy_out "$container" /run/interop/out/ca.pem "$out/ca.pem" || return 1
  interop_copy_out "$container" /run/interop/out/wrong-ca.pem "$out/wrong-ca.pem" || return 1

  old="$(net_derive_secret kpasswd-old "$INTEROP_MIT_ADMIN_PASSWORD")" || return 1
  new="$(net_derive_secret kpasswd-new "$INTEROP_MIT_ADMIN_PASSWORD")" || return 1
  net_kdcproxy_self_check "$old" "$new" || return 1

  interop_env INTEROP_KDCPROXY_CONTAINER "$container"
  interop_env INTEROP_KDCPROXY "$host:$port"
  interop_env INTEROP_KDCPROXY_URL "https://localhost:$port/KdcProxy"
  interop_env INTEROP_KDCPROXY_CONTAINER_URL https://kdcproxy.test.rskrb5/KdcProxy
  interop_env INTEROP_KDCPROXY_CA "$out/ca.pem"
  interop_env INTEROP_KDCPROXY_WRONG_CA "$out/wrong-ca.pem"
  interop_env INTEROP_KDCPROXY_REALM TEST.RSKRB5
  interop_env INTEROP_KDCPROXY_KPASSWD_USER proxypwuser
  interop_env INTEROP_KDCPROXY_KPASSWD_USER_PASSWORD "$new"
}

# net_kdcproxy_self_check OLD NEW: the three proxy checks of the header.
net_kdcproxy_self_check() {
  local fixture=kdcproxy dir="$INTEROP_STATE_DIR/kdcproxy"
  : >"$dir/selfcheck.txt"
  net_kdcproxy_check kinit ca.pem "kinit -k -t /in/mit/testuser1.keytab testuser1@TEST.RSKRB5" ||
    { net_failed "$fixture" kinit "$dir/kinit.log"; return 1; }
  net_expect "$fixture" kinit "$dir/kinit.log" \
    "Sending HTTPS request to https " \
    'TLS certificate name matched "kdcproxy.test.rskrb5"' \
    "Received answer (" || return 1

  if net_kdcproxy_check wrong-ca wrong-ca.pem "kinit -k -t /in/mit/testuser1.keytab testuser1@TEST.RSKRB5"; then
    interop_die "fixture $fixture self-check wrong-ca failed: kinit succeeded with an unrelated CA as http_anchors"
    return 1
  fi
  net_expect "$fixture" wrong-ca "$dir/wrong-ca.log" "TLS certificate error at " || return 1
  net_refuse "$fixture" wrong-ca "$dir/wrong-ca.log" "TLS certificate name matched" || return 1

  net_kdcproxy_check kpasswd ca.pem "kpasswd proxypwuser@TEST.RSKRB5" "$(printf '%s\n%s\n%s' "$1" "$2" "$2")" ||
    { net_failed "$fixture" kpasswd "$dir/kpasswd.log"; return 1; }
  net_expect "$fixture" kpasswd "$dir/kpasswd.log" \
    "Sending HTTPS request to https " \
    'TLS certificate name matched "kdcproxy.test.rskrb5"' \
    "Password changed." || return 1
  interop_log "fixture $fixture self-check passed (KDC and kpasswd over MS-KKDCP/HTTPS, wrong CA refused)"
}

fixture_kdcproxy_logs() {
  net_logs kdcproxy "$1"
}
