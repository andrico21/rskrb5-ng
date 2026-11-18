# shellcheck shell=bash
# Host side of the Negotiate HTTP fixture `httpd` (lane 1D-b, plan 2 todo 1
# step 2), sourced by scripts/interop/run.sh. Layout contract:
# scripts/interop/lib.sh; shared helpers: scripts/interop/net-common/net.sh.
#
# Container rskrb5-interop-httpd (hostname and network alias
# httpd.test.rskrb5): Apache httpd 2.4 with mod_auth_gssapi 1.6.5
# (net-httpd/Dockerfile). /whoami/ requires Negotiate for the service
# HTTP/httpd.test.rskrb5@TEST.RSKRB5 (created by
# mit/provision.d/51-net-services.sh) and answers with the authenticated
# principal and the mechanism mod_auth_gssapi published, one `key=value` per
# line (principal=, mechanism=, auth-type=). Plain HTTP only, no TLS, and no
# channel bindings: mod_auth_gssapi 1.6.5 cannot check them (FU-IOP-P01).
# Published on 127.0.0.1: INTEROP_HTTPD_PORT (default 19180) -> 80.
# The service keytab is copied out of mit-kdc into the private state
# directory and streamed into the container's tmpfs through `exec -i` (the
# same stdin mechanism as interop_deliver_secrets; never argv, env or a
# layer). No extra capability and no --privileged.
#
# Self-check (Debian curl with GSS-API and MIT 1.21 kinit, in a throwaway
# container of this image): an unauthenticated GET gets 401 with
# `WWW-Authenticate: Negotiate`; after kinit as testuser1, `curl --negotiate
# -u :` gets 200 with a Negotiate reply token (mutual authentication) and the
# body names testuser1@TEST.RSKRB5 and the Negotiate/krb5 mechanism; the
# Apache access log records the same user.

# shellcheck source=scripts/interop/net-common/net.sh
source "$INTEROP_ROOT/scripts/interop/net-common/net.sh"

interop_fixture httpd

# Client profile of the self-check: TEST.RSKRB5 on the container network, no
# host-name canonicalisation (the service is HTTP/httpd.test.rskrb5).
net_httpd_client_conf() {
  cat <<'EOF'
[libdefaults]
    default_realm = TEST.RSKRB5
    dns_lookup_kdc = false
    dns_lookup_realm = false
    dns_canonicalize_hostname = false
    rdns = false

[realms]
    TEST.RSKRB5 = {
        kdc = kdc.test.rskrb5:88
    }

[domain_realm]
    .test.rskrb5 = TEST.RSKRB5
EOF
}

fixture_httpd_up() {
  local fixture=httpd container dir out image host=127.0.0.1
  local port="${INTEROP_HTTPD_PORT:-19180}"
  container="$(interop_container_name "$fixture")"
  dir="$INTEROP_ROOT/scripts/interop/net-httpd"
  out="$INTEROP_STATE_DIR/httpd"
  net_require_mit "$fixture" || return 1
  interop_prepare_private_dir "$out" || return 1
  interop_copy_out "$INTEROP_MIT_CONTAINER" /run/interop/out/httpd.keytab "$out/http.keytab" || return 1

  image="$(interop_build_image httpd "$dir")" || return 1
  interop_env INTEROP_HTTPD_IMAGE "$image"
  interop_run_container "$fixture" "$image" \
    --hostname httpd.test.rskrb5 --network-alias httpd.test.rskrb5 \
    --tmpfs /run/gssapi:rw,mode=0755 \
    -p "$host:$port:80/tcp" || interop_die "fixture $fixture: container $container did not start" || return 1
  interop_rt exec -i "$container" sh -c \
    'umask 077 && cat >/run/interop/http.keytab.tmp && mv /run/interop/http.keytab.tmp /run/interop/http.keytab' \
    <"$out/http.keytab" || interop_die "fixture $fixture: could not deliver the service keytab" || return 1
  interop_wait_ready "$fixture" || return 1
  interop_wait_tcp "$fixture" "$host" "$port" || return 1

  interop_env INTEROP_HTTPD_CONTAINER "$container"
  interop_env INTEROP_HTTPD "$host:$port"
  interop_env INTEROP_HTTPD_URL "http://$host:$port/whoami/"
  interop_env INTEROP_HTTPD_HOST httpd.test.rskrb5
  interop_env INTEROP_HTTPD_CONTAINER_URL http://httpd.test.rskrb5/whoami/
  interop_env INTEROP_HTTPD_REALM TEST.RSKRB5
  interop_env INTEROP_HTTPD_SERVICE HTTP/httpd.test.rskrb5
  interop_env INTEROP_HTTPD_KEYTAB "$out/http.keytab"
  interop_env INTEROP_HTTPD_TLS none
  interop_env INTEROP_HTTPD_CHANNEL_BINDINGS unsupported
  net_httpd_self_check "$image"
}

net_httpd_self_check() {
  local fixture=httpd dir="$INTEROP_STATE_DIR/httpd" url=http://httpd.test.rskrb5/whoami/
  : >"$dir/selfcheck.txt"
  net_check_run httpd-client "$1" -v "$INTEROP_STATE_DIR/mit:/in/mit:ro" -e KRB5_CONFIG=/tmp/krb5.conf \
    -e KRB5CCNAME=FILE:/tmp/cc -- \
    "set -e; printf '%s\n' \"\$0\" >/tmp/krb5.conf
     echo '--- anonymous'; curl -sS -i $url
     echo '--- negotiate'; kinit -k -t /in/mit/testuser1.keytab testuser1@TEST.RSKRB5
     curl -sS -i --negotiate -u : $url" \
    "$(net_httpd_client_conf)" >"$dir/client.log" || { net_failed "$fixture" client "$dir/client.log"; return 1; }
  sed -n '/^--- anonymous/,/^--- negotiate/p' "$dir/client.log" >"$dir/anonymous.log"
  sed -n '/^--- negotiate/,$p' "$dir/client.log" >"$dir/negotiate.log"
  net_expect "$fixture" anonymous "$dir/anonymous.log" "HTTP/1.1 401 Unauthorized" "WWW-Authenticate: Negotiate" || return 1
  net_refuse "$fixture" anonymous "$dir/anonymous.log" "principal=" || return 1
  net_expect "$fixture" negotiate "$dir/negotiate.log" \
    "HTTP/1.1 200 OK" "WWW-Authenticate: Negotiate " \
    "principal=testuser1@TEST.RSKRB5" "mechanism=Negotiate/krb5" "auth-type=Negotiate" || return 1
  interop_rt logs "$(interop_container_name "$fixture")" >"$dir/server.log" 2>&1 || true
  net_expect "$fixture" server "$dir/server.log" '"GET /whoami/ HTTP/1.1" 200 user=testuser1@TEST.RSKRB5' || return 1
  interop_log "fixture $fixture self-check passed (401 Negotiate challenge, SPNEGO login as testuser1@TEST.RSKRB5)"
}

fixture_httpd_logs() {
  net_logs httpd "$1"
}
