#!/bin/bash
# Entrypoint of the MS-KKDCP KDC proxy fixture `kdcproxy` (lane 1D-b).
#
# 1. Generates the per-run TLS material in the tmpfs /run/interop/tls: a test
#    CA (EC P-256), the server certificate it signs (SAN DNS
#    kdcproxy.test.rskrb5, DNS localhost, IP 127.0.0.1; serverAuth), and an
#    unrelated "wrong" CA for negative tests. Only the two CA certificates are
#    copied to /run/interop/out (ca.pem, wrong-ca.pem).
# 2. Serves kdcproxy (WSGI application kdcproxy:application, path /KdcProxy
#    and every other path) with gunicorn over HTTPS on port 443, workers as
#    nobody.
# 3. Waits (bounded) until 443 accepts TCP connections, writes
#    /run/interop/ready, and exits non-zero naming the fixture when gunicorn
#    exits.
set -euo pipefail

readonly FIXTURE=kdcproxy
readonly RUN_DIR=/run/interop
readonly TLS="$RUN_DIR/tls"
readonly OUT="$RUN_DIR/out"
readonly READY="$RUN_DIR/ready"

log() {
  printf 'interop[%s]: %s\n' "$FIXTURE" "$*" >&2
}

fail() {
  log "FAILED: $*"
  exit 1
}

# new_ca NAME CN: a self-signed EC P-256 CA, key and certificate in $TLS.
new_ca() {
  openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=$2" -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout "$TLS/$1.key" -out "$TLS/$1.pem" 2>/dev/null || fail "could not create the $1 CA"
}

generate_tls() {
  mkdir -p "$TLS" "$OUT"
  new_ca ca "rskrb5 interop kdcproxy test CA"
  new_ca wrong-ca "rskrb5 interop unrelated test CA"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=kdcproxy.test.rskrb5" -keyout "$TLS/server.key" -out "$TLS/server.csr" 2>/dev/null ||
    fail "could not create the server key"
  printf '%s\n' \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" \
    "subjectAltName=DNS:kdcproxy.test.rskrb5,DNS:localhost,IP:127.0.0.1" >"$TLS/server.ext"
  openssl x509 -req -in "$TLS/server.csr" -CA "$TLS/ca.pem" -CAkey "$TLS/ca.key" -CAcreateserial \
    -days 2 -extfile "$TLS/server.ext" -out "$TLS/server.pem" 2>/dev/null || fail "could not sign the server certificate"
  rm -f "$TLS/ca.key" "$TLS/wrong-ca.key" "$TLS/server.csr" "$TLS/server.ext"
  chown nobody:nogroup "$TLS/server.key"
  cp "$TLS/ca.pem" "$OUT/ca.pem"
  cp "$TLS/wrong-ca.pem" "$OUT/wrong-ca.pem"
  log "generated the per-run test CA and server certificate"
}

tcp_open() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

main() {
  umask 077
  rm -f "$READY"
  generate_tls
  gunicorn --bind 0.0.0.0:443 --workers 2 --user nobody --group nogroup \
    --certfile "$TLS/server.pem" --keyfile "$TLS/server.key" \
    --access-logfile - --error-logfile - kdcproxy:application &
  local pid=$! limit="${INTEROP_DAEMON_TIMEOUT:-60}" waited=0
  trap 'kill "$pid" 2>/dev/null; exit 143' TERM INT
  until tcp_open 443; do
    kill -0 "$pid" 2>/dev/null || fail "gunicorn exited before listening on 443"
    ((waited < limit)) || fail "port 443 did not accept connections within ${limit}s"
    sleep 1
    waited=$((waited + 1))
  done
  : >"$READY"
  log "ready (gunicorn pid $pid serving kdcproxy on https port 443)"
  local status=0
  wait "$pid" || status=$?
  fail "gunicorn exited with status $status"
}

main "$@"
