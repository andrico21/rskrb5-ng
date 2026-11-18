# shellcheck shell=bash
# Host side of the SSSD KCM fixture `kcm` (lane 1D-b, plan 2 todo 1 step 2),
# sourced by scripts/interop/run.sh. Layout contract: scripts/interop/lib.sh;
# shared helpers: scripts/interop/net-common/net.sh.
#
# Container rskrb5-interop-kcm runs sssd_kcm (SSSD 2.10.1, Debian trixie,
# net-kcm/Dockerfile). Socket mechanism (works with rootless Podman and with
# Docker): the host directory $INTEROP_STATE_DIR/kcm/socket (mode 0700, owned
# by the invoking user) is bind-mounted read-write at /run/kcm, and sssd_kcm
# creates its socket /run/kcm/kcm.sock there (mode 0777, the SSSD default), so
# the host path INTEROP_KCM_SOCKET reaches the daemon; a filesystem Unix socket
# does not depend on the container's network namespace. SSSD keys caches by
# the client's peer uid as the daemon sees it: under rootless Podman the
# invoking user is uid 0 in the container's user namespace, under Docker the
# host uid is passed through. The socket path must fit sun_path (108 bytes).
# The caches live in the tmpfs /var/lib/sss/secrets. No published port, no
# extra capability, no --privileged.
#
# Self-check: MIT 1.22.2 kinit -c KCM: in a throwaway mit-kdc image container
# that mounts the same socket directory stores a TGT through the socket (trace
# line "Storing ... in KCM:"), MIT klist reads it back from KCM:, the
# fixture's own klist reads it back through the daemon, and a host-side KCM
# GET_DEFAULT_CACHE request over INTEROP_KCM_SOCKET gets status 0.

# shellcheck source=scripts/interop/net-common/net.sh
source "$INTEROP_ROOT/scripts/interop/net-common/net.sh"

interop_fixture kcm

# net_kcm_host_probe SOCKET: one KCM protocol 2.0 GET_DEFAULT_CACHE request
# (opcode 20) from the host; prints the status and the default cache name.
net_kcm_host_probe() {
  python3 - "$1" <<'EOF'
import socket
import struct
import sys

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.settimeout(10)
    sock.connect(sys.argv[1])
    request = struct.pack(">BBH", 2, 0, 20)
    sock.sendall(struct.pack(">I", len(request)) + request)
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            sys.exit("KCM daemon closed the connection")
        header += chunk
    (length,) = struct.unpack(">I", header)
    if not 4 <= length <= 4096:
        sys.exit(f"KCM reply length {length} out of bounds")
    reply = b""
    while len(reply) < length:
        chunk = sock.recv(length - len(reply))
        if not chunk:
            sys.exit("KCM reply truncated")
        reply += chunk
(status,) = struct.unpack(">i", reply[:4])
name = reply[4:].split(b"\0", 1)[0].decode("ascii", "replace")
print(f"host KCM GET_DEFAULT_CACHE status {status} name {name}")
EOF
}

fixture_kcm_up() {
  local fixture=kcm container dir out socket_dir socket image
  container="$(interop_container_name "$fixture")"
  dir="$INTEROP_ROOT/scripts/interop/net-kcm"
  out="$INTEROP_STATE_DIR/kcm"
  socket_dir="$out/socket"
  socket="$socket_dir/kcm.sock"
  net_require_mit "$fixture" || return 1
  ((${#socket} < 108)) ||
    interop_die "fixture $fixture: socket path $socket is ${#socket} bytes, over the 107-byte sun_path limit; set INTEROP_STATE_DIR shorter" || return 1
  interop_prepare_private_dir "$out" || return 1
  interop_prepare_private_dir "$socket_dir" || return 1

  image="$(interop_build_image kcm "$dir")" || return 1
  interop_env INTEROP_KCM_IMAGE "$image"
  interop_run_container "$fixture" "$image" \
    --tmpfs /var/lib/sss/secrets:rw,mode=0700 \
    -v "$socket_dir:/run/kcm" || interop_die "fixture $fixture: container $container did not start" || return 1
  interop_wait_ready "$fixture" || return 1
  [[ -S "$socket" ]] || interop_die "fixture $fixture: socket $socket is not visible on the host" || return 1

  interop_env INTEROP_KCM_CONTAINER "$container"
  interop_env INTEROP_KCM_SOCKET "$socket"
  interop_env INTEROP_KCM_CONTAINER_SOCKET /run/kcm/kcm.sock
  interop_env INTEROP_KCM_SOCKET_DIR "$socket_dir"
  net_kcm_self_check
}

net_kcm_self_check() {
  local fixture=kcm dir="$INTEROP_STATE_DIR/kcm" container
  container="$(interop_container_name "$fixture")"
  : >"$dir/selfcheck.txt"
  net_check_run kcm-client "$INTEROP_MIT_IMAGE" \
    -v "$INTEROP_STATE_DIR/mit:/in/mit:ro" -v "$dir/socket:/run/kcm" \
    -e KRB5_CONFIG=/tmp/krb5.conf -- \
    "set -e; printf '%s\n' '[libdefaults]' ' default_realm = TEST.RSKRB5' ' dns_lookup_kdc = false' \
      ' kcm_socket = /run/kcm/kcm.sock' '[realms]' ' TEST.RSKRB5 = {' '  kdc = kdc.test.rskrb5:88' ' }' >/tmp/krb5.conf;
     KRB5_TRACE=/dev/stderr kinit -k -t /in/mit/testuser1.keytab -c KCM: testuser1@TEST.RSKRB5; klist -c KCM:" \
    >"$dir/client.log" || { net_failed "$fixture" client "$dir/client.log"; return 1; }
  net_expect "$fixture" client "$dir/client.log" \
    "Storing testuser1@TEST.RSKRB5 -> krbtgt/TEST.RSKRB5@TEST.RSKRB5 in KCM:" \
    "Ticket cache: KCM:" \
    "Default principal: testuser1@TEST.RSKRB5" || return 1

  interop_rt exec "$container" klist -c KCM: >"$dir/server.log" 2>&1 ||
    { net_failed "$fixture" server "$dir/server.log"; return 1; }
  net_expect "$fixture" server "$dir/server.log" \
    "Ticket cache: KCM:" "Default principal: testuser1@TEST.RSKRB5" "krbtgt/TEST.RSKRB5@TEST.RSKRB5" || return 1

  net_kcm_host_probe "$INTEROP_KCM_SOCKET" >"$dir/host.log" 2>&1 ||
    { net_failed "$fixture" host "$dir/host.log"; return 1; }
  net_expect "$fixture" host "$dir/host.log" "host KCM GET_DEFAULT_CACHE status 0 name " || return 1
  interop_log "fixture $fixture self-check passed (MIT kinit/klist through SSSD KCM, host socket answers)"
}

fixture_kcm_logs() {
  net_logs kcm "$1"
}
