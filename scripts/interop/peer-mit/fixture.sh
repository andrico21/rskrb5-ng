# shellcheck shell=bash
# Host side of the external-peer fixture `mit-peer` (plan 2 todo 1, lane 1F),
# sourced by scripts/interop/run.sh. See the layout contract in
# scripts/interop/lib.sh.
#
# DIRECTORY NAME: the fixture lives in scripts/interop/peer-mit/, not mit-peer/:
# run.sh sources scripts/interop/*/fixture.sh in glob order and starts the
# fixtures in that order, and this fixture needs mit-kdc up first; 'mit-peer/'
# sorts before 'mit/' in the C collation ('-' < '/'), 'peer-mit/' after it in
# every collation (the same reason lane 1D-b uses net-*).
#
# Two containers of one image (MIT krb5 1.22.2 + gss-client/gss-server +
# negoextest + the adapter peer-adapter, protocol: peer/peer.c), no capability
# (--cap-drop ALL, no-new-privileges, no --privileged), user peer (10001); the
# tmpfs mounts are mode 1777 because Podman's --tmpfs has no uid= option; every
# file in them is created 0600 by the one user peer:
#   rskrb5-interop-mit-peer      networks rskrb5-interop (the KDC, alias
#                                kdc.test.rskrb5) and rskrb5-interop-iso;
#                                hostname mit-peer.test.rskrb5; adapter on
#                                127.0.0.1:INTEROP_MIT_PEER_PORT (19401)
#   rskrb5-interop-mit-peer-iso  network rskrb5-interop-iso ONLY: no route to
#                                the KDC (the IAKERB initiator side); adapter on
#                                127.0.0.1:INTEROP_MIT_PEER_ISO_PORT (19402)
# The keytabs the adapter and the self-check read are streamed into the tmpfs
# /run/peer/keytabs of the containers (mode 0600), never baked in.

interop_fixture mit-peer
interop_suite peer interop_peer mit-kdc mit-peer mit-peer-iso

readonly PEER_ISO_NETWORK=rskrb5-interop-iso
readonly PEER_HOSTNAME=mit-peer.test.rskrb5
readonly PEER_KDC_ALIAS=kdc.test.rskrb5
readonly PEER_SELFCHECK=/opt/interop/peer/selfcheck.sh

# peer_run NAME NETWORK PORT HOSTNAME IMAGE: starts one adapter container.
peer_run() {
  local name="$1" network="$2" port="$3" hostname="$4" image="$5"
  interop_rt run -d --name "$(interop_container_name "$name")" \
    --label "$INTEROP_LABEL=1" --network "$network" --hostname "$hostname" \
    --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /run/interop:rw,mode=1777 --tmpfs /run/peer:rw,mode=1777 \
    --env "INTEROP_PEER_FIXTURE=$name" \
    -p "127.0.0.1:$port:4401/tcp" "$image" >/dev/null ||
    interop_die "fixture mit-peer: container $name did not start"
}

# peer_put CONTAINER SOURCE DEST: streams a host file into the container's tmpfs, mode 0600.
peer_put() {
  # shellcheck disable=SC2016  # the script runs in the container, which expands $1
  interop_rt exec -i "$1" sh -c 'umask 077 && cat >"$1"' sh "$3" <"$2" ||
    interop_die "fixture mit-peer: could not deliver $2 into $1"
}

# peer_exec WHAT CONTAINER COMMAND...: runs an in-container check, prints its
# output, and fails the fixture, naming it, when the command fails.
peer_exec() {
  local what="$1" container="$2" output
  shift 2
  if ! output="$(interop_rt exec "$container" "$@" 2>&1)"; then
    printf '%s\n' "$output" >&2
    interop_die "fixture mit-peer: self-check '$what' failed in $container"
    return 1
  fi
  printf '%s\n' "$output" >&2
  PEER_OUTPUT="$output"
}

# peer_expect WHAT TEXT FRAGMENT: the fixture fails unless TEXT contains FRAGMENT.
peer_expect() {
  [[ "$2" == *"$3"* ]] || interop_die "fixture mit-peer: self-check '$1': expected '$3' in the output:
$2" || return 1
  interop_log "self-check ok: $1: '$3'"
}

# peer_wait_file CONTAINER FILE PATTERN: bounded poll for a pattern in a log.
peer_wait_file() {
  local tries=0
  until interop_rt exec "$1" grep -q -- "$3" "$2" 2>/dev/null; do
    tries=$((tries + 1))
    ((tries <= 60)) || interop_die "fixture mit-peer: no '$3' in $2 of $1 within 30 s" || return 1
    sleep 0.5
  done
}

# peer_gss MECH CLIENT_CONTAINER HOST: one gss-server (in rskrb5-interop-mit-peer,
# one connection, -export) and one gss-client run; sets PEER_OUTPUT (client)
# and PEER_SERVER (server log).
peer_gss() {
  local mech="$1" client="$2" host="$3" server
  server="$(interop_container_name mit-peer)"
  interop_rt exec -d "$server" "$PEER_SELFCHECK" serve "$mech" >/dev/null || return 1
  peer_wait_file "$server" "/run/peer/gss-server-$mech.log" 'starting\.\.\.' || return 1
  peer_exec "gss-client $mech" "$client" "$PEER_SELFCHECK" client "$mech" "$host" || return 1
  peer_wait_file "$server" "/run/peer/gss-server-$mech.log" 'Received message' || return 1
  PEER_SERVER="$(interop_rt exec "$server" cat "/run/peer/gss-server-$mech.log")"
}

# peer_selfcheck_network MAIN ISO KDC_IP: the isolated container cannot reach the KDC.
peer_selfcheck_network() {
  local main="$1" iso="$2" kdc_ip="$3"
  interop_rt exec "$main" getent hosts "$PEER_KDC_ALIAS" >/dev/null ||
    interop_die "fixture mit-peer: $main cannot resolve $PEER_KDC_ALIAS" || return 1
  interop_rt exec "$main" timeout 5 bash -c "exec 3<>/dev/tcp/$kdc_ip/88" ||
    interop_die "fixture mit-peer: $main cannot reach the KDC at $kdc_ip:88" || return 1
  if interop_rt exec "$iso" getent hosts "$PEER_KDC_ALIAS" >/dev/null 2>&1; then
    interop_die "fixture mit-peer: the isolated container resolves $PEER_KDC_ALIAS"
    return 1
  fi
  if interop_rt exec "$iso" timeout 5 bash -c "exec 3<>/dev/tcp/$kdc_ip/88" >/dev/null 2>&1; then
    interop_die "fixture mit-peer: the isolated container reaches the KDC at $kdc_ip:88"
    return 1
  fi
  peer_exec "kinit from the connected container" "$main" kinit -k -t /run/peer/keytabs/peeruser.keytab \
    -c FILE:/run/peer/cc-kinit peeruser || return 1
  if interop_rt exec "$iso" kinit -k -t /run/peer/keytabs/peeruser.keytab -c FILE:/run/peer/cc-kinit peeruser >/dev/null 2>&1; then
    interop_die "fixture mit-peer: kinit succeeded from the isolated container"
    return 1
  fi
  interop_log "self-check ok: isolated container: $PEER_KDC_ALIAS unresolvable, $kdc_ip:88 unreachable, kinit fails; connected container: resolves, connects, kinit succeeds"
}

# peer_selfcheck_gss MAIN ISO: krb5, SPNEGO and IAKERB (KDC blocked) exchanges.
peer_selfcheck_gss() {
  local main="$1" iso="$2"
  peer_gss krb5 "$main" "$PEER_HOSTNAME" || return 1
  peer_expect "gss-client -krb5 verified the server signature" "$PEER_OUTPUT" 'Signature verified.' || return 1
  peer_expect "gss-server accepted the krb5 mechanism" "$PEER_SERVER" 'mechanism OID { 1 2 840 113554 1 2 2 }' || return 1
  peer_expect "gss-server saw the client principal" "$PEER_SERVER" 'peeruser@TEST.RSKRB5' || return 1
  peer_expect "gss-server exported and imported the context" "$PEER_SERVER" 'Exported context' || return 1
  peer_gss spnego "$main" "$PEER_HOSTNAME" || return 1
  peer_expect "gss-client -spnego verified the server signature" "$PEER_OUTPUT" 'Signature verified.' || return 1
  # The isolated container cannot use the krb5 mechanism (no KDC route)...
  local server
  server="$(interop_container_name mit-peer)"
  interop_rt exec -d "$server" "$PEER_SELFCHECK" serve krb5-blocked >/dev/null || return 1
  peer_wait_file "$server" /run/peer/gss-server-krb5-blocked.log 'starting\.\.\.' || return 1
  if interop_rt exec "$iso" "$PEER_SELFCHECK" client krb5-blocked "$PEER_HOSTNAME" >/dev/null 2>&1; then
    interop_die "fixture mit-peer: the isolated container completed a krb5 exchange"
    return 1
  fi
  # ...but IAKERB through the connected acceptor works, KDC still blocked.
  peer_gss iakerb "$iso" "$PEER_HOSTNAME" || return 1
  peer_expect "gss-client -iakerb (KDC blocked) verified the server signature" "$PEER_OUTPUT" 'Signature verified.' || return 1
  peer_expect "gss-server accepted the IAKERB mechanism" "$PEER_SERVER" 'mechanism OID { 1 3 6 1 5 2 5 }' || return 1
  peer_expect "gss-server saw the client principal over IAKERB" "$PEER_SERVER" 'peeruser@TEST.RSKRB5' || return 1
}

fixture_mit_peer_up() {
  local fixture=mit-peer main iso image dir out kdc kdc_ip host=127.0.0.1
  local port="${INTEROP_MIT_PEER_PORT:-19401}" iso_port="${INTEROP_MIT_PEER_ISO_PORT:-19402}"
  main="$(interop_container_name mit-peer)"
  iso="$(interop_container_name mit-peer-iso)"
  kdc="$(interop_container_name mit-kdc)"
  dir="$INTEROP_ROOT/scripts/interop/peer-mit"
  out="$INTEROP_STATE_DIR/mit-peer"
  [[ -n "${INTEROP_MIT_ADMIN_PASSWORD:-}" ]] ||
    interop_die "fixture $fixture needs the mit-kdc fixture started first (INTEROP_MIT_ADMIN_PASSWORD is unset)" || return 1

  image="$(interop_build_image mit-peer "$dir")" || return 1
  interop_env INTEROP_MIT_PEER_IMAGE "$image"
  # The same derivation as scripts/interop/mit/provision.d/70-peer.sh.
  interop_env INTEROP_MIT_PEER_USER_PASSWORD \
    "$(printf '%s' "rskrb5-interop peer-user v1${INTEROP_MIT_ADMIN_PASSWORD}" | sha256sum | cut -c1-32)"

  # Docker isolates user-defined bridge networks from each other by default;
  # Podman's netavark needs isolate=strict (plain isolate=true only separates
  # networks that are both isolated, and rskrb5-interop is not).
  local -a iso_options=()
  [[ "$INTEROP_RT" == podman ]] && iso_options=(--opt isolate=strict)
  interop_rt network create --label "$INTEROP_LABEL=1" "${iso_options[@]}" "$PEER_ISO_NETWORK" >/dev/null ||
    interop_die "fixture $fixture: could not create the network $PEER_ISO_NETWORK" || return 1
  peer_run mit-peer "$INTEROP_NETWORK" "$port" "$PEER_HOSTNAME" "$image" || return 1
  interop_rt network connect --alias "$PEER_HOSTNAME" "$PEER_ISO_NETWORK" "$main" >/dev/null ||
    interop_die "fixture $fixture: could not connect $main to $PEER_ISO_NETWORK" || return 1
  peer_run mit-peer-iso "$PEER_ISO_NETWORK" "$iso_port" mit-peer-iso.test.rskrb5 "$image" || return 1
  interop_wait_ready mit-peer || return 1
  interop_wait_ready mit-peer-iso || return 1
  interop_wait_tcp "$fixture" "$host" "$port" || return 1
  interop_wait_tcp "$fixture" "$host" "$iso_port" || return 1

  interop_prepare_private_dir "$out" || return 1
  local file
  for file in peer-acceptor.keytab peer-rust.keytab peeruser.keytab; do
    interop_copy_out "$kdc" "/run/interop/out/$file" "$out/$file" || return 1
  done
  peer_put "$main" "$out/peer-acceptor.keytab" /run/peer/keytabs/acceptor.keytab || return 1
  peer_put "$main" "$out/peeruser.keytab" /run/peer/keytabs/peeruser.keytab || return 1
  peer_put "$iso" "$out/peeruser.keytab" /run/peer/keytabs/peeruser.keytab || return 1

  kdc_ip="$(interop_rt inspect -f "{{(index .NetworkSettings.Networks \"$INTEROP_NETWORK\").IPAddress}}" "$kdc")" || return 1
  [[ "$kdc_ip" =~ ^[0-9.]+$ ]] || interop_die "fixture $fixture: cannot read the KDC address of $kdc" || return 1
  peer_exec "adapter frames" "$main" "$PEER_SELFCHECK" frames || return 1
  peer_exec "negoextest under SPNEGO/NegoEx" "$main" "$PEER_SELFCHECK" negoex || return 1
  peer_selfcheck_network "$main" "$iso" "$kdc_ip" || return 1
  peer_selfcheck_gss "$main" "$iso" || return 1

  interop_env INTEROP_MIT_PEER_CONTAINER "$main"
  interop_env INTEROP_MIT_PEER_ISO_CONTAINER "$iso"
  interop_env INTEROP_MIT_PEER_ADDR "$host:$port"
  interop_env INTEROP_MIT_PEER_ISO_ADDR "$host:$iso_port"
  interop_env INTEROP_MIT_PEER_SERVICE "peer@$PEER_HOSTNAME"
  interop_env INTEROP_MIT_PEER_SERVICE_PRINCIPAL "peer/$PEER_HOSTNAME"
  interop_env INTEROP_MIT_PEER_ACCEPTOR_KEYTAB_ID acceptor
  interop_env INTEROP_MIT_PEER_USER peeruser
  interop_env INTEROP_MIT_PEER_USER_KEYTAB_ID peeruser
  interop_env INTEROP_MIT_PEER_RUST_SERVICE peer/rust.test.rskrb5
  interop_env INTEROP_MIT_PEER_RUST_KEYTAB "$out/peer-rust.keytab"
  interop_env INTEROP_MIT_PEER_NEGOEX_OIDS 2.25.1414534758,2.25.1175737388
}

fixture_mit_peer_logs() {
  local dir="$1" name container
  for name in mit-peer mit-peer-iso; do
    container="$(interop_container_name "$name")"
    interop_rt exec "$container" cat /run/peer/adapter.log >"$dir/$name-adapter.log" 2>/dev/null || true
  done
}
