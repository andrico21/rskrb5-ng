# shellcheck shell=bash
# Plan 2 todo 27 (WP-20, replay backends and the authenticated message API): the
# `replay` suite and the fixture `replay`, sourced by scripts/interop/run.sh.
# See the layout contract in scripts/interop/lib.sh.
#
# The fixture adds ONE container to the mit-peer fixture, from the same image
# (MIT krb5 1.22.2 and the adapter, scripts/interop/peer-mit/): rskrb5-interop-replay
# runs the adapter with KRB5RCACHENAME=file2:/run/peer/rc.file2, so MIT's own
# acceptor keeps its replay evidence in a `file2` cache file the test copies out
# of the container and into it (the test shares one cache file between this
# crate's File2ReplayStore and MIT's library; the mit-peer container keeps MIT's
# default `dfl` file). Nothing new is built: the image is the one the mit-peer
# fixture built, which is why the directory name `replay` sorts after `peer-mit`.
#
# MIT drop-ins: none. Port: 19770 (INTEROP_REPLAY_PORT), 127.0.0.1 only, the
# adapter of the container. No capability (--cap-drop ALL, no-new-privileges, no
# --privileged); the keytabs are streamed into the tmpfs /run/peer/keytabs
# (mode 0600) after readiness, never baked in. Names: container
# rskrb5-interop-replay (interop_container_name replay), label $INTEROP_LABEL.

interop_fixture replay
interop_suite replay interop_replay mit-kdc mit-peer replay

readonly REPLAY_HOSTNAME=replay-peer.test.rskrb5
readonly REPLAY_RCACHE=/run/peer/rc.file2

fixture_replay_up() {
  local fixture=replay container port host=127.0.0.1 image out
  port="$(interop_port INTEROP_REPLAY_PORT 19770)" || return 1
  container="$(interop_container_name replay)"
  image="${INTEROP_MIT_PEER_IMAGE:-}"
  [[ -n "$image" ]] ||
    interop_die "fixture $fixture needs the mit-peer fixture started first (INTEROP_MIT_PEER_IMAGE is unset)" || return 1
  out="$INTEROP_STATE_DIR/mit-peer"
  [[ -r "$out/peer-acceptor.keytab" && -r "$out/peeruser.keytab" ]] ||
    interop_die "fixture $fixture needs the keytabs the mit-peer fixture copied out ($out)" || return 1

  interop_rt run -d --name "$container" \
    --label "$INTEROP_LABEL=1" --network "$INTEROP_NETWORK" --hostname "$REPLAY_HOSTNAME" \
    --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /run/interop:rw,mode=1777 --tmpfs /run/peer:rw,mode=1777 \
    --env "INTEROP_PEER_FIXTURE=$fixture" --env "KRB5RCACHENAME=file2:$REPLAY_RCACHE" \
    -p "127.0.0.1:$port:4401/tcp" "$image" >/dev/null ||
    interop_die "fixture $fixture: container $container did not start" || return 1
  interop_wait_ready replay || return 1
  interop_wait_tcp "$fixture" "$host" "$port" || return 1
  peer_put "$container" "$out/peer-acceptor.keytab" /run/peer/keytabs/acceptor.keytab || return 1
  peer_put "$container" "$out/peeruser.keytab" /run/peer/keytabs/peeruser.keytab || return 1

  interop_env INTEROP_REPLAY_CONTAINER "$container"
  interop_env INTEROP_REPLAY_ADDR "$host:$port"
  interop_env INTEROP_REPLAY_RCACHE "$REPLAY_RCACHE"
  interop_env INTEROP_REPLAY_ACCEPTOR_KEYTAB "$out/peer-acceptor.keytab"
}

fixture_replay_logs() {
  local dir="$1" container
  container="$(interop_container_name replay)"
  interop_rt exec "$container" cat /run/peer/adapter.log >"$dir/replay-adapter.log" 2>/dev/null || true
}
