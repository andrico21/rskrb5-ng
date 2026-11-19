# shellcheck shell=bash
# Plan 2 todo 11 (WP-09a, credential stores): the `ccache` suite and its
# fixture `ccache-mit`, sourced by scripts/interop/run.sh after mit/ (the
# directory name `suite-ccache` sorts after every fixture directory, so the
# mit-kdc image, keytabs and KDC exist already). Layout contract:
# scripts/interop/lib.sh.
#
# Container rskrb5-interop-ccache-mit runs the mit-kdc image (MIT krb5 1.22.2
# client tools) with a shell that only waits; it serves nothing. Share
# mechanism (rootless Podman and Docker): the host directory
# $INTEROP_STATE_DIR/ccache (mode 0700, owned by the invoking user) is
# bind-mounted read-write at /ccache. The tests run MIT kinit, klist, kswitch
# and kvno through `<runtime> exec --user INTEROP_CCACHE_MIT_EXEC_USER`, so the
# files MIT writes are owned by the invoking user on the host: under rootless
# Podman container uid 0 is that user; under Docker the host uid and gid are
# passed. The files stay mode 0600 and the Rust stores, which refuse files of
# another owner, read them. The container reaches the KDC as
# kdc.test.rskrb5:88 on the rskrb5-interop network. No published port, no
# extra capability, no --privileged.
#
# Self-check at up: MIT kinit writes a DIR collection into the share and klist
# -A lists it; on the host the collection's `primary` pointer exists, the cache
# file starts with the version-4 bytes 05 04, and it belongs to the invoking
# user, which proves the bind mount and the uid mapping before any test.

interop_fixture ccache-mit
interop_suite ccache interop_ccache mit-kdc ccache-mit

# ccache_mit_exec SCRIPT: runs SCRIPT with bash in the container as the exec
# user, with the share's krb5.conf.
ccache_mit_exec() {
  interop_rt exec --user "$INTEROP_CCACHE_MIT_EXEC_USER" -e KRB5_CONFIG=/ccache/krb5.conf \
    "$INTEROP_CCACHE_MIT_CONTAINER" bash -c "$1"
}

fixture_ccache_mit_up() {
  local fixture=ccache-mit container share version
  container="$(interop_container_name "$fixture")"
  share="$INTEROP_STATE_DIR/ccache"
  interop_prepare_private_dir "$share" || return 1
  (umask 077 && cp "$INTEROP_STATE_DIR/mit/testuser1.keytab" "$INTEROP_STATE_DIR/mit/preauthuser.keytab" "$share/") ||
    interop_die "fixture $fixture: could not copy the MIT keytabs into $share" || return 1
  printf '%s\n' '[libdefaults]' ' default_realm = TEST.RSKRB5' ' dns_lookup_kdc = false' \
    ' dns_lookup_realm = false' ' rdns = false' '[realms]' ' TEST.RSKRB5 = {' \
    '  kdc = kdc.test.rskrb5:88' ' }' >"$share/krb5.conf"
  for version in 1 2 3 4; do
    sed "s/^\[libdefaults\]\$/[libdefaults]\n ccache_type = $version/" "$share/krb5.conf" >"$share/krb5-v$version.conf"
  done
  chmod 600 "$share"/*.conf

  interop_rt run -d --name "$container" --label "$INTEROP_LABEL=1" --network "$INTEROP_NETWORK" \
    --tmpfs /run/interop:rw,mode=0700 -v "$share:/ccache" --entrypoint /bin/bash \
    "$INTEROP_MIT_IMAGE" -c 'touch /run/interop/ready && exec sleep infinity' >/dev/null ||
    interop_die "fixture $fixture: container $container did not start" || return 1
  interop_wait_ready "$fixture" || return 1

  interop_env INTEROP_CCACHE_MIT_CONTAINER "$container"
  interop_env INTEROP_CCACHE_MIT_SHARE "$share"
  interop_env INTEROP_CCACHE_MIT_MOUNT /ccache
  case "$INTEROP_RT" in
    podman) interop_env INTEROP_CCACHE_MIT_EXEC_USER 0:0 ;;
    *) interop_env INTEROP_CCACHE_MIT_EXEC_USER "$(id -u):$(id -g)" ;;
  esac
  interop_env INTEROP_CCACHE_MIT_USER testuser1
  interop_env INTEROP_CCACHE_MIT_SECOND_USER preauthuser
  ccache_mit_self_check
}

ccache_mit_self_check() {
  local fixture=ccache-mit share="$INTEROP_STATE_DIR/ccache" log header
  log="$share/selfcheck.log"
  ccache_mit_exec 'set -e; kinit -k -t /ccache/testuser1.keytab -c DIR:/ccache/selfcheck testuser1@TEST.RSKRB5;
    klist -A -c DIR:/ccache/selfcheck' >"$log" 2>&1 ||
    { interop_log_tail "$INTEROP_CCACHE_MIT_CONTAINER"; cat "$log" >&2; interop_die "fixture $fixture: MIT kinit into DIR:/ccache/selfcheck failed"; return 1; }
  if ! grep -q 'Ticket cache: DIR::/ccache/selfcheck/tkt' "$log" ||
    ! grep -q 'Default principal: testuser1@TEST.RSKRB5' "$log"; then
    cat "$log" >&2
    interop_die "fixture $fixture: klist -A did not list the DIR collection"
    return 1
  fi
  [[ -f "$share/selfcheck/primary" && -O "$share/selfcheck/tkt" ]] ||
    interop_die "fixture $fixture: the collection is not visible on the host or not owned by $(id -un)" || return 1
  header="$(od -An -tx1 -N2 "$share/selfcheck/tkt" | tr -d ' ')"
  [[ "$header" == 0504 ]] || interop_die "fixture $fixture: cache version bytes $header, expected 0504" || return 1
  rm -rf "$share/selfcheck"
  interop_log "fixture $fixture self-check passed (MIT kinit/klist -A on DIR:/ccache, host sees a version-4 cache it owns)"
}

fixture_ccache_mit_logs() {
  local summary="$INTEROP_STATE_DIR/ccache/selfcheck.log"
  [[ -f "$summary" ]] && cp "$summary" "$1/ccache-mit-selfcheck.log"
  return 0
}
