# shellcheck shell=bash
# Plan 2 todo 12 (WP-09b, KCM client): the `kcm` suite and its fixture
# `kcm-mit`, sourced by scripts/interop/run.sh after net-kcm/ (the directory
# name `suite-kcm` sorts after every fixture directory, so the mit-kdc image,
# its keytabs and KDC and the `kcm` fixture (SSSD's sssd_kcm on a socket in a
# host-visible directory) exist already). Layout contract:
# scripts/interop/lib.sh.
#
# Container rskrb5-interop-kcm-mit runs the mit-kdc image (MIT krb5 1.22.2
# client tools) with a shell that only waits; it serves nothing. It mounts the
# `kcm` fixture's socket directory at /run/kcm and a private directory
# $INTEROP_STATE_DIR/kcm-mit (keytab, krb5.conf with kcm_socket =
# /run/kcm/kcm.sock) at /kcm-mit. The tests run MIT kinit, klist, kswitch,
# kvno and kdestroy through `<runtime> exec --user INTEROP_KCM_MIT_EXEC_USER`,
# and the crate connects to the same daemon from the host through
# INTEROP_KCM_SOCKET. SSSD names a cache `<uid>:<name>` after the peer user
# as the daemon sees it: under rootless Podman the invoking user is uid 0 in
# the container's user namespace and the exec user is root (uid 0); under
# Docker the host uid passes through and the exec user is the invoking user,
# so both sides are the same daemon user either way (INTEROP_KCM_UID). No
# published port, no extra capability, no --privileged.
#
# Self-check at up: MIT kinit stores a TGT in KCM:<uid>:selfcheck through the
# socket and MIT klist reads it back, so the shared socket, the exec user and
# the KDC are proved before any test.

interop_fixture kcm-mit
interop_suite kcm interop_kcm mit-kdc kcm kcm-mit

# kcm_mit_exec SCRIPT: runs SCRIPT with bash in the container as the exec
# user, with the share's krb5.conf.
kcm_mit_exec() {
  interop_rt exec --user "$INTEROP_KCM_MIT_EXEC_USER" -e KRB5_CONFIG=/kcm-mit/krb5.conf \
    "$INTEROP_KCM_MIT_CONTAINER" bash -c "$1"
}

fixture_kcm_mit_up() {
  local fixture=kcm-mit container share
  container="$(interop_container_name "$fixture")"
  share="$INTEROP_STATE_DIR/kcm-mit"
  interop_prepare_private_dir "$share" || return 1
  (umask 077 && cp "$INTEROP_STATE_DIR/mit/testuser1.keytab" "$share/") ||
    interop_die "fixture $fixture: could not copy the MIT keytab into $share" || return 1
  printf '%s\n' '[libdefaults]' ' default_realm = TEST.RSKRB5' ' dns_lookup_kdc = false' \
    ' dns_lookup_realm = false' ' rdns = false' ' kcm_socket = /run/kcm/kcm.sock' \
    ' default_ccache_name = KCM:' '[realms]' ' TEST.RSKRB5 = {' '  kdc = kdc.test.rskrb5:88' ' }' >"$share/krb5.conf"
  chmod 600 "$share/krb5.conf"

  interop_rt run -d --name "$container" --label "$INTEROP_LABEL=1" --network "$INTEROP_NETWORK" \
    --tmpfs /run/interop:rw,mode=0700 -v "$share:/kcm-mit" -v "$INTEROP_KCM_SOCKET_DIR:/run/kcm" \
    --entrypoint /bin/bash "$INTEROP_MIT_IMAGE" -c 'touch /run/interop/ready && exec sleep infinity' >/dev/null ||
    interop_die "fixture $fixture: container $container did not start" || return 1
  interop_wait_ready "$fixture" || return 1

  interop_env INTEROP_KCM_MIT_CONTAINER "$container"
  interop_env INTEROP_KCM_MIT_SHARE "$share"
  case "$INTEROP_RT" in
    podman)
      interop_env INTEROP_KCM_MIT_EXEC_USER 0:0
      interop_env INTEROP_KCM_UID 0
      ;;
    *)
      interop_env INTEROP_KCM_MIT_EXEC_USER "$(id -u):$(id -g)"
      interop_env INTEROP_KCM_UID "$(id -u)"
      ;;
  esac
  interop_env INTEROP_KCM_MIT_USER testuser1
  kcm_mit_self_check
}

kcm_mit_self_check() {
  local fixture=kcm-mit share="$INTEROP_STATE_DIR/kcm-mit" uid log
  log="$share/selfcheck.log"
  case "$INTEROP_RT" in
    podman) uid=0 ;;
    *) uid="$(id -u)" ;;
  esac
  kcm_mit_exec "set -e; kinit -k -t /kcm-mit/testuser1.keytab -c KCM:$uid:selfcheck testuser1@TEST.RSKRB5;
    klist -c KCM:$uid:selfcheck; kdestroy -c KCM:$uid:selfcheck" >"$log" 2>&1 ||
    { interop_log_tail "$(interop_container_name "$fixture")"; cat "$log" >&2; interop_die "fixture $fixture: MIT kinit into KCM:$uid:selfcheck failed"; return 1; }
  if ! grep -q "Ticket cache: KCM:$uid:selfcheck" "$log" ||
    ! grep -q 'Default principal: testuser1@TEST.RSKRB5' "$log"; then
    cat "$log" >&2
    interop_die "fixture $fixture: klist did not read the cache back through the KCM daemon"
    return 1
  fi
  interop_log "fixture $fixture self-check passed (MIT kinit/klist/kdestroy on KCM:$uid:selfcheck through the shared socket)"
}

fixture_kcm_mit_logs() {
  local summary="$INTEROP_STATE_DIR/kcm-mit/selfcheck.log"
  [[ -f "$summary" ]] && cp "$summary" "$1/kcm-mit-selfcheck.log"
  return 0
}
