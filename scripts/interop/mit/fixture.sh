# shellcheck shell=bash
# Host side of the MIT krb5 1.22.2 fixture `mit-kdc` (lane 1C), sourced by
# scripts/interop/run.sh. See the layout contract in scripts/interop/lib.sh.
#
# Container rskrb5-interop-mit-kdc (hostname kdc.test.rskrb5, network alias
# kdc.test.rskrb5 on rskrb5-interop): krb5kdc and kadmind of realm
# TEST.RSKRB5. Tmpfs mounts hold the KDC database, its stash, the secrets and
# the exported keytabs. Published on 127.0.0.1 (TCP and UDP for 88 and 464):
#   INTEROP_MIT_KDC_PORT (default 18088) -> 88, INTEROP_MIT_KPASSWD_PORT
#   (18464) -> 464, INTEROP_MIT_KADMIN_PORT (18749) -> 749.
# No extra capability and no --privileged.

interop_fixture mit-kdc
interop_suite mit interop_mit mit-kdc

fixture_mit_kdc_up() {
  local fixture=mit-kdc container image dir out
  container="$(interop_container_name "$fixture")"
  local host=127.0.0.1
  local kdc_port="${INTEROP_MIT_KDC_PORT:-18088}"
  local kpasswd_port="${INTEROP_MIT_KPASSWD_PORT:-18464}"
  local kadmin_port="${INTEROP_MIT_KADMIN_PORT:-18749}"
  dir="$INTEROP_ROOT/scripts/interop/mit"
  out="$INTEROP_STATE_DIR/mit"

  image="$(interop_build_image mit "$dir")" || return 1
  interop_env INTEROP_MIT_IMAGE "$image"
  interop_env INTEROP_MIT_USER_PASSWORD "$(interop_new_secret)"
  interop_env INTEROP_MIT_PREAUTH_USER_PASSWORD "$(interop_new_secret)"
  interop_env INTEROP_MIT_KPASSWD_USER_PASSWORD "$(interop_new_secret)"
  interop_env INTEROP_MIT_KPASSWD_USER_NEW_PASSWORD "$(interop_new_secret)"
  interop_env INTEROP_MIT_ADMIN_PASSWORD "$(interop_new_secret)"

  interop_run_container "$fixture" "$image" \
    --hostname kdc.test.rskrb5 --network-alias kdc.test.rskrb5 \
    --tmpfs /var/lib/krb5kdc:rw,mode=0700 \
    -p "$host:$kdc_port:88/tcp" -p "$host:$kdc_port:88/udp" \
    -p "$host:$kpasswd_port:464/tcp" -p "$host:$kpasswd_port:464/udp" \
    -p "$host:$kadmin_port:749/tcp" || interop_die "fixture $fixture: container $container did not start" || return 1
  interop_deliver_secrets "$container" INTEROP_MIT_USER_PASSWORD INTEROP_MIT_PREAUTH_USER_PASSWORD \
    INTEROP_MIT_KPASSWD_USER_PASSWORD INTEROP_MIT_ADMIN_PASSWORD || return 1
  interop_wait_ready "$fixture" || return 1
  interop_wait_tcp "$fixture" "$host" "$kdc_port" || return 1
  interop_wait_tcp "$fixture" "$host" "$kpasswd_port" || return 1
  interop_wait_tcp "$fixture" "$host" "$kadmin_port" || return 1

  interop_prepare_private_dir "$out" || return 1
  local file
  for file in http.keytab host.keytab testuser1.keytab preauthuser.keytab kinit.ccache; do
    interop_copy_out "$container" "/run/interop/out/$file" "$out/$file" || return 1
  done

  interop_env INTEROP_MIT_CONTAINER "$container"
  interop_env INTEROP_MIT_REALM TEST.RSKRB5
  interop_env INTEROP_MIT_KDC "$host:$kdc_port"
  interop_env INTEROP_MIT_KPASSWD "$host:$kpasswd_port"
  interop_env INTEROP_MIT_KADMIN "$host:$kadmin_port"
  interop_env INTEROP_MIT_USER testuser1
  interop_env INTEROP_MIT_USER_KEYTAB "$out/testuser1.keytab"
  interop_env INTEROP_MIT_PREAUTH_USER preauthuser
  interop_env INTEROP_MIT_PREAUTH_USER_KEYTAB "$out/preauthuser.keytab"
  interop_env INTEROP_MIT_KPASSWD_USER kpasswduser
  interop_env INTEROP_MIT_HTTP_SERVICE HTTP/http.test.rskrb5
  interop_env INTEROP_MIT_HTTP_KEYTAB "$out/http.keytab"
  interop_env INTEROP_MIT_HOST_SERVICE host/mit-kdc.test.rskrb5
  interop_env INTEROP_MIT_HOST_KEYTAB "$out/host.keytab"
  interop_env INTEROP_MIT_KINIT_CCACHE "FILE:$out/kinit.ccache"
  interop_env INTEROP_MIT_ADMIN_PRINCIPAL admin/admin
  interop_env INTEROP_MIT_DISPOSABLE_PRINCIPALS "kadm5test1 kadm5test2"
}

fixture_mit_kdc_logs() {
  local dir="$1" container file
  container="$(interop_container_name mit-kdc)"
  for file in krb5kdc.log kadmind.log krb5lib.log; do
    interop_rt exec "$container" cat "/var/log/krb5/$file" >"$dir/mit-kdc-$file" 2>/dev/null || true
  done
}
