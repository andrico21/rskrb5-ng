# shellcheck shell=bash
# Host side of the second MIT realm fixture `mit-other` (lane 1D-b, plan 2
# todo 1 step 2), sourced by scripts/interop/run.sh. Layout contract:
# scripts/interop/lib.sh; shared helpers: scripts/interop/net-common/net.sh.
#
# Container rskrb5-interop-mit-other (hostname kdc.other.rskrb5, network
# aliases kdc.other.rskrb5 and kdc.far.example) runs the mit-kdc image (MIT
# krb5 1.22.2, built from scripts/interop/mit/, reused by its tag) with this
# directory bind-mounted read-only at /opt/interop/net-other and its own
# entrypoint and profiles: one krb5kdc serves OTHER.RSKRB5 and FAR.EXAMPLE,
# kadmind serves OTHER.RSKRB5. Tmpfs holds the databases, stashes, secrets and
# keytabs. Published on 127.0.0.1 (TCP and UDP for 88 and 464):
#   INTEROP_MIT_OTHER_KDC_PORT (default 19188) -> 88,
#   INTEROP_MIT_OTHER_KPASSWD_PORT (19164) -> 464,
#   INTEROP_MIT_OTHER_KADMIN_PORT (19149) -> 749.
# No extra capability and no --privileged.
#
# Topology (cross-realm keys in both databases of each trust, same kvno 1 and
# the same four AES enctypes):
#
#     TEST.RSKRB5  <==== direct trust ====>  OTHER.RSKRB5  <==== direct ====>  FAR.EXAMPLE
#     (mit-kdc)    krbtgt/OTHER@TEST and      (mit-other)   krbtgt/FAR@OTHER    (mit-other)
#                  krbtgt/TEST@OTHER                        and krbtgt/OTHER@FAR
#
#   - TEST <-> OTHER: hierarchical neighbours under RSKRB5, but the route is
#     the direct trust; MIT clients and the Rust referral client ask TEST for
#     krbtgt/OTHER.RSKRB5@TEST.RSKRB5 directly.
#   - TEST -> FAR.EXAMPLE is NON-HIERARCHICAL: FAR.EXAMPLE shares no suffix
#     with TEST.RSKRB5 (the hierarchical path TEST.RSKRB5 -> RSKRB5 -> EXAMPLE
#     -> FAR.EXAMPLE names realms that do not exist), there is no
#     TEST<->FAR trust, and the TEST KDC has no [capaths]. The only route is
#     TEST -> OTHER -> FAR, which a client finds only through its own
#     [capaths] TEST.RSKRB5 = { FAR.EXAMPLE = OTHER.RSKRB5 } (written to
#     INTEROP_MIT_OTHER_CAPATHS_CONF); the FAR KDC checks the transited
#     realm OTHER.RSKRB5 against the same capaths (net-other/krb5.conf).
#
# Self-check (MIT 1.22.2 kinit/kvno with KRB5_TRACE in a throwaway mit-kdc
# image container): an OTHER user gets a TEST service ticket and a TEST user
# an OTHER service ticket (each through the cross-realm TGT, asserted in the
# trace); a TEST user's FAR.EXAMPLE service ticket fails without [capaths] and
# succeeds with it, the trace showing the path through OTHER.RSKRB5.

# shellcheck source=scripts/interop/net-common/net.sh
source "$INTEROP_ROOT/scripts/interop/net-common/net.sh"

interop_fixture mit-other

# Client-side profile of the self-check: the three realms on the container
# network; with $1 = capaths, the [capaths] entry for the FAR.EXAMPLE route.
net_other_client_conf() {
  cat <<'EOF'
[libdefaults]
    default_realm = TEST.RSKRB5
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    dns_canonicalize_hostname = false

[realms]
    TEST.RSKRB5 = {
        kdc = kdc.test.rskrb5:88
    }
    OTHER.RSKRB5 = {
        kdc = kdc.other.rskrb5:88
    }
    FAR.EXAMPLE = {
        kdc = kdc.far.example:88
    }
EOF
  if [[ "${1:-}" == capaths ]]; then
    cat <<'EOF'

[capaths]
    TEST.RSKRB5 = {
        OTHER.RSKRB5 = .
        FAR.EXAMPLE = OTHER.RSKRB5
    }
EOF
  fi
}

# net_other_kvno NAME CLIENT KEYTAB SERVICE [capaths]: kinit CLIENT from
# KEYTAB (a file in the mounted state dirs) and kvno SERVICE with a trace;
# writes the output to $INTEROP_STATE_DIR/mit-other/NAME.log and returns the
# kvno status.
net_other_kvno() {
  local name="$1" client="$2" keytab="$3" service="$4" mode="${5:-}" log conf
  log="$INTEROP_STATE_DIR/mit-other/$name.log"
  conf="$(net_other_client_conf "$mode")"
  net_check_run "mit-other-$name" "$INTEROP_MIT_IMAGE" \
    -v "$INTEROP_STATE_DIR/mit:/in/mit:ro" -v "$INTEROP_STATE_DIR/mit-other:/in/mit-other:ro" \
    -e KRB5_CONFIG=/tmp/krb5.conf -e KRB5CCNAME=FILE:/tmp/cc -- \
    "set -e; printf '%s\n' \"\$0\" >/tmp/krb5.conf; kinit -k -t '$keytab' '$client'; KRB5_TRACE=/dev/stderr kvno '$service'" \
    "$conf" >"$log"
}

fixture_mit_other_up() {
  local fixture=mit-other container dir out host=127.0.0.1
  local kdc_port kpasswd_port kadmin_port
  kdc_port="$(interop_port INTEROP_MIT_OTHER_KDC_PORT 19188)" || return 1
  kpasswd_port="$(interop_port INTEROP_MIT_OTHER_KPASSWD_PORT 19164)" || return 1
  kadmin_port="$(interop_port INTEROP_MIT_OTHER_KADMIN_PORT 19149)" || return 1
  container="$(interop_container_name "$fixture")"
  dir="$INTEROP_ROOT/scripts/interop/net-other"
  out="$INTEROP_STATE_DIR/mit-other"
  net_require_mit "$fixture" || return 1

  interop_env INTEROP_MIT_OTHER_USER_PASSWORD "$(interop_new_secret)"
  interop_env INTEROP_MIT_OTHER_ADMIN_PASSWORD "$(interop_new_secret)"
  interop_env INTEROP_MIT_OTHER_FAR_CROSS_REALM_SECRET "$(interop_new_secret)"
  local cross
  cross="$(net_derive_secret cross-realm "$INTEROP_MIT_ADMIN_PASSWORD")" || return 1
  interop_env INTEROP_MIT_OTHER_CROSS_REALM_SECRET "$cross"

  interop_run_container "$fixture" "$INTEROP_MIT_IMAGE" \
    --hostname kdc.other.rskrb5 --network-alias kdc.other.rskrb5 --network-alias kdc.far.example \
    --tmpfs /var/lib/krb5kdc:rw,mode=0700 \
    -v "$dir:/opt/interop/net-other:ro" \
    -e KRB5_CONFIG=/opt/interop/net-other/krb5.conf -e KRB5_KDC_PROFILE=/opt/interop/net-other/kdc.conf \
    --init --entrypoint /opt/interop/net-other/entrypoint.sh \
    -p "$host:$kdc_port:88/tcp" -p "$host:$kdc_port:88/udp" \
    -p "$host:$kpasswd_port:464/tcp" -p "$host:$kpasswd_port:464/udp" \
    -p "$host:$kadmin_port:749/tcp" ||
    interop_die "fixture $fixture: container $container did not start" || return 1
  interop_deliver_secrets "$container" INTEROP_MIT_OTHER_USER_PASSWORD INTEROP_MIT_OTHER_ADMIN_PASSWORD \
    INTEROP_MIT_OTHER_CROSS_REALM_SECRET INTEROP_MIT_OTHER_FAR_CROSS_REALM_SECRET || return 1
  interop_wait_ready "$fixture" || return 1
  interop_wait_tcp "$fixture" "$host" "$kdc_port" || return 1
  interop_wait_tcp "$fixture" "$host" "$kpasswd_port" || return 1
  interop_wait_tcp "$fixture" "$host" "$kadmin_port" || return 1

  interop_prepare_private_dir "$out" || return 1
  local file
  for file in otheruser.keytab http-other.keytab http-far.keytab; do
    interop_copy_out "$container" "/run/interop/out/$file" "$out/$file" || return 1
  done
  (umask 077 && net_other_client_conf capaths >"$out/capaths.conf")

  interop_env INTEROP_MIT_OTHER_CONTAINER "$container"
  interop_env INTEROP_MIT_OTHER_REALM OTHER.RSKRB5
  interop_env INTEROP_MIT_OTHER_KDC "$host:$kdc_port"
  interop_env INTEROP_MIT_OTHER_KPASSWD "$host:$kpasswd_port"
  interop_env INTEROP_MIT_OTHER_KADMIN "$host:$kadmin_port"
  interop_env INTEROP_MIT_OTHER_USER otheruser
  interop_env INTEROP_MIT_OTHER_USER_KEYTAB "$out/otheruser.keytab"
  interop_env INTEROP_MIT_OTHER_ADMIN_PRINCIPAL admin/admin
  interop_env INTEROP_MIT_OTHER_HTTP_SERVICE HTTP/http.other.rskrb5
  interop_env INTEROP_MIT_OTHER_HTTP_KEYTAB "$out/http-other.keytab"
  interop_env INTEROP_MIT_OTHER_FAR_REALM FAR.EXAMPLE
  interop_env INTEROP_MIT_OTHER_FAR_KDC "$host:$kdc_port"
  interop_env INTEROP_MIT_OTHER_FAR_HTTP_SERVICE HTTP/http.far.example
  interop_env INTEROP_MIT_OTHER_FAR_HTTP_KEYTAB "$out/http-far.keytab"
  interop_env INTEROP_MIT_OTHER_CAPATHS_CONF "$out/capaths.conf"

  net_other_self_check
}

net_other_self_check() {
  local fixture=mit-other dir="$INTEROP_STATE_DIR/mit-other"
  : >"$dir/selfcheck.txt"
  net_other_kvno other-to-test otheruser@OTHER.RSKRB5 /in/mit-other/otheruser.keytab \
    HTTP/http.test.rskrb5@TEST.RSKRB5 ||
    { net_failed "$fixture" other-to-test "$dir/other-to-test.log"; return 1; }
  net_expect "$fixture" other-to-test "$dir/other-to-test.log" \
    "Requesting TGT krbtgt/TEST.RSKRB5@OTHER.RSKRB5 using TGT krbtgt/OTHER.RSKRB5@OTHER.RSKRB5" \
    "Received creds for desired service HTTP/http.test.rskrb5@TEST.RSKRB5" || return 1

  net_other_kvno test-to-other testuser1@TEST.RSKRB5 /in/mit/testuser1.keytab \
    HTTP/http.other.rskrb5@OTHER.RSKRB5 ||
    { net_failed "$fixture" test-to-other "$dir/test-to-other.log"; return 1; }
  net_expect "$fixture" test-to-other "$dir/test-to-other.log" \
    "Requesting TGT krbtgt/OTHER.RSKRB5@TEST.RSKRB5 using TGT krbtgt/TEST.RSKRB5@TEST.RSKRB5" \
    "Received creds for desired service HTTP/http.other.rskrb5@OTHER.RSKRB5" || return 1

  if net_other_kvno far-without-capaths testuser1@TEST.RSKRB5 /in/mit/testuser1.keytab \
    HTTP/http.far.example@FAR.EXAMPLE; then
    interop_die "fixture $fixture self-check far-without-capaths failed: a TEST client reached FAR.EXAMPLE without [capaths]"
    return 1
  fi
  net_refuse "$fixture" far-without-capaths "$dir/far-without-capaths.log" \
    "Received creds for desired service HTTP/http.far.example@FAR.EXAMPLE" || return 1

  net_other_kvno far-with-capaths testuser1@TEST.RSKRB5 /in/mit/testuser1.keytab \
    HTTP/http.far.example@FAR.EXAMPLE capaths ||
    { net_failed "$fixture" far-with-capaths "$dir/far-with-capaths.log"; return 1; }
  net_expect "$fixture" far-with-capaths "$dir/far-with-capaths.log" \
    "Requesting TGT krbtgt/OTHER.RSKRB5@TEST.RSKRB5 using TGT krbtgt/TEST.RSKRB5@TEST.RSKRB5" \
    "Requesting TGT krbtgt/FAR.EXAMPLE@OTHER.RSKRB5 using TGT krbtgt/OTHER.RSKRB5@TEST.RSKRB5" \
    "Received creds for desired service HTTP/http.far.example@FAR.EXAMPLE" || return 1
  interop_log "fixture $fixture self-check passed (TEST<->OTHER trust, capaths-only route to FAR.EXAMPLE)"
}

fixture_mit_other_logs() {
  local dir="$1" container file
  container="$(interop_container_name mit-other)"
  for file in krb5kdc.log kadmind.log krb5lib.log; do
    interop_rt exec "$container" cat "/var/log/krb5/$file" >"$dir/mit-other-$file" 2>/dev/null || true
  done
  net_logs mit-other "$dir"
}
