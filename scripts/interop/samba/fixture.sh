# shellcheck shell=bash
# Host side of the Samba AD DC fixtures `samba-res` and `samba-user` (lane 1E),
# sourced by scripts/interop/run.sh. See the layout contract in
# scripts/interop/lib.sh.
#
# Topology (one image, rskrb5-interop/samba:<hash>, Debian trixie Samba 4.22):
#
#   rskrb5-interop-samba-user                rskrb5-interop-samba-res
#   DC dcuser.user.rskrb5                    DC dcres.res.rskrb5
#   realm USER.RSKRB5, NetBIOS USER   <==>   realm RES.RSKRB5, NetBIOS RES
#             bidirectional forest trust (samba-tool domain trust create
#             --type=forest --direction=both, created from samba-user, trust.sh;
#             the USER-side trusted-domain object allows RC4 session keys,
#             0x1c, for the seeded RC4 trust scenario; the trust keys are AES)
#
#   DNS: each DC resolves through its own Samba DNS server (its zone), whose
#   `dns forwarder` is the runtime's DNS server on the network rskrb5-interop;
#   that server knows every container alias, so dcuser.user.rskrb5 reaches
#   dcres.res.rskrb5 and back by name. The trust addresses the remote DC by
#   that IP, and every Kerberos client names the KDCs explicitly, so neither
#   forest needs the other's SRV records.
#
#   Published on 127.0.0.1 (TCP, and UDP for 88 and 464):
#     samba-user: KDC 19300->88, kpasswd 19301->464, LDAP 19302->389, LDAPS 19303->636
#     samba-res:  KDC 19310->88, kpasswd 19311->464, LDAP 19312->389, LDAPS 19313->636
#   (INTEROP_SAMBA_<USER|RES>_<KDC|KPASSWD|LDAP|LDAPS>_PORT override them).
#
# Settings of both DCs (entrypoint.sh provision_domain): domain and DC
# functional level 2016 (claims, authentication policies, compound
# identity). Samba (at any functional level) puts a zero-length claims buffer
# into the PAC of a user without claims and of every ticket across the trust
# (claims do not cross it), which the crate's PAC parser refuses (register row
# FU-IOP-P14, todo 22): s4uclient, kpasswduser or any cross-trust ticket
# reproduce it; testuser1 and resuser carry a claim; `ldap server
# require strong auth = yes` and `tls enabled = yes` (channel-binding
# enforcement: LDAP SASL binds over TLS need correct tls-endpoint channel
# bindings, simple binds need TLS, plain LDAP needs sign or seal; Samba 4.21+);
# `kdc enable fast = yes`; NT ACLs in a TDB (`vfs objects = dfs_samba4
# acl_xattr xattr_tdb`), so the containers need NO extra capability and no
# --privileged; test password policy without complexity, minimum age or
# history (setup-*.sh).
#
# Accounts (setup-user.sh, setup-res.sh), every password generated per run:
#   USER.RSKRB5: testuser1 (client, claim Department=Interop), testuser3
#     (DONT_REQUIRE_PREAUTH; Samba still requires pre-authentication,
#     FU-IOP-P15), testuser2 (HTTP/user2.user.rskrb5, AES,
#     claims and compound-identity support bits), kpasswduser (Rust kpasswd,
#     FU-TST-06), kpasswdcheck (self-check kpasswd), setpwtarget (targeted
#     set-password target), s4uclient (the impersonated user), svc-s4u
#     (HTTP/s4u.user.rskrb5, protocol transition, constrained delegation to
#     HTTP/backend.user.rskrb5 only), svc-rbcd (HTTP/rbcd.user.rskrb5,
#     protocol transition, no msDS-AllowedToDelegateTo: only RBCD on
#     svc-backend lets it delegate), svc-backend (HTTP/backend.user.rskrb5,
#     msDS-AllowedToActOnBehalfOfOtherIdentity = svc-rbcd), svc-denied
#     (HTTP/denied.user.rskrb5, nobody may delegate to it); Administrator.
#   RES.RSKRB5: sysHTTP (HTTP/host.res.rskrb5, AES and RC4-HMAC), resuser
#     (client, claim Department=Interop); Administrator.
#
# Order: samba-res starts first; samba-user then starts, creates the trust
# (trust.sh, needs both administrators' passwords) and runs the self-check
# (selfcheck.sh): a fixture that runs but does not deliver a feature fails
# `up`, naming samba-user. INTEROP_SAMBA=0 leaves both fixtures and the
# `samba` suite unregistered (the `mit` job of interop.yml sets it; the
# `samba` job runs every suite).

if [[ "${INTEROP_SAMBA:-1}" != 0 ]]; then
  interop_fixture samba-res
  interop_fixture samba-user
  interop_suite samba interop_samba samba-user samba-res
fi

# samba_start ROLE IMAGE KDC KPASSWD LDAP LDAPS SECRET...: starts the DC of
# ROLE with its ports published, delivers SECRET... and waits until it serves.
samba_start() {
  local role="$1" image="$2" kdc="$3" kpasswd="$4" ldap="$5" ldaps="$6" host=127.0.0.1
  shift 6
  local fixture="samba-$role" dc
  dc="$(samba_dc_name "$role")"
  interop_run_container "$fixture" "$image" \
    --hostname "$dc" --network-alias "$dc" -e "SAMBA_ROLE=$role" \
    --tmpfs /var/lib/samba:rw,mode=0755 \
    -p "$host:$kdc:88/tcp" -p "$host:$kdc:88/udp" \
    -p "$host:$kpasswd:464/tcp" -p "$host:$kpasswd:464/udp" \
    -p "$host:$ldap:389/tcp" -p "$host:$ldaps:636/tcp" ||
    interop_die "fixture $fixture: container $(interop_container_name "$fixture") did not start" || return 1
  interop_deliver_secrets "$(interop_container_name "$fixture")" "$@" || return 1
  interop_wait_ready "$fixture" || return 1
  local port
  for port in "$kdc" "$kpasswd" "$ldap" "$ldaps"; do
    interop_wait_tcp "$fixture" "$host" "$port" || return 1
  done
}

samba_dc_name() {
  case "$1" in
    user) printf 'dcuser.user.rskrb5' ;;
    res) printf 'dcres.res.rskrb5' ;;
  esac
}

# samba_copy_out FIXTURE FILE...: copies /run/interop/out/FILE... into
# $INTEROP_STATE_DIR/FIXTURE/ (mode 0600).
samba_copy_out() {
  local fixture="$1" out="$INTEROP_STATE_DIR/$1" file
  shift
  interop_prepare_private_dir "$out" || return 1
  for file in "$@"; do
    interop_copy_out "$(interop_container_name "$fixture")" "/run/interop/out/$file" "$out/$file" || return 1
  done
}

# samba_env PREFIX ROLE KDC KPASSWD LDAP LDAPS: the endpoint and domain keys.
samba_env() {
  local prefix="$1" role="$2" host=127.0.0.1 realm
  realm="${role^^}.RSKRB5"
  interop_env "${prefix}_CONTAINER" "$(interop_container_name "samba-$role")"
  interop_env "${prefix}_REALM" "$realm"
  interop_env "${prefix}_NETBIOS" "${role^^}"
  interop_env "${prefix}_DNS_DOMAIN" "${realm,,}"
  interop_env "${prefix}_DC" "$(samba_dc_name "$role")"
  interop_env "${prefix}_KDC" "$host:$3"
  interop_env "${prefix}_KPASSWD" "$host:$4"
  interop_env "${prefix}_LDAP" "$host:$5"
  interop_env "${prefix}_LDAPS" "$host:$6"
  interop_env "${prefix}_LDAPS_CA" "$INTEROP_STATE_DIR/samba-$role/ldaps-ca.pem"
  interop_env "${prefix}_ADMIN_PRINCIPAL" Administrator
}

fixture_samba_res_up() {
  local image prefix=INTEROP_SAMBA_RES out="$INTEROP_STATE_DIR/samba-res"
  local kdc="${INTEROP_SAMBA_RES_KDC_PORT:-19310}" kpasswd="${INTEROP_SAMBA_RES_KPASSWD_PORT:-19311}"
  local ldap="${INTEROP_SAMBA_RES_LDAP_PORT:-19312}" ldaps="${INTEROP_SAMBA_RES_LDAPS_PORT:-19313}"
  image="$(interop_build_image samba "$INTEROP_ROOT/scripts/interop/samba")" || return 1
  interop_env "${prefix}_IMAGE" "$image"
  interop_env "${prefix}_ADMIN_PASSWORD" "$(interop_new_secret)"
  interop_env "${prefix}_HTTP_ACCOUNT_PASSWORD" "$(interop_new_secret)"
  interop_env "${prefix}_USER_PASSWORD" "$(interop_new_secret)"
  samba_start res "$image" "$kdc" "$kpasswd" "$ldap" "$ldaps" \
    "${prefix}_ADMIN_PASSWORD" "${prefix}_HTTP_ACCOUNT_PASSWORD" "${prefix}_USER_PASSWORD" || return 1
  samba_copy_out samba-res syshttp.keytab http.keytab ldaps-ca.pem || return 1
  samba_env "$prefix" res "$kdc" "$kpasswd" "$ldap" "$ldaps"
  interop_env "${prefix}_HTTP_SERVICE" HTTP/host.res.rskrb5
  interop_env "${prefix}_HTTP_ACCOUNT" sysHTTP
  interop_env "${prefix}_HTTP_ACCOUNT_KEYTAB" "$out/syshttp.keytab"
  interop_env "${prefix}_HTTP_KEYTAB" "$out/http.keytab"
  interop_env "${prefix}_USER" resuser
  interop_env "${prefix}_CLAIM_TYPE" Department
  interop_env "${prefix}_CLAIM_VALUE" Interop
}

fixture_samba_user_up() {
  local image prefix=INTEROP_SAMBA_USER out="$INTEROP_STATE_DIR/samba-user" name
  local kdc="${INTEROP_SAMBA_USER_KDC_PORT:-19300}" kpasswd="${INTEROP_SAMBA_USER_KPASSWD_PORT:-19301}"
  local ldap="${INTEROP_SAMBA_USER_LDAP_PORT:-19302}" ldaps="${INTEROP_SAMBA_USER_LDAPS_PORT:-19303}"
  local -a secrets=()
  [[ -n "${INTEROP_SAMBA_RES_ADMIN_PASSWORD:-}" ]] ||
    interop_die "fixture samba-user needs samba-res (its trust partner) started first" || return 1
  image="$(interop_build_image samba "$INTEROP_ROOT/scripts/interop/samba")" || return 1
  interop_env "${prefix}_IMAGE" "$image"
  for name in ADMIN USER NOPREAUTH_USER HTTP_ACCOUNT KPASSWD_USER KPASSWD_USER_NEW KPASSWD_CHECK \
    KPASSWD_CHECK_NEW SETPW_TARGET S4U_CLIENT S4U_ACCOUNT RBCD_ACCOUNT DELEGATION_TARGET DELEGATION_DENIED; do
    interop_env "${prefix}_${name}_PASSWORD" "$(interop_new_secret)"
    # The new kpasswduser password is the Rust client's to set: never delivered.
    [[ "$name" == KPASSWD_USER_NEW ]] || secrets+=("${prefix}_${name}_PASSWORD")
  done
  secrets+=(INTEROP_SAMBA_RES_ADMIN_PASSWORD INTEROP_SAMBA_RES_USER_PASSWORD)
  samba_start user "$image" "$kdc" "$kpasswd" "$ldap" "$ldaps" "${secrets[@]}" || return 1
  local container
  container="$(interop_container_name samba-user)"
  interop_rt exec "$container" /opt/interop/samba/trust.sh ||
    interop_die "fixture samba-user: the forest trust USER.RSKRB5 <-> RES.RSKRB5 was not created" || return 1
  interop_rt exec "$container" /opt/interop/samba/selfcheck.sh ||
    interop_die "fixture samba-user: self-check failed (container $container)" || return 1
  samba_copy_out samba-user testuser1.keytab testuser3.keytab testuser2.keytab http.keytab \
    svc-s4u.keytab svc-rbcd.keytab svc-backend.keytab ldaps-ca.pem || return 1
  samba_env "$prefix" user "$kdc" "$kpasswd" "$ldap" "$ldaps"
  interop_env "${prefix}_TRUST" "forest bidirectional USER.RSKRB5 RES.RSKRB5"
  interop_env "${prefix}_USER" testuser1
  interop_env "${prefix}_USER_KEYTAB" "$out/testuser1.keytab"
  interop_env "${prefix}_NOPREAUTH_USER" testuser3
  interop_env "${prefix}_NOPREAUTH_USER_KEYTAB" "$out/testuser3.keytab"
  interop_env "${prefix}_HTTP_SERVICE" HTTP/user2.user.rskrb5
  interop_env "${prefix}_HTTP_ACCOUNT" testuser2
  interop_env "${prefix}_HTTP_ACCOUNT_KEYTAB" "$out/testuser2.keytab"
  interop_env "${prefix}_HTTP_KEYTAB" "$out/http.keytab"
  interop_env "${prefix}_KPASSWD_USER" kpasswduser
  interop_env "${prefix}_SETPW_TARGET" setpwtarget
  interop_env "${prefix}_S4U_CLIENT" s4uclient
  interop_env "${prefix}_S4U_ACCOUNT" svc-s4u
  interop_env "${prefix}_S4U_SERVICE" HTTP/s4u.user.rskrb5
  interop_env "${prefix}_S4U_KEYTAB" "$out/svc-s4u.keytab"
  interop_env "${prefix}_RBCD_ACCOUNT" svc-rbcd
  interop_env "${prefix}_RBCD_SERVICE" HTTP/rbcd.user.rskrb5
  interop_env "${prefix}_RBCD_KEYTAB" "$out/svc-rbcd.keytab"
  interop_env "${prefix}_DELEGATION_TARGET" HTTP/backend.user.rskrb5
  interop_env "${prefix}_DELEGATION_TARGET_KEYTAB" "$out/svc-backend.keytab"
  interop_env "${prefix}_DELEGATION_DENIED" HTTP/denied.user.rskrb5
  interop_env "${prefix}_CLAIM_TYPE" Department
  interop_env "${prefix}_CLAIM_VALUE" Interop
}

samba_logs() {
  interop_rt exec "$(interop_container_name "$1")" cat /run/interop/provision.log >"$2/$1-provision.log" 2>/dev/null || true
}

fixture_samba_res_logs() {
  samba_logs samba-res "$1"
}

fixture_samba_user_logs() {
  samba_logs samba-user "$1"
}
