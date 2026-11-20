# shellcheck shell=bash
# Host side of the DNS fixture `dns` (lane 1D-b, plan 2 todo 1 step 2),
# sourced by scripts/interop/run.sh. Layout contract: scripts/interop/lib.sh;
# shared helpers: scripts/interop/net-common/net.sh. This directory is named
# net-zone so it sorts after every other net-* fixture: the zones carry their
# container addresses and host ports.
#
# Container rskrb5-interop-dns: CoreDNS 1.15.0 (net-zone/Dockerfile) with a
# Corefile and zones rendered per run into $INTEROP_STATE_DIR/dns/coredns and
# bind-mounted read-only. Two views of the same records for the realms
# TEST.RSKRB5 (zone test.rskrb5) and OTHER.RSKRB5 (zone other.rskrb5):
#   port 53, the container-network view: targets are the fixtures' container
#     addresses and container ports (88, 464, 749; kdcproxy on 443);
#     INTEROP_DNS_CONTAINER_SERVER.
#   port 1053, the host view, published on 127.0.0.1 as INTEROP_DNS_PORT
#     (default 19153, UDP and TCP; INTEROP_DNS_SERVER, INTEROP_DNS_UDP,
#     INTEROP_DNS_TCP): targets resolve to 127.0.0.1 and carry the published
#     host ports (18088/18464/18749 for TEST, 19188/19164/19149 for OTHER,
#     https://localhost:19143/KdcProxy for the proxy).
# Records per realm (net_zone_file): TXT _kerberos (realm lookup); SRV
# _kerberos._udp/_tcp, _kerberos-master._udp/_tcp, _kpasswd._udp/_tcp,
# _kerberos-adm._tcp; URI _kerberos (krb5srv:m:udp primary, krb5srv::tcp, and
# for TEST krb5srv::kkdcp through the proxy), URI _kpasswd (tcp, udp); the
# site-specific names of site lab1 (_kerberos._udp/_tcp.lab1._sites and URI
# _kerberos.lab1._sites, target kdc-lab1); and kdc6 AAAA (host view ::1; the
# container view only when the network has IPv6). Ports are published on
# 127.0.0.1 only, so the ::1 record is discovery data: nothing listens there.
# No extra capability and no --privileged.
#
# Self-check: dig in the fixture answers every record type in both views, the
# URI/SRV/TXT/site/AAAA data parse; MIT 1.22.2 kinit (throwaway mit-kdc image
# container whose resolv.conf names this server, dns_lookup_kdc = true, no
# kdc relation) finds the TEST KDC by URI, by SRV (dns_uri_lookup = false) and
# by the lab1 site record (sitename = lab1), and the OTHER KDC by URI, each
# asserted in the trace; CoreDNS's query log shows the lookups.

# shellcheck source=scripts/interop/net-common/net.sh
source "$INTEROP_ROOT/scripts/interop/net-common/net.sh"

interop_fixture dns
# The Rust scenarios of the network fixtures (tests/interop_net.rs); kdcproxy
# and kcm are proven by their self-checks until todos 16 and 12 add scenarios.
interop_suite net interop_net mit-kdc mit-other dns httpd

NET_ZONE_SITE=lab1

# net_zone_file DOMAIN REALM KDC_ADDRESS PORTS [EXTRA]: prints the zone of
# DOMAIN (the realm's lower-case name) for one view. PORTS is
# "<kdc> <kpasswd> <kadmin>"; KDC_ADDRESS is the IPv4 address of the KDC
# names; EXTRA lines (more A/AAAA/URI records) are appended verbatim.
net_zone_file() {
  local domain="$1" realm="$2" address="$3" kdc kpasswd kadmin
  read -r kdc kpasswd kadmin <<<"$4"
  [[ "$domain" =~ ^[a-z0-9.-]+$ && "$realm" == "${domain^^}" ]] ||
    interop_die "zone $domain does not match realm $realm" || return 1
  [[ "$address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || interop_die "zone $domain: bad KDC address '$address'" || return 1
  [[ "$kdc$kpasswd$kadmin" =~ ^[0-9]+$ && -n "$kadmin" ]] || interop_die "zone $domain: bad ports '$4'" || return 1
  cat <<EOF
\$ORIGIN $domain.
\$TTL 60
@                        IN SOA  ns.$domain. hostmaster.$domain. ( 1 3600 600 86400 60 )
@                        IN NS   ns.$domain.
ns                       IN A    127.0.0.1
kdc                      IN A    $address
kdc-$NET_ZONE_SITE                 IN A    $address
_kerberos                IN TXT  "$realm"
_kerberos._udp           IN SRV  0 0 $kdc kdc.$domain.
_kerberos._tcp           IN SRV  0 0 $kdc kdc.$domain.
_kerberos-master._udp    IN SRV  0 0 $kdc kdc.$domain.
_kerberos-master._tcp    IN SRV  0 0 $kdc kdc.$domain.
_kpasswd._udp            IN SRV  0 0 $kpasswd kdc.$domain.
_kpasswd._tcp            IN SRV  0 0 $kpasswd kdc.$domain.
_kerberos-adm._tcp       IN SRV  0 0 $kadmin kdc.$domain.
_kerberos                IN URI  10 1 "krb5srv:m:udp:kdc.$domain:$kdc"
_kerberos                IN URI  20 1 "krb5srv::tcp:kdc.$domain:$kdc"
_kpasswd                 IN URI  10 1 "krb5srv::tcp:kdc.$domain:$kpasswd"
_kpasswd                 IN URI  20 1 "krb5srv::udp:kdc.$domain:$kpasswd"
_kerberos._udp.$NET_ZONE_SITE._sites IN SRV  0 0 $kdc kdc-$NET_ZONE_SITE.$domain.
_kerberos._tcp.$NET_ZONE_SITE._sites IN SRV  0 0 $kdc kdc-$NET_ZONE_SITE.$domain.
_kerberos.$NET_ZONE_SITE._sites      IN URI  10 1 "krb5srv:m:udp:kdc-$NET_ZONE_SITE.$domain:$kdc"
EOF
  [[ -z "${5:-}" ]] || printf '%s\n' "$5"
}

# net_zone_corefile: the Corefile of both views (zones under /etc/coredns).
net_zone_corefile() {
  local port view zone
  for port in 53 1053; do
    view=container
    [[ "$port" == 1053 ]] && view=host
    for zone in test.rskrb5 other.rskrb5; do
      printf '%s:%s {\n    file /etc/coredns/%s/%s.zone\n    log\n    errors\n}\n' "$zone" "$port" "$view" "$zone"
    done
  done
}

# net_zone_render DIR: writes the Corefile and both views' zones into DIR.
net_zone_render() {
  local dir="$1" mit_ip other_ip proxy_ip httpd_ip ipv6 extra
  mit_ip="$(net_container_ip "$INTEROP_MIT_CONTAINER")" || return 1
  other_ip="$(net_container_ip "$INTEROP_MIT_OTHER_CONTAINER")" || return 1
  proxy_ip="$(net_container_ip "$INTEROP_KDCPROXY_CONTAINER")" || return 1
  httpd_ip="$(net_container_ip "$INTEROP_HTTPD_CONTAINER")" || return 1
  ipv6="$(net_container_ipv6 "$INTEROP_MIT_CONTAINER")"
  mkdir -p "$dir/container" "$dir/host"
  net_zone_corefile >"$dir/Corefile"

  extra="kdcproxy                 IN A    $proxy_ip
httpd                    IN A    $httpd_ip
_kerberos                IN URI  30 1 \"krb5srv::kkdcp:https://kdcproxy.test.rskrb5/KdcProxy\""
  [[ -n "$ipv6" ]] && extra+=$'\n'"kdc6                     IN AAAA $ipv6"
  net_zone_file test.rskrb5 TEST.RSKRB5 "$mit_ip" "88 464 749" "$extra" >"$dir/container/test.rskrb5.zone" || return 1
  net_zone_file other.rskrb5 OTHER.RSKRB5 "$other_ip" "88 464 749" >"$dir/container/other.rskrb5.zone" || return 1

  extra="kdcproxy                 IN A    127.0.0.1
httpd                    IN A    127.0.0.1
kdc6                     IN AAAA ::1
_kerberos                IN URI  30 1 \"krb5srv::kkdcp:https://localhost:$(net_port "$INTEROP_KDCPROXY")/KdcProxy\""
  net_zone_file test.rskrb5 TEST.RSKRB5 127.0.0.1 \
    "$(net_port "$INTEROP_MIT_KDC") $(net_port "$INTEROP_MIT_KPASSWD") $(net_port "$INTEROP_MIT_KADMIN")" \
    "$extra" >"$dir/host/test.rskrb5.zone" || return 1
  net_zone_file other.rskrb5 OTHER.RSKRB5 127.0.0.1 \
    "$(net_port "$INTEROP_MIT_OTHER_KDC") $(net_port "$INTEROP_MIT_OTHER_KPASSWD") $(net_port "$INTEROP_MIT_OTHER_KADMIN")" \
    "kdc6                     IN AAAA ::1" >"$dir/host/other.rskrb5.zone" || return 1
  chmod -R a+rX "$dir"
}

fixture_dns_up() {
  local fixture=dns container dir out image host=127.0.0.1 ip
  local port
  port="$(interop_port INTEROP_DNS_PORT 19153)" || return 1
  container="$(interop_container_name "$fixture")"
  dir="$INTEROP_ROOT/scripts/interop/net-zone"
  out="$INTEROP_STATE_DIR/dns"
  net_require_mit "$fixture" || return 1
  [[ -n "${INTEROP_MIT_OTHER_CONTAINER:-}" && -n "${INTEROP_KDCPROXY_CONTAINER:-}" && -n "${INTEROP_HTTPD_CONTAINER:-}" ]] ||
    interop_die "fixture $fixture needs fixtures mit-other, kdcproxy and httpd to be up first" || return 1
  interop_prepare_private_dir "$out" || return 1
  net_zone_render "$out/coredns" || return 1

  image="$(interop_build_image dns "$dir")" || return 1
  interop_env INTEROP_DNS_IMAGE "$image"
  interop_run_container "$fixture" "$image" \
    -v "$out/coredns:/etc/coredns:ro" \
    -p "$host:$port:1053/udp" -p "$host:$port:1053/tcp" ||
    interop_die "fixture $fixture: container $container did not start" || return 1
  interop_wait_ready "$fixture" || return 1
  interop_wait_tcp "$fixture" "$host" "$port" || return 1
  ip="$(net_container_ip "$container")" || return 1

  interop_env INTEROP_DNS_CONTAINER "$container"
  interop_env INTEROP_DNS "$host:$port"
  interop_env INTEROP_DNS_SERVER "$host:$port"
  interop_env INTEROP_DNS_UDP "$host:$port"
  interop_env INTEROP_DNS_TCP "$host:$port"
  interop_env INTEROP_DNS_CONTAINER_SERVER "$ip:53"
  interop_env INTEROP_DNS_ZONES "test.rskrb5 other.rskrb5"
  interop_env INTEROP_DNS_SITE "$NET_ZONE_SITE"
  interop_env INTEROP_DNS_IPV6_HOST kdc6.test.rskrb5
  net_zone_self_check "$ip"
}

# net_zone_dig CHECK PORT TYPE NAME...: `dig +short` for each NAME in the
# fixture against one view; fails on a dig error or an empty answer.
net_zone_dig() {
  local check="$1" port="$2" type="$3" name answer
  shift 3
  for name in "$@"; do
    answer="$(interop_rt exec "$(interop_container_name dns)" \
      dig +short +time=2 +tries=2 -p "$port" -t "$type" @127.0.0.1 "$name" 2>&1)" || return 1
    printf '%s %s: %s\n' "$type" "$name" "${answer//$'\n'/ | }" >>"$INTEROP_STATE_DIR/dns/$check.log"
    [[ -n "$answer" ]] || return 1
  done
}

# net_zone_kinit CHECK IP PRINCIPAL KEYTAB [REALM RELATIONS]: traced MIT kinit
# with DNS discovery only, the resolver pointed at IP.
net_zone_kinit() {
  local check="$1" ip="$2" principal="$3" keytab="$4" relations="${5:-}" realm conf uri=true
  realm="${principal#*@}"
  [[ "$check" != srv ]] || uri=false
  conf="[libdefaults]
    default_realm = $realm
    dns_lookup_kdc = true
    dns_uri_lookup = $uri
    dns_lookup_realm = false
    dns_canonicalize_hostname = false
    rdns = false
[realms]
    $realm = {
$relations
    }"
  net_check_run "dns-$check" "$INTEROP_MIT_IMAGE" \
    -v "$INTEROP_STATE_DIR/mit:/in/mit:ro" -v "$INTEROP_STATE_DIR/mit-other:/in/mit-other:ro" \
    -e KRB5_CONFIG=/tmp/krb5.conf -e KRB5CCNAME=FILE:/tmp/cc -e KRB5_TRACE=/dev/stderr -- \
    "set -e; printf 'nameserver %s\n' '$ip' >/etc/resolv.conf; printf '%s\n' \"\$0\" >/tmp/krb5.conf
     kinit -k -t '$keytab' '$principal'" "$conf" >"$INTEROP_STATE_DIR/dns/$check.log"
}

net_zone_self_check() {
  local fixture=dns ip="$1" dir="$INTEROP_STATE_DIR/dns" view port kdc
  : >"$dir/selfcheck.txt"
  for view in container host; do
    port=53
    kdc=88
    if [[ "$view" == host ]]; then
      port=1053
      kdc="$(net_port "$INTEROP_MIT_KDC")"
    fi
    : >"$dir/dig-$view.log"
    if ! net_zone_dig "dig-$view" "$port" SRV _kerberos._udp.TEST.RSKRB5 _kerberos._tcp.TEST.RSKRB5 \
      _kpasswd._udp.TEST.RSKRB5 _kpasswd._tcp.TEST.RSKRB5 _kerberos-adm._tcp.TEST.RSKRB5 \
      "_kerberos._udp.$NET_ZONE_SITE._sites.TEST.RSKRB5" _kerberos._udp.OTHER.RSKRB5 ||
      ! net_zone_dig "dig-$view" "$port" URI _kerberos.TEST.RSKRB5 "_kerberos.$NET_ZONE_SITE._sites.TEST.RSKRB5" \
        _kpasswd.OTHER.RSKRB5 ||
      ! net_zone_dig "dig-$view" "$port" TXT _kerberos.test.rskrb5 _kerberos.other.rskrb5; then
      net_failed "$fixture" "dig-$view" "$dir/dig-$view.log"
      return 1
    fi
    net_expect "$fixture" "dig-$view" "$dir/dig-$view.log" \
      "0 0 $kdc kdc.test.rskrb5." "0 0 $kdc kdc-$NET_ZONE_SITE.test.rskrb5." \
      "10 1 \"krb5srv:m:udp:kdc.test.rskrb5:$kdc\"" "20 1 \"krb5srv::tcp:kdc.test.rskrb5:$kdc\"" \
      "30 1 \"krb5srv::kkdcp:https://" "10 1 \"krb5srv:m:udp:kdc-$NET_ZONE_SITE.test.rskrb5:$kdc\"" \
      '"TEST.RSKRB5"' '"OTHER.RSKRB5"' "kdc.other.rskrb5." "krb5srv::tcp:kdc.other.rskrb5:" || return 1
  done
  net_zone_dig dig-host 1053 AAAA kdc6.test.rskrb5 kdc6.other.rskrb5 ||
    { net_failed "$fixture" dig-host "$dir/dig-host.log"; return 1; }
  net_expect "$fixture" dig-host "$dir/dig-host.log" "AAAA kdc6.test.rskrb5: ::1" "AAAA kdc6.other.rskrb5: ::1" || return 1

  net_zone_kinit uri "$ip" testuser1@TEST.RSKRB5 /in/mit/testuser1.keytab ||
    { net_failed "$fixture" uri "$dir/uri.log"; return 1; }
  net_expect "$fixture" uri "$dir/uri.log" "Sending DNS URI query for _kerberos.TEST.RSKRB5." \
    'URI answer: 10 1 "krb5srv:m:udp:kdc.test.rskrb5:88"' "Resolving hostname kdc.test.rskrb5" || return 1
  net_refuse "$fixture" uri "$dir/uri.log" "Sending DNS SRV query" || return 1

  net_zone_kinit srv "$ip" testuser1@TEST.RSKRB5 /in/mit/testuser1.keytab ||
    { net_failed "$fixture" srv "$dir/srv.log"; return 1; }
  net_expect "$fixture" srv "$dir/srv.log" "Sending DNS SRV query for _kerberos._udp.TEST.RSKRB5." \
    'SRV answer: 0 0 88 "kdc.test.rskrb5' "Resolving hostname kdc.test.rskrb5" || return 1
  net_refuse "$fixture" srv "$dir/srv.log" "Sending DNS URI query" || return 1

  net_zone_kinit site "$ip" testuser1@TEST.RSKRB5 /in/mit/testuser1.keytab "        sitename = $NET_ZONE_SITE" ||
    { net_failed "$fixture" site "$dir/site.log"; return 1; }
  net_expect "$fixture" site "$dir/site.log" "Sending DNS URI query for _kerberos.$NET_ZONE_SITE._sites.TEST.RSKRB5." \
    "URI answer: 10 1 \"krb5srv:m:udp:kdc-$NET_ZONE_SITE.test.rskrb5:88\"" \
    "Resolving hostname kdc-$NET_ZONE_SITE.test.rskrb5" || return 1

  net_zone_kinit other "$ip" otheruser@OTHER.RSKRB5 /in/mit-other/otheruser.keytab ||
    { net_failed "$fixture" other "$dir/other.log"; return 1; }
  net_expect "$fixture" other "$dir/other.log" "Sending DNS URI query for _kerberos.OTHER.RSKRB5." \
    'URI answer: 10 1 "krb5srv:m:udp:kdc.other.rskrb5:88"' "Resolving hostname kdc.other.rskrb5" || return 1

  interop_rt logs "$(interop_container_name "$fixture")" >"$dir/server.log" 2>&1 || true
  # CoreDNS logs query names in lower case.
  net_expect "$fixture" server "$dir/server.log" '"URI IN _kerberos.test.rskrb5.' \
    '"SRV IN _kerberos._udp.test.rskrb5.' '"A IN kdc.test.rskrb5.' || return 1
  interop_log "fixture $fixture self-check passed (SRV/URI/TXT/site/AAAA records; MIT found the KDCs by URI, SRV and site)"
}

fixture_dns_logs() {
  net_logs dns "$1"
}
