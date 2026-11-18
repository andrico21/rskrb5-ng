# shellcheck shell=bash
# Helpers shared by the MIT network fixtures of lane 1D-b (plan 2 todo 1):
# net-httpd (httpd), net-kcm (kcm), net-kdcproxy (kdcproxy), net-other
# (mit-other) and net-zone (dns). Sourced by each of their fixture.sh files
# (this directory has no fixture.sh, so run.sh does not register it). See the
# layout contract in scripts/interop/lib.sh.
#
# Ordering: run.sh starts fixtures in the glob order of their directories, and
# every fixture here needs mit-kdc (scripts/interop/mit/) to be up first. The
# directories are named net-* so they sort after mit/ in every collation (C
# puts '-' before '/', so a mit-* name would start before mit/), and net-zone
# sorts last because its zone carries the other fixtures' addresses.
#
# Self-checks: each fixture ends its fixture_<id>_up with a self-check that
# drives it with the reference tools and asserts the mechanism actually used
# (net_expect). MIT 1.22.2 client tools run in a throwaway container of the
# mit-kdc image (net_check_run) on the interop network, with KRB5_TRACE on.
# Only the asserted lines are kept as the fixture's self-check summary.

# net_require_mit FIXTURE: fails unless mit-kdc already recorded its image
# and KDC endpoint in this run.
net_require_mit() {
  [[ -n "${INTEROP_MIT_IMAGE:-}" && -n "${INTEROP_MIT_KDC:-}" ]] ||
    interop_die "fixture $1 needs fixture mit-kdc (scripts/interop/mit/) to be up first"
}

# net_port HOST:PORT: prints PORT.
net_port() {
  printf '%s' "${1##*:}"
}

# net_container_ip CONTAINER: prints the container's IPv4 address on the
# interop network.
net_container_ip() {
  local ip
  ip="$(interop_rt inspect -f "{{(index .NetworkSettings.Networks \"$INTEROP_NETWORK\").IPAddress}}" "$1" 2>/dev/null)" || ip=""
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    interop_die "container $1 has no IPv4 address on network $INTEROP_NETWORK" || return 1
  printf '%s' "$ip"
}

# net_container_ipv6 CONTAINER: prints the container's global IPv6 address on
# the interop network, or nothing when the network has no IPv6.
net_container_ipv6() {
  interop_rt inspect -f "{{(index .NetworkSettings.Networks \"$INTEROP_NETWORK\").GlobalIPv6Address}}" "$1" 2>/dev/null || true
}

# net_derive_secret LABEL ADMIN_PASSWORD: prints a per-run secret derived
# from the per-run kadmin password of mit-kdc, for a TEST.RSKRB5 principal
# that mit/provision.d creates with the same derivation inside the TEST
# container (mit/fixture.sh delivers a fixed secret list there, so a lane-1D-b
# drop-in cannot receive a new secret of its own). One-way: the first 32 hex
# characters of sha256("rskrb5-interop <LABEL> v1:<admin password>").
# Labels: cross-realm (krbtgt/OTHER.RSKRB5@TEST.RSKRB5 and
# krbtgt/TEST.RSKRB5@OTHER.RSKRB5, 50-other-realm.sh), kpasswd-old and
# kpasswd-new (proxypwuser, 51-net-services.sh).
net_derive_secret() {
  [[ "$1" =~ ^[a-z-]+$ ]] || interop_die "invalid derivation label '$1'" || return 1
  [[ "$2" =~ ^[A-Za-z0-9]+$ ]] || interop_die "secret derivation needs the mit-kdc admin password" || return 1
  printf 'rskrb5-interop %s v1:%s' "$1" "$2" | sha256sum | cut -c1-32
}

# net_mask_trace: copies stdin to stdout with MIT trace key hashes
# ("{etype}/{hash}", e.g. aes256-cts/1A2B) masked.
net_mask_trace() {
  sed -E 's#([a-z0-9-]+)/[0-9A-F]{4}([^0-9A-Za-z]|$)#\1/<masked>\2#g'
}

# net_expect FIXTURE CHECK LOG PATTERN...: fails naming the fixture and the
# check unless LOG contains every fixed-string PATTERN; appends each matched
# line to the fixture's self-check summary
# $INTEROP_STATE_DIR/<fixture>/selfcheck.txt.
net_expect() {
  local fixture="$1" check="$2" log="$3" pattern line summary
  shift 3
  summary="$INTEROP_STATE_DIR/$fixture/selfcheck.txt"
  for pattern in "$@"; do
    line="$(grep -F -m1 -- "$pattern" "$log" || true)"
    if [[ -z "$line" ]]; then
      interop_log "fixture $fixture self-check $check: last lines of $log:"
      tail -n 25 "$log" | net_mask_trace >&2
      interop_die "fixture $fixture self-check $check failed: no line contains '$pattern'"
      return 1
    fi
    printf '%s: %s\n' "$check" "$line" | net_mask_trace >>"$summary"
  done
}

# net_failed FIXTURE CHECK LOG: reports a self-check whose command failed,
# with the masked tail of LOG, and fails naming the fixture.
net_failed() {
  interop_log "fixture $1 self-check $2: last lines of $3:"
  tail -n 25 "$3" | net_mask_trace >&2
  interop_die "fixture $1 self-check $2 failed: its command exited non-zero"
}

# net_refuse FIXTURE CHECK LOG PATTERN: fails naming the fixture and the check
# when LOG contains PATTERN (a negative self-check that must not succeed).
net_refuse() {
  local fixture="$1" check="$2" log="$3" pattern="$4"
  if grep -qF -- "$pattern" "$log"; then
    interop_die "fixture $fixture self-check $check failed: unexpected '$pattern'"
    return 1
  fi
  printf '%s: no line contains %s (as required)\n' "$check" "$pattern" >>"$INTEROP_STATE_DIR/$fixture/selfcheck.txt"
}

# net_check_run NAME IMAGE [run options...] -- SCRIPT [ARG0]: runs the bash
# SCRIPT in a throwaway, labelled container of IMAGE (usually
# $INTEROP_MIT_IMAGE, the MIT krb5 1.22.2 client tools) on the interop
# network; prints its combined output and returns its status. `down` removes
# the container if the run is interrupted.
net_check_run() {
  local name="$1" image="$2"
  shift 2
  local -a options=()
  while (($# > 0)) && [[ "$1" != -- ]]; do
    options+=("$1")
    shift
  done
  [[ "${1:-}" == -- ]] || interop_die "net_check_run $name: missing -- before the command" || return 1
  shift
  interop_rt run --rm --name "rskrb5-interop-check-$name" --label "$INTEROP_LABEL=1" \
    --network "$INTEROP_NETWORK" --entrypoint /bin/bash "${options[@]}" "$image" -c "$@" 2>&1
}

# net_logs FIXTURE DIR: copies the fixture's self-check summary into DIR.
net_logs() {
  local summary="$INTEROP_STATE_DIR/$1/selfcheck.txt"
  [[ -f "$summary" ]] && cp "$summary" "$2/$1-selfcheck.txt"
  return 0
}
