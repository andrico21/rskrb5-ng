# shellcheck shell=bash
# Sourced by the lane 1D-a provision.d scripts (20-fast, 30-spake, 40-otp,
# 45-pkinit, 48-anonymous). The helpers of 10-base-realm.sh, repeated here
# because provision.d scripts run as separate processes: idempotent principal
# creation through kadmin.local, which exits 0 even when a query fails, so every
# query names the text it must report.
readonly REALM=TEST.RSKRB5
# OUT is read by the provision.d scripts that source this file (SC2034).
# shellcheck disable=SC2034
readonly OUT=/run/interop/out

# kadmin_query QUERY EXPECT: runs one kadmin.local query, fails unless the
# output contains EXPECT. A `-pw` argument is never echoed.
kadmin_query() {
  local query="$1" expect="$2" output
  output="$(kadmin.local -r "$REALM" -q "$query" 2>&1)" || {
    printf 'kadmin.local failed: %s\n' "${query%% -pw *}" >&2
    return 1
  }
  if [[ "$output" != *"$expect"* ]]; then
    printf 'kadmin.local did not report "%s" for: %s\n' "$expect" "${query%% -pw *}" >&2
    return 1
  fi
}

principal_exists() {
  kadmin.local -r "$REALM" -q "getprinc $1" 2>/dev/null | grep -q '^Principal: '
}

# ensure_principal NAME [addprinc options...]: creates NAME once.
ensure_principal() {
  local name="$1"
  shift
  if principal_exists "$name"; then
    return 0
  fi
  kadmin_query "addprinc $* $name" "Principal \"$name@$REALM\" created"
  printf 'created %s@%s\n' "$name" "$REALM"
}

# set_principal_string NAME KEY VALUE: sets a string attribute (VALUE has no
# spaces; kadmin splits its command line on whitespace).
set_principal_string() {
  kadmin_query "set_string $1 $2 $3" "Attribute set for principal"
  printf 'set string %s on %s@%s\n' "$2" "$1" "$REALM"
}
