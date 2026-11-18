#!/bin/bash
# Base realm TEST.RSKRB5 of the MIT interop fixture (lane 1C). Idempotent:
# an existing database, principal or keytab is kept or rewritten, never
# duplicated. Passwords come from the environment exported by entrypoint.sh
# (INTEROP_MIT_*_PASSWORD, generated per run by run.sh); they are passed only
# to kadmin.local inside this container and never printed.
#
# Principals (names are part of the layout contract, see scripts/interop/lib.sh):
#   testuser1                 disposable user, password, renewable tickets
#   preauthuser               +requires_preauth, password
#   kpasswduser               disposable password-change account, +requires_preauth
#   HTTP/http.test.rskrb5     service, random keys, keytab out/http.keytab
#   host/mit-kdc.test.rskrb5  host keytab out/host.keytab
#     Both services are +no_auth_data_required: MIT 1.20+ puts a PAC without
#     KERB_VALIDATION_INFO into every other service ticket
#     (src/kdc/kdc_authdata.c:479-494), which the rskrb5-ng acceptor refuses
#     today (reported library defect); PAC interop is added with the PAC work.
#   admin/admin               kadmind administrator (ACL: everything)
#   kadm5test1, kadm5test2    disposable principals for kadm5 work
# Every principal has AES-SHA2 and AES-SHA1 keys (kdc.conf supported_enctypes).
set -euo pipefail

readonly REALM=TEST.RSKRB5
readonly OUT=/run/interop/out

: "${INTEROP_MIT_USER_PASSWORD:?}" "${INTEROP_MIT_PREAUTH_USER_PASSWORD:?}"
: "${INTEROP_MIT_KPASSWD_USER_PASSWORD:?}" "${INTEROP_MIT_ADMIN_PASSWORD:?}"

# Runs one kadmin.local query and fails unless its output contains `expect`
# (kadmin.local exits 0 even when the query fails).
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

exists() {
  kadmin.local -r "$REALM" -q "getprinc $1" 2>/dev/null | grep -q '^Principal: '
}

# ensure_principal NAME [addprinc options...]: creates NAME once.
ensure_principal() {
  local name="$1"
  shift
  if exists "$name"; then
    return 0
  fi
  kadmin_query "addprinc $* $name" "Principal \"$name@$REALM\" created"
  printf 'created %s@%s\n' "$name" "$REALM"
}

export_keytab() {
  local file="$OUT/$1" name="$2"
  rm -f "$file"
  kadmin_query "ktadd -k $file -norandkey $name" "added to keytab"
  printf 'exported %s@%s to out/%s\n' "$name" "$REALM" "$1"
}

if [[ ! -f /var/lib/krb5kdc/principal ]]; then
  # The master password protects the stash on this container's tmpfs only.
  kdb5_util create -s -r "$REALM" -P "$(head -c 48 /dev/urandom | base64 -w0)" >/dev/null
  printf 'created the %s database\n' "$REALM"
fi

kadmin_query "modprinc -maxrenewlife \"7 days\" krbtgt/$REALM" "modified"
ensure_principal testuser1 -maxrenewlife '"7 days"' -pw "$INTEROP_MIT_USER_PASSWORD"
ensure_principal preauthuser +requires_preauth -pw "$INTEROP_MIT_PREAUTH_USER_PASSWORD"
ensure_principal kpasswduser +requires_preauth -pw "$INTEROP_MIT_KPASSWD_USER_PASSWORD"
ensure_principal HTTP/http.test.rskrb5 +no_auth_data_required -randkey
ensure_principal host/mit-kdc.test.rskrb5 +no_auth_data_required -randkey
ensure_principal admin/admin -pw "$INTEROP_MIT_ADMIN_PASSWORD"
ensure_principal kadm5test1 -randkey
ensure_principal kadm5test2 -randkey

export_keytab http.keytab HTTP/http.test.rskrb5
export_keytab host.keytab host/mit-kdc.test.rskrb5
export_keytab testuser1.keytab testuser1
export_keytab preauthuser.keytab preauthuser
