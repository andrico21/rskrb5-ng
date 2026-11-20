#!/usr/bin/env bash
# The macOS fixture of rskrb5-ng-os (plan 2 todo 14), for CI only: a
# throwaway MIT 1.22.2 realm from Homebrew `krb5` on 127.0.0.1:19648, a client
# with a random password, and two caches MIT `kinit` seeds: `API:<uuid>`
# (Kerberos.framework CCAPI, whose residuals are UUIDs on current macOS) and
# `KCM:<name>` in the system's `org.h5l.kcm` service. It exports the
# variables the ignored tests read (`src/macos/tests.rs`) to `$GITHUB_ENV`.
set -euo pipefail

brew install krb5 >/dev/null
mit="$(brew --prefix krb5)"
realm=FIXTURE.RSKRB5-NG.TEST
dir="$RUNNER_TEMP/rskrb5-ng-os-realm"
mkdir -p "$dir"
password="$(openssl rand -hex 24)"
echo "::add-mask::$password"

cat >"$dir/krb5.conf" <<CONF
[libdefaults]
  default_realm = $realm
  dns_lookup_kdc = false
  dns_lookup_realm = false
[realms]
  $realm = {
    kdc = 127.0.0.1:19648
  }
CONF
cat >"$dir/kdc.conf" <<CONF
[kdcdefaults]
  kdc_listen = 127.0.0.1:19648
  kdc_tcp_listen = 127.0.0.1:19648
[realms]
  $realm = {
    database_name = $dir/principal
    key_stash_file = $dir/stash
    acl_file = $dir/kadm5.acl
  }
CONF
touch "$dir/kadm5.acl"
export KRB5_CONFIG="$dir/krb5.conf" KRB5_KDC_PROFILE="$dir/kdc.conf"
"$mit/sbin/kdb5_util" -r "$realm" create -s -P "$(openssl rand -hex 24)" >/dev/null
"$mit/sbin/kadmin.local" -r "$realm" -q "addprinc -pw $password fixture" >/dev/null
nohup "$mit/sbin/krb5kdc" -n >"$dir/kdc.log" 2>&1 &
for _ in $(seq 1 50); do
  if nc -z 127.0.0.1 19648 2>/dev/null; then break; fi
  sleep 0.2
done

api="$(uuidgen)"
kcm="rskrb5-ng-os-$(uuidgen)"
echo "$password" | "$mit/bin/kinit" -c "API:$api" "fixture@$realm"
"$mit/bin/klist" -c "API:$api"
echo "$password" | "$mit/bin/kinit" -c "KCM:$kcm" "fixture@$realm"
"$mit/bin/klist" -c "KCM:$kcm"

{
  echo "KRB5_CONFIG=$dir/krb5.conf"
  echo "RSKRB5_NG_OS_PRINCIPAL=fixture@$realm"
  echo "RSKRB5_NG_OS_API_CACHE=$api"
  echo "RSKRB5_NG_OS_API_COPY=$(uuidgen)"
  echo "RSKRB5_NG_OS_KCM_CACHE=$kcm"
  echo "RSKRB5_NG_OS_MIT_BIN=$mit/bin"
  echo "RSKRB5_NG_OS_MIT_KINIT=$mit/bin/kinit"
  echo "RSKRB5_NG_OS_KRB5_CONF=$dir/krb5.conf"
  echo "RSKRB5_NG_OS_PASSWORD=$password"
} >>"$GITHUB_ENV"
