#!/bin/bash
# Plan 2 todo 25 (WP-17, localauth): the local accounts and .k5login files that
# MIT's krb5_kuserok (localauth-probe) and this crate's authorizer are asked
# about. tests/interop_localauth rebuilds the same states under a temporary
# directory (it cannot chown to root or to another user) and compares answers.
#   lauthmapped  no .k5login (reached through an auth_to_local RULE)
#   lauthnone    no .k5login (reached through auth_to_local_names)
#   lauthlist    .k5login owned by the account, mode 0644, lists preauthuser
#   lauthother   .k5login lists preauthuser but belongs to another user
#   lauthwide    .k5login lists preauthuser, mode 0666 (MIT does not look)
#   lauthlink    .k5login is a symbolic link to a file that lists preauthuser
# Idempotent; nothing secret is involved.
set -euo pipefail

readonly REALM=TEST.RSKRB5
readonly LISTED="preauthuser@$REALM"

for account in lauthmapped lauthnone lauthlist lauthother lauthwide lauthlink; do
  id -u "$account" >/dev/null 2>&1 ||
    useradd --create-home --shell /usr/sbin/nologin "$account"
done

# k5login FILE OWNER MODE: writes the one-line file and sets owner and mode.
k5login() {
  printf '%s\n' "$LISTED" >"$1"
  chown "$2" "$1"
  chmod "$3" "$1"
}

k5login /home/lauthlist/.k5login lauthlist 0644
k5login /home/lauthother/.k5login lauthnone 0644
k5login /home/lauthwide/.k5login lauthwide 0666
k5login /home/lauthlink/k5login.real lauthlink 0644
ln -sfn /home/lauthlink/k5login.real /home/lauthlink/.k5login
printf 'created the localauth accounts and .k5login files\n'
