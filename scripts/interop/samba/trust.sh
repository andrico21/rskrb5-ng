#!/bin/bash
# Creates the bidirectional forest trust USER.RSKRB5 <-> RES.RSKRB5. Run by
# fixture.sh inside the samba-user container after both DCs are ready. The
# remote DC is addressed by the IP of its network alias dcres.res.rskrb5 (no
# DNS SRV lookup of the other forest is needed). Both administrators'
# credentials go through mode-0600 authentication files on the tmpfs
# /run/interop, removed on exit; nothing is passed on argv.
set -euo pipefail
# shellcheck source=scripts/interop/samba/lib-dc.sh
source /opt/interop/samba/lib-dc.sh
load_secrets
[[ "$SAMBA_ROLE" == user ]] || fail "trust.sh runs in the samba-user container"

readonly REMOTE_AUTH="$RUN_DIR/res-admin.auth" LOCAL_AUTH="$RUN_DIR/user-admin.auth"
trap 'rm -f "$REMOTE_AUTH" "$LOCAL_AUTH"' EXIT
umask 077
printf 'username = Administrator\npassword = %s\ndomain = RES\n' "${INTEROP_SAMBA_RES_ADMIN_PASSWORD:?}" >"$REMOTE_AUTH"
printf 'username = Administrator\npassword = %s\ndomain = USER\n' "${INTEROP_SAMBA_USER_ADMIN_PASSWORD:?}" >"$LOCAL_AUTH"

remote_ip="$(getent hosts dcres.res.rskrb5 | awk '{ print $1; exit }')"
[[ -n "$remote_ip" ]] || fail "dcres.res.rskrb5 does not resolve"
quiet samba-tool domain trust create res.rskrb5 --type=forest --direction=both \
  --create-location=both --ipaddress="$remote_ip" --authentication-file="$REMOTE_AUTH" \
  --local-dc-ipaddress=127.0.0.1 --local-dc-authentication-file="$LOCAL_AUTH"
samba-tool domain trust show res.rskrb5 --local-dc-ipaddress=127.0.0.1 \
  --local-dc-authentication-file="$LOCAL_AUTH" 2>&1 | grep -E 'TrustType|TrustDirection|TrustAttributes|NetbiosName|DnsDomain' >&2 || true
log "forest trust $REALM <-> RES.RSKRB5 created (both directions, remote DC $remote_ip)"
