#!/bin/bash
# Accounts of the domain RES.RSKRB5 (fixture samba-res), run by entrypoint.sh
# once samba listens; see setup-user.sh.
set -euo pipefail
# shellcheck source=scripts/interop/samba/lib-dc.sh
source /opt/interop/samba/lib-dc.sh
load_secrets

quiet samba-tool domain passwordsettings set --complexity=off --min-pwd-age=0 --history-length=0

# The resource-domain HTTP service of the trust scenarios: AES and, for the
# seeded RC4 trust scenario (allow_rc4 opt-in on the client), RC4-HMAC.
create_user sysHTTP INTEROP_SAMBA_RES_HTTP_ACCOUNT_PASSWORD
add_spn sysHTTP HTTP/host.res.rskrb5
quiet python3 "$ACCOUNT_TOOL" enctypes sysHTTP 0x1c

# Claims: a claim type sourced from the user attribute `department`, issued
# into the PAC (domain functional level 2016).
quiet samba-tool domain claim claim-type create --attribute=department --class=user \
  --name=Department --description="rskrb5 interop claim"

# A client of the resource domain (the reverse trust direction) with the
# claim Department=Interop.
create_user resuser INTEROP_SAMBA_RES_USER_PASSWORD department=Interop

export_keytab syshttp.keytab sysHTTP@RES.RSKRB5
export_keytab http.keytab HTTP/host.res.rskrb5@RES.RSKRB5
log "accounts, SPNs, claims and keytabs of $REALM ready"
