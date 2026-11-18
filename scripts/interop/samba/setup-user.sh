#!/bin/bash
# Accounts of the domain USER.RSKRB5 (fixture samba-user), run by
# entrypoint.sh once samba listens. Every password comes from the run's
# secrets; keytabs go to the tmpfs /run/interop/out, which fixture.sh copies
# out. Names are the contract of tests/interop_samba.rs and of later todos
# (paste-ready list in fixture.sh).
set -euo pipefail
# shellcheck source=scripts/interop/samba/lib-dc.sh
source /opt/interop/samba/lib-dc.sh
load_secrets

# Test-domain password policy: no complexity rule (the generated secrets are
# random [A-Za-z0-9], not always of three character classes), no minimum age
# and no history, so a password may change right after it was set.
quiet samba-tool domain passwordsettings set --complexity=off --min-pwd-age=0 --history-length=0

# Claims: a claim type sourced from the user attribute `department`, issued
# into the PAC (domain functional level 2016). Samba puts a zero-length claims
# buffer into the PAC of a user without claims, which the crate's PAC parser
# refuses (register row FU-IOP-P14, todo 22), so the clients whose PACs the
# scenarios validate carry a claim.
quiet samba-tool domain claim claim-type create --attribute=department --class=user \
  --name=Department --description="rskrb5 interop claim"

# Clients.
create_user testuser1 INTEROP_SAMBA_USER_USER_PASSWORD department=Interop
# testuser3 has DONT_REQUIRE_PREAUTH, but Samba 4.22 still requires
# pre-authentication from it (register row FU-IOP-P15).
create_user testuser3 INTEROP_SAMBA_USER_NOPREAUTH_USER_PASSWORD
quiet python3 "$ACCOUNT_TOOL" uac testuser3 DONT_REQUIRE_PREAUTH
create_user s4uclient INTEROP_SAMBA_USER_S4U_CLIENT_PASSWORD
create_user kpasswduser INTEROP_SAMBA_USER_KPASSWD_USER_PASSWORD
create_user kpasswdcheck INTEROP_SAMBA_USER_KPASSWD_CHECK_PASSWORD
create_user setpwtarget INTEROP_SAMBA_USER_SETPW_TARGET_PASSWORD

# The HTTP service of the Negotiate and PAC scenarios: AES and, for the
# seeded RC4 trust scenario (allow_rc4 opt-in on the client), RC4-HMAC
# session keys, plus the compound-identity (0x20000) and claims (0x40000)
# support bits.
create_user testuser2 INTEROP_SAMBA_USER_HTTP_ACCOUNT_PASSWORD
add_spn testuser2 HTTP/user2.user.rskrb5
quiet python3 "$ACCOUNT_TOOL" enctypes testuser2 0x6001c

# Delegation (every service account AES only). svc-s4u: protocol transition
# (S4U2Self evidence for any user) and classic constrained delegation to
# HTTP/backend only. svc-backend: resource-based constrained delegation from
# svc-rbcd only. svc-denied: the target nobody may delegate to.
create_user svc-backend INTEROP_SAMBA_USER_DELEGATION_TARGET_PASSWORD
add_spn svc-backend HTTP/backend.user.rskrb5
quiet python3 "$ACCOUNT_TOOL" enctypes svc-backend 0x18
create_user svc-denied INTEROP_SAMBA_USER_DELEGATION_DENIED_PASSWORD
add_spn svc-denied HTTP/denied.user.rskrb5
quiet python3 "$ACCOUNT_TOOL" enctypes svc-denied 0x18
create_user svc-s4u INTEROP_SAMBA_USER_S4U_ACCOUNT_PASSWORD
add_spn svc-s4u HTTP/s4u.user.rskrb5
quiet python3 "$ACCOUNT_TOOL" enctypes svc-s4u 0x18
quiet samba-tool delegation for-any-protocol svc-s4u on
quiet samba-tool delegation add-service svc-s4u HTTP/backend.user.rskrb5
create_user svc-rbcd INTEROP_SAMBA_USER_RBCD_ACCOUNT_PASSWORD
add_spn svc-rbcd HTTP/rbcd.user.rskrb5
quiet python3 "$ACCOUNT_TOOL" enctypes svc-rbcd 0x18
# Samba's KDC (Heimdal, third_party/heimdal/kdc/mssfu.c) refuses S4U2Proxy,
# RBCD included, unless the evidence ticket is forwardable, so svc-rbcd also
# needs protocol transition; it has no msDS-AllowedToDelegateTo, so only the
# RBCD descriptor on svc-backend can let it delegate.
quiet samba-tool delegation for-any-protocol svc-rbcd on
quiet samba-tool delegation add-principal svc-backend svc-rbcd

export_keytab testuser1.keytab testuser1@USER.RSKRB5
export_keytab testuser3.keytab testuser3@USER.RSKRB5
export_keytab testuser2.keytab testuser2@USER.RSKRB5
export_keytab http.keytab HTTP/user2.user.rskrb5@USER.RSKRB5
export_keytab svc-s4u.keytab svc-s4u@USER.RSKRB5
export_keytab svc-rbcd.keytab svc-rbcd@USER.RSKRB5
export_keytab svc-backend.keytab HTTP/backend.user.rskrb5@USER.RSKRB5
log "accounts, SPNs, delegation, claims and keytabs of $REALM ready"
