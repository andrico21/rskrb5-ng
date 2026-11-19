# Samba AD DC interop fixture (lane 1E): one image, two containers
# (rskrb5-interop-samba-user, domain USER.RSKRB5, and rskrb5-interop-samba-res,
# domain RES.RSKRB5). Built by scripts/interop/run.sh (Docker in CI, rootless
# Podman locally); see scripts/interop/lib.sh for the layout contract and
# scripts/interop/samba/fixture.sh for the topology.
#
# Pins:
# - base: the Debian 13 "trixie" slim index digest lane 1C pinned for the MIT
#   fixture (`skopeo inspect docker://docker.io/library/debian:trixie-20261104-slim`).
# - Samba and every other package: an immutable snapshot of the Debian archive
#   (snapshot.debian.org, SAMBA_SNAPSHOT, the date of the base image), read over
#   http like the base image's own sources; apt still verifies the signed Release
#   file with the archive keys of the pinned base (`Check-Valid-Until` is off
#   because a snapshot's Release file expires). The Samba packages are named at
#   the exact version SAMBA_VERSION (Debian trixie 4.22.11, the Debian stable
#   security-maintained build), and the build fails unless `dpkg-query` reports
#   exactly that version and `samba -V` reports 4.21 or later (channel-binding
#   enforcement of `ldap server require strong auth`, claims and authentication
#   policies need it). The version is also a label of the image, which the
#   fixture logs and records as INTEROP_SAMBA_VERSION. To move the pin, change
#   both ARGs together (the snapshot of a newer base image date, the version it
#   carries; `snapshot.debian.org/mr/package/samba/` lists them). MIT
#   krb5-user provides the reference client tools of the self-check (kinit,
#   kvno -U/-P, kpasswd, klist); OpenLDAP's ldapwhoami with the Cyrus GSSAPI
#   module checks the LDAP channel-binding enforcement.
#
# Secrets: none in any layer. The domains are provisioned at container start
# from passwords run.sh generates per run and streams into the tmpfs
# /run/interop/secrets; the sam database, the krbtgt and trust keys and every
# exported keytab live on tmpfs mounts (fixture.sh).
#
# Capabilities: none beyond the runtime defaults, no --privileged. Samba keeps
# its NT ACLs in `security.NTACL` extended attributes, which need
# CAP_SYS_ADMIN in the initial user namespace (not available to rootless
# Podman); the fixture instead stacks the `xattr_tdb` VFS module, which keeps
# every extended attribute in a TDB file (entrypoint.sh, provision options).
# Samba switches to the Unix IDs it allocates for domain SIDs (setgroups);
# its default allocation range starts at 3000000, which a rootless Podman
# user namespace does not map (it maps 0-65536), so the provisioning template
# idmap_init.ldif is changed to allocate from 30000-39999 instead (provision
# panicked with "Security context active token stack underflow" otherwise).

ARG BASE_IMAGE=docker.io/library/debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ARG SAMBA_SNAPSHOT=20261104T000000Z
ARG SAMBA_VERSION=2:4.22.11+dfsg-0+deb13u1

FROM ${BASE_IMAGE}
ARG SAMBA_SNAPSHOT
ARG SAMBA_VERSION
ENV DEBIAN_FRONTEND=noninteractive
LABEL org.rskrb5.interop.samba-version="${SAMBA_VERSION}"
RUN rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list \
    && printf '%s\n' 'Types: deb' \
        "URIs: http://snapshot.debian.org/archive/debian/${SAMBA_SNAPSHOT}/" \
        'Suites: trixie' 'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
        >/etc/apt/sources.list.d/snapshot.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
        krb5-user ldap-utils ldb-tools libsasl2-modules-gssapi-mit tini \
        samba=${SAMBA_VERSION} samba-ad-dc=${SAMBA_VERSION} samba-ad-provision=${SAMBA_VERSION} \
        samba-dsdb-modules=${SAMBA_VERSION} samba-vfs-modules=${SAMBA_VERSION} winbind=${SAMBA_VERSION} \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/samba/smb.conf /etc/krb5.conf \
    && sed -i 's/^lowerBound: 3000000$/lowerBound: 30000/; s/^upperBound: 4000000$/upperBound: 39999/' \
        /usr/share/samba/setup/idmap_init.ldif \
    && grep -qx 'lowerBound: 30000' /usr/share/samba/setup/idmap_init.ldif \
    && [ "$(dpkg-query -W -f '${Version}' samba)" = "${SAMBA_VERSION}" ] \
    && version="$(samba -V | sed -n 's/^Version \([0-9]*\)\.\([0-9]*\)\..*/\1 \2/p')" \
    && set -- $version \
    && { [ "$1" -gt 4 ] || { [ "$1" -eq 4 ] && [ "$2" -ge 21 ]; }; } \
    && samba -V
COPY krb5.conf account.py entrypoint.sh lib-dc.sh selfcheck.sh setup-res.sh setup-user.sh trust.sh \
    /opt/interop/samba/
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 389/tcp 464/tcp 464/udp 636/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/interop/samba/entrypoint.sh"]
