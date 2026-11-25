# SSSD KCM credential-cache daemon fixture `kcm` (lane 1D-b, plan 2 todo 1):
# sssd_kcm serving the MIT/Heimdal KCM protocol on a Unix socket in a
# host-visible bind mount. Built by scripts/interop/run.sh (Docker in CI,
# rootless Podman locally); layout contract in scripts/interop/lib.sh.
#
# Pins:
# - base: the same digest-pinned Debian 13 "trixie" slim index as
#   scripts/interop/mit/Dockerfile.
# - Every package: an immutable snapshot of the Debian archive
#   (snapshot.debian.org, KCM_SNAPSHOT, the date of the base image), read over
#   http like the base image's own sources, exactly as scripts/interop/samba/
#   Dockerfile does it; apt still verifies the signed Release file with the
#   archive keys of the pinned base (`Check-Valid-Until` is off because a
#   snapshot's Release file expires). sssd-kcm is named at the exact version
#   SSSD_KCM_VERSION that snapshot carries (SSSD 2.10.1), and the build fails
#   unless `dpkg-query` reports exactly that version. A Debian update that
#   replaces the package in the live archive (it did once: 2.10.1-2+b1 became
#   2.10.1-2+deb13u1 and every fresh build broke) cannot break the build any
#   more. To move the pin, change both ARGs together (the snapshot of a newer
#   base image date, the version it carries). krb5-user (Debian MIT 1.21) gives
#   the server-side klist of the self-check.
#
# Secrets: none in any layer. The credential caches live in the tmpfs
# /var/lib/sss/secrets (fixture.sh). sssd.conf is root-owned mode 0600, as
# SSSD requires. No capability beyond the runtime defaults (sssd_kcm runs as
# the container's root user and logs its capability set at start).

ARG BASE_IMAGE=docker.io/library/debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ARG KCM_SNAPSHOT=20261104T000000Z
ARG SSSD_KCM_VERSION=2.10.1-2+b1

FROM ${BASE_IMAGE}
ARG KCM_SNAPSHOT
ARG SSSD_KCM_VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list \
    && printf '%s\n' 'Types: deb' \
        "URIs: http://snapshot.debian.org/archive/debian/${KCM_SNAPSHOT}/" \
        'Suites: trixie' 'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
        >/etc/apt/sources.list.d/snapshot.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends "sssd-kcm=${SSSD_KCM_VERSION}" krb5-user tini \
    && rm -rf /var/lib/apt/lists/* \
    && [ "$(dpkg-query -W -f '${Version}' sssd-kcm)" = "${SSSD_KCM_VERSION}" ] \
    && test -x /usr/libexec/sssd/sssd_kcm \
    && rm -f /etc/krb5.conf.d/kcm_default_ccache
COPY sssd.conf /etc/sssd/sssd.conf
COPY krb5.conf /etc/krb5.conf
COPY entrypoint.sh /opt/interop/kcm/entrypoint.sh
RUN chown root:root /etc/sssd/sssd.conf && chmod 0600 /etc/sssd/sssd.conf
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/interop/kcm/entrypoint.sh"]
