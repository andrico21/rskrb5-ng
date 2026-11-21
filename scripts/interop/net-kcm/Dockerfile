# SSSD KCM credential-cache daemon fixture `kcm` (lane 1D-b, plan 2 todo 1):
# sssd_kcm serving the MIT/Heimdal KCM protocol on a Unix socket in a
# host-visible bind mount. Built by scripts/interop/run.sh (Docker in CI,
# rootless Podman locally); layout contract in scripts/interop/lib.sh.
#
# Pins:
# - base: the same digest-pinned Debian 13 "trixie" slim index as
#   scripts/interop/mit/Dockerfile; packages from its archive, verified by
#   the archive keys in the base image.
# - sssd-kcm: exactly SSSD_KCM_VERSION below (Debian trixie, SSSD 2.10.1). A
#   Debian update that removes this version fails the build; bump it then.
#   krb5-user (Debian MIT 1.21) gives the server-side klist of the self-check.
#
# Secrets: none in any layer. The credential caches live in the tmpfs
# /var/lib/sss/secrets (fixture.sh). sssd.conf is root-owned mode 0600, as
# SSSD requires. No capability beyond the runtime defaults (sssd_kcm runs as
# the container's root user and logs its capability set at start).

ARG BASE_IMAGE=docker.io/library/debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

FROM ${BASE_IMAGE}
ARG SSSD_KCM_VERSION=2.10.1-2+deb13u1
RUN apt-get update \
    && apt-get install -y --no-install-recommends "sssd-kcm=${SSSD_KCM_VERSION}" krb5-user tini \
    && rm -rf /var/lib/apt/lists/* \
    && test -x /usr/libexec/sssd/sssd_kcm \
    && rm -f /etc/krb5.conf.d/kcm_default_ccache
COPY sssd.conf /etc/sssd/sssd.conf
COPY krb5.conf /etc/krb5.conf
COPY entrypoint.sh /opt/interop/kcm/entrypoint.sh
RUN chown root:root /etc/sssd/sssd.conf && chmod 0600 /etc/sssd/sssd.conf
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/interop/kcm/entrypoint.sh"]
