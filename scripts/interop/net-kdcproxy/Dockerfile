# MS-KKDCP KDC proxy fixture `kdcproxy` (lane 1D-b, plan 2 todo 1): latchset
# kdcproxy served over HTTPS by gunicorn, in front of the TEST.RSKRB5 KDC and
# kpasswd of fixture mit-kdc. Built by scripts/interop/run.sh (Docker in CI,
# rootless Podman locally); layout contract in scripts/interop/lib.sh.
#
# Pins:
# - base: the same digest-pinned Debian 13 "trixie" slim index as
#   scripts/interop/mit/Dockerfile; Debian packages (python3, gunicorn
#   23.0.0, python3-dnspython 2.7.0, python3-pyasn1 0.6.1, openssl) come
#   from its archive, verified by the archive keys in the base image.
# - kdcproxy 1.1.0 (latchset; includes the CVE-2025-59088 fix): the PyPI
#   source tarball, checked against the sha256 below (PyPI JSON API,
#   2026-11-18). Only its pure-Python package directory is installed.
#
# Secrets: none in any layer. The entrypoint generates a per-run TLS test CA,
# the server certificate (SAN kdcproxy.test.rskrb5, localhost, 127.0.0.1)
# and an unrelated "wrong" CA into the tmpfs /run/interop at start; the
# private keys never leave it, only the two CA certificates are copied out.
# No capability beyond the runtime defaults: gunicorn's master binds 443 as
# the container's root user and its workers run as nobody.

ARG BASE_IMAGE=docker.io/library/debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

FROM ${BASE_IMAGE}
ARG KDCPROXY_VERSION=1.1.0
ARG KDCPROXY_SHA256=b76254ada4fd7ade1aee4d5a1344d7c95beb813ff49934c01cd468c51602406d
ARG KDCPROXY_URL=https://files.pythonhosted.org/packages/eb/f0/dc03373b9b28555fdeca38e0790055e56bdae74612e673728340af8789f9/kdcproxy-1.1.0.tar.gz
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl gunicorn openssl python3 python3-dnspython python3-pyasn1 tini \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    curl -fsSL --retry 3 -o /tmp/kdcproxy.tar.gz "$KDCPROXY_URL"; \
    echo "${KDCPROXY_SHA256}  /tmp/kdcproxy.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/kdcproxy; \
    tar -xzf /tmp/kdcproxy.tar.gz -C /opt/kdcproxy --strip-components=1 "kdcproxy-${KDCPROXY_VERSION}/kdcproxy"; \
    rm /tmp/kdcproxy.tar.gz; \
    PYTHONPATH=/opt/kdcproxy python3 -c 'import kdcproxy; kdcproxy.application'
ENV PYTHONPATH=/opt/kdcproxy \
    KDCPROXY_CONFIG=/etc/kdcproxy.conf
COPY kdcproxy.conf /etc/kdcproxy.conf
COPY entrypoint.sh /opt/interop/kdcproxy/entrypoint.sh
EXPOSE 443/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/interop/kdcproxy/entrypoint.sh"]
