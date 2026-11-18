# Negotiate-protected HTTP fixture `httpd` (lane 1D-b, plan 2 todo 1): Apache
# httpd with mod_auth_gssapi, protecting /whoami/ for the service
# HTTP/httpd.test.rskrb5@TEST.RSKRB5. Built by scripts/interop/run.sh (Docker
# in CI, rootless Podman locally); layout contract in scripts/interop/lib.sh.
#
# Pins:
# - base: the same digest-pinned Debian 13 "trixie" slim index as
#   scripts/interop/mit/Dockerfile; Apache httpd 2.4 (trixie), its build
#   headers and Debian's MIT krb5 1.21 GSSAPI library come from that archive,
#   verified by the archive keys in the base image.
# - mod_auth_gssapi 1.6.5 (the latest upstream release, 2022-08-29), built from
#   the upstream release tarball, checked against the sha256 below and against
#   the sha512 that upstream publishes next to it (2026-11-18).
#   Channel bindings: mod_auth_gssapi 1.6.5 has no channel-binding support; it
#   passes GSS_C_NO_CHANNEL_BINDINGS to gss_accept_sec_context
#   (src/mod_auth_gssapi.c:1240), and upstream master dbcb637 (2024-09-10) is
#   the same, so this fixture neither enforces nor checks CBT (register row
#   FU-IOP-P01 of docs/review/parity-register.md).
# - curl (Debian, GSS-API enabled) and krb5-user are the client tools of the
#   fixture's self-check, run from a throwaway container of this image.
#
# Secrets: none in any layer. run.sh streams the service keytab into the
# tmpfs /run/interop at start (net-httpd/fixture.sh); the entrypoint hands a
# copy to the www-data workers in the tmpfs /run/gssapi. No capability beyond
# the runtime defaults: Apache binds port 80 as root and serves as www-data.

ARG BASE_IMAGE=docker.io/library/debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

FROM ${BASE_IMAGE} AS build
ARG MAG_VERSION=1.6.5
ARG MAG_SHA256=a4bb89a2704b2a9461fbc9c0397f326b092c358d9d12b6311c2aa63d161f0530
ARG MAG_SHA512=97eb6dff90e686cd5d25c2925987bf51dbdf627720e74105204ec4625455255548414a03599cfd5a85734f5496f6a7b1f09760771a8278e8348e6ca35b6c48d0
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apache2-dev bison build-essential ca-certificates curl flex libkrb5-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN set -eu; \
    curl -fsSL --retry 3 -o mag.tar.gz \
        "https://github.com/gssapi/mod_auth_gssapi/releases/download/v${MAG_VERSION}/mod_auth_gssapi-${MAG_VERSION}.tar.gz"; \
    echo "${MAG_SHA256}  mag.tar.gz" | sha256sum -c -; \
    echo "${MAG_SHA512}  mag.tar.gz" | sha512sum -c -; \
    tar -xzf mag.tar.gz; \
    cd "mod_auth_gssapi-${MAG_VERSION}"; \
    ./configure; \
    make -j"$(nproc)"; \
    install -D -m 0644 src/.libs/mod_auth_gssapi.so /out/mod_auth_gssapi.so

FROM ${BASE_IMAGE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apache2 ca-certificates curl krb5-user libgssapi-krb5-2 tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/mod_auth_gssapi.so /usr/lib/apache2/modules/mod_auth_gssapi.so
COPY rskrb5-interop.conf /etc/apache2/sites-available/rskrb5-interop.conf
COPY whoami.shtml /var/www/rskrb5/whoami/index.shtml
COPY entrypoint.sh /opt/interop/httpd/entrypoint.sh
RUN echo "LoadModule auth_gssapi_module /usr/lib/apache2/modules/mod_auth_gssapi.so" \
        >/etc/apache2/mods-available/auth_gssapi.load \
    && a2enmod -q auth_gssapi include \
    && a2dissite -q 000-default \
    && a2ensite -q rskrb5-interop \
    && apache2ctl -t
EXPOSE 80/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/interop/httpd/entrypoint.sh"]
