# MIT krb5 1.22.2 interop fixture (realm TEST.RSKRB5): KDC and kadmind in one
# container. Built by scripts/interop/run.sh (Docker in CI, rootless Podman
# locally); see scripts/interop/lib.sh for the layout contract.
#
# Pins:
# - base: Debian 13 "trixie" slim, multi-arch index digest resolved with
#   `skopeo inspect docker://docker.io/library/debian:trixie-20261104-slim`
#   (2026-11-18). Debian stable, glibc, maintained, ships the build
#   dependencies and tini; its apt archives are verified by the archive keys in
#   the base image.
# - source: krb5-1.22.2.tar.gz, checked against the sha256 below AND against
#   MIT's detached PGP signature made by the release key
#   C4493CB739F4A89F9852CBC20CBA08575F8372DF (Greg Hudson <ghudson@mit.edu>,
#   listed on https://web.mit.edu/kerberos/dist/index.html; the public key in
#   krb5-release-key.asc was fetched from keyserver.ubuntu.com).
#
# Secrets: none in any layer. run.sh generates the principals' passwords per
# run and streams them into the running container's tmpfs; the KDC database,
# its stash and every exported keytab live on tmpfs mounts (see run.sh).
# No capability beyond the runtime defaults is needed: the daemons bind ports
# 88/464/749 as the container's root user.
#
# Extension points (later lanes): add a stage or COPY lines below the marked
# block; add provisioning scripts to provision.d/ (run in name order after the
# base realm, before the daemons start) and started.d/ (after the daemons
# listen, before the ready marker); add profile fragments to
# /etc/krb5.conf.d/ and /etc/krb5kdc/kdc.conf.d/ (both included by the base
# profiles). The `build` stage keeps the configured source tree in
# /src/krb5-1.22.2 so a later stage can build MIT test programs from it.

ARG BASE_IMAGE=docker.io/library/debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

FROM ${BASE_IMAGE} AS build
ARG KRB5_VERSION=1.22.2
ARG KRB5_SHA256=3243ffbc8ea4d4ac22ddc7dd2a1dc54c57874c40648b60ff97009763554eaf13
ARG KRB5_SIGNING_KEY=C4493CB739F4A89F9852CBC20CBA08575F8372DF
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bison build-essential ca-certificates curl gnupg libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY krb5-release-key.asc /src/krb5-release-key.asc
WORKDIR /src
RUN set -eu; \
    url="https://kerberos.org/dist/krb5/1.22/krb5-${KRB5_VERSION}.tar.gz"; \
    curl -fsSL --retry 3 -o krb5.tar.gz "$url"; \
    curl -fsSL --retry 3 -o krb5.tar.gz.asc "$url.asc"; \
    echo "${KRB5_SHA256}  krb5.tar.gz" | sha256sum -c -; \
    GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \
    gpg --batch --quiet --import /src/krb5-release-key.asc; \
    gpg --batch --status-fd 1 --verify krb5.tar.gz.asc krb5.tar.gz >verify.status 2>verify.log; \
    grep -E "^\[GNUPG:\] VALIDSIG .* ${KRB5_SIGNING_KEY}\$" verify.status; \
    rm -rf "$GNUPGHOME" verify.status verify.log krb5.tar.gz.asc; \
    tar -xzf krb5.tar.gz; \
    rm krb5.tar.gz
WORKDIR /src/krb5-${KRB5_VERSION}/src
RUN ./configure --prefix=/opt/krb5 --sysconfdir=/etc --localstatedir=/var/lib \
        --runstatedir=/run --without-ldap --without-tcl \
    && make -j"$(nproc)" \
    && make install

FROM ${BASE_IMAGE} AS mit
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3t64 openssl tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/krb5 /opt/krb5
ENV PATH=/opt/krb5/sbin:/opt/krb5/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    KRB5_CONFIG=/etc/krb5.conf \
    KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf
RUN mkdir -p /etc/krb5.conf.d /etc/krb5kdc/kdc.conf.d /var/log/krb5 \
    && krb5-config --version | grep -qx "Kerberos 5 release 1.22.2"
COPY krb5.conf /etc/krb5.conf
COPY kdc.conf kadm5.acl /etc/krb5kdc/
COPY entrypoint.sh /opt/interop/mit/entrypoint.sh
COPY provision.d/ /opt/interop/mit/provision.d/
COPY started.d/ /opt/interop/mit/started.d/
# --- later lanes: COPY their profile fragments and provision.d scripts here ---
# Lane 1D-a (advanced preauth: FAST, SPAKE, OTP, PKINIT, anonymous): profile
# fragments (SPAKE groups; KDC-side FAST, SPAKE, OTP and PKINIT relations),
# the kadmin helpers of its provision.d scripts, the client-side PKINIT anchor
# profile and the container-side self-checks run by fixture.sh. The openssl
# CLI (apt, above) generates the per-run PKINIT test CA in
# provision.d/45-pkinit.sh; no key or certificate is built into any layer.
COPY krb5.conf.d/ /etc/krb5.conf.d/
COPY kdc.conf.d/ /etc/krb5kdc/kdc.conf.d/
COPY preauth/ /opt/interop/mit/preauth/
EXPOSE 88/tcp 88/udp 464/tcp 464/udp 749/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/interop/mit/entrypoint.sh"]
