# External-peer adapter fixture `mit-peer` (plan 2 todo 1, lane 1F): the pinned
# MIT krb5 1.22.2 built from source with its sample GSS applications
# (gss-client, gss-server, `-iakerb`), the `negoextest` NegoEx test mechanism,
# and the adapter scripts/interop/peer-mit/peer/ compiled against that build.
# Built by scripts/interop/run.sh (Docker in CI, rootless Podman locally); see
# scripts/interop/lib.sh for the layout contract. It is a SEPARATE image from
# scripts/interop/mit/ (the KDC), with the same pins.
#
# Pins (identical to scripts/interop/mit/Dockerfile, whose `build` stage this
# one repeats instruction for instruction so a container builder reuses its
# cached layers):
# - base: Debian 13 "trixie" slim, multi-arch index digest resolved with
#   `skopeo inspect docker://docker.io/library/debian:trixie-20261104-slim`
#   (2026-11-18); its apt archives are verified by the archive keys in the base.
# - source: krb5-1.22.2.tar.gz, checked against the sha256 below AND against
#   MIT's detached PGP signature by the release key
#   C4493CB739F4A89F9852CBC20CBA08575F8372DF (krb5-release-key.asc).
#
# Secrets: none in any layer. The keytabs the adapter and the self-check use
# are streamed by fixture.sh into a tmpfs (/run/peer/keytabs) at run time.
# Runtime: the adapter and every daemon-less tool run as the unprivileged user
# peer (10001); the container needs no capability (fixture.sh drops all of
# them and sets no-new-privileges). The adapter listens on 4401; the self-check
# gss-server on 4402 (container network only).

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
# --- lane 1F: what `make install` leaves out ---
# The negoextest plugin and MIT's own t_context program (SPNEGO/NegoEx loop of
# both ends) are built by `make` / on demand but not installed.
RUN make -C tests/gssapi t_context \
    && mkdir -p /opt/krb5/libexec/interop \
    && install -m 0755 plugins/gssapi/negoextest/gss_negoextest.so /opt/krb5/lib/gss_negoextest.so \
    && install -m 0755 tests/gssapi/t_context /opt/krb5/libexec/interop/t_context

FROM build AS adapter
COPY peer/ /src/peer/
WORKDIR /src/peer
RUN gcc -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
        -I/opt/krb5/include -o /opt/krb5/libexec/interop/peer-adapter \
        peer.c peer_wire.c peer_util.c peer_cred.c peer_ctx.c peer_msg.c peer_krb.c \
        -L/opt/krb5/lib -Wl,-rpath,/opt/krb5/lib -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err

FROM ${BASE_IMAGE} AS mit-peer
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3t64 tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin peer
COPY --from=adapter /opt/krb5 /opt/krb5
ENV PATH=/opt/krb5/sbin:/opt/krb5/bin:/opt/krb5/libexec/interop:/usr/sbin:/usr/bin:/sbin:/bin \
    KRB5_CONFIG=/etc/krb5.conf \
    LD_LIBRARY_PATH=/opt/krb5/lib
RUN mkdir -p /etc/gss /opt/interop/peer \
    && krb5-config --version | grep -qx "Kerberos 5 release 1.22.2"
COPY krb5.conf /etc/krb5.conf
COPY gss-mech.negoextest /etc/gss/mech.negoextest
COPY entrypoint.sh selfcheck.sh /opt/interop/peer/
USER 10001:10001
EXPOSE 4401/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/interop/peer/entrypoint.sh"]
