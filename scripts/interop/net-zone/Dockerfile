# DNS fixture `dns` (lane 1D-b, plan 2 todo 1): CoreDNS serving the
# Kerberos discovery zones test.rskrb5 and other.rskrb5 (SRV, URI, TXT, a
# site-specific name, an IPv6 record) that run.sh renders per run and
# bind-mounts read-only at /etc/coredns (net-zone/fixture.sh). Built by
# scripts/interop/run.sh; layout contract in scripts/interop/lib.sh.
#
# Pins:
# - CoreDNS 1.15.0: the coredns binary is copied from the official image
#   docker.io/coredns/coredns:1.15.0, pinned by its multi-arch index digest
#   (skopeo inspect --raw | sha256sum, 2026-11-18). That image has no shell,
#   so the runtime stage adds the contract's readiness marker and the dig
#   client of the fixture self-check.
# - base: the same digest-pinned Debian 13 "trixie" slim index as
#   scripts/interop/mit/Dockerfile; bind9-dnsutils (dig) and tini from its
#   archive, verified by the archive keys in the base image.
#
# Secrets: none (DNS data only). No capability beyond the runtime defaults:
# CoreDNS binds 53 and 1053 as the container's root user.

ARG COREDNS_IMAGE=docker.io/coredns/coredns:1.15.0@sha256:0a9d8c8ddf34347eb59aad9a8784f0710de88d6d112726d11d271f9bc6daca26
ARG BASE_IMAGE=docker.io/library/debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

FROM ${COREDNS_IMAGE} AS coredns

FROM ${BASE_IMAGE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends bind9-dnsutils tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=coredns /coredns /usr/local/bin/coredns
RUN /usr/local/bin/coredns -version | grep -q '^CoreDNS-1\.15\.0$'
COPY entrypoint.sh /opt/interop/dns/entrypoint.sh
EXPOSE 53/udp 53/tcp 1053/udp 1053/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/interop/dns/entrypoint.sh"]
