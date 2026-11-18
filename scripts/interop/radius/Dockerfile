# FreeRADIUS 3.2.10 fixture `radius` of the MIT interop realm (lane 1D-a): the
# RADIUS backend of the KDC's OTP preauthentication module. Built by
# scripts/interop/run.sh (Docker in CI, rootless Podman locally); see
# scripts/interop/lib.sh for the layout contract.
#
# Pin: the upstream image freeradius/freeradius-server:3.2.10-alpine
# (Alpine 3.24, FreeRADIUS 3.2.10, 2026-10-26), by its multi-arch index digest,
# resolved on 2026-11-18 with
#   skopeo inspect --raw docker://docker.io/freeradius/freeradius-server:3.2.10-alpine | sha256sum
# (the amd64 manifest of that index is
# sha256:a91800b6dfebb704a1f223d7f4dc20fbe0bfea1abd88675d47c2c2152b1210bd).
# The tag in the reference documents the version; the digest binds it.
#
# Secrets: none in any layer. entrypoint.sh copies the stock raddb to the
# tmpfs /run/interop and writes there the clients.conf entry (the per-run
# shared secret) and the users file (the per-run OTP token) from the secrets
# run.sh streams into the running container.
# No capability beyond the runtime defaults and no privileged mode: radiusd
# runs as root inside the container and binds UDP 1812 only (published on
# 127.0.0.1 by fixture.sh, reachable from the KDC as radius.test.rskrb5:1812).
FROM docker.io/freeradius/freeradius-server:3.2.10-alpine@sha256:01b03eb6a699683727b0bd8ae34e6b9a7bf5a9716dccd4893535a678e27dfbe2
COPY entrypoint.sh selfcheck.sh /opt/interop/radius/
EXPOSE 1812/udp
ENTRYPOINT ["/opt/interop/radius/entrypoint.sh"]
