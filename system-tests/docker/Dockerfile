# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.96.0-bookworm@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc AS builder
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --release -p pepper-agent -p pepper-cli \
    && mkdir -p /out \
    && cp /src/target/release/pepper-agent /src/target/release/pepper /out/

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
ARG SOURCE_COMMIT=unknown
LABEL org.opencontainers.image.source="https://github.com/peppermesh/pepper" \
      org.opencontainers.image.revision="${SOURCE_COMMIT}" \
      org.opencontainers.image.title="Pepper system-test runtime"
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates curl iproute2 jq nftables procps socat tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 pepper \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin pepper \
    && mkdir -p /control /var/lib/pepper/identity /var/lib/pepper/metadata /var/lib/pepper/storage /var/lib/pepper/compute \
    && chown -R pepper:pepper /control /var/lib/pepper
COPY --from=builder /out/pepper-agent /usr/local/bin/pepper-agent
COPY --from=builder /out/pepper /usr/local/bin/pepper
COPY dev/s3-contract/node-entrypoint.sh /usr/local/bin/s3-contract-node
RUN chmod 755 /usr/local/bin/s3-contract-node
ENTRYPOINT ["/usr/bin/tini", "--"]
USER 65532:65532
CMD ["pepper-agent", "--help"]
