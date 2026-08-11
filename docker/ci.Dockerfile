# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Local CI runner image. Provides the exact toolchain and helper binaries the
# GitHub `ci`, `License checks`, and `system-smoke` workflows use, so the merge
# gate can be reproduced offline with `make docker-ci`.
#
# The repository is bind-mounted at /workspace at run time (see the Makefile
# docker-* targets); this image intentionally contains no source, so a single
# build serves every branch and working-tree change.

# Pepper needs rustc >= 1.96 (libsqlite3-sys 0.38 uses the cfg_select feature);
# the default host `stable` of 1.92 cannot build the workspace. This pin also
# fixes the rustfmt/clippy versions so `fmt --check` matches what formatted the
# tree. Override with `--build-arg RUST_VERSION=...` to track the CI runner's
# floating `stable`.
ARG RUST_VERSION=1.97.1
FROM rust:${RUST_VERSION}-bookworm

# Pinned to the versions the workflows install (ci.yml audit job, licenses.yml).
ARG CARGO_AUDIT_VERSION=0.22.2
ARG CARGO_DENY_VERSION=0.20.2

# Tools the process-backend system tests shell out to (mirrors the runtime
# image) plus make/git/jq for the Makefile targets and the DCO check. protoc is
# vendored by pepper-network's build script, so it is deliberately omitted.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates curl git make jq iproute2 nftables procps socat pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy

# Compile the audit/license gates into the image once so runs start instantly.
RUN cargo install cargo-audit --version ${CARGO_AUDIT_VERSION} --locked \
    && cargo install cargo-deny --version ${CARGO_DENY_VERSION} --locked

WORKDIR /workspace
CMD ["make", "ci"]
