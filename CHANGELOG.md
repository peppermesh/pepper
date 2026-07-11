<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to Pepper are documented here.

## [0.1.0] - Unreleased

Initial developer-preview release of Pepper's distributed content-addressed storage and data-local Firecracker compute platform.

### Included

- Apache License 2.0 distribution terms, DCO 1.1 contribution policy, automated sign-off enforcement, and dependency license checks.
- Immutable raw blocks and chunked object/directory DAGs.
- Replicated and Reed-Solomon erasure-coded storage.
- Signed provider records, pinning, garbage collection, corruption recovery, and repair.
- Authenticated QUIC node networking and local HTTP/CLI interfaces.
- Firecracker-only compute with CID inputs, captured outputs/logs, cancellation, limits, and signed receipts.
- Metrics, administrative status, metadata backup, and development multi-node configuration.

### Release scope

Version 0.1.0 is an early-access release intended for evaluation and controlled deployments. It does not yet provide tenant isolation, public-federation abuse resistance, Byzantine durability, confidential compute, or attestation. Operators should keep the P2P listener behind an appropriate network security boundary and use authentication, reviewed rootfs images, resource limits, and the Firecracker jailer where applicable.

### Known limitations

- The normal CI suite does not execute a real Firecracker/KVM workload; that coverage requires the host-gated workflow.
- EC object reconstruction is intentionally bounded and buffered rather than streamed.
- Metadata backup requires a stopped or quiescent agent.
- Replicated repair currently uses serialized full scans; richer indexing and per-peer backoff are future work.
- Age-based GC grace periods, tenant quotas, and online coordinated backup are not implemented.
