<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to Pepper are documented here.

## [0.2.0] - Unreleased

### Changed

- Completed transactional namespace implementation Phase 0: modularized agent service boundaries, transactional metadata schema-1 to schema-2 migration, centralized pin persistence, verified backup metadata, stable machine-readable API errors, and a disabled-by-default namespace feature gate.
- Completed Phase 1 typed DAG traversal with a reusable codec registry, bounded deterministic traversal, built-in manifest handlers, GC/pin/repair/locality integration, DAG inspection, custom-codec retention tests, and parser fuzzing.
- Completed Phase 2 with the canonical `0x07` ordered Merkle radix map, copy-on-write updates, deterministic roots, bounded point/range/prefix reads, root-bound cursors, whole-tree validation, DAG/GC value retention, randomized model testing, stable vectors, decoder fuzzing, and a verified one-million-key benchmark.
- Completed Phase 3 with canonical namespace descriptor/checkpoint/commit formats (`0x08`–`0x0a`), deterministic snapshot transactions, read-your-writes, CID/generation conflicts, idempotent replay, immutable history, named snapshots, monotonic rollback, retention intents, checkpoint recovery, authorization hooks, stable vectors, and decoder fuzzing.
- Completed Phase 4 with OpenRaft-backed three-node namespace groups, schema-3 redb consensus repositories, durable vote/log/applied state, immutable checkpoint snapshots and compaction, restart recovery, multi-group isolation, consensus resource admission, and signed node capacity advertisements.
- Completed Phase 5 with authenticated QUIC Raft/forwarding RPCs, signed expiring discovery records, bounded leader rediscovery, exact-three capacity-aware placement, CID-verified checkpoint fetches over Pepper's data plane, learner catch-up and safe replacement, membership epochs, and explicit fork-risk disaster recovery.
- Completed Phase 6 with the shared durability-gated publication coordinator, schema-4 staging/read leases and publication intents, atomic Raft-log/state protection records, distributed signed-pin reconciliation, retention-driven release, GC/repair integration, conflict-retained uploads, abandoned-staging cleanup, and publication fault injection.
- Completed Phase 7 with namespace lifecycle, historical consistency, KV mutation/scan/transaction, snapshot, diff/rollback, and administrative HTTP APIs; native `pepper namespace`, `pepper kv`, and `pepper admin namespace` commands; authenticated replica bootstrap/recovery; stable namespace errors and CLI exit categories; and put-file conflict retention.
- Completed Phase 8 with canonical `0x0b` bucket object/tombstone descriptors, conditional versioned put/get/head/delete/list/versions, root-bound pagination, immutable version chains, namespace snapshot/rollback reuse, durability-gated object publication, bucket HTTP endpoints, and the native `pepper bucket` CLI.
- Completed Phase 9 with canonical filesystem root/inode codecs `0x0c` and `0x0d`, Merkle-map directories, ordinary object-backed files, structurally shared atomic tree commits, history/diff/checkout/restore/rollback/clone operations, safe atomic restoration, explicit rejection of unsupported filesystem types, HTTP endpoints, and the native `pepper fs` CLI.
- Completed Phase 10 with namespace/Raft/publication/Merkle metrics and readiness, persisted-group startup recovery, leader-routed publication, signed identity-bound backup manifests and verified restore, single-live-process identity fencing, release benchmarks and acceptance mapping, consistency/durability documentation, and replacement/quorum-loss operator runbooks.
- Added authenticated, bounded, payload-redacted operational diagnostics for local blocks, GC protection, publication intents, providers, erasure shards, repair outcomes, read-resolution routes, RPC traffic, and namespace replica state, together with per-command-class Raft encoded-size metrics and independent system-test CID, placement, replication, provider, GC, and erasure checkers.
- Completed system-test storage Phase 4 with backend-neutral raw block, deduplication, replication-factor, placement, provider fallback, loss/repair, capacity, object, generated-directory, erasure tolerance/repair, pin ownership, GC, DAG registry, and corruption scenarios; deterministic storage mutation primitives; exact CID/byte models; restart and node-loss coverage; and isolated scheduled Docker execution.
- Completed system-test Phase 5 with independent namespace/KV, bucket-version, and filesystem-tree models; all-voter revision/root verification; identity fencing; any-ingress routing; semantic idempotency; leader failover; checkpoint restart; bucket/filesystem node-loss durability; structural-sharing/history checks; and backend-neutral stopped-volume backup/restore.
- Completed system-test Phase 6 with typed stop/kill/pause, directional UDP partition, bounded netem, deletion/corruption/pressure/read-only storage faults, restricted Docker network helpers, stopped-agent storage mutation, original-byte forensics, RAII healing, deterministic concurrent nemesis schedules, post-heal convergence checks, and fault activation/isolation/cleanup scenarios.
- Completed system-test Phase 7 with controller-monotonic concurrent KV histories, a bounded linearizability checker for reads/conditional mutations/atomic transactions/idempotent replay, minimized counterexamples, continuous consensus/durability/GC/publication/learner invariants, committed-index diagnostics, and selective minority-partition convergence coverage.
- Changed namespace pin propagation to schedule bounded peer synchronization concurrently after durable local persistence, preventing unavailable peers from serially delaying publication while reconciliation retains eventual propagation.
- Completed system-test Phase 8 with pull-request smoke, nightly functional, serialized chaos, rotating-seed, bounded-parallelism, cleanup enforcement, and tiered artifact-retention workflows; added machine-checked legacy removal gates and CI ownership/triage policy.
- Added `RAFT-004` learner replacement under concurrent namespace metadata writes, including learner/catch-up observation, three-voter convergence, old-epoch fencing, and exact post-promotion reads; bounded transition RPC epoch tolerance now permits authenticated Raft catch-up across in-flight membership epochs.
- Completed system-test Phase 9 with fixed-kernel `SOAK-001` workload and leak/growth regression analysis, non-owning stable-address Tailscale/direct-WAN `WAN-001` qualification, disposable host-gated Firecracker/KVM `KVM-001` execution and cancellation, weekly isolated workflows, and a commit-bound release qualification report gate over archived smoke, functional, chaos, soak, WAN, and KVM matrices.
- Fixed idempotency validation to reject same-ID/different-intent reuse while allowing retries whose server-derived base revision or timestamp changes, allowed metadata-only namespace commands to use empty staging-root sets, and bounded unavailable-peer namespace pin synchronization during failover.

### Planned

- Transactional namespace and immutable-state publication layer, including traversable DAG codecs, persistent Merkle maps, three-node Raft namespace groups, snapshot transactions, native `namespace`/`kv`/`bucket`/`fs` CLI surfaces, a versioned object namespace, and snapshot filesystem tooling.

## [0.1.0] - 2026-07-11

Initial developer-preview release of Pepper's distributed content-addressed storage and data-local Firecracker compute platform.

### Included

- Apache License 2.0 distribution terms, DCO 1.1 contribution policy, automated sign-off enforcement, and dependency license checks.
- Immutable raw blocks and chunked object/directory DAGs.
- Replicated and Reed-Solomon erasure-coded storage.
- Signed provider records, implicit root pinning for user-facing puts, authenticated pin synchronization, pin-driven garbage collection, corruption recovery, and repair.
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
