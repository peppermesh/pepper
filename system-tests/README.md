<!-- SPDX-License-Identifier: Apache-2.0 -->

# Pepper System Tests

This is an intentionally nested Cargo workspace. It keeps orchestration dependencies and slow end-to-end scenarios out of Pepper's product workspace and per-commit unit-test path.

## System scenarios

```bash
cargo run --manifest-path system-tests/Cargo.toml -- list
# Docker is the default and builds the digest-pinned image when absent.
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario REPL-001 --seed 42
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario EC-001 --seed 42
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario OBJECT-001 --seed 42
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario REPL-004 --seed 42
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario NS-003 --seed 42
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario FS-002 --seed 42
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario BACKUP-002 --seed 42
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario FAULT-002 --seed 42
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario NEMESIS-001 --seed 42
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario LIN-001 --seed 42 --backend process
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario RAFT-002 --seed 42
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario RAFT-004 --seed 42

# Fixed-kernel soak qualification (CI normally uses six hours).
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario SOAK-001 --seed 42 --backend docker \
  --duration-seconds 21600 --expected-kernel "$(uname -r)"

# A pre-provisioned WAN topology is observed but never mutated by the backend.
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario WAN-001 --seed 42 --backend remote \
  --wan-mode tailscale --topology /secure/config/tailscale-topology.json
# Start from topologies/wan-tailscale.example.json or wan-direct.example.json;
# replace all addresses and public node identity descriptors.

# On a disposable Linux/KVM host with the required image environment variables.
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario KVM-001 --seed 42 --backend kvm

# The local-process backend remains available for fast debugging.
cargo run --manifest-path system-tests/Cargo.toml -- run \
  --scenario BOOT-002 --seed 42 --backend process
```

The process backend builds `pepper-agent` when needed. Pass `--agent-bin PATH` to test a specific binary or `--no-build` to require a prebuilt binary. The Docker backend uses `bollard`, creates a per-run internal bridge and four named volumes per node, and executes HTTP requests inside each node's network namespace so the product API remains loopback-only. Pass `--image REF`; `--no-image-build` requires that exact image or digest to exist. The remote backend accepts only stable literal Tailscale or public direct-WAN addresses and deliberately provides no lifecycle, shell, fault, or storage mutation operations. The KVM backend validates Linux, writable `/dev/kvm`, Firecracker, a pinned kernel, and a bounded disposable rootfs before launching the process-backed scenario.

Every run creates a unique directory under `system-tests/artifacts/` containing `run.json`, `topology.json`, `events.jsonl`, `junit.xml`, redacted configs/logs, observations, `artifact-manifest.json`, and an executable `reproduce.sh`. Docker runs additionally contain `compose.yaml`, container/network inspection records, and a volume manifest; reproduction uses the recorded immutable image digest. Process state lives in a separately managed temporary directory. Docker state uses run-scoped named volumes. Identity private keys are never copied into forensic artifacts, and all ephemeral state is removed during cleanup.

## Tests and formatting

```bash
cargo test --manifest-path system-tests/Cargo.toml --locked
cargo clippy --manifest-path system-tests/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path system-tests/Cargo.toml -- --check
```

The local-process backend owns every child through an RAII process guard. Normal completion, errors, panics, interrupts, and backend drop all trigger bounded termination and reap children. Scenario completion uses condition-based waits with explicit deadlines; fixed sleeps are limited to polling intervals, declared fault durations, and process termination grace periods.

Concurrent KV histories use controller-monotonic invocation/completion intervals and a bounded Wing-Gong-style search covering reads, conditional put/delete, atomic transactions, idempotent replay, and conflict outcomes. Explicitly historical reads must carry the stale label and are archived but excluded from the linearizable history. The default bound is 64 operations, 1,000,000 explored states, and five seconds; failures retain a minimized known counterexample. Continuous consensus, durability, GC-protection, publication-intent, and learner checks accept at most 10,000 samples and retain the latest 256 samples.

Faults are represented by typed, bounded declarations. Docker UDP partitions and netem run in short-lived root helpers joined only to the selected agent network namespace; agents remain non-root and helpers receive only `NET_ADMIN`. Storage paths are relative and confined. Destructive storage changes are made while the agent is stopped, original bytes are copied to `fault-originals/`, and healing also occurs while stopped. Fault guards heal explicitly or asynchronously on drop, with cleanup failures retained in the run artifacts. `NEMESIS-001` records its deterministic schedule and seed while running workload operations concurrently, then polls post-heal health and exact immutable reads.

Generated run artifacts are ignored by Git. Versioned schemas and fixtures are committed. Release owners generate the final commit-bound report from downloaded tier archives with:

```bash
cargo run --manifest-path system-tests/Cargo.toml -- qualify \
  --artifacts qualification-input \
  --policy system-tests/ci/qualification-policy.json \
  --output qualification-report/qualification.json \
  --release-commit "$(git rev-parse HEAD)"
```

CI tier definitions, seed rotation, retention, ownership, triage, and the conservative legacy-test removal gate are specified in [`CI.md`](CI.md). Pull requests run a small process-backend smoke matrix; scheduled functional and serialized chaos workflows run isolated Docker scenarios.
