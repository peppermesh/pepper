<!-- SPDX-License-Identifier: Apache-2.0 -->

# Pepper Phase 0 baseline runner

This runner captures reproducible evidence for the shared-data-plane and Kafka
implementation plan. It executes a versioned TOML suite and retains:

- the exact Git revision, branch, dirty state, and `Cargo.lock` checksum;
- CPU, memory, block-device, filesystem, kernel, and Rust metadata;
- `/proc` CPU, memory, disk, and network counters around every repetition;
- Pepper metrics snapshots before and after the suite;
- exact expanded commands, exit status, timeout state, and wall time;
- complete stdout/stderr with SHA-256 hashes; and
- a checksum manifest covering the artifact directory.

The runner never treats a missing required metric endpoint, failed command, or
timeout as a successful baseline. Cases may also declare `required_stdout`
markers so a filtered test command that executes zero tests cannot pass
silently.

## Validate suites

```bash
cargo run -p pepper-phase0 -- validate \
  --suite benchmarks/pepper-phase0/suites/local-smoke.toml
```

## Run an exploratory local baseline

The runner rejects a dirty worktree by default. `--allow-dirty` is permitted
only for exploratory evidence and records the dirty state in `run.json`.

```bash
cargo run --release -p pepper-phase0 -- run \
  --suite benchmarks/pepper-phase0/suites/local-smoke.toml \
  --output-directory target/phase0-local-smoke \
  --allow-dirty
```

## Deployment baselines

`pepper-platform.toml` requires a running three-node Pepper cluster and a
persistent filesystem directory. `kafka-comparator.toml` uses the pinned
three-node external Kafka cluster in `kafka/compose.yaml` and executes the
Kafka distribution's performance tools inside its first broker.
`consensus-density.toml` is self-contained and measures 100, 1,000, and 10,000
single-voter groups in isolated release-mode processes.

Every publishable comparison must use the same hosts, storage, network,
replication, acknowledgment, compression, record/batch sizes, concurrency,
duration, and cache state. The suite files are templates: copy them into the
artifact directory and replace exploratory scales with the accepted
qualification matrix before publishing results.
