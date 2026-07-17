<!-- SPDX-License-Identifier: Apache-2.0 -->

# Pepper

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Pepper is a private peer-to-peer fabric for content-addressed storage and data-local Firecracker compute.

> **Current release:** Pepper 0.2.0 is a developer-preview release intended for evaluation and controlled private-cluster deployments, not untrusted public networks or production multi-tenant workloads.

## Features

- Immutable blocks, chunked objects, and directory snapshots
- Replication and Reed-Solomon erasure coding
- Signed pins, garbage collection, repair, and corruption recovery
- Transactional namespaces and a linearizable key-value API backed by three-node Raft groups
- Versioned buckets and immutable snapshot-based filesystem trees
- An opt-in S3-compatible gateway with Signature Version 4 and durable multipart uploads
- Authenticated QUIC networking and a loopback-only HTTP API
- Firecracker-only compute with CID inputs, bounded outputs, cancellation, and signed receipts

## Quick start

```sh
# Build and initialize the development node
cargo build --workspace --release
./target/release/pepper-agent init --config ./dev/node1.toml

# Start it
./target/release/pepper-agent --config ./dev/node1.toml
```

In another terminal:

```sh
./target/release/pepper node status

printf 'hello pepper\n' > /tmp/input.txt
./target/release/pepper --json block put /tmp/input.txt
./target/release/pepper block get '<cid>' -o /tmp/output.txt
```

`dev/node1.toml` is for local development only. See [`dev/node2.toml`](dev/node2.toml) for a second node.

## Objects and directories

```sh
./target/release/pepper --json object put /tmp/input.txt
./target/release/pepper object get '<object-cid>' -o /tmp/output.txt

./target/release/pepper --json dir put ./directory
./target/release/pepper dir get '<directory-cid>' ./restored
```

Use `--erasure DATA:PARITY` with `object put` to request erasure coding.

## Retention and GC

User-facing puts automatically pin their root CID. Delete the pin through the node that created it before collecting the data:

```sh
./target/release/pepper pin status '<root-cid>'
./target/release/pepper pin delete '<root-cid>'
./target/release/pepper admin gc --dry-run
./target/release/pepper admin gc
```

Pins protect all blocks reachable from an object or directory root.

## Compute

```sh
./target/release/pepper compute submit ./job.json
./target/release/pepper compute status '<job-id>'
./target/release/pepper compute logs '<job-id>'
./target/release/pepper compute output '<job-id>'
```

Compute requires Linux, KVM, Firecracker, a configured guest kernel, and an allowlisted CID-backed ext4 rootfs containing `/pepper-guest-agent`. Pepper does not support local-process execution.

## Security

The HTTP API binds to loopback. Use an authenticated proxy or VPN for remote access. Non-loopback P2P listeners require a protected cluster secret.

## Project policies

- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace

# Nested, backend-neutral system-test workspace
cargo test --manifest-path system-tests/Cargo.toml --locked
cargo run --manifest-path system-tests/Cargo.toml --locked -- list
cargo run --manifest-path system-tests/Cargo.toml --locked -- \
  run --scenario REPL-001 --backend docker --seed 42
```

Three-node system scenarios run on the scheduled/manual integration workflow. See [`system-tests/README.md`](system-tests/README.md) for local execution and artifact reproduction.

## License

Licensed under [Apache License 2.0](LICENSE). Contributions require a per-commit [DCO 1.1](DCO) sign-off.
