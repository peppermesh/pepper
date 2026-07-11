<!-- SPDX-License-Identifier: Apache-2.0 -->

# Pepper

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Pepper is a private-first peer-to-peer storage and compute fabric. The current implementation covers **Phase 0-10 plus later storage/network enhancements**: project skeleton, agent/CLI startup, config loading, identity generation, redb metadata initialization, logging, node status, a local immutable content-addressed block store, QUIC peer-to-peer block reads, replicated block writes with durability receipts, provider discovery with bounded peer-gossip/DHT-style lookup, delegated provider indexes, relay block reads, background repair, chunked object DAGs, optional Reed-Solomon erasure-coded objects with proactive shard-copy rebalancing, directory snapshots, pins, local garbage collection, Firecracker compute runtime with optional jailer/CID-rootfs support, data-local compute scheduling, and private-cluster hardening basics. See `docs/design/TRUST_BOUNDARIES.md` for the multi-node trust model.

## Quick start

Initialize a development node:

```sh
cargo run -p pepper-agent -- init --config ./dev/node1.toml
```

Start the agent:

```sh
cargo run -p pepper-agent -- --config ./dev/node1.toml
```

In another terminal, query status:

```sh
cargo run -p pepper-cli -- node status
# or JSON
cargo run -p pepper-cli -- --json node status
```

Store and retrieve a local block:

```sh
printf 'hello pepper\n' > /tmp/pepper-input.txt
cargo run -p pepper-cli -- --json block put /tmp/pepper-input.txt
cargo run -p pepper-cli -- block has '<cid-from-put>'
cargo run -p pepper-cli -- block get '<cid-from-put>' -o /tmp/pepper-output.txt
diff /tmp/pepper-input.txt /tmp/pepper-output.txt
```

Run a two-node P2P smoke test:

```sh
cargo run -p pepper-agent -- init --config ./dev/node1.toml
cargo run -p pepper-agent -- init --config ./dev/node2.toml
cargo run -p pepper-agent -- --config ./dev/node1.toml
cargo run -p pepper-agent -- --config ./dev/node2.toml

cargo run -p pepper-cli -- --api http://127.0.0.1:9080 node peers
cargo run -p pepper-cli -- --api http://127.0.0.1:9081 --json block put /tmp/pepper-input.txt
cargo run -p pepper-cli -- --api http://127.0.0.1:9080 block get '<cid-from-node2>' -o /tmp/pepper-p2p-output.txt
```

Replicated writes return a durability receipt:

```sh
cargo run -p pepper-cli -- --api http://127.0.0.1:9080 --json block put /tmp/pepper-input.txt
```

Background repair runs automatically. For example, start node1 and node2, write a block, stop node2, then start node3. Node1's repair loop will probe provider health and copy under-replicated local blocks to healthy replacement nodes toward the configured replication factor. Operators can also trigger a pass with `pepper admin repair`.

Store and restore an object or directory snapshot (normal replicated objects stream in bounded chunks through both CLI and agent; EC encoding/reconstruction is additionally capped at 256 MiB input and 512 MiB encoded working memory):

```sh
cargo run -p pepper-cli -- --json object put /tmp/pepper-input.txt
# Optional for large/cold objects: Reed-Solomon erasure coding as DATA:PARITY shards.
cargo run -p pepper-cli -- --json object put /tmp/pepper-input.txt --erasure 6:3
cargo run -p pepper-cli -- object get '<object-root-cid>' -o /tmp/pepper-output.txt

cargo run -p pepper-cli -- --json dir put ./some-directory
cargo run -p pepper-cli -- dir get '<dir-root-cid>' ./some-directory-restored
# Root restores are refused by default; only trusted manifests may opt in with
# PEPPER_ALLOW_ROOT_RESTORE=1.
```

Pin data and run GC:

```sh
cargo run -p pepper-cli -- pin create '<root-cid>' --replicas 1
cargo run -p pepper-cli -- pin status '<root-cid>'
cargo run -p pepper-cli -- admin gc --dry-run
cargo run -p pepper-cli -- admin gc
cargo run -p pepper-cli -- pin delete '<root-cid>'
```

Submit a compute job:

```sh
cargo run -p pepper-cli -- compute submit ./job.json
cargo run -p pepper-cli -- compute status '<job-id>'
cargo run -p pepper-cli -- compute logs '<job-id>'
cargo run -p pepper-cli -- compute cancel '<job-id>' # queued/delegated jobs
cargo run -p pepper-cli -- compute output '<job-id>'
```

Set `"runtime": "firecracker"` and `"rootfs_cid": "..."` in the job spec to run under Firecracker. Firecracker jobs require a CID-backed ext4 rootfs image containing executable `/pepper-guest-agent`. Rootfs CIDs must be listed in `compute.firecracker_allowed_rootfs_cids` by default; `firecracker_allow_untrusted_rootfs = true` is an explicit unsafe development opt-in because host image tooling parses the ext4 image before VM boot. Generated host BusyBox rootfs images are intentionally not supported. The host must have `/dev/kvm`, a Firecracker binary, `mkfs.ext4`, `debugfs`, and a readable guest kernel path configured by `compute.firecracker_kernel_image` or `PEPPER_FIRECRACKER_KERNEL_IMAGE`. The rootfs and input disks are attached read-only; stdout/stderr/status/progress/cancel files and declared outputs live on a separate writable output disk, with compatibility symlinks such as `/output` pointing into it. The guest agent speaks Pepper's versioned vsock protocol for long-lived status/log/progress streaming, polling fallback, and cancellation acknowledgements. Workloads can report progress with `/pepper-guest-agent --progress <value> --message <text>`.

When multiple peers can run a submitted job, the ingress agent asks peers for compute offers and prefers nodes that already hold the input CIDs/chunks. Remote job status and logs are proxied through the submitting agent.

Back up the local redb metadata database while the node is stopped or quiescent:

```sh
cargo run -p pepper-agent -- --config ./dev/node1.toml backup --output ./metadata.backup.redb
```

Health, metrics, and admin endpoints:

```sh
curl http://127.0.0.1:9080/healthz
curl http://127.0.0.1:9080/metrics
curl http://127.0.0.1:9080/v1/admin/status
curl http://127.0.0.1:9080/v1/admin/storage
curl http://127.0.0.1:9080/v1/admin/erasure
cargo run -p pepper-cli -- admin erasure
curl -X POST http://127.0.0.1:9080/v1/admin/repair
curl -X POST http://127.0.0.1:9080/v1/admin/corruption-scan
```

Node-signed request/response authentication and QUIC certificate channel binding are always enabled. `[auth].cluster_secret_path` is additionally required when the P2P listener is not loopback. The built-in HTTP API is restricted to loopback; use `auth.api_bearer_token` locally and a TLS-authenticated reverse proxy or VPN for remote access. Use `pepper --api-token ...` or `PEPPER_API_TOKEN` when `auth.api_bearer_token` is configured. Optional `[limits]` settings cap block/object sizes, compute timeouts, HTTP/RPC request rates, and EC repair bandwidth/concurrency. Optional `[erasure]` settings can automatically use Reed-Solomon coding for objects over a size threshold; `admin erasure` reports EC health. Optional `node.failure_domain` and `[node.placement_labels]` values such as `region`, `zone`, `rack`, and `disk_class` help EC shard placement avoid correlated failures; EC placement/rebalance also avoids nodes without enough advertised free storage. Firecracker compute requires job-level `rootfs_cid` ext4 images containing an executable `/pepper-guest-agent`, uses read-only root/input disks plus a writable output disk, enforces configured/job resource input-output size limits, supports optional cgroup v2 memory/CPU limits, supports optional jailer UID/GID/chroot settings with stale-jail protection, configures a bounded versioned guest-agent control stream through Firecracker's host Unix-socket vsock CONNECT protocol, records heartbeat/progress/cancel events and persisted cancel lifecycle fields, and runs with no network/no API, process-group cleanup, and seccomp level 2/no-new-privileges when strict sandboxing is enabled. Storage locations enforce soft/hard pressure policy: normal writes stop before hard pressure while repair/replica writes may fill to configured capacity; `admin storage` reports pressure state.

## Development checks

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Design docs

- Product requirements: [`docs/design/PRD.md`](docs/design/PRD.md)
- Detailed design and implementation plan: [`docs/design/DETAILED_DESIGN.md`](docs/design/DETAILED_DESIGN.md)
- Implementation status: [`docs/design/IMPLEMENTATION_STATUS.md`](docs/design/IMPLEMENTATION_STATUS.md)
- License policy: [`docs/LICENSE_POLICY.md`](docs/LICENSE_POLICY.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development, provenance, and pull-request requirements. Security issues must be reported through the private process in [SECURITY.md](SECURITY.md).

## License

PepperMesh is licensed under the [Apache License, Version 2.0](LICENSE).

Contributions are accepted under the [Developer Certificate of Origin, Version 1.1](DCO). By contributing, you certify that you have the right to submit your contribution under the terms described in the DCO.

All commits containing contributions must include a `Signed-off-by` line.
