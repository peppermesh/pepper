<!-- SPDX-License-Identifier: Apache-2.0 -->

# Pepper SQLite benchmark

This benchmark runs identical SQL and the same bundled SQLite build against:

1. an ordinary local filesystem database using SQLite's default VFS; and
2. a database reached through Pepper's production Unix-socket VFS.

It measures connection-cache point reads and sequential scans,
connection-open/query/close reads with a fresh SQLite page cache, one-row
autocommit inserts, and 10/100/1,000-row transactions. Every
backend uses `journal_mode=DELETE`, `synchronous=FULL`, `mmap_size=0`, the same
page size, payload, SQLite cache budget, seed data, statement order, and
transaction count. Setup and final `PRAGMA integrity_check` are outside the
measured intervals.

The Pepper result intentionally includes VFS RPC, data durability, writer
coordination, and Raft publication. It is an end-to-end service comparison,
not a raw disk-device comparison.

## Run

Start a healthy three-peer Pepper cluster with SQLite enabled. Select one
peer's HTTP API and local SQLite socket, then run a release build:

```bash
cargo run --release -p pepper-sqlite-benchmark -- \
  --api http://127.0.0.1:9080 \
  --socket /path/to/peer/data/sqlite.sock \
  --filesystem-directory /path/to/persistent-disk/pepper-sqlite-benchmark \
  --environment-label "3 peers, local NVMe, replicated x3" \
  --output artifacts/sqlite-filesystem-vs-pepper.json
```

`--filesystem-directory` is mandatory whenever the filesystem backend is
selected. Point it at the persistent filesystem being compared, not `/tmp` on
a host where `/tmp` is `tmpfs`. The benchmark creates and removes a private
subdirectory beneath it. Place Pepper peer data on the same storage class when
the goal is to isolate VFS, replication, and consensus overhead.

The benchmark creates a unique Pepper database by default. Pass
`--database NAME --reuse-database` only when retaining and replacing the
benchmark table in an existing database is intentional. Reuse can preserve
old page allocation and should not be used for clean release baselines.

Useful scale controls include:

```text
--seed-rows 10000
--payload-bytes 256
--point-reads 2000
--scans 3
--reopen-reads 25
--batch-sizes 1,10,100,1000
--transactions-per-batch 10
--sqlite-cache-kib 8192
```

Use `--target filesystem` for a local smoke run without Pepper, or
`--target pepper` to measure only the VFS. The default `--target both` prints
per-backend p50/p95/p99 latency, operation throughput, and Pepper/filesystem
ratios. JSON includes host/build metadata, the full configuration, effective
pragmas, Pepper's final database configuration/snapshot metadata, setup time,
sample counts, elapsed time, latency distribution, throughput, final row
count, and integrity result.

For publishable results, archive the JSON together with CPU, memory, storage,
kernel, topology, Pepper commit, durability policy, cache state, and whether
the agents share the benchmark host.
