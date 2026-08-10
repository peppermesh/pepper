<!-- SPDX-License-Identifier: Apache-2.0 -->

# Pepper performance parity harness

`pepper-parity` answers one question with evidence: is Pepper at least as
performant as the best-of-breed provider of the same API at the same
guarantee level, on the same hardware?

Design: `docs/design/PERFORMANCE_PARITY_HARNESS.md` in the internal docs
repository. The harness reuses the existing per-API load drivers
(`pepper-s3-throughput loadgen`, the pinned Kafka perf tools,
`pepper-sqlite-benchmark`), adds competitor topologies, normalizes every
measurement into one cell-result schema, and computes a parity verdict with
explicit gates.

## Commands

Validate a suite and print its expanded cell matrix:

```bash
cargo run -p pepper-parity -- validate \
  --suite benchmarks/pepper-parity/suites/s3-vs-minio.toml
```

Run a suite (brings each target up, measures every cell strictly
sequentially, tears the target down, writes artifacts, prints the report,
and exits non-zero when a required gate fails):

```bash
PEPPER_BENCH_ROOT=/mnt/pepper-bench/parity \
PEPPER_BENCH_CONFIG_DIR=/mnt/pepper-bench/parity-config \
cargo run --release -p pepper-parity -- run \
  --suite benchmarks/pepper-parity/suites/s3-vs-minio.toml \
  --output-directory target/parity-s3
```

Recompute a report from retained cell records:

```bash
cargo run -p pepper-parity -- report \
  --suite benchmarks/pepper-parity/suites/s3-vs-minio.toml \
  --records target/parity-s3/cell-records.json
```

## Artifact layout

```text
<output>/run.json                    provenance (git, host, suite hash)
<output>/<target>/rep<N>/<cell>/     command.json, stdout/stderr, driver
                                     output, normalized cell-record.json
<output>/cell-records.json           all normalized measurements
<output>/parity-report.{json,md}     ratios, verdicts, suite gate
```

## Rules the harness enforces

- exactly one `subject` target (Pepper); `competitor` rows are gated;
  `ceiling` rows (raw device, local SQLite) are informational;
- targets never run concurrently;
- a discarded warmup pass runs before each cell's first repetition when
  `workload.warmup_seconds` is non-zero (targets may declare a dedicated
  `warmup` command; the Kafka and SQLite drivers warm up internally);
- guarantee audits (`[targets.audit]` command steps) run once per target
  after readiness; a failing audit invalidates every cell of that target —
  numbers without the promised guarantee are not comparable;
- cells with failure rates above the gate threshold are `invalid`, never
  pass/fail; one-sided latency measurements are `invalid`; drivers without
  latency percentiles (Kafka consumer perf) gate on throughput alone;
- suites with `required = true` gates fail the process on any failed or
  invalid cell.

## Checked-in suites

| Suite | Profile | Competitor | Audit |
| --- | --- | --- | --- |
| `s3-vs-minio.toml` | `s3-single-durable` | MinIO single node | acknowledged PUT pool, SIGKILL all nodes, restart, read-back |
| `kafka-vs-kafka-fsync-quorum.toml` | `kafka-fsync-quorum` | Apache Kafka KRaft ×3, `flush.messages=1` | SIGKILL all brokers, end-offset read-back |
| `kafka-vs-kafka-replicated-ack.toml` | `kafka-replicated-ack` | Apache Kafka KRaft ×3, default flush | SIGKILL one broker (the profile's claim) |
| `sqlite-vs-rqlite.toml` | `sql-replicated-3x` | rqlite ×3, linearizable reads | acknowledged rows, SIGKILL all nodes, restart, exact count |

Both Kafka suites drive Pepper and Apache Kafka through the identical pinned
Apache Kafka perf tools (`topologies/kafka-driver.sh`); workload
`concurrency` is the partition count. The SQLite suite drives both services
with `pepper-sqlite-benchmark` (which now includes an rqlite HTTP backend);
cells map to benchmark workload names via `topologies/sqlite-driver.sh`.
Topology bootstrap scripts (`prepare-pepper-kafka.sh`,
`prepare-pepper-sqlite.sh`) generate the Pepper node configs through
`pepper-s3-throughput prepare-topology` and enable the relevant listener.

## Status

Tier 1 is implemented: the harness core plus S3-vs-MinIO, both
Kafka-vs-Apache-Kafka durability profiles, and SQLite-vs-rqlite, all with
guarantee audits. Tier 2 (KV-vs-etcd, native object vs Kubo, Ceph RGW) and
nightly qualification wiring remain per the design doc. The checked-in
suites are exploratory templates: qualification runs must raise durations,
repetitions, per-cell volumes, and read-pool sizes to the accepted matrix
and pin competitor image digests.
