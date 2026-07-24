<!-- SPDX-License-Identifier: Apache-2.0 -->

# Pinned external Kafka comparator

This compose project runs three combined KRaft broker/controller nodes from the
official Apache Kafka 4.3.1 image. The image is pinned by digest, topics use
replication factor 3 and minimum ISR 2, and unclean leader election and topic
auto-creation are disabled.

The data root is deliberately supplied by the operator so Kafka and Pepper can
be placed on the same qualified storage class. The directory must be empty for
a clean run and writable by uid/gid 1000:

```bash
export KAFKA_DATA_ROOT=/qualified-storage/pepper-phase0-kafka
install -d -m 0755 \
  "$KAFKA_DATA_ROOT/broker-1" \
  "$KAFKA_DATA_ROOT/broker-2" \
  "$KAFKA_DATA_ROOT/broker-3"
sudo chown -R 1000:1000 "$KAFKA_DATA_ROOT"
docker compose -f benchmarks/pepper-phase0/kafka/compose.yaml up -d --wait
```

Run the suite from the repository root:

```bash
export KAFKA_CONTAINER=pepper-phase0-kafka-1
export KAFKA_BOOTSTRAP_SERVERS=broker-1:9092
export KAFKA_BENCHMARK_TOPIC=pepper-phase0
export KAFKA_BENCHMARK_PARTITIONS=12
export KAFKA_BENCHMARK_RECORDS=10000000
cargo run --release -p pepper-phase0 -- run \
  --suite benchmarks/pepper-phase0/suites/kafka-comparator.toml \
  --output-directory target/phase0-kafka-comparator
```

Kafka's normal replicated profile acknowledges after ISR replication but does
not force an `fsync` for every record. Run that profile with
`KAFKA_LOG_FLUSH_INTERVAL_MESSAGES` unset. To measure the stricter
per-message-flush bound, start a fresh, empty cluster with
`KAFKA_LOG_FLUSH_INTERVAL_MESSAGES=1`. Never compare the two profiles without
labeling the durability difference. Pepper parity claims must use the profile
whose failure contract matches the Pepper configuration under test.

The host client bootstrap addresses are
`localhost:19092,localhost:29092,localhost:39092`. The suite uses the internal
listener because the Kafka performance tools execute in `broker-1`.

Stop the cluster with:

```bash
docker compose -f benchmarks/pepper-phase0/kafka/compose.yaml down
```

This command does not remove the bind-mounted benchmark data.
