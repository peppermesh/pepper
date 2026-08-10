#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Kafka parity driver. Runs the pinned Apache Kafka perf tools inside an
# existing container so Pepper and Apache Kafka are measured through the
# identical client stack.
#
# usage:
#   kafka-driver.sh measure <container> <bootstrap> <operation> \
#       <payload_size_bytes> <partitions> <repetition> <rf> <topic-extra-config>
#   kafka-driver.sh audit-produce <container> <bootstrap> <rf> <topic-extra-config>
#   kafka-driver.sh audit-verify  <container> <bootstrap>
#
# <rf> is the Kafka-protocol replication factor: 3 for a genuine multi-broker
# Apache Kafka cluster, 1 for Pepper (a single-broker protocol front-end whose
# partition durability comes from Pepper's own consensus layer beneath it, not
# from Kafka-level replicas). <topic-extra-config> is a topic-level config such
# as "min.insync.replicas=2", or "none" to omit it (Pepper's quorum semantics
# are fixed by its consensus layer).

set -euo pipefail

mode=${1:?mode}
container=${2:?exec container}
bootstrap=${3:?bootstrap servers}

BIN=/opt/kafka/bin
AUDIT_TOPIC=parity-audit
AUDIT_RECORDS=20000
AUDIT_RECORD_BYTES=1024
# The checked-in exploratory template moves ~256 MiB per cell; qualification
# runs raise this (see PERFORMANCE_PARITY_HARNESS.md section 5). Baseline
# and smoke runs may shrink it through the environment.
CELL_BYTES=${PEPPER_PARITY_KAFKA_CELL_BYTES:-268435456}
MINIMUM_RECORDS=${PEPPER_PARITY_KAFKA_MINIMUM_RECORDS:-10000}

create_topic() {
    local topic=$1 partitions=$2 rf=$3 extra=$4
    local args=(
        "$BIN/kafka-topics.sh" --bootstrap-server "$bootstrap"
        --create --if-not-exists --topic "$topic"
        --partitions "$partitions" --replication-factor "$rf"
    )
    if [ "$extra" != "none" ]; then
        args+=(--config "$extra")
    fi
    docker exec "$container" "${args[@]}"
}

produce() {
    local topic=$1 size=$2 records=$3 warmup=$4
    docker exec "$container" "$BIN/kafka-producer-perf-test.sh" \
        --bootstrap-server "$bootstrap" \
        --topic "$topic" \
        --num-records "$records" \
        --record-size "$size" \
        --throughput -1 \
        --warmup-records "$warmup" \
        --command-property \
        acks=all \
        enable.idempotence=false \
        compression.type=none \
        linger.ms=5 \
        batch.size=65536
}

consume() {
    local topic=$1 records=$2 group=$3
    docker exec "$container" "$BIN/kafka-consumer-perf-test.sh" \
        --bootstrap-server "$bootstrap" \
        --topic "$topic" \
        --group "$group" \
        --num-records "$records" \
        --timeout 300000
}

case "$mode" in
measure)
    operation=${4:?operation}
    size=${5:?payload size bytes}
    partitions=${6:?partitions}
    repetition=${7:?repetition}
    rf=${8:?replication factor}
    extra=${9:?topic extra config or none}
    topic="parity-${operation}-${size}-p${partitions}-r${repetition}"
    records=$((CELL_BYTES / size))
    if [ "$records" -lt "$MINIMUM_RECORDS" ]; then
        records=$MINIMUM_RECORDS
    fi
    create_topic "$topic" "$partitions" "$rf" "$extra"
    case "$operation" in
    produce)
        produce "$topic" "$size" "$records" "$MINIMUM_RECORDS"
        ;;
    consume)
        # Fill the topic first; the fill's producer summary does not match
        # the consumer parser's CSV header, so mixed stdout stays parseable.
        produce "$topic" "$size" "$records" 0
        consume "$topic" "$records" "parity-$topic"
        ;;
    *)
        echo "unsupported operation $operation" >&2
        exit 2
        ;;
    esac
    ;;
audit-produce)
    rf=${4:?replication factor}
    extra=${5:?topic extra config or none}
    create_topic "$AUDIT_TOPIC" 1 "$rf" "$extra"
    produce "$AUDIT_TOPIC" "$AUDIT_RECORD_BYTES" "$AUDIT_RECORDS" 0
    ;;
audit-verify)
    end_offsets=$(docker exec "$container" "$BIN/kafka-get-offsets.sh" \
        --bootstrap-server "$bootstrap" --topic "$AUDIT_TOPIC" --time -1)
    total=$(printf '%s\n' "$end_offsets" | awk -F: '{sum += $NF} END {print sum + 0}')
    echo "acknowledged=$AUDIT_RECORDS durable_end_offset=$total"
    if [ "$total" -lt "$AUDIT_RECORDS" ]; then
        echo "durability audit failed: $((AUDIT_RECORDS - total)) acknowledged records lost" >&2
        exit 1
    fi
    ;;
*)
    echo "unsupported mode $mode" >&2
    exit 2
    ;;
esac
