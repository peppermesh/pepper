#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# One-command, Docker-based Kafka parity benchmark: Pepper vs Apache Kafka
# 4.3.1 at a matched durability guarantee. Everything under test runs in
# pinned containers — the Pepper topology (pepper-s3-throughput:local), the
# Apache Kafka comparator cluster, and the perf-test client tools — while this
# script orchestrates lifecycle, measurement, the SIGKILL durability audits,
# and the parity report through the pepper-parity runner.
#
# usage:
#   benchmarks/pepper-parity/run-kafka-parity.sh [fsync-quorum|replicated-ack]
#
# environment:
#   PEPPER_BENCH_ROOT   data root on the filesystem under test
#                       (default /data/pepper-bench/s3fix)
#   SCALE               smoke (default) | full — full uses the checked-in
#                       256 MiB per-cell volume; smoke trims it for quick runs
#   REBUILD_IMAGE       1 to force a rebuild of pepper-s3-throughput:local
#   OUTPUT_ROOT         report directory root (default
#                       benchmarks/pepper-parity/results)

set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"

suite_name=${1:-fsync-quorum}
suite="benchmarks/pepper-parity/suites/kafka-vs-kafka-${suite_name}.toml"
[ -f "$suite" ] || {
    echo "unknown suite '$suite_name' (expected fsync-quorum or replicated-ack)" >&2
    exit 2
}

export PEPPER_BENCH_ROOT=${PEPPER_BENCH_ROOT:-/data/pepper-bench/s3fix}
export PEPPER_BENCH_CONFIG_DIR=${PEPPER_BENCH_CONFIG_DIR:-$PEPPER_BENCH_ROOT/.runtime-config}

case "${SCALE:-smoke}" in
smoke)
    # Trimmed per-cell volume: enough records for stable rates on both sides
    # without the multi-hour qualification volume.
    export PEPPER_PARITY_KAFKA_CELL_BYTES=$((16 * 1024 * 1024))
    export PEPPER_PARITY_KAFKA_MINIMUM_RECORDS=3000
    ;;
full) ;; # kafka-driver.sh defaults: 256 MiB cells
*)
    echo "SCALE must be smoke or full" >&2
    exit 2
    ;;
esac

# The Apache Kafka comparator image runs as uid 1000; if Docker creates the
# bind-mounted data directories on demand they come up root-owned and broker
# storage formatting fails with AccessDenied. Pre-create them writable.
kafka_root="$PEPPER_BENCH_ROOT/kafka"
mkdir -p "$kafka_root" 2>/dev/null || true
if [ ! -w "$kafka_root" ] || find "$kafka_root" -maxdepth 1 ! -writable 2>/dev/null | grep -q .; then
    docker run --rm -v "$kafka_root":/fix alpine:3 chown -R 1000:1000 /fix
fi
mkdir -p "$kafka_root/broker-1" "$kafka_root/broker-2" "$kafka_root/broker-3"

# The Pepper side runs the local image; build it when missing or on request.
if [ "${REBUILD_IMAGE:-0}" = "1" ] || ! docker image inspect pepper-s3-throughput:local >/dev/null 2>&1; then
    docker build -f system-tests/docker/Dockerfile -t pepper-s3-throughput:local .
fi

# The runner binary orchestrates lifecycle/audit/measure/report.
cargo build --release -p pepper-parity

stamp=$(date -u +%Y%m%dT%H%M%SZ)
output="${OUTPUT_ROOT:-benchmarks/pepper-parity/results}/kafka-${suite_name}-${SCALE:-smoke}-${stamp}"
mkdir -p "$output"

./target/release/pepper-parity validate --suite "$suite"
./target/release/pepper-parity run --suite "$suite" --output-directory "$output"

echo
echo "report: $output/report.md"
