#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# One-command, Docker-based S3 parity benchmark: Pepper vs MinIO. Both systems
# run in containers on the same filesystem; the loadgen drives both through the
# identical S3 client path, and each side passes its guarantee audit before its
# cells count.
#
# Profiles:
#   single      (default) single-node durable-on-ack: Pepper trio at RF=1 vs
#               single MinIO with MINIO_DRIVE_SYNC=on; audit is
#               SIGKILL-all + restart + readback.
#   replicated  one-node fault tolerance: Pepper trio at RF=3 vs distributed
#               MinIO (3 nodes x 2 drives, EC:2, drive sync on); audit ingests
#               through node 1, SIGKILLs node 1, and reads back through node 2
#               while node 1 is down.
#
# usage:
#   benchmarks/pepper-parity/run-s3-parity.sh
#   PROFILE=replicated benchmarks/pepper-parity/run-s3-parity.sh
#
# environment:
#   PROFILE             single (default) | replicated
#   PEPPER_BENCH_ROOT   data root on the filesystem under test (defaults:
#                       /data/pepper-bench/s3fix for single,
#                       /data/pepper-bench/s3rep for replicated — kept apart
#                       so RF=1 and RF=3 state never mix)
#   SCALE               smoke (default) | full — smoke trims the checked-in
#                       suite to 20 s cells, 2 repetitions, and drops the
#                       64 MiB payload tier; full runs the suite as committed
#   REBUILD_IMAGE       1 to force a rebuild of pepper-s3-throughput:local
#   OUTPUT_ROOT         report directory root (default
#                       benchmarks/pepper-parity/results)

set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"

profile=${PROFILE:-single}
case "$profile" in
single)
    suite_base=benchmarks/pepper-parity/suites/s3-vs-minio.toml
    default_root=/data/pepper-bench/s3fix
    slug=s3-minio
    ;;
replicated)
    suite_base=benchmarks/pepper-parity/suites/s3-vs-minio-replicated.toml
    default_root=/data/pepper-bench/s3rep
    slug=s3-minio-replicated
    ;;
*)
    echo "PROFILE must be single or replicated" >&2
    exit 2
    ;;
esac

export PEPPER_BENCH_ROOT=${PEPPER_BENCH_ROOT:-$default_root}
export PEPPER_BENCH_CONFIG_DIR=${PEPPER_BENCH_CONFIG_DIR:-$PEPPER_BENCH_ROOT/.runtime-config}

if [ "${REBUILD_IMAGE:-0}" = "1" ] || ! docker image inspect pepper-s3-throughput:local >/dev/null 2>&1; then
    docker build -f system-tests/docker/Dockerfile -t pepper-s3-throughput:local .
fi

cargo build --release -p pepper-parity -p pepper-s3-throughput

stamp=$(date -u +%Y%m%dT%H%M%SZ)
scale=${SCALE:-smoke}
output="${OUTPUT_ROOT:-benchmarks/pepper-parity/results}/${slug}-${scale}-${stamp}"
mkdir -p "$output"

if [ "$scale" = "full" ]; then
    # Full scale keeps the checked-in 60 s cells and repetitions, but the
    # runner's 10 s warmup invocations still need loadgen's --allow-short.
    suite="$output/$(basename "$suite_base" .toml)-full.toml"
    sed -e 's/^\( *\)"loadgen",$/\1"loadgen",\n\1"--allow-short",/' \
        "$suite_base" > "$suite"
elif [ "$scale" = "smoke" ]; then
    # Trimmed copy of the checked-in suite: shorter cells, fewer repetitions,
    # no 64 MiB tier. The copy lives in the artifact directory for provenance.
    suite="$output/$(basename "$suite_base" .toml)-smoke.toml"
    # Short cells need loadgen's --allow-short (it enforces 60 s otherwise);
    # inject it into the measure commands only (the standalone "loadgen" line),
    # never into the audit steps.
    sed -e 's/^payload_sizes_bytes = .*/payload_sizes_bytes = [4096, 1048576]/' \
        -e 's/^duration_seconds = .*/duration_seconds = 20/' \
        -e 's/^repetitions = .*/repetitions = 2/' \
        -e 's/^\( *\)"loadgen",$/\1"loadgen",\n\1"--allow-short",/' \
        "$suite_base" > "$suite"
else
    echo "SCALE must be smoke or full" >&2
    exit 2
fi

./target/release/pepper-parity validate --suite "$suite"
./target/release/pepper-parity run --suite "$suite" --output-directory "$output"

echo
echo "report: $output/parity-report.md"
