#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Bootstrap the Pepper-with-Kafka topology: generate the standard benchmark
# node configs, then enable the Kafka listener on the three single-profile
# nodes. `kafka.allow_insecure_remote` is restricted to this isolated
# benchmark Docker network, mirroring the S3 benchmark's API posture; it is
# not a deployment recommendation.
#
# Requires PEPPER_BENCH_ROOT. Idempotent.

set -euo pipefail

root=${PEPPER_BENCH_ROOT:?set PEPPER_BENCH_ROOT}
config_dir="$root/.runtime-config"

${PEPPER_PARITY_CARGO:-cargo} run --release -p pepper-s3-throughput -- prepare-topology --root "$root" "$@"

add_kafka() {
    local file=$1 broker_id=$2 advertise_ip=$3
    if grep -q '^\[kafka\]' "$config_dir/$file"; then
        return
    fi
    cat >> "$config_dir/$file" <<EOF

[kafka]
enabled = true
bind_addr = "0.0.0.0:9095"
advertise_addr = "${advertise_ip}:9095"
broker_id = ${broker_id}
cluster_id = "pepper-parity-kafka"
allow_insecure_remote = true
EOF
}

add_kafka single.toml 1 172.30.43.10
add_kafka single2.toml 2 172.30.43.14
add_kafka single3.toml 3 172.30.43.15

echo "kafka listeners enabled in $config_dir/single*.toml"
