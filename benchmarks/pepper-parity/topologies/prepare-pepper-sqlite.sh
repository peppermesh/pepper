#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Bootstrap the Pepper-with-SQLite topology: generate the standard benchmark
# node configs, then enable the SQLite service on the three single-profile
# nodes. The VFS socket stays at its default `<data.path>/sqlite.sock`,
# which lives on the bind-mounted benchmark root, so the host reaches the
# ingress node's socket at $PEPPER_BENCH_ROOT/single/metadata/sqlite.sock.
# Keep PEPPER_BENCH_ROOT short: Unix socket paths are limited to ~108 bytes.
#
# Requires PEPPER_BENCH_ROOT. Idempotent.

set -euo pipefail

root=${PEPPER_BENCH_ROOT:?set PEPPER_BENCH_ROOT}
config_dir="$root/.runtime-config"

# The sql-replicated-3x profile requires replicated durability; the
# checked-in configs default to factor 1, which cannot satisfy a namespace
# publication durability barrier on a 3-node cluster.
${PEPPER_PARITY_CARGO:-cargo} run --release -p pepper-s3-throughput -- prepare-topology --root "$root" --replication-factor 3 "$@"

add_sqlite() {
    local file=$1
    if grep -q '^\[sqlite\]' "$config_dir/$file"; then
        return
    fi
    cat >> "$config_dir/$file" <<EOF

[sqlite]
enabled = true
EOF
}

add_sqlite single.toml
add_sqlite single2.toml
add_sqlite single3.toml

echo "sqlite service enabled in $config_dir/single*.toml"
