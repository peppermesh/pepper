#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

config_path=${1:?usage: s3-contract-node CONFIG}
node_name=${PEPPER_TEST_NODE_NAME:?PEPPER_TEST_NODE_NAME is required}
cluster_secret=${PEPPER_TEST_CLUSTER_SECRET:?PEPPER_TEST_CLUSTER_SECRET is required}
s3_secret=${PEPPER_TEST_S3_SECRET:?PEPPER_TEST_S3_SECRET is required}
restart_marker="/control/${node_name}.restart"
restart_ack="/control/${node_name}.restarting"
generation_file="/control/${node_name}.generation"

mkdir -p /var/lib/pepper/identity /control
umask 077
printf '%s\n' "$cluster_secret" > /var/lib/pepper/identity/cluster.secret
printf '%s\n' "$s3_secret" > /var/lib/pepper/identity/s3.secret
rm -f "$restart_marker" "$restart_ack"

agent_pid=
watcher_pid=
proxy_pid=
stopping=0

stop_processes() {
    stopping=1
    if [ -n "$watcher_pid" ]; then
        kill "$watcher_pid" 2>/dev/null || true
    fi
    if [ -n "$agent_pid" ]; then
        kill -TERM "$agent_pid" 2>/dev/null || true
    fi
    if [ -n "$proxy_pid" ]; then
        kill "$proxy_pid" 2>/dev/null || true
    fi
}

trap stop_processes INT TERM

# Pepper's HTTP API remains loopback-only. This bridge is reachable only from
# the isolated Compose network and exists solely for the black-box S3 test.
socat TCP-LISTEN:19080,bind=0.0.0.0,reuseaddr,fork TCP:127.0.0.1:9080 &
proxy_pid=$!

generation=0
while [ "$stopping" -eq 0 ]; do
    generation=$((generation + 1))
    printf '%s\n' "$generation" > "$generation_file"

    pepper-agent --config "$config_path" &
    agent_pid=$!

    (
        while kill -0 "$agent_pid" 2>/dev/null; do
            if [ -f "$restart_marker" ]; then
                rm -f "$restart_marker"
                : > "$restart_ack"
                kill -TERM "$agent_pid" 2>/dev/null || true
                exit 0
            fi
            sleep 1
        done
    ) &
    watcher_pid=$!

    set +e
    wait "$agent_pid"
    agent_status=$?
    set -e
    agent_pid=

    kill "$watcher_pid" 2>/dev/null || true
    wait "$watcher_pid" 2>/dev/null || true
    watcher_pid=

    if [ "$stopping" -ne 0 ]; then
        break
    fi
    if [ -f "$restart_ack" ]; then
        rm -f "$restart_ack"
        continue
    fi

    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
    exit "$agent_status"
done

if [ -n "$proxy_pid" ]; then
    wait "$proxy_pid" 2>/dev/null || true
fi
