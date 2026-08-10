#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# SQLite parity driver. The pepper-sqlite-benchmark measures all workloads in
# one pass, so `measure` caches one benchmark report per (backend,
# repetition) beside the cell directories and emits the per-cell selection
# JSON the harness's sqlite parser expects. Audit modes write acknowledged
# rows and verify them after the suite's kill/restart steps.
#
# usage:
#   sqlite-driver.sh measure <backend> <workload> <repetition> <output>
#   sqlite-driver.sh audit-produce <backend>
#   sqlite-driver.sh audit-verify  <backend>
#
# <backend>: pepper_vfs | rqlite
#
# Environment: PEPPER_BENCH_ROOT (pepper socket discovery), optional
# PEPPER_PARITY_SQLITE_API (default http://127.0.0.1:29080) and
# PEPPER_PARITY_RQLITE_URL (default http://127.0.0.1:24001).

set -euo pipefail

mode=${1:?mode}
backend=${2:?backend}

api=${PEPPER_PARITY_SQLITE_API:-http://127.0.0.1:29080}
rqlite_url=${PEPPER_PARITY_RQLITE_URL:-http://127.0.0.1:24001}
# Cargo invocation override, e.g. "cargo +1.97.1" on hosts whose default
# toolchain is older than the workspace's SQLite dependencies require.
cargo_command=${PEPPER_PARITY_CARGO:-cargo}
socket="${PEPPER_BENCH_ROOT:?set PEPPER_BENCH_ROOT}/single/metadata/sqlite.sock"
AUDIT_DATABASE=parity-audit
AUDIT_ROWS=1000

pepper_sql() {
    $cargo_command run -q --release -p pepper-sqlite-vfs --bin pepper-sqlite -- \
        --socket "$socket" "$AUDIT_DATABASE" "$1"
}

rqlite_execute() {
    python3 - "$rqlite_url" "$1" <<'EOF'
import json, sys, urllib.request
url, sql = sys.argv[1], sys.argv[2]
request = urllib.request.Request(
    f"{url}/db/execute?transaction",
    data=json.dumps([[sql]]).encode(),
    headers={"Content-Type": "application/json"},
)
body = json.load(urllib.request.urlopen(request, timeout=60))
for result in body.get("results", []):
    if "error" in result:
        raise SystemExit(f"rqlite statement failed: {result['error']}")
EOF
}

rqlite_count() {
    python3 - "$rqlite_url" "$1" <<'EOF'
import json, sys, urllib.request
url, sql = sys.argv[1], sys.argv[2]
request = urllib.request.Request(
    f"{url}/db/query?level=strong",
    data=json.dumps([[sql]]).encode(),
    headers={"Content-Type": "application/json"},
)
body = json.load(urllib.request.urlopen(request, timeout=60))
result = body["results"][0]
if "error" in result:
    raise SystemExit(f"rqlite query failed: {result['error']}")
print(result["values"][0][0])
EOF
}

case "$mode" in
measure)
    workload=${3:?workload}
    repetition=${4:?repetition}
    output=${5:?output path}
    cell_directory=$(dirname "$output")
    repetition_directory=$(dirname "$cell_directory")
    report="$repetition_directory/sqlite-report-$backend.json"
    if [ ! -f "$report" ]; then
        case "$backend" in
        pepper_vfs)
            $cargo_command run -q --release -p pepper-sqlite-benchmark -- \
                --target pepper \
                --api "$api" \
                --socket "$socket" \
                --batch-sizes 1,100 \
                --environment-label "pepper-parity" \
                --output "$report"
            ;;
        rqlite)
            $cargo_command run -q --release -p pepper-sqlite-benchmark -- \
                --target rqlite \
                --rqlite-url "$rqlite_url" \
                --batch-sizes 1,100 \
                --environment-label "pepper-parity" \
                --output "$report"
            ;;
        *)
            echo "unsupported backend $backend" >&2
            exit 2
            ;;
        esac
    fi
    python3 - "$backend" "$workload" "$report" "$output" <<'EOF'
import json, sys
backend, workload, report_path, output_path = sys.argv[1:5]
with open(report_path) as handle:
    report = json.load(handle)
selection = {"backend": backend, "workload": workload, "report": report}
with open(output_path, "w") as handle:
    json.dump(selection, handle)
EOF
    ;;
audit-produce)
    case "$backend" in
    pepper_vfs)
        curl -fsS -X POST "$api/v1/sqlite/databases" \
            -H 'Content-Type: application/json' \
            -d "{\"database\": \"$AUDIT_DATABASE\", \"request_id\": \"parity-audit-$$\"}" \
            > /dev/null
        pepper_sql "CREATE TABLE IF NOT EXISTS audit_rows(id INTEGER PRIMARY KEY)"
        pepper_sql "DELETE FROM audit_rows"
        pepper_sql "INSERT INTO audit_rows(id) WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM cnt WHERE x < $AUDIT_ROWS) SELECT x FROM cnt"
        ;;
    rqlite)
        rqlite_execute "CREATE TABLE IF NOT EXISTS audit_rows(id INTEGER PRIMARY KEY)"
        rqlite_execute "DELETE FROM audit_rows"
        rqlite_execute "INSERT INTO audit_rows(id) WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM cnt WHERE x < $AUDIT_ROWS) SELECT x FROM cnt"
        ;;
    *)
        echo "unsupported backend $backend" >&2
        exit 2
        ;;
    esac
    ;;
audit-verify)
    case "$backend" in
    pepper_vfs)
        count=$(pepper_sql "SELECT count(*) FROM audit_rows" | tail -1)
        ;;
    rqlite)
        count=$(rqlite_count "SELECT count(*) FROM audit_rows")
        ;;
    *)
        echo "unsupported backend $backend" >&2
        exit 2
        ;;
    esac
    echo "acknowledged=$AUDIT_ROWS durable=$count"
    if [ "$count" != "$AUDIT_ROWS" ]; then
        echo "durability audit failed: expected $AUDIT_ROWS rows, found $count" >&2
        exit 1
    fi
    ;;
*)
    echo "unsupported mode $mode" >&2
    exit 2
    ;;
esac
