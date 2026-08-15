#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the system-nightly or system-chaos scenario suite locally, mirroring the
# CI workflows: same runner, same Docker backend, same deterministic seed
# scheme (day * 1000 + offset; CI adds a run-number component). The scenario
# list and offsets are parsed from the workflow file itself so the local suite
# can never drift from CI.
#
# usage:
#   scripts/run-system-suite.sh nightly              # full nightly suite
#   scripts/run-system-suite.sh chaos                # full chaos suite
#   scripts/run-system-suite.sh nightly BUCKET-001   # one scenario
#
# environment:
#   SEED     exact reproduction seed (default: day-derived, per scenario)
#   IMAGE    test image tag (default pepper-system-test:local; the harness
#            builds it from the working tree when the tag does not exist)
#   REBUILD  1 to remove the image first so it is rebuilt from the current tree

set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"

suite=${1:?usage: run-system-suite.sh <nightly|chaos> [scenario]}
only=${2:-}
case "$suite" in
nightly) workflow=.github/workflows/system-nightly.yml ;;
chaos) workflow=.github/workflows/system-chaos.yml ;;
*)
    echo "suite must be nightly or chaos" >&2
    exit 2
    ;;
esac

image=${IMAGE:-pepper-system-test:local}
if [ "${REBUILD:-0}" = "1" ]; then
    docker rmi "$image" >/dev/null 2>&1 || true
fi

# Matrix rows look like: - { scenario: BUCKET-001, offset: 26 } (chaos rows
# add a slot column). Emit "scenario offset" pairs.
matrix=$(sed -n 's/.*{ scenario: \([A-Z0-9-]*\),.* offset: \([0-9]*\) }.*/\1 \2/p' "$workflow")
[ -n "$matrix" ] || { echo "no scenario matrix found in $workflow" >&2; exit 1; }

day=$(( $(date -u +%s) / 86400 ))
passed=()
failed=()
while read -r scenario offset; do
    if [ -n "$only" ] && [ "$scenario" != "$only" ]; then
        continue
    fi
    seed=${SEED:-$(( day * 1000 + offset ))}
    echo "=== $scenario seed=$seed"
    if cargo run --manifest-path system-tests/Cargo.toml --locked -- \
        run --scenario "$scenario" --seed "$seed" \
        --backend docker --image "$image"; then
        passed+=("$scenario")
    else
        failed+=("$scenario seed=$seed")
    fi
done <<<"$matrix"

if [ -n "$only" ] && [ ${#passed[@]} -eq 0 ] && [ ${#failed[@]} -eq 0 ]; then
    echo "scenario $only is not in the $suite matrix" >&2
    exit 2
fi
echo
echo "$suite suite: ${#passed[@]} passed, ${#failed[@]} failed"
for entry in ${failed[@]+"${failed[@]}"}; do
    echo "  FAIL $entry"
done
[ ${#failed[@]} -eq 0 ]
