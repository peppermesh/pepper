#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Release automation driver: turns the manual qualification/release choreography
# into four resumable steps (see `make help`):
#
#   candidate  push release/v<version> at the RC commit (triggers system-smoke)
#              and dispatch system-nightly, system-chaos, system-soak on it
#   status     show the latest run of each suite for the RC commit
#   qualify    wait for all four suites, then dispatch release-qualification
#              with the collected run IDs and watch it
#   publish    verify qualification passed, create the annotated tag, push it,
#              and create a DRAFT prerelease with notes + qualification report
#
# Every step re-derives state from GitHub by the RC commit SHA, so steps can be
# re-run (or run from another machine) at any time without local state.
#
# usage: scripts/release.sh <candidate|status|qualify|publish> <version>
# environment:
#   COMMIT         RC commit (default: HEAD for candidate; release branch head otherwise)
#   SOAK_DURATION  soak duration seconds for dispatch (default: workflow default 18000)
#   NOTES_DIR      hand-written notes directory (default ../internal-docs/pepper-docs/releases)

set -euo pipefail

command=${1:?usage: release.sh <candidate|status|qualify|publish> <version>}
version=${2:?missing version (e.g. 0.3.0)}
branch="release/v${version}"
repo=$(gh repo view --json nameWithOwner -q .nameWithOwner)
suites=(system-smoke system-nightly system-chaos system-soak)

resolve_commit() {
    if [ -n "${COMMIT:-}" ]; then
        git rev-parse "$COMMIT"
    elif [ "$command" = "candidate" ]; then
        git rev-parse HEAD
    else
        git ls-remote origin "refs/heads/$branch" | cut -f1 | grep . \
            || { echo "no $branch on origin; run 'make release-candidate VERSION=$version' first" >&2; exit 1; }
    fi
}
commit=$(resolve_commit)

# Latest run of a workflow file for the RC commit: "<id> <status> <conclusion> <url>"
latest_run() {
    gh api "repos/$repo/actions/workflows/$1.yml/runs?head_sha=$commit&per_page=1" \
        -q '.workflow_runs[0] | select(.) | "\(.id) \(.status) \(.conclusion // "-") \(.html_url)"'
}

case "$command" in
candidate)
    git push origin "$commit:refs/heads/$branch"
    echo "pushed $branch at $commit (system-smoke triggers on the push)"
    gh workflow run system-nightly.yml --ref "$branch"
    gh workflow run system-chaos.yml --ref "$branch"
    if [ -n "${SOAK_DURATION:-}" ]; then
        gh workflow run system-soak.yml --ref "$branch" -f duration_seconds="$SOAK_DURATION"
    else
        gh workflow run system-soak.yml --ref "$branch"
    fi
    echo "dispatched system-nightly, system-chaos, system-soak on $branch"
    echo "next: make release-status VERSION=$version   (or release-qualify to wait)"
    ;;

status)
    echo "RC commit $commit ($branch)"
    for suite in "${suites[@]}" release-qualification; do
        printf '%-24s %s\n' "$suite" "$(latest_run "$suite" || true)"
    done
    ;;

qualify)
    declare -A run_ids
    echo "waiting for ${suites[*]} on $commit (safe to interrupt and re-run)"
    while :; do
        pending=0
        for suite in "${suites[@]}"; do
            line=$(latest_run "$suite" || true)
            if [ -z "$line" ]; then
                echo "  $suite: no run found yet"
                pending=1
                continue
            fi
            read -r id run_status conclusion _url <<<"$line"
            case "$run_status/$conclusion" in
            completed/success) run_ids[$suite]=$id ;;
            completed/*)
                echo "$suite run $id concluded '$conclusion' on $commit; fix and re-run it, then re-run qualify" >&2
                exit 1
                ;;
            *)
                echo "  $suite: run $id $run_status"
                pending=1
                ;;
            esac
        done
        [ "$pending" = 0 ] && break
        sleep 120
    done
    echo "all suites green; dispatching release-qualification"
    gh workflow run release-qualification.yml --ref "$branch" \
        -f release_commit="$commit" \
        -f version="$version" \
        -f smoke_run_id="${run_ids[system-smoke]}" \
        -f functional_run_id="${run_ids[system-nightly]}" \
        -f chaos_run_id="${run_ids[system-chaos]}" \
        -f soak_run_id="${run_ids[system-soak]}"
    sleep 10
    read -r qual_id _ <<<"$(latest_run release-qualification)"
    gh run watch "$qual_id" --exit-status
    echo "qualification passed; next: make release-publish VERSION=$version"
    ;;

publish)
    line=$(latest_run release-qualification || true)
    read -r qual_id run_status conclusion _url <<<"${line:-}"
    if [ "$run_status/$conclusion" != "completed/success" ]; then
        echo "no successful release-qualification run for $commit (found: ${line:-none})" >&2
        exit 1
    fi
    report_dir=$(mktemp -d)
    gh run download "$qual_id" --repo "$repo" --dir "$report_dir"
    if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
        echo "tag v$version already exists locally; skipping tag creation"
    else
        git tag -a "v$version" "$commit" \
            -m "Pepper v$version - Developer Preview" \
            -m "Qualified by GitHub Actions release-qualification run $qual_id."
    fi
    git push origin "v$version"
    notes="${NOTES_DIR:-../internal-docs/pepper-docs/releases}/$version.md"
    if [ -f "$notes" ]; then
        notes_args=(--notes-file "$notes")
    else
        echo "no hand-written notes at $notes; using generated notes" >&2
        notes_args=(--generate-notes)
    fi
    gh release create "v$version" \
        --title "Pepper v$version - Developer Preview" \
        --prerelease --draft --verify-tag \
        "${notes_args[@]}" \
        "$report_dir"/*/qualification.json
    echo "draft release created — review the notes on GitHub, then click Publish"
    ;;

*)
    echo "unknown command $command" >&2
    exit 2
    ;;
esac
