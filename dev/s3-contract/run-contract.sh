#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

node1=${PEPPER_S3_NODE1:?PEPPER_S3_NODE1 is required}
node2=${PEPPER_S3_NODE2:?PEPPER_S3_NODE2 is required}
node3=${PEPPER_S3_NODE3:?PEPPER_S3_NODE3 is required}
work=/tmp/pepper-s3-contract
bucket="pepper-contract-$(date +%s)-$$"

mkdir -p "$work"

log() {
    printf '%s\n' "[s3-contract] $*"
}

fail() {
    printf '%s\n' "[s3-contract] FAIL: $*" >&2
    exit 1
}

s3() {
    endpoint=$1
    shift
    aws --no-cli-pager --region us-east-1 --endpoint-url "$endpoint" s3api "$@"
}

wait_for_gateway() {
    endpoint=$1
    attempts=0
    until s3 "$endpoint" list-buckets >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 60 ]; then
            fail "gateway $endpoint did not become ready"
        fi
        sleep 1
    done
}

log "waiting for all S3 gateways"
wait_for_gateway "$node1"
wait_for_gateway "$node2"
wait_for_gateway "$node3"

# Give authenticated peer catalogs time to converge after the final node starts.
sleep 3

log "creating $bucket through node1"
attempts=0
until s3 "$node1" create-bucket --bucket "$bucket" >/dev/null 2>"$work/create.err"; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 30 ]; then
        sed -n '1,120p' "$work/create.err" >&2
        fail "bucket creation did not obtain a three-node replica set"
    fi
    sleep 1
done

log "resolving the bucket through node2 and listing it through node3"
s3 "$node2" head-bucket --bucket "$bucket" >/dev/null
listed_bucket=$(s3 "$node3" list-buckets --query "Buckets[?Name=='$bucket'].Name | [0]" --output text)
[ "$listed_bucket" = "$bucket" ] || fail "node3 did not list $bucket"

log "round-tripping a normal object across gateways"
printf 'pepper AWS CLI contract object\n' > "$work/small.txt"
s3 "$node1" put-object --bucket "$bucket" --key small.txt --body "$work/small.txt" >/dev/null
s3 "$node2" get-object --bucket "$bucket" --key small.txt "$work/small.out" >/dev/null
cmp "$work/small.txt" "$work/small.out" || fail "normal object content changed"
listed_key=$(s3 "$node3" list-objects-v2 --bucket "$bucket" --query "Contents[?Key=='small.txt'].Key | [0]" --output text)
[ "$listed_key" = "small.txt" ] || fail "node3 did not list small.txt"

log "validating range reads, checksums, and server-side copy"
s3 "$node2" get-object --bucket "$bucket" --key small.txt --range bytes=0-5 "$work/range.out" >/dev/null
printf 'pepper' > "$work/range.expected"
cmp "$work/range.expected" "$work/range.out" || fail "range response content changed"
s3 "$node2" put-object --bucket "$bucket" --key checksum.txt --body "$work/small.txt" --checksum-algorithm SHA256 >/dev/null
s3 "$node3" copy-object --bucket "$bucket" --key copied.txt --copy-source "$bucket/small.txt" >/dev/null
s3 "$node1" get-object --bucket "$bucket" --key copied.txt "$work/copied.out" >/dev/null
cmp "$work/small.txt" "$work/copied.out" || fail "CopyObject content changed"

log "round-tripping bucket tagging, CORS, and lifecycle configuration"
printf '{"TagSet":[{"Key":"suite","Value":"docker"}]}' > "$work/tagging.json"
s3 "$node1" put-bucket-tagging --bucket "$bucket" --tagging "file://$work/tagging.json"
tag_value=$(s3 "$node2" get-bucket-tagging --bucket "$bucket" --query "TagSet[?Key=='suite'].Value | [0]" --output text)
[ "$tag_value" = "docker" ] || fail "bucket tagging did not round-trip"
printf '{"CORSRules":[{"AllowedOrigins":["https://example.test"],"AllowedMethods":["GET"],"AllowedHeaders":["*"]}]}' > "$work/cors.json"
s3 "$node2" put-bucket-cors --bucket "$bucket" --cors-configuration "file://$work/cors.json"
cors_origin=$(s3 "$node3" get-bucket-cors --bucket "$bucket" --query 'CORSRules[0].AllowedOrigins[0]' --output text)
[ "$cors_origin" = "https://example.test" ] || fail "bucket CORS did not round-trip"
printf '{"Rules":[{"ID":"abort-stale","Status":"Enabled","Filter":{"Prefix":""},"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":1}}]}' > "$work/lifecycle.json"
s3 "$node3" put-bucket-lifecycle-configuration --bucket "$bucket" --lifecycle-configuration "file://$work/lifecycle.json"
lifecycle_days=$(s3 "$node1" get-bucket-lifecycle-configuration --bucket "$bucket" --query 'Rules[0].AbortIncompleteMultipartUpload.DaysAfterInitiation' --output text)
[ "$lifecycle_days" = "1" ] || fail "bucket lifecycle did not round-trip"

log "restarting node1's Pepper process while preserving its Docker volume"
old_generation=$(sed -n '1p' /control/node1.generation)
: > /control/node1.restart
attempts=0
while :; do
    new_generation=$(sed -n '1p' /control/node1.generation 2>/dev/null || true)
    if [ -n "$new_generation" ] && [ "$new_generation" -gt "$old_generation" ]; then
        break
    fi
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 60 ]; then
        fail "node1 did not restart"
    fi
    sleep 1
done
wait_for_gateway "$node1"
s3 "$node1" head-bucket --bucket "$bucket" >/dev/null
s3 "$node1" get-object --bucket "$bucket" --key small.txt "$work/small-after-restart.out" >/dev/null
cmp "$work/small.txt" "$work/small-after-restart.out" || fail "object changed after node1 restart"

log "performing a multipart upload through alternating gateways"
dd if=/dev/zero of="$work/part1" bs=1048576 count=5 2>/dev/null
printf 'pepper multipart tail through node3\n' > "$work/part2"
cp "$work/part1" "$work/expected"
dd if="$work/part2" of="$work/expected" oflag=append conv=notrunc 2>/dev/null

upload_id=$(s3 "$node2" create-multipart-upload --bucket "$bucket" --key multipart.bin --query UploadId --output text)
[ -n "$upload_id" ] && [ "$upload_id" != "None" ] || fail "missing multipart upload ID"

etag1=$(s3 "$node2" upload-part --bucket "$bucket" --key multipart.bin --part-number 1 --upload-id "$upload_id" --body "$work/part1" --query ETag --output text)
etag2=$(s3 "$node3" upload-part --bucket "$bucket" --key multipart.bin --part-number 2 --upload-id "$upload_id" --body "$work/part2" --query ETag --output text)
etag1=${etag1#\"}
etag1=${etag1%\"}
etag2=${etag2#\"}
etag2=${etag2%\"}

parts_count=$(s3 "$node1" list-parts --bucket "$bucket" --key multipart.bin --upload-id "$upload_id" --query 'length(Parts)' --output text)
[ "$parts_count" = "2" ] || fail "expected two multipart parts, got $parts_count"

printf '{"Parts":[{"ETag":"%s","PartNumber":1},{"ETag":"%s","PartNumber":2}]}\n' \
    "$etag1" "$etag2" > "$work/complete.json"
s3 "$node3" complete-multipart-upload \
    --bucket "$bucket" \
    --key multipart.bin \
    --upload-id "$upload_id" \
    --multipart-upload "file://$work/complete.json" >/dev/null

s3 "$node2" get-object --bucket "$bucket" --key multipart.bin "$work/multipart.out" >/dev/null
cmp "$work/expected" "$work/multipart.out" || fail "completed multipart object content changed"

log "performing UploadPartCopy through another gateway"
s3 "$node1" put-object --bucket "$bucket" --key copy-source.bin --body "$work/part1" >/dev/null
copy_upload_id=$(s3 "$node2" create-multipart-upload --bucket "$bucket" --key copied-multipart.bin --query UploadId --output text)
copy_etag1=$(s3 "$node3" upload-part-copy --bucket "$bucket" --key copied-multipart.bin --part-number 1 --upload-id "$copy_upload_id" --copy-source "$bucket/copy-source.bin" --query CopyPartResult.ETag --output text)
copy_etag2=$(s3 "$node1" upload-part --bucket "$bucket" --key copied-multipart.bin --part-number 2 --upload-id "$copy_upload_id" --body "$work/part2" --query ETag --output text)
copy_etag1=${copy_etag1#\"}
copy_etag1=${copy_etag1%\"}
copy_etag2=${copy_etag2#\"}
copy_etag2=${copy_etag2%\"}
printf '{"Parts":[{"ETag":"%s","PartNumber":1},{"ETag":"%s","PartNumber":2}]}\n' \
    "$copy_etag1" "$copy_etag2" > "$work/copy-complete.json"
s3 "$node2" complete-multipart-upload --bucket "$bucket" --key copied-multipart.bin --upload-id "$copy_upload_id" --multipart-upload "file://$work/copy-complete.json" >/dev/null
s3 "$node3" get-object --bucket "$bucket" --key copied-multipart.bin "$work/copied-multipart.out" >/dev/null
cmp "$work/expected" "$work/copied-multipart.out" || fail "UploadPartCopy content changed"

log "aborting an upload through a different gateway"
abandoned_id=$(s3 "$node3" create-multipart-upload --bucket "$bucket" --key abandoned.bin --query UploadId --output text)
s3 "$node2" abort-multipart-upload --bucket "$bucket" --key abandoned.bin --upload-id "$abandoned_id"
remaining=$(s3 "$node1" list-multipart-uploads --bucket "$bucket" --query "Uploads[?UploadId=='$abandoned_id'].UploadId | [0]" --output text)
[ "$remaining" = "None" ] || [ -z "$remaining" ] || fail "aborted upload is still listed"

log "deleting objects in one multi-object request"
printf '{"Objects":[{"Key":"small.txt"},{"Key":"checksum.txt"},{"Key":"copied.txt"},{"Key":"multipart.bin"},{"Key":"copy-source.bin"},{"Key":"copied-multipart.bin"}],"Quiet":false}' > "$work/delete.json"
s3 "$node2" delete-objects --bucket "$bucket" --delete "file://$work/delete.json" >/dev/null
remaining_keys=$(s3 "$node1" list-objects-v2 --bucket "$bucket" --query 'Contents[].Key' --output text)
[ -z "$remaining_keys" ] || [ "$remaining_keys" = "None" ] \
    || fail "expected an empty bucket, found: $remaining_keys"

log "deleting and recreating the empty bucket"
s3 "$node3" delete-bucket --bucket "$bucket"
if s3 "$node1" head-bucket --bucket "$bucket" >/dev/null 2>&1; then
    fail "deleted bucket still resolves"
fi
s3 "$node1" create-bucket --bucket "$bucket" >/dev/null
s3 "$node2" head-bucket --bucket "$bucket" >/dev/null
s3 "$node3" delete-bucket --bucket "$bucket"

log "PASS: AWS CLI range, checksum, copy, multipart-copy, multi-delete, bucket controls, restart, and delete contract"
