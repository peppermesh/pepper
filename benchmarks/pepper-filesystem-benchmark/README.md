<!-- SPDX-License-Identifier: Apache-2.0 -->

# Pepper filesystem benchmark

This benchmark measures a versioned Pepper filesystem through its production
HTTP APIs. It separately reports:

- initial content upload;
- initial immutable tree commit and publication;
- changed-content upload;
- incremental tree commit and publication;
- checkout metadata/tree resolution;
- physical content materialization and byte verification; and
- end-to-end changed-content upload plus commit.

Every iteration replaces a deterministic rotating subset of files, commits
against the exact previous revision, checks out that revision, downloads every
file, verifies deterministic bytes, writes the tree beneath a private
disk-backed scratch directory, and removes the checkout.

```bash
cargo run --release -p pepper-filesystem-benchmark -- \
  --api http://127.0.0.1:9080 \
  --scratch-directory /path/to/persistent/filesystem \
  --files 1000 \
  --file-bytes 4096 \
  --mutation-percent 10 \
  --iterations 10 \
  --output artifacts/filesystem.json
```

The JSON report includes latency distributions, throughput, logical scale,
final revision/root, verified files/bytes, and Pepper metrics before and after.
The benchmark creates a uniquely named filesystem and does not delete its
committed Pepper data.
