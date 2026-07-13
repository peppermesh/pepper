<!-- SPDX-License-Identifier: Apache-2.0 -->

# Pepper System Test Schemas — Version 1

These Draft 2020-12 JSON Schemas freeze the Phase 0 contracts for:

- `run.json` — run identity, environment, seed, result, and artifact references;
- `topology.json` — test network, nodes, volumes, resources, and policies;
- `events.jsonl` entries — ordered lifecycle, operation, fault, observation, and invariant events;
- node observation files;
- artifact manifest and redaction metadata.

## Compatibility rules

1. Writers emit `schema_version: 1` and validate before artifact publication.
2. Readers reject unknown major schema versions by default.
3. Version 1 may add optional properties because event and observation records intentionally permit extension.
4. Required-property changes, semantic reinterpretation, enum removal, or type changes require a version-2 directory.
5. Unknown event/observation detail fields are retained when artifacts are transformed.
6. Paths are artifact-relative. Absolute paths and parent traversal are prohibited in run and artifact manifests.
7. JSONL event sequence numbers are strictly increasing within one run. Wall-clock timestamps are informational; controller monotonic timestamps order events.
8. Secrets and private keys are never valid schema extensions. Artifact redaction is mandatory before CI upload.

## Canonical filenames

```text
run.json
topology.json
events.jsonl
artifact-manifest.json
observations/<node>/<sequence>.json
```

Phase 1 must copy these schemas into the system-test runner's packaged resources without changing bytes, then add validation tests and valid/invalid fixtures.
