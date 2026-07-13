<!-- SPDX-License-Identifier: Apache-2.0 -->

# System-test image

`Dockerfile` is a multi-stage, digest-pinned image used only by the Docker system-test backend. It contains release builds of `pepper-agent` and `pepper`, CA certificates, and bounded diagnostic/network tools (`curl`, `jq`, `ip`, `tc`, and `nft`). The final image defaults to UID/GID 65532 with `tini`; node containers drop all Linux capabilities and enable `no-new-privileges`. `NET_ADMIN` is added only when a reviewed cluster specification requests network fault injection.

The runner builds through the Docker Engine API using Bollard:

```bash
cargo run --manifest-path system-tests/Cargo.toml --locked -- \
  run --scenario REPL-001 --backend docker --seed 42
```

The tested image content ID is recorded in `run.json`, `compose.yaml`, and `reproduce.sh`. To qualify updated base images, replace both tag and digest, build, verify the non-root user/tool inventory, run process and Docker `REPL-001`, and retain the resulting artifact manifests.
