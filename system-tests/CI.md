<!-- SPDX-License-Identifier: Apache-2.0 -->

# System-test CI tiers

## Tiers

| Workflow | Trigger | Backend | Parallelism | Purpose |
| --- | --- | --- | --- | --- |
| `system-smoke` | pull request and protected-branch push | process | 2 | Fast deterministic bootstrap, storage, namespace-model, and linearizability gates. |
| `system-nightly` | daily or manual | Docker | 3 | Functional capability matrix with one isolated cluster per job. |
| `system-chaos` | daily or manual | Docker | 1 | Fault, nemesis, partition, and learner-replacement coverage without host contention. |
| `legacy-removal-gate` | manual only | process/real QUIC | 1 | Retained timing-sensitive tests while historical replacement evidence accumulates. |
| `system-soak` | weekly or manual | Docker on a fixed-kernel runner | 1 | Long-run namespace/storage churn with RSS, descriptor, and disk-growth regression analysis. |
| `system-wan` | weekly or manual | non-owning remote | 2 | Tailscale and public direct-WAN cross-node storage and linearizable namespace qualification. |
| `firecracker-host-gated` | dedicated/manual | host KVM | 1 | Real Firecracker execution and cancellation on an eligible disposable runner. |
| `release-qualification` | manual release gate | archived runs | 1 | Commit-bound completeness and archive-integrity report across every required tier. |

The ordinary `ci` workflow runs product tests and framework self-tests only. It does not launch distributed scenarios.

## Seeds and reproduction

Pull-request smoke uses a fixed seed. Daily jobs rotate from the UTC day; soak and WAN jobs rotate from the UTC week. A manual dispatch may supply an exact seed. The selected seed appears in the artifact name, `run.json`, event stream, and generated `reproduce.sh`. Soak reproduction also records its duration and exact host kernel.

## Artifact retention

- Pull-request smoke artifacts: 7 days.
- Successful nightly functional artifacts: 14 days.
- Failed nightly functional artifacts: 30 days.
- Successful chaos artifacts: 30 days.
- Failed chaos artifacts: 60 days.
- Soak, WAN, and KVM qualification artifacts: 60 days.
- Commit-bound release qualification reports: 90 days.

Uploads run under `always()` and reject missing artifact directories. Artifacts must remain secret-redacted. Every Docker job also checks for run-labeled container, network, and volume leakage and attempts label-confined cleanup before failing.

## Ownership and triage

The storage-and-consensus maintainers own system-test failures. Triage starts with `failure.txt`, `run.json`, the minimized checker counterexample when present, and `reproduce.sh`. A failure is reproduced using its archived image digest and seed before being classified as product, framework, runner, or infrastructure failure. Repeated infrastructure-only failures require an issue and may not be hidden by weakening an invariant.

Chaos and nightly jobs use bounded `max-parallel` values so independent clusters do not starve Raft timers on hosted runners. Slow scenarios remain separate matrix jobs; they are never combined into one long process.

## Soak, WAN, KVM, and release qualification

`SOAK-001` requires `--duration-seconds` and `--expected-kernel`. CI uses a six-hour default on the `pepper-soak` runner and rejects kernel drift before provisioning. It repeatedly writes and reads bounded content, advances namespace metadata, restarts followers, and archives raw samples plus least-squares RSS, descriptor, and storage-growth analysis. The agent image digest and kernel lock are release evidence.

`WAN-001` uses the non-owning `remote` backend. It accepts a schema-v1 topology containing stable literal addresses and never starts, stops, logs into, faults, or reads storage from operator-owned nodes. Tailscale mode accepts only `100.64.0.0/10` or `fd7a:115c:a1e0::/48`; direct mode requires public non-Tailscale addresses. Each topology must have at least three distinct failure domains. Runner variables point to topology files and must not contain credentials.

`KVM-001` requires Linux, writable `/dev/kvm`, `firecracker`, `PEPPER_FIRECRACKER_KERNEL_IMAGE`, and `PEPPER_FIRECRACKER_ROOTFS_IMAGE`. It uploads the CID-addressed rootfs, runs a real guest, verifies successful output capture, verifies cancellation, and rejects leaked Firecracker processes. Images and runners are disposable.

A release owner supplies successful smoke, functional, chaos, soak, WAN, and KVM workflow run IDs to `release-qualification`. The workflow verifies every source run is successful and has the exact release commit, downloads its archives, and applies `ci/qualification-policy.json`. Missing scenarios, wrong backends, absent evidence, missing Docker digests, unfinalized manifests, unsafe paths, or commit mismatches produce an incomplete JSON and Markdown report and fail the gate.

## Legacy removal gate

`ci/removal-gates.json` is the machine-checked migration inventory. A test marked `remove-after-historical-gate` remains source-controlled until its replacements have at least 20 successful scheduled runs spanning at least seven distinct UTC days, equivalent safety assertions, reproduction artifacts, and linked review evidence. Tests whose replacement set is incomplete cannot be removed. Lower-level deterministic tests and focused protocol smoke tests remain even after system replacement.
