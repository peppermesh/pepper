# SPDX-License-Identifier: Apache-2.0
#
# Reproduce the GitHub CI gate locally. Each target mirrors a step from
# .github/workflows/{ci,licenses,dco,system-smoke}.yml. Run `make ci` for the
# merge-blocking checks on the host, or `make docker-ci` to run them in the
# pinned CI image (needed if your host `stable` toolchain is older than 1.96).

CARGO ?= cargo
DOCKER ?= docker
SYSTEM_MANIFEST := system-tests/Cargo.toml

# Largest multi-process contracts. The workspace `test` step skips them (they
# run on isolated CI runners); `make multinode` runs them one by one. Keep this
# list in sync with .github/workflows/ci.yml.
MULTINODE_TESTS := \
	s3_adaptive_erasure_transfer_plans_preserve_canonical_layout \
	s3_catalog_survives_gateway_loss_and_concurrent_load \
	s3_placement_owned_repair_fails_over_migrates_and_collects_extras \
	s3_small_objects_pack_into_partitioned_ec_extents \
	s3_streaming_six_plus_three_survives_three_missing_shards
SKIP_FLAGS := $(foreach t,$(MULTINODE_TESTS),--skip $(t))

# system-smoke.yml matrix + fixed seed.
SMOKE_SCENARIOS := BOOT-002 BLOCK-001 NS-003 LIN-001 SQLITE-001 SQLITE-003
SYSTEM_TEST_SEED ?= 20260712

CARGO_AUDIT_VERSION := 0.22.2
CARGO_DENY_VERSION := 0.20.2
DCO_BASE ?= origin/main

CI_IMAGE ?= pepper-ci:local
CI_DOCKERFILE := docker/ci.Dockerfile
RUST_VERSION ?= 1.97.1
DOCKER_MOUNTS := -v "$(CURDIR)":/workspace:z -v pepper-ci-cache:/cache \
	-e CARGO_TARGET_DIR=/cache/target -e CARGO_HOME=/cache/cargo -w /workspace

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Reproduce GitHub CI locally (mirrors .github/workflows):"
	@echo "  make ci           # merge gate: lockfile fmt clippy test system-tests licenses audit"
	@echo "  make ci-full      # ci + multinode + smoke (slow; process/network heavy)"
	@echo "  make fmt clippy test system-tests multinode audit licenses dco smoke"
	@echo "  make fmt-fix      # apply rustfmt to the root and system-tests workspaces"
	@echo "  make tools        # install pinned cargo-audit ($(CARGO_AUDIT_VERSION)) + cargo-deny ($(CARGO_DENY_VERSION))"
	@echo "  make kafka-bench  # Docker-based Kafka parity: Pepper vs Apache Kafka, matched guarantee"
	@echo "  make docker-image # build the pinned CI image ($(CI_IMAGE))"
	@echo "  make docker-ci    # run 'make ci' inside the CI image (hermetic toolchain)"
	@echo "  make docker-shell # interactive shell in the CI image"
	@echo "Overrides: CARGO= RUST_VERSION= DCO_BASE= SYSTEM_TEST_SEED= CI_IMAGE="

# ---- ci.yml : rust job ----------------------------------------------------

.PHONY: ci
ci: lockfile fmt clippy test system-tests licenses audit
	@echo "== ci gate passed =="

.PHONY: ci-full
ci-full: ci multinode smoke
	@echo "== ci-full passed =="

.PHONY: lockfile
lockfile:
	$(CARGO) metadata --locked --format-version 1 > /dev/null

.PHONY: fmt
fmt:
	$(CARGO) fmt --all -- --check

.PHONY: fmt-fix
fmt-fix:
	$(CARGO) fmt --all
	$(CARGO) fmt --manifest-path $(SYSTEM_MANIFEST)

.PHONY: clippy
clippy:
	$(CARGO) clippy --locked --workspace --all-targets -- -D warnings

.PHONY: test
test:
	$(CARGO) test --locked --workspace -- --test-threads=1 $(SKIP_FLAGS)

.PHONY: system-tests
system-tests:
	$(CARGO) metadata --manifest-path $(SYSTEM_MANIFEST) --locked --format-version 1 > /dev/null
	$(CARGO) fmt --manifest-path $(SYSTEM_MANIFEST) -- --check
	$(CARGO) clippy --manifest-path $(SYSTEM_MANIFEST) --locked --all-targets -- -D warnings
	$(CARGO) test --manifest-path $(SYSTEM_MANIFEST) --locked

# ---- ci.yml : multinode-contract matrix -----------------------------------

.PHONY: multinode
multinode:
	@set -e; for t in $(MULTINODE_TESTS); do \
		echo "== multinode $$t =="; \
		$(CARGO) test --locked -p pepper-agent --test multinode "$$t" -- --exact --nocapture --test-threads=1; \
	done

# ---- ci.yml : audit job ---------------------------------------------------

.PHONY: audit
audit: ensure-cargo-audit
	$(CARGO) audit
	$(CARGO) audit --file $(SYSTEM_MANIFEST:Cargo.toml=Cargo.lock)

.PHONY: ensure-cargo-audit
ensure-cargo-audit:
	@command -v cargo-audit >/dev/null || $(CARGO) install cargo-audit --version $(CARGO_AUDIT_VERSION) --locked

# ---- licenses.yml ---------------------------------------------------------

.PHONY: licenses
licenses: ensure-cargo-deny
	$(CARGO) deny check

.PHONY: ensure-cargo-deny
ensure-cargo-deny:
	@command -v cargo-deny >/dev/null || $(CARGO) install cargo-deny --version $(CARGO_DENY_VERSION) --locked

.PHONY: tools
tools:
	$(CARGO) install cargo-audit --version $(CARGO_AUDIT_VERSION) --locked
	$(CARGO) install cargo-deny --version $(CARGO_DENY_VERSION) --locked

# ---- dco.yml --------------------------------------------------------------
# Approximates the workflow: every non-merge commit in DCO_BASE..HEAD must carry
# a Signed-off-by trailer.

.PHONY: dco
dco:
	@set -e; \
	commits=$$(git rev-list --reverse --no-merges $(DCO_BASE)..HEAD); \
	if [ -z "$$commits" ]; then echo "No commits in $(DCO_BASE)..HEAD."; exit 0; fi; \
	fail=0; \
	for c in $$commits; do \
		if ! git show -s --format=%B $$c | grep -Eq '^Signed-off-by: .+ <[^<>[:space:]]+@[^<>[:space:]]+>[[:space:]]*$$'; then \
			echo "Missing Signed-off-by: $$(git show -s --format='%h %s' $$c)"; fail=1; \
		fi; \
	done; \
	if [ $$fail -ne 0 ]; then exit 1; fi; \
	echo "DCO OK for $(DCO_BASE)..HEAD"

# ---- system-smoke.yml -----------------------------------------------------
# Process backend spawns local pepper-agent nodes; some scenarios use nftables
# (needs NET_ADMIN). Run on the host, or in the CI image with --cap-add=NET_ADMIN.

.PHONY: smoke
smoke:
	$(CARGO) build --locked -p pepper-agent -p pepper-cli
	@set -e; for s in $(SMOKE_SCENARIOS); do \
		echo "== smoke $$s (seed $(SYSTEM_TEST_SEED)) =="; \
		$(CARGO) run --manifest-path $(SYSTEM_MANIFEST) --locked -- \
			run --scenario "$$s" --seed "$(SYSTEM_TEST_SEED)" --backend process --no-build; \
	done

# ---- Kafka parity benchmark (Docker-based) --------------------------------
# Pepper vs Apache Kafka 4.3.1 at a matched durability guarantee. Both systems
# and the perf client run in pinned containers; includes the SIGKILL
# durability audit on each side. Reports land in benchmarks/pepper-parity/results.

.PHONY: kafka-bench
kafka-bench:
	bash benchmarks/pepper-parity/run-kafka-parity.sh fsync-quorum

.PHONY: kafka-bench-full
kafka-bench-full:
	SCALE=full bash benchmarks/pepper-parity/run-kafka-parity.sh fsync-quorum

.PHONY: kafka-bench-replicated
kafka-bench-replicated:
	bash benchmarks/pepper-parity/run-kafka-parity.sh replicated-ack

# S3 parity: Pepper vs MinIO (MINIO_DRIVE_SYNC=on) at single-node
# durable-on-ack, same filesystem, SIGKILL audit on both sides.
.PHONY: s3-bench
s3-bench:
	bash benchmarks/pepper-parity/run-s3-parity.sh

.PHONY: s3-bench-full
s3-bench-full:
	SCALE=full bash benchmarks/pepper-parity/run-s3-parity.sh

# Replicated profile: Pepper RF=3 vs distributed MinIO (3 nodes x 2 drives,
# EC:2, drive sync on) — one-node fault tolerance on both sides, audited by
# SIGKILLing the ingest node and reading back through a surviving node.
.PHONY: s3-bench-replicated
s3-bench-replicated:
	PROFILE=replicated bash benchmarks/pepper-parity/run-s3-parity.sh

.PHONY: s3-bench-replicated-full
s3-bench-replicated-full:
	PROFILE=replicated SCALE=full bash benchmarks/pepper-parity/run-s3-parity.sh

# ---- System suites (local) ------------------------------------------------
#
# Run the CI nightly/chaos scenario suites locally with the same runner,
# Docker backend, and day-derived seed scheme. The scenario lists are parsed
# from the workflow files so local runs cannot drift from CI.
#   make system-nightly                       # full nightly suite
#   make system-chaos SCENARIO=RAFT-002       # one scenario
# Overrides: SCENARIO= SEED= IMAGE= REBUILD=1 (rebuild image from tree)

.PHONY: system-nightly
system-nightly:
	bash scripts/run-system-suite.sh nightly $(SCENARIO)

.PHONY: system-chaos
system-chaos:
	bash scripts/run-system-suite.sh chaos $(SCENARIO)

# ---- Release --------------------------------------------------------------
#
# Four resumable steps driven by scripts/release.sh (state lives in GitHub,
# keyed by the RC commit — every step can be re-run safely):
#   make release-candidate VERSION=0.3.0   # push release/v0.3.0, launch suites
#   make release-status    VERSION=0.3.0   # one-line status per suite
#   make release-qualify   VERSION=0.3.0   # wait for suites, run qualification
#   make release-publish   VERSION=0.3.0   # tag + draft prerelease with report
# Overrides: COMMIT= (RC commit), SOAK_DURATION= (seconds), NOTES_DIR=

RELEASE_VERSION_REQUIRED = @test -n "$(VERSION)" || { echo "set VERSION=<x.y.z>"; exit 2; }

.PHONY: release-candidate
release-candidate:
	$(RELEASE_VERSION_REQUIRED)
	bash scripts/release.sh candidate $(VERSION)

.PHONY: release-status
release-status:
	$(RELEASE_VERSION_REQUIRED)
	bash scripts/release.sh status $(VERSION)

.PHONY: release-qualify
release-qualify:
	$(RELEASE_VERSION_REQUIRED)
	bash scripts/release.sh qualify $(VERSION)

.PHONY: release-publish
release-publish:
	$(RELEASE_VERSION_REQUIRED)
	bash scripts/release.sh publish $(VERSION)

# ---- Docker ---------------------------------------------------------------

.PHONY: docker-image
docker-image:
	$(DOCKER) build -f $(CI_DOCKERFILE) --build-arg RUST_VERSION=$(RUST_VERSION) -t $(CI_IMAGE) .

.PHONY: docker-ci
docker-ci: docker-image
	$(DOCKER) run --rm -t $(DOCKER_MOUNTS) $(CI_IMAGE) make ci

.PHONY: docker-shell
docker-shell: docker-image
	$(DOCKER) run --rm -it $(DOCKER_MOUNTS) $(CI_IMAGE) bash
