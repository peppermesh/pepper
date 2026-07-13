// SPDX-License-Identifier: Apache-2.0

//! Backend-neutral end-to-end system testing for Pepper.

pub mod harness;
pub mod oracles;
pub mod qualification;
pub mod scenarios;

pub use harness::{
    artifacts::{RunArtifacts, RunResult},
    backend::{ClusterBackend, Fault, FaultGuard, RestartPolicy},
    cluster::{Cluster, ClusterSpec, NodeHandle, NodeId, NodeSpec},
    context::{RunContext, ScenarioContext},
    docker::DockerBackend,
    faults::{FaultScheduleEntry, NemesisScheduler, deterministic_fault},
    history::{Invocation, OperationHistory},
    process::ProcessBackend,
    remote::{RemoteBackend, WanMode},
    scenario::{Scenario, ScenarioRequirements},
};

use anyhow::{Result, bail};
use scenarios::{
    BackupRestoreScenario, BackupValidationScenario, BlockReplicationScenario,
    BucketDurabilityScenario, BucketModelScenario, BucketPaginationScenario, CapacityScenario,
    ContinuousPartitionScenario, CorruptionScenario, DagRegistryScenario, DeduplicationScenario,
    DirectoryScenario, ErasureInventoryScenario, ErasureRepairScenario, ErasureToleranceScenario,
    FilesystemHistoryScenario, FilesystemSharingScenario, FilesystemTreeScenario,
    GarbageCollectionScenario, IdentityFencingScenario, KvmFirecrackerScenario,
    LearnerReplacementScenario, LinearizabilityScenario, NamespaceCreationScenario,
    NamespaceFailoverScenario, NamespaceIdempotencyScenario, NamespaceRestartScenario,
    NamespaceRoutingScenario, NamespaceTransactionScenario, NemesisScenario, NetworkFaultScenario,
    ObjectScenario, PinDeletionScenario, PinProtectionScenario, PlacementScenario,
    ProcessFaultScenario, ProviderFallbackScenario, RawBlockScenario, RepairScenario,
    SoakQualificationScenario, StorageFaultScenario, ThreeNodeBootstrapScenario,
    WanQualificationScenario,
};
use std::sync::Arc;

/// Stable scenario registry used by the CLI and CI filters.
pub fn scenario_names() -> &'static [(&'static str, &'static str)] {
    &[
        ("BOOT-002", "bootstrap-three-node"),
        ("BOOT-003", "identity-live-process-fencing"),
        ("BLOCK-001", "raw-block-lifecycle"),
        ("BLOCK-002", "block-deduplication"),
        ("REPL-001", "block-replication-factors"),
        ("REPL-002", "replica-placement"),
        ("REPL-003", "provider-fallback"),
        ("REPL-004", "replica-loss-repair"),
        ("REPL-005", "storage-capacity-pressure"),
        ("OBJECT-001", "object-boundaries-and-recovery"),
        ("DIR-001", "generated-directory-manifest"),
        ("EC-001", "erasure-inventory-three-node"),
        ("EC-002", "erasure-tolerance"),
        ("EC-003", "erasure-shard-repair"),
        ("PIN-001", "pin-dag-protection"),
        ("PIN-002", "pin-owner-deletion"),
        ("GC-001", "garbage-collection-protection"),
        ("DAG-001", "storage-dag-registry"),
        ("CORRUPT-001", "corruption-quarantine-repair"),
        ("NS-001", "namespace-three-replica-creation"),
        ("NS-002", "namespace-any-ingress-routing"),
        ("NS-003", "namespace-transaction-model"),
        ("NS-004", "namespace-idempotent-retry"),
        ("RAFT-001", "namespace-leader-failover"),
        ("RAFT-003", "namespace-sequential-restart"),
        ("BUCKET-001", "bucket-version-model"),
        ("BUCKET-002", "bucket-root-bound-pagination"),
        ("BUCKET-003", "bucket-node-loss-durability"),
        ("FS-001", "filesystem-generated-tree"),
        ("FS-002", "filesystem-structural-sharing"),
        ("FS-003", "filesystem-history-rollback-clone"),
        ("BACKUP-001", "quiesced-signed-backup"),
        ("BACKUP-002", "backup-restore-catchup"),
        ("FAULT-001", "process-fault-primitives"),
        ("FAULT-002", "udp-partition-netem-primitives"),
        ("FAULT-003", "storage-fault-primitives"),
        ("NEMESIS-001", "concurrent-seeded-nemesis"),
        ("LIN-001", "concurrent-kv-linearizability"),
        ("RAFT-002", "namespace-minority-partition-continuous"),
        ("RAFT-004", "learner-replacement-during-writes"),
        ("SOAK-001", "fixed-kernel-growth-soak"),
        ("WAN-001", "tailscale-direct-wan"),
        ("KVM-001", "firecracker-rootfs-cancel"),
    ]
}

pub fn scenario_by_name(name: &str) -> Result<Arc<dyn Scenario>> {
    match name {
        "BOOT-002" | "bootstrap-three-node" => Ok(Arc::new(ThreeNodeBootstrapScenario)),
        "BOOT-003" | "identity-live-process-fencing" => Ok(Arc::new(IdentityFencingScenario)),
        "BLOCK-001" | "raw-block-lifecycle" => Ok(Arc::new(RawBlockScenario)),
        "BLOCK-002" | "block-deduplication" => Ok(Arc::new(DeduplicationScenario)),
        "REPL-001" | "block-replication-factors" | "block-replication-three-node" => {
            Ok(Arc::new(BlockReplicationScenario))
        }
        "REPL-002" | "replica-placement" => Ok(Arc::new(PlacementScenario)),
        "REPL-003" | "provider-fallback" => Ok(Arc::new(ProviderFallbackScenario)),
        "REPL-004" | "replica-loss-repair" => Ok(Arc::new(RepairScenario)),
        "REPL-005" | "storage-capacity-pressure" => Ok(Arc::new(CapacityScenario)),
        "OBJECT-001" | "object-boundaries-and-recovery" => Ok(Arc::new(ObjectScenario)),
        "DIR-001" | "generated-directory-manifest" => Ok(Arc::new(DirectoryScenario)),
        "EC-001" | "erasure-inventory-three-node" => Ok(Arc::new(ErasureInventoryScenario)),
        "EC-002" | "erasure-tolerance" => Ok(Arc::new(ErasureToleranceScenario)),
        "EC-003" | "erasure-shard-repair" => Ok(Arc::new(ErasureRepairScenario)),
        "PIN-001" | "pin-dag-protection" => Ok(Arc::new(PinProtectionScenario)),
        "PIN-002" | "pin-owner-deletion" => Ok(Arc::new(PinDeletionScenario)),
        "GC-001" | "garbage-collection-protection" => Ok(Arc::new(GarbageCollectionScenario)),
        "DAG-001" | "storage-dag-registry" => Ok(Arc::new(DagRegistryScenario)),
        "CORRUPT-001" | "corruption-quarantine-repair" => Ok(Arc::new(CorruptionScenario)),
        "NS-001" | "namespace-three-replica-creation" => Ok(Arc::new(NamespaceCreationScenario)),
        "NS-002" | "namespace-any-ingress-routing" => Ok(Arc::new(NamespaceRoutingScenario)),
        "NS-003" | "namespace-transaction-model" => Ok(Arc::new(NamespaceTransactionScenario)),
        "NS-004" | "namespace-idempotent-retry" => Ok(Arc::new(NamespaceIdempotencyScenario)),
        "RAFT-001" | "namespace-leader-failover" => Ok(Arc::new(NamespaceFailoverScenario)),
        "RAFT-003" | "namespace-sequential-restart" => Ok(Arc::new(NamespaceRestartScenario)),
        "BUCKET-001" | "bucket-version-model" => Ok(Arc::new(BucketModelScenario)),
        "BUCKET-002" | "bucket-root-bound-pagination" => Ok(Arc::new(BucketPaginationScenario)),
        "BUCKET-003" | "bucket-node-loss-durability" => Ok(Arc::new(BucketDurabilityScenario)),
        "FS-001" | "filesystem-generated-tree" => Ok(Arc::new(FilesystemTreeScenario)),
        "FS-002" | "filesystem-structural-sharing" => Ok(Arc::new(FilesystemSharingScenario)),
        "FS-003" | "filesystem-history-rollback-clone" => Ok(Arc::new(FilesystemHistoryScenario)),
        "BACKUP-001" | "quiesced-signed-backup" => Ok(Arc::new(BackupValidationScenario)),
        "BACKUP-002" | "backup-restore-catchup" => Ok(Arc::new(BackupRestoreScenario)),
        "FAULT-001" | "process-fault-primitives" => Ok(Arc::new(ProcessFaultScenario)),
        "FAULT-002" | "udp-partition-netem-primitives" => Ok(Arc::new(NetworkFaultScenario)),
        "FAULT-003" | "storage-fault-primitives" => Ok(Arc::new(StorageFaultScenario)),
        "NEMESIS-001" | "concurrent-seeded-nemesis" => Ok(Arc::new(NemesisScenario)),
        "LIN-001" | "concurrent-kv-linearizability" => Ok(Arc::new(LinearizabilityScenario)),
        "RAFT-002" | "namespace-minority-partition-continuous" => {
            Ok(Arc::new(ContinuousPartitionScenario))
        }
        "RAFT-004" | "learner-replacement-during-writes" => {
            Ok(Arc::new(LearnerReplacementScenario))
        }
        "SOAK-001" | "fixed-kernel-growth-soak" => Ok(Arc::new(SoakQualificationScenario)),
        "WAN-001" | "tailscale-direct-wan" => Ok(Arc::new(WanQualificationScenario)),
        "KVM-001" | "firecracker-rootfs-cancel" => Ok(Arc::new(KvmFirecrackerScenario)),
        _ => bail!("unknown scenario {name:?}"),
    }
}
