// SPDX-License-Identifier: Apache-2.0

mod backup_suite;
mod block_replication;
mod bootstrap;
mod bucket_suite;
mod erasure_inventory;
mod erasure_resilience;
mod fault_injection;
mod filesystem_suite;
mod identity_fencing;
mod immutable_content;
mod namespace_suite;
mod phase7;
mod phase8;
mod phase9;
mod pin_gc;
mod storage_resilience;

pub use backup_suite::{BackupRestoreScenario, BackupValidationScenario};
pub use block_replication::BlockReplicationScenario;
pub use bootstrap::ThreeNodeBootstrapScenario;
pub use bucket_suite::{BucketDurabilityScenario, BucketModelScenario, BucketPaginationScenario};
pub use erasure_inventory::ErasureInventoryScenario;
pub use erasure_resilience::{ErasureRepairScenario, ErasureToleranceScenario};
pub use fault_injection::{
    NemesisScenario, NetworkFaultScenario, ProcessFaultScenario, StorageFaultScenario,
};
pub use filesystem_suite::{
    FilesystemHistoryScenario, FilesystemSharingScenario, FilesystemTreeScenario,
};
pub use identity_fencing::IdentityFencingScenario;
pub use immutable_content::{
    DagRegistryScenario, DeduplicationScenario, DirectoryScenario, ObjectScenario, RawBlockScenario,
};
pub use namespace_suite::{
    NamespaceCreationScenario, NamespaceFailoverScenario, NamespaceIdempotencyScenario,
    NamespaceRestartScenario, NamespaceRoutingScenario, NamespaceTransactionScenario,
};
pub use phase7::{ContinuousPartitionScenario, LinearizabilityScenario};
pub use phase8::LearnerReplacementScenario;
pub use phase9::{KvmFirecrackerScenario, SoakQualificationScenario, WanQualificationScenario};
pub use pin_gc::{GarbageCollectionScenario, PinDeletionScenario, PinProtectionScenario};
pub use storage_resilience::{
    CapacityScenario, CorruptionScenario, PlacementScenario, ProviderFallbackScenario,
    RepairScenario,
};

use crate::harness::{
    backend::ExecRequest, client::PepperClient, cluster::ClusterSpec, context::ScenarioContext,
    wait::eventually,
};
use anyhow::{Result, bail};
use serde_json::json;
use std::time::Duration;

pub(super) async fn json_request(
    client: &PepperClient,
    node: &crate::harness::cluster::NodeRuntime,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> Result<(u16, serde_json::Value)> {
    let response = client
        .request(
            node,
            method,
            path,
            Some("application/json"),
            serde_json::to_vec(&body)?,
            90,
        )
        .await?;
    let value = if response.body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&response.body).unwrap_or_else(
            |_| serde_json::json!({"unparsed":String::from_utf8_lossy(&response.body)}),
        )
    };
    Ok((response.status, value))
}

pub(super) async fn json_success_eventually(
    client: &PepperClient,
    node: &crate::harness::cluster::NodeRuntime,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value> {
    eventually(
        &format!("successful {method} {path}"),
        Duration::from_secs(45),
        Duration::from_millis(250),
        || async {
            let (status, value) = json_request(client, node, method, path, body.clone()).await?;
            if (200..300).contains(&status) {
                Ok(Some(value))
            } else if matches!(status, 409 | 503) {
                Ok(None)
            } else {
                bail!("{method} {path} returned HTTP {status}: {value}")
            }
        },
    )
    .await
}

async fn bootstrap_three_nodes(context: &mut ScenarioContext) -> Result<PepperClient> {
    bootstrap_cluster(context, ClusterSpec::three_node(context.run.seed)).await
}

async fn bootstrap_cluster(
    context: &mut ScenarioContext,
    spec: ClusterSpec,
) -> Result<PepperClient> {
    let cluster = context
        .backend
        .clone()
        .provision(spec, &context.run)
        .await?;
    context.cluster = Some(cluster);
    let cluster = context.cluster.as_ref().expect("cluster assigned");
    let client = PepperClient::new(context.run.events.clone(), context.backend.clone());

    let first = cluster.spec.nodes[0].id.clone();
    cluster.backend.start(&first).await?;
    let first_runtime = cluster.node(&first)?.clone();
    eventually(
        "first Pepper agent health",
        Duration::from_secs(20),
        Duration::from_millis(100),
        || async { Ok(client.health(&first_runtime).await?.then_some(())) },
    )
    .await?;

    for node in cluster.spec.nodes.iter().skip(1) {
        cluster.backend.start(&node.id).await?;
    }
    for node in &cluster.spec.nodes {
        let runtime = cluster.node(&node.id)?.clone();
        eventually(
            &format!("{} health", node.id),
            Duration::from_secs(20),
            Duration::from_millis(100),
            || async {
                Ok((client.health(&runtime).await? && client.ready(&runtime).await?).then_some(()))
            },
        )
        .await?;
    }
    let expected_peers = cluster.spec.nodes.len().saturating_sub(1);
    for node in &cluster.spec.nodes {
        let runtime = cluster.node(&node.id)?.clone();
        eventually(
            &format!("{} peer convergence", node.id),
            Duration::from_secs(30),
            Duration::from_millis(200),
            || async { Ok((client.peer_count(&runtime).await? >= expected_peers).then_some(())) },
        )
        .await?;
    }
    let cli = cluster
        .backend
        .exec(
            &first,
            ExecRequest {
                command: vec!["pepper".to_string(), "--help".to_string()],
                stdin: Vec::new(),
                timeout_seconds: 5,
                max_output_bytes: 4096,
            },
        )
        .await?;
    anyhow::ensure!(
        cli.exit_code == 0 && String::from_utf8_lossy(&cli.stdout).contains("Usage: pepper"),
        "Pepper CLI execution failed: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
    context.run.events.record(
        "observation",
        json!({"node_id":first,"details":{"backend_cli_execution":true,"help_bytes":cli.stdout.len()}}),
    )?;
    context.run.events.record(
        "invariant",
        json!({
            "invariant_id":"LIV-NODE-001","invariant_result":"pass",
            "details":{"healthy_nodes":cluster.spec.nodes.len(),"minimum_peers_per_node":cluster.spec.nodes.len().saturating_sub(1)}
        }),
    )?;
    Ok(client)
}
