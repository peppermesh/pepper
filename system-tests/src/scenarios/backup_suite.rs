// SPDX-License-Identifier: Apache-2.0

use super::{
    bootstrap_cluster, bootstrap_three_nodes, json_success_eventually,
    namespace_suite::{find_leader, wait_namespace_converged},
};
use crate::harness::{
    backend::ExecRequest,
    cluster::ClusterSpec,
    context::ScenarioContext,
    scenario::{Scenario, ScenarioRequirements},
    wait::eventually,
};
use anyhow::{Result, ensure};
use async_trait::async_trait;
use serde_json::json;
use std::time::Duration;

pub struct BackupValidationScenario;
pub struct BackupRestoreScenario;

fn requirements() -> ScenarioRequirements {
    ScenarioRequirements {
        minimum_nodes: 3,
        ..ScenarioRequirements::default()
    }
}

fn maintenance_paths(
    cluster: &crate::harness::cluster::Cluster,
    node: &crate::harness::cluster::NodeRuntime,
) -> (String, String) {
    if cluster.backend.metadata().name == "docker" {
        (
            "/etc/pepper/config.toml".into(),
            "/var/lib/pepper/compute/namespace-backup.redb".into(),
        )
    } else {
        (
            node.config_path.display().to_string(),
            node.data_path
                .join("compute/namespace-backup.redb")
                .display()
                .to_string(),
        )
    }
}

async fn backup(
    cluster: &crate::harness::cluster::Cluster,
    node: &crate::harness::cluster::NodeRuntime,
) -> Result<(String, String)> {
    let (config, output) = maintenance_paths(cluster, node);
    let result = cluster
        .backend
        .offline_exec(
            &node.id,
            ExecRequest {
                command: vec![
                    "pepper-agent".into(),
                    "--config".into(),
                    config.clone(),
                    "backup".into(),
                    "--output".into(),
                    output.clone(),
                ],
                stdin: Vec::new(),
                timeout_seconds: 30,
                max_output_bytes: 64 * 1024,
            },
        )
        .await?;
    ensure!(
        result.exit_code == 0,
        "backup failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let check = cluster.backend.offline_exec(&node.id, ExecRequest {
        command: vec!["sh".into(), "-c".into(), format!("test -s '{output}' && jq -e '.payload.format_version == 1 and .payload.schema_version >= 1 and (.payload.metadata_blake3|length == 64) and (.signature_hex|length == 128)' '{output}.manifest.json'")],
        stdin: Vec::new(), timeout_seconds: 10, max_output_bytes: 4096,
    }).await?;
    ensure!(
        check.exit_code == 0,
        "backup manifest validation failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    Ok((config, output))
}

#[async_trait]
impl Scenario for BackupValidationScenario {
    fn id(&self) -> &'static str {
        "BACKUP-001"
    }
    fn name(&self) -> &'static str {
        "quiesced-signed-backup"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = json_success_eventually(
            &client,
            &nodes[0],
            "POST",
            "/v1/namespaces",
            json!({"kind":"kv","alias":"backup-001"}),
        )
        .await?;
        let namespace = created["namespace_id"].as_str().unwrap();
        wait_namespace_converged(&client, cluster, namespace, 0, created["root_cid"].as_str())
            .await?;
        cluster.backend.stop(&nodes[0].id).await?;
        let (_, output) = backup(cluster, &nodes[0]).await?;
        cluster.backend.start(&nodes[0].id).await?;
        eventually(
            "backed-up node restart",
            Duration::from_secs(30),
            Duration::from_millis(200),
            || async { Ok(client.health(&nodes[0]).await?.then_some(())) },
        )
        .await?;
        context.run.events.record("invariant", json!({"invariant_id":"SAF-BACKUP-001","invariant_result":"pass","details":{"namespace":namespace,"quiesced":true,"backup_path_class":"compute-volume","manifest_verified":true,"output":output.rsplit('/').next()}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for BackupRestoreScenario {
    fn id(&self) -> &'static str {
        "BACKUP-002"
    }
    fn name(&self) -> &'static str {
        "backup-restore-catchup"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let spec = ClusterSpec::storage_cluster(context.run.seed, 4, 3, 128 * 1024 * 1024);
        let client = bootstrap_cluster(context, spec).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = json_success_eventually(
            &client,
            &nodes[0],
            "POST",
            "/v1/namespaces",
            json!({"kind":"kv","alias":"backup-002"}),
        )
        .await?;
        let namespace = created["namespace_id"].as_str().unwrap().to_string();
        let backup_identity = created["replica_nodes"][0].as_str().unwrap();
        let backup_node = nodes
            .iter()
            .find(|node| node.node_identity == backup_identity)
            .expect("backup replica is in topology")
            .clone();
        wait_namespace_converged(
            &client,
            cluster,
            &namespace,
            0,
            created["root_cid"].as_str(),
        )
        .await?;
        let value1 = client.put_block(&nodes[0], b"before-backup").await?;
        let first = json_success_eventually(&client, &nodes[0], "POST", "/v1/kv/put", json!({"namespace":namespace,"key_hex":hex::encode("before"),"value_cid":value1.cid,"request_id":"before-backup"})).await?;
        wait_namespace_converged(&client, cluster, &namespace, 1, first["root_cid"].as_str())
            .await?;
        let value2_response = client
            .request(
                &nodes[1],
                "POST",
                "/v1/blocks?replication_factor=3",
                Some("application/octet-stream"),
                b"after-backup".to_vec(),
                30,
            )
            .await?;
        ensure!((200..300).contains(&value2_response.status));
        let value2: pepper_types::DurabilityReceipt =
            serde_json::from_slice(&value2_response.body)?;
        cluster.backend.stop(&backup_node.id).await?;
        let (config, output) = backup(cluster, &backup_node).await?;
        let leader = find_leader(&client, cluster, &namespace).await?;
        let leader = cluster.node(&leader)?.clone();
        let (second_status, second) = super::json_request(&client, &leader, "POST", "/v1/kv/put", json!({"namespace":namespace,"key_hex":hex::encode("after"),"value_cid":value2.cid,"request_id":"after-backup"})).await?;
        ensure!(
            (200..300).contains(&second_status),
            "write while backup replica was offline failed with HTTP {second_status}: {second}"
        );
        ensure!(second["namespace_revision"].as_u64() == Some(2));
        let restored = cluster
            .backend
            .offline_exec(
                &backup_node.id,
                ExecRequest {
                    command: vec![
                        "pepper-agent".into(),
                        "--config".into(),
                        config,
                        "restore".into(),
                        "--input".into(),
                        output,
                        "--force".into(),
                    ],
                    stdin: Vec::new(),
                    timeout_seconds: 30,
                    max_output_bytes: 64 * 1024,
                },
            )
            .await?;
        ensure!(
            restored.exit_code == 0,
            "restore failed: {}",
            String::from_utf8_lossy(&restored.stderr)
        );
        cluster.backend.start(&backup_node.id).await?;
        eventually(
            "restored node health",
            Duration::from_secs(30),
            Duration::from_millis(200),
            || async { Ok(client.health(&backup_node).await?.then_some(())) },
        )
        .await?;
        wait_namespace_converged(&client, cluster, &namespace, 2, second["root_cid"].as_str())
            .await?;
        context.run.events.record("invariant", json!({"invariant_id":"LIV-BACKUP-001","invariant_result":"pass","details":{"namespace":namespace,"backup_revision":1,"restored_revision":2,"caught_up_before_completion":true}}))?;
        Ok(())
    }
}
