// SPDX-License-Identifier: Apache-2.0

use super::bootstrap_cluster;
use crate::{
    harness::{
        cluster::ClusterSpec,
        context::ScenarioContext,
        scenario::{Scenario, ScenarioRequirements},
        wait::eventually,
    },
    oracles::{
        OracleNode, block_inventory, deterministic_bytes, expected_replicas, storage_relative_path,
        verify_provider_inventory,
    },
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use pepper_types::Cid;
use serde_json::json;
use std::{collections::BTreeSet, time::Duration};

pub struct PlacementScenario;
pub struct ProviderFallbackScenario;
pub struct RepairScenario;
pub struct CapacityScenario;
pub struct CorruptionScenario;

fn requirements() -> ScenarioRequirements {
    ScenarioRequirements {
        minimum_nodes: 3,
        ..ScenarioRequirements::default()
    }
}

#[async_trait]
impl Scenario for PlacementScenario {
    fn id(&self) -> &'static str {
        "REPL-002"
    }
    fn name(&self) -> &'static str {
        "replica-placement"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let spec = ClusterSpec::storage_cluster(context.run.seed, 4, 2, 128 * 1024 * 1024);
        let client = bootstrap_cluster(context, spec).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let payload = deterministic_bytes(b"repl-002", context.run.seed, 512 * 1024);
        let receipt = put_until_durable(&client, &ingress, &payload, 2).await?;
        let oracle_nodes = cluster
            .spec
            .nodes
            .iter()
            .map(|node| OracleNode {
                node_id: cluster.nodes[&node.id].node_identity.clone(),
                failure_domain: node.failure_domain.clone(),
            })
            .collect::<Vec<_>>();
        let expected = expected_replicas(&receipt.cid, &oracle_nodes, 2)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let actual = receipt
            .replica_nodes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        ensure!(
            actual == expected,
            "credited replicas differ from rendezvous oracle"
        );
        for identity in &actual {
            let node = cluster
                .nodes
                .values()
                .find(|node| &node.node_identity == identity)
                .context("credited replica missing from topology")?;
            let inventory = block_inventory(&cluster.backend, &node.id, identity).await?;
            ensure!(
                inventory
                    .iter()
                    .any(|entry| entry.cid == receipt.cid && entry.integrity_state == "verified"),
                "credited replica lacks verified physical bytes"
            );
        }
        let domains = cluster
            .spec
            .nodes
            .iter()
            .filter(|node| actual.contains(&cluster.nodes[&node.id].node_identity))
            .map(|node| node.failure_domain.clone())
            .collect::<BTreeSet<_>>();
        ensure!(
            domains.len() == 2,
            "placement did not use distinct failure domains"
        );
        context.run.events.record("invariant", json!({"invariant_id":"SAF-PLACEMENT-001","invariant_result":"pass","details":{"cid":receipt.cid,"nodes":actual,"failure_domains":domains}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for ProviderFallbackScenario {
    fn id(&self) -> &'static str {
        "REPL-003"
    }
    fn name(&self) -> &'static str {
        "provider-fallback"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let spec = ClusterSpec::storage_cluster(context.run.seed, 4, 1, 128 * 1024 * 1024);
        let client = bootstrap_cluster(context, spec).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let payload = deterministic_bytes(b"repl-003", context.run.seed, 345_678);
        let receipt = client.put_block(&ingress, &payload).await?;
        ensure!(receipt.replicas_accepted == 1);
        let holders = receipt
            .replica_nodes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let physical = physical_nodes(cluster, &receipt.cid).await?;
        let reader = cluster
            .nodes
            .values()
            .find(|node| !physical.contains(&node.node_identity))
            .context("no non-provider reader")?
            .clone();
        let provider_response = client
            .request(
                &reader,
                "GET",
                &format!(
                    "/v1/admin/diagnostics/providers/{}",
                    encode_segment(&receipt.cid.to_string())
                ),
                None,
                Vec::new(),
                10,
            )
            .await?;
        ensure!(provider_response.status == 200);
        let diagnostic: serde_json::Value = serde_json::from_slice(&provider_response.body)?;
        let providers = diagnostic["data"]["providers"]
            .as_array()
            .context("providers missing")?;
        verify_provider_inventory(providers, unix_seconds())?;
        ensure!(
            providers
                .iter()
                .any(|provider| holders.contains(provider["node_id"].as_str().unwrap_or_default()))
        );
        ensure!(client.get_block(&reader, &receipt.cid).await? == payload);
        let trace = client
            .request(
                &reader,
                "GET",
                &format!(
                    "/v1/admin/diagnostics/reads/{}",
                    encode_segment(&receipt.cid.to_string())
                ),
                None,
                Vec::new(),
                10,
            )
            .await?;
        ensure!(trace.status == 200);
        let trace: serde_json::Value = serde_json::from_slice(&trace.body)?;
        let expected_cid = receipt.cid.to_string();
        ensure!(
            trace["data"]["entries"]
                .as_array()
                .is_some_and(|entries| entries.iter().any(|entry| entry["cid"].as_str()
                    == Some(expected_cid.as_str())
                    && entry["verified_bytes"].as_u64() == Some(payload.len() as u64)
                    && matches!(
                        entry["route"].as_str(),
                        Some("direct_provider" | "relay_provider" | "peer_fallback")
                    ))),
            "provider read trace missing"
        );
        let reader_inventory =
            block_inventory(&cluster.backend, &reader.id, &reader.node_identity).await?;
        ensure!(
            reader_inventory
                .iter()
                .any(|entry| entry.cid == receipt.cid),
            "fallback read did not admit a verified cache copy"
        );
        context.run.events.record("invariant", json!({"invariant_id":"CONV-PROVIDER-001","invariant_result":"pass","details":{"cid":receipt.cid,"provider":holders,"reader":reader.node_identity,"exact_bytes":true}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for CapacityScenario {
    fn id(&self) -> &'static str {
        "REPL-005"
    }
    fn name(&self) -> &'static str {
        "storage-capacity-pressure"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let spec = ClusterSpec::storage_cluster(context.run.seed, 3, 1, 3 * 1024 * 1024);
        let client = bootstrap_cluster(context, spec).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let first_payload = deterministic_bytes(b"capacity-first", context.run.seed, 1024 * 1024);
        let first = client.put_block(&ingress, &first_payload).await?;
        let mut rejected = false;
        for index in 0..12u64 {
            let payload =
                deterministic_bytes(b"capacity-fill", context.run.seed ^ index, 1024 * 1024);
            let response = client
                .request(
                    &ingress,
                    "POST",
                    "/v1/blocks",
                    Some("application/octet-stream"),
                    payload,
                    30,
                )
                .await?;
            if !(200..300).contains(&response.status) {
                ensure!(
                    matches!(response.status, 400 | 409 | 413 | 507),
                    "unexpected capacity status {}",
                    response.status
                );
                rejected = true;
                break;
            }
        }
        ensure!(rejected, "capacity pressure did not reject a bounded write");
        ensure!(
            client.get_block(&ingress, &first.cid).await? == first_payload,
            "capacity rejection damaged existing data"
        );
        let status = client
            .request(&ingress, "GET", "/v1/admin/storage", None, Vec::new(), 10)
            .await?;
        ensure!(status.status == 200);
        context.run.events.record("invariant", json!({"invariant_id":"SEC-LIMIT-001","invariant_result":"pass","details":{"capacity_bytes":3 * 1024 * 1024,"write_rejected":true,"existing_bytes_preserved":true}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for RepairScenario {
    fn id(&self) -> &'static str {
        "REPL-004"
    }
    fn name(&self) -> &'static str {
        "replica-loss-repair"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        repair_case(context, false).await
    }
}

#[async_trait]
impl Scenario for CorruptionScenario {
    fn id(&self) -> &'static str {
        "CORRUPT-001"
    }
    fn name(&self) -> &'static str {
        "corruption-quarantine-repair"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        repair_case(context, true).await
    }
}

async fn repair_case(context: &mut ScenarioContext, corrupt: bool) -> Result<()> {
    let spec = ClusterSpec::storage_cluster(context.run.seed, 3, 3, 128 * 1024 * 1024);
    let client = bootstrap_cluster(context, spec).await?;
    let cluster = context.cluster.as_ref().expect("cluster exists");
    let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
    let payload = deterministic_bytes(
        if corrupt { b"corrupt-001" } else { b"repl-004" },
        context.run.seed,
        700_001,
    );
    let receipt = put_until_durable(&client, &ingress, &payload, 3).await?;
    let victim_identity = receipt
        .replica_nodes
        .first()
        .context("repair receipt has no replica")?;
    let victim = cluster
        .nodes
        .values()
        .find(|node| &node.node_identity == victim_identity)
        .context("repair victim missing")?
        .clone();
    let path = storage_relative_path(&receipt.cid);
    if corrupt {
        cluster
            .backend
            .overwrite_storage_file(&victim.id, &path, b"definitely-not-the-cid-payload")
            .await?;
    } else {
        cluster
            .backend
            .remove_storage_file(&victim.id, &path)
            .await?;
    }
    cluster
        .backend
        .restart(
            &victim.id,
            crate::harness::backend::RestartPolicy::PreserveAll,
        )
        .await?;
    eventually(
        "faulted node restart",
        Duration::from_secs(20),
        Duration::from_millis(100),
        || async { Ok(client.health(&victim).await?.then_some(())) },
    )
    .await?;
    if corrupt {
        let scan = client
            .request(
                &victim,
                "POST",
                "/v1/admin/corruption-scan",
                Some("application/json"),
                b"{}".to_vec(),
                30,
            )
            .await?;
        ensure!((200..300).contains(&scan.status), "corruption scan failed");
    }
    let trigger = cluster
        .nodes
        .values()
        .find(|node| node.id != victim.id)
        .context("repair trigger missing")?
        .clone();
    let repair = client
        .request(
            &trigger,
            "POST",
            "/v1/admin/repair",
            Some("application/json"),
            b"{}".to_vec(),
            60,
        )
        .await?;
    ensure!(
        (200..300).contains(&repair.status),
        "repair trigger failed: {}",
        repair.status
    );
    eventually(
        "verified replica repair",
        Duration::from_secs(45),
        Duration::from_millis(500),
        || async {
            let inventory =
                block_inventory(&cluster.backend, &victim.id, &victim.node_identity).await?;
            Ok(inventory
                .iter()
                .any(|entry| entry.cid == receipt.cid && entry.integrity_state == "verified")
                .then_some(()))
        },
    )
    .await?;
    let expected_cid = receipt.cid.to_string();
    let mut repair_recorded = false;
    for node in cluster.nodes.values() {
        let diagnostic = client
            .request(
                node,
                "GET",
                "/v1/admin/diagnostics/repairs?limit=256",
                None,
                Vec::new(),
                10,
            )
            .await?;
        ensure!(diagnostic.status == 200);
        let diagnostic: serde_json::Value = serde_json::from_slice(&diagnostic.body)?;
        repair_recorded |= diagnostic["data"]["entries"]
            .as_array()
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry["cid"].as_str() == Some(expected_cid.as_str())
                        && entry["result"] == "verified"
                        && entry["verified_bytes"].as_u64() == Some(payload.len() as u64)
                })
            });
    }
    ensure!(
        repair_recorded,
        "repair diagnostic omitted verified repair result"
    );
    for node in cluster.nodes.values() {
        if block_inventory(&cluster.backend, &node.id, &node.node_identity)
            .await?
            .iter()
            .any(|entry| entry.cid == receipt.cid)
        {
            ensure!(client.get_block(node, &receipt.cid).await? == payload);
        }
    }
    let invariant = if corrupt {
        "SAF-EC-002"
    } else {
        "LIV-REPAIR-001"
    };
    context.run.events.record("invariant", json!({"invariant_id":invariant,"invariant_result":"pass","details":{"cid":receipt.cid,"faulted_node":victim.node_identity,"fault":if corrupt {"corrupt"} else {"delete"},"verified_replicas":3}}))?;
    Ok(())
}

async fn put_until_durable(
    client: &crate::harness::client::PepperClient,
    ingress: &crate::harness::cluster::NodeRuntime,
    payload: &[u8],
    factor: usize,
) -> Result<pepper_types::DurabilityReceipt> {
    eventually(
        &format!("factor-{factor} durability receipt"),
        Duration::from_secs(30),
        Duration::from_millis(250),
        || async {
            let receipt = client.put_block(ingress, payload).await?;
            Ok((receipt.replicas_accepted == factor).then_some(receipt))
        },
    )
    .await
}

async fn physical_nodes(
    cluster: &crate::harness::cluster::Cluster,
    cid: &Cid,
) -> Result<BTreeSet<String>> {
    let mut nodes = BTreeSet::new();
    for node in cluster.nodes.values() {
        let inventory = block_inventory(&cluster.backend, &node.id, &node.node_identity).await?;
        if inventory
            .iter()
            .any(|entry| entry.cid == *cid && entry.integrity_state == "verified")
        {
            nodes.insert(node.node_identity.clone());
        }
    }
    Ok(nodes)
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn encode_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}
