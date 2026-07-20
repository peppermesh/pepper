// SPDX-License-Identifier: Apache-2.0

use super::bootstrap_cluster;
use crate::{
    harness::{
        cluster::ClusterSpec,
        context::ScenarioContext,
        scenario::{Scenario, ScenarioRequirements},
        wait::eventually,
    },
    oracles::{block_inventory, deterministic_bytes, storage_relative_path},
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use pepper_types::{Cid, ErasureManifest};
use serde_json::json;
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

pub struct ErasureToleranceScenario;
pub struct ErasureRepairScenario;

fn requirements(nodes: usize) -> ScenarioRequirements {
    ScenarioRequirements {
        minimum_nodes: nodes,
        ..ScenarioRequirements::default()
    }
}

#[async_trait]
impl Scenario for ErasureToleranceScenario {
    fn id(&self) -> &'static str {
        "EC-002"
    }
    fn name(&self) -> &'static str {
        "erasure-tolerance"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements(5)
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let spec = ClusterSpec::storage_cluster(context.run.seed, 5, 3, 128 * 1024 * 1024);
        let client = bootstrap_cluster(context, spec).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();

        let reader = cluster
            .nodes
            .values()
            .find(|node| node.id != ingress.id)
            .unwrap();
        let mut combinations = 0usize;
        for left in 0..5 {
            for right in (left + 1)..5 {
                let payload = deterministic_bytes(
                    b"ec-002-success",
                    context.run.seed ^ combinations as u64,
                    777_777 + combinations,
                );
                let receipt = client.put_erasure_object(&ingress, &payload, 3, 2).await?;
                let manifest = client.erasure_manifest(&ingress, &receipt.cid).await?;
                ensure!(manifest.data_shards == 3 && manifest.parity_shards == 2);
                remove_shards(cluster, &manifest, &[left, right]).await?;
                let reconstructed =
                    client
                        .get_object(reader, &receipt.cid)
                        .await
                        .with_context(|| {
                            format!("reconstruction failed with missing indexes {left},{right}")
                        })?;
                ensure!(
                    reconstructed == payload,
                    "K valid shards did not reconstruct exact bytes with missing indexes {left},{right}"
                );
                combinations += 1;
            }
        }
        ensure!(
            combinations == 10,
            "not every K-of-5 combination was checked"
        );

        let failure_payload = deterministic_bytes(b"ec-002-failure", context.run.seed, 888_889);
        let failure_receipt = client
            .put_erasure_object(&ingress, &failure_payload, 3, 2)
            .await?;
        let failure_manifest = client
            .erasure_manifest(&ingress, &failure_receipt.cid)
            .await?;
        remove_shards(cluster, &failure_manifest, &[0, 1, 4]).await?;
        wait_for_nodes(&client, cluster).await?;
        let failed = client
            .request(
                reader,
                "GET",
                &format!(
                    "/v1/objects/{}",
                    encode_segment(&failure_receipt.cid.to_string())
                ),
                None,
                Vec::new(),
                30,
            )
            .await?;
        ensure!(
            failed.status >= 400,
            "fewer than K shards unexpectedly reconstructed"
        );
        let health = client
            .request(&ingress, "GET", "/healthz", None, Vec::new(), 5)
            .await?;
        ensure!(
            health.status == 200,
            "failed reconstruction harmed node liveness"
        );
        context.run.events.record("invariant", json!({"invariant_id":"SAF-EC-001","invariant_result":"pass","details":{"layout":"3+2","k_of_n_combinations":combinations,"failed_missing_shards":3,"exact_bytes":true}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for ErasureRepairScenario {
    fn id(&self) -> &'static str {
        "EC-003"
    }
    fn name(&self) -> &'static str {
        "erasure-shard-repair"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements(4)
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let spec = ClusterSpec::storage_cluster(context.run.seed, 4, 3, 128 * 1024 * 1024);
        let client = bootstrap_cluster(context, spec).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let payload = deterministic_bytes(b"ec-003", context.run.seed, 654_321);
        let receipt = client.put_erasure_object(&ingress, &payload, 2, 1).await?;
        let manifest = client.erasure_manifest(&ingress, &receipt.cid).await?;
        let target = manifest
            .stripes
            .first()
            .and_then(|stripe| stripe.shards.first())
            .context("erasure manifest has no shards")?
            .cid
            .clone();
        let locations = shard_locations(cluster, &manifest).await?;
        let victim_id = locations
            .get(&target)
            .and_then(|nodes| nodes.first())
            .context("target shard has no physical location")?
            .clone();
        let victim = cluster.node(&victim_id)?.clone();
        cluster
            .backend
            .remove_storage_file(&victim.id, &storage_relative_path(&target))
            .await?;
        cluster
            .backend
            .restart(
                &victim.id,
                crate::harness::backend::RestartPolicy::PreserveAll,
            )
            .await?;
        eventually(
            "erasure repair victim restart",
            Duration::from_secs(20),
            Duration::from_millis(100),
            || async { Ok(client.health(&victim).await?.then_some(())) },
        )
        .await?;
        let repair = client
            .request(
                &ingress,
                "POST",
                "/v1/admin/repair",
                Some("application/json"),
                Vec::new(),
                60,
            )
            .await?;
        ensure!((200..300).contains(&repair.status));
        eventually(
            "erasure shard rebuilt",
            Duration::from_secs(45),
            Duration::from_millis(500),
            || async {
                let locations = shard_locations(cluster, &manifest).await?;
                Ok(locations
                    .get(&target)
                    .is_some_and(|nodes| !nodes.is_empty())
                    .then_some(()))
            },
        )
        .await?;
        ensure!(client.get_object(&ingress, &receipt.cid).await? == payload);
        let diagnostic = client
            .request(
                &ingress,
                "GET",
                "/v1/admin/diagnostics/repairs?limit=256",
                None,
                Vec::new(),
                10,
            )
            .await?;
        ensure!(diagnostic.status == 200);
        let diagnostic: serde_json::Value = serde_json::from_slice(&diagnostic.body)?;
        let target_text = target.to_string();
        ensure!(
            diagnostic["data"]["entries"]
                .as_array()
                .is_some_and(|entries| entries
                    .iter()
                    .any(|entry| entry["cid"].as_str() == Some(target_text.as_str())
                        && entry["repair_kind"] == "erasure_shard"
                        && entry["result"] == "verified")),
            "erasure repair diagnostic missing"
        );
        context.run.events.record("invariant", json!({"invariant_id":"LIV-REPAIR-001","invariant_result":"pass","details":{"manifest":receipt.cid,"rebuilt_shard":target,"exact_reconstruction":true}}))?;
        Ok(())
    }
}

async fn wait_for_nodes(
    client: &crate::harness::client::PepperClient,
    cluster: &crate::harness::cluster::Cluster,
) -> Result<()> {
    for node in cluster.nodes.values() {
        eventually(
            &format!("{} restart after shard fault", node.id),
            Duration::from_secs(20),
            Duration::from_millis(100),
            || async { Ok(client.health(node).await?.then_some(())) },
        )
        .await?;
    }
    Ok(())
}

async fn remove_shards(
    cluster: &crate::harness::cluster::Cluster,
    manifest: &ErasureManifest,
    indexes: &[usize],
) -> Result<()> {
    let locations = shard_locations(cluster, manifest).await?;
    let mut by_node = BTreeMap::<crate::harness::cluster::NodeId, Vec<Cid>>::new();
    for stripe in &manifest.stripes {
        for index in indexes {
            let shard = stripe
                .shards
                .get(*index)
                .context("shard index out of bounds")?;
            for node in locations.get(&shard.cid).into_iter().flatten() {
                by_node
                    .entry(node.clone())
                    .or_default()
                    .push(shard.cid.clone());
            }
        }
    }
    for (node, cids) in by_node {
        for cid in cids {
            cluster
                .backend
                .remove_storage_file(&node, &storage_relative_path(&cid))
                .await?;
        }
    }
    Ok(())
}

async fn shard_locations(
    cluster: &crate::harness::cluster::Cluster,
    manifest: &ErasureManifest,
) -> Result<HashMap<Cid, Vec<crate::harness::cluster::NodeId>>> {
    let mut locations = HashMap::new();
    for node in cluster.nodes.values() {
        let inventory = block_inventory(&cluster.backend, &node.id, &node.node_identity).await?;
        for shard in manifest.stripes.iter().flat_map(|stripe| &stripe.shards) {
            if inventory
                .iter()
                .any(|entry| entry.cid == shard.cid && entry.integrity_state == "verified")
            {
                locations
                    .entry(shard.cid.clone())
                    .or_insert_with(Vec::new)
                    .push(node.id.clone());
            }
        }
    }
    Ok(locations)
}

fn encode_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}
