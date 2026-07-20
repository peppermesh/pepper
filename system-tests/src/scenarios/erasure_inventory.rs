// SPDX-License-Identifier: Apache-2.0

use super::bootstrap_three_nodes;
use crate::{
    harness::{
        backend::HttpRequest,
        context::ScenarioContext,
        scenario::{Scenario, ScenarioRequirements},
    },
    oracles::{block_inventory, verify_erasure_inventory, verify_provider_inventory},
};
use anyhow::{Result, ensure};
use async_trait::async_trait;
use pepper_types::CODEC_ERASURE_MANIFEST;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub struct ErasureInventoryScenario;

#[async_trait]
impl Scenario for ErasureInventoryScenario {
    fn id(&self) -> &'static str {
        "EC-001"
    }

    fn name(&self) -> &'static str {
        "erasure-inventory-three-node"
    }

    fn requirements(&self) -> ScenarioRequirements {
        ScenarioRequirements {
            minimum_nodes: 3,
            ..ScenarioRequirements::default()
        }
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("bootstrap creates cluster");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let payload = deterministic_payload(context.run.seed, 128 * 1024);
        let receipt = client.put_erasure_object(&ingress, &payload, 2, 1).await?;
        ensure!(
            receipt.codec == CODEC_ERASURE_MANIFEST,
            "object receipt is not an erasure manifest"
        );
        let manifest = client.erasure_manifest(&ingress, &receipt.cid).await?;
        manifest.validate()?;
        ensure!(manifest.data_shards == 2 && manifest.parity_shards == 1);

        let mut physical_locations = BTreeMap::<String, BTreeSet<String>>::new();
        for node in cluster.nodes.values() {
            let inventory =
                block_inventory(&cluster.backend, &node.id, &node.node_identity).await?;
            for shard in manifest.stripes.iter().flat_map(|stripe| &stripe.shards) {
                if let Some(entry) = inventory.iter().find(|entry| entry.cid == shard.cid) {
                    ensure!(entry.integrity_state == "verified");
                    ensure!(entry.logical_size_bytes == shard.size);
                    ensure!(entry.stored_size_bytes.is_some_and(|size| size > 0));
                    physical_locations
                        .entry(shard.cid.to_string())
                        .or_default()
                        .insert(node.node_identity.clone());
                }
            }
        }
        let expected_shard_cids = manifest
            .stripes
            .iter()
            .flat_map(|stripe| &stripe.shards)
            .map(|shard| shard.cid.to_string())
            .collect::<BTreeSet<_>>();
        ensure!(
            physical_locations.keys().cloned().collect::<BTreeSet<_>>() == expected_shard_cids,
            "one or more shards are absent from physical inventories"
        );
        ensure!(
            physical_locations.values().all(|nodes| nodes.len() == 1),
            "initial erasure placement did not use one distinct node per shard"
        );
        ensure!(client.get_object(&ingress, &receipt.cid).await? == payload);

        let response = cluster
            .backend
            .http(
                &ingress.id,
                HttpRequest {
                    method: "GET".to_string(),
                    path: format!(
                        "/v1/admin/diagnostics/erasure/{}",
                        encode_segment(&receipt.cid.to_string())
                    ),
                    content_type: None,
                    body: Vec::new(),
                    timeout_seconds: 15,
                },
            )
            .await?;
        ensure!(
            response.status == 200,
            "erasure diagnostic returned HTTP {}",
            response.status
        );
        let diagnostic: serde_json::Value = serde_json::from_slice(&response.body)?;
        ensure!(diagnostic["diagnostic_version"] == 1);
        ensure!(diagnostic["consistency"] == "local");
        let shards = diagnostic["data"]["shards"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("erasure diagnostic shards missing"))?;
        let expected = manifest
            .stripes
            .iter()
            .enumerate()
            .flat_map(|(stripe_index, stripe)| {
                stripe
                    .shards
                    .iter()
                    .map(move |shard| (stripe_index, shard.index, shard.cid.clone(), shard.size))
            })
            .collect::<Vec<_>>();
        verify_erasure_inventory(shards, &expected)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        for shard in shards {
            let providers = shard["providers"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default();
            ensure!(
                !providers.is_empty(),
                "erasure shard has no provider diagnostic"
            );
            verify_provider_inventory(providers, now)?;
        }
        context.run.events.record(
            "invariant",
            json!({
                "invariant_id":"SAF-EC-001","invariant_result":"pass",
                "details":{"manifest_cid":receipt.cid,"shards":expected.len(),"physical_locations":physical_locations}
            }),
        )?;
        Ok(())
    }
}

fn deterministic_payload(seed: u64, bytes: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes);
    let mut counter = 0u64;
    while output.len() < bytes {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pepper-system-erasure-payload-v1");
        hasher.update(&seed.to_be_bytes());
        hasher.update(&counter.to_be_bytes());
        output.extend_from_slice(hasher.finalize().as_bytes());
        counter += 1;
    }
    output.truncate(bytes);
    output
}

fn encode_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}
