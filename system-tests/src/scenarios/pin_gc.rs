// SPDX-License-Identifier: Apache-2.0

use super::bootstrap_three_nodes;
use crate::{
    harness::{
        context::ScenarioContext,
        scenario::{Scenario, ScenarioRequirements},
        wait::eventually,
    },
    oracles::{block_inventory, deterministic_bytes, verify_gc_reasons, verify_pin_inventory},
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use pepper_types::{DurabilityReceipt, ObjectManifest};
use serde_json::json;
use std::time::Duration;

pub struct PinProtectionScenario;
pub struct PinDeletionScenario;
pub struct GarbageCollectionScenario;

fn requirements() -> ScenarioRequirements {
    ScenarioRequirements {
        minimum_nodes: 3,
        ..ScenarioRequirements::default()
    }
}

#[async_trait]
impl Scenario for PinProtectionScenario {
    fn id(&self) -> &'static str {
        "PIN-001"
    }
    fn name(&self) -> &'static str {
        "pin-dag-protection"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let payload = deterministic_bytes(b"pin-001", context.run.seed, 4 * 1024 * 1024 + 31);
        let response = client
            .request(
                &ingress,
                "POST",
                "/v1/objects",
                Some("application/octet-stream"),
                payload.clone(),
                60,
            )
            .await?;
        ensure!((200..300).contains(&response.status));
        let receipt: DurabilityReceipt = serde_json::from_slice(&response.body)?;
        let manifest: ObjectManifest =
            serde_json::from_slice(&client.get_block(&ingress, &receipt.cid).await?)?;
        let mut protected = vec![receipt.cid.clone()];
        protected.extend(manifest.chunks.iter().map(|chunk| chunk.cid.clone()));
        for node in cluster.nodes.values() {
            let pin = client
                .request(
                    node,
                    "GET",
                    &format!("/v1/pins/{}", encode_segment(&receipt.cid.to_string())),
                    None,
                    Vec::new(),
                    10,
                )
                .await?;
            ensure!(pin.status == 200);
            verify_pin_inventory(
                &serde_json::from_slice(&pin.body)?,
                &receipt.cid.to_string(),
                &ingress.node_identity,
                3,
            )?;
            for cid in &protected {
                let response = client
                    .request(
                        node,
                        "GET",
                        &format!(
                            "/v1/admin/diagnostics/gc/{}",
                            encode_segment(&cid.to_string())
                        ),
                        None,
                        Vec::new(),
                        20,
                    )
                    .await?;
                ensure!(response.status == 200);
                let diagnostic: serde_json::Value = serde_json::from_slice(&response.body)?;
                let reasons = diagnostic["data"]["reasons"]
                    .as_array()
                    .context("GC reasons missing")?;
                verify_gc_reasons(reasons)?;
                ensure!(
                    reasons.iter().any(|reason| reason["class"] == "pin"),
                    "reachable CID lacked pin protection"
                );
            }
        }
        for node in cluster.nodes.values() {
            let gc = client
                .request(
                    node,
                    "POST",
                    "/v1/admin/gc",
                    Some("application/json"),
                    Vec::new(),
                    30,
                )
                .await?;
            ensure!((200..300).contains(&gc.status));
            ensure!(client.get_object(node, &receipt.cid).await? == payload);
        }
        context.run.events.record("invariant", json!({"invariant_id":"SAF-GC-001","invariant_result":"pass","details":{"root":receipt.cid,"reachable_blocks":protected.len(),"nodes":3}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for PinDeletionScenario {
    fn id(&self) -> &'static str {
        "PIN-002"
    }
    fn name(&self) -> &'static str {
        "pin-owner-deletion"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let owner_a = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let owner_b = cluster.node(&cluster.spec.nodes[1].id)?.clone();
        let payload = deterministic_bytes(b"pin-002", context.run.seed, 222_222);
        let receipt = client.put_block(&owner_a, &payload).await?;
        let second = client
            .request(
                &owner_b,
                "POST",
                "/v1/pins",
                Some("application/json"),
                serde_json::to_vec(&json!({"root_cid":receipt.cid,"replication_factor":3}))?,
                30,
            )
            .await?;
        ensure!((200..300).contains(&second.status));
        let deleted = client
            .request(
                &owner_a,
                "DELETE",
                &format!("/v1/pins/{}", encode_segment(&receipt.cid.to_string())),
                None,
                Vec::new(),
                30,
            )
            .await?;
        ensure!(deleted.status == 200);
        for node in cluster.nodes.values() {
            let status = client
                .request(
                    node,
                    "GET",
                    &format!("/v1/pins/{}", encode_segment(&receipt.cid.to_string())),
                    None,
                    Vec::new(),
                    10,
                )
                .await?;
            let status: serde_json::Value = serde_json::from_slice(&status.body)?;
            ensure!(
                status["pins"].as_array().is_some_and(|pins| pins
                    .iter()
                    .any(|pin| pin["owner"] == owner_b.node_identity && pin["status"] == "active")),
                "other owner's pin was removed"
            );
            let gc = client
                .request(
                    node,
                    "POST",
                    "/v1/admin/gc",
                    Some("application/json"),
                    Vec::new(),
                    30,
                )
                .await?;
            ensure!((200..300).contains(&gc.status));
            ensure!(client.get_block(node, &receipt.cid).await? == payload);
        }
        context.run.events.record("invariant", json!({"invariant_id":"CONV-PIN-001","invariant_result":"pass","details":{"root":receipt.cid,"deleted_owner":owner_a.node_identity,"preserved_owner":owner_b.node_identity}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for GarbageCollectionScenario {
    fn id(&self) -> &'static str {
        "GC-001"
    }
    fn name(&self) -> &'static str {
        "garbage-collection-protection"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let pinned_payload = deterministic_bytes(b"gc-pinned", context.run.seed, 123_456);
        let pinned = client.put_block(&ingress, &pinned_payload).await?;
        let unpinned_payload = deterministic_bytes(b"gc-unpinned", context.run.seed, 234_567);
        let response = client
            .request(
                &ingress,
                "POST",
                "/v1/objects?pin=false",
                Some("application/octet-stream"),
                unpinned_payload,
                30,
            )
            .await?;
        ensure!((200..300).contains(&response.status));
        let unpinned: DurabilityReceipt = serde_json::from_slice(&response.body)?;
        for node in cluster.nodes.values() {
            let gc = client
                .request(
                    node,
                    "POST",
                    "/v1/admin/gc",
                    Some("application/json"),
                    Vec::new(),
                    30,
                )
                .await?;
            ensure!((200..300).contains(&gc.status));
        }
        eventually(
            "unprotected DAG collection",
            Duration::from_secs(20),
            Duration::from_millis(250),
            || async {
                let mut present = 0;
                for node in cluster.nodes.values() {
                    let inventory =
                        block_inventory(&cluster.backend, &node.id, &node.node_identity).await?;
                    if inventory.iter().any(|entry| entry.cid == unpinned.cid) {
                        present += 1;
                    }
                }
                Ok((present == 0).then_some(()))
            },
        )
        .await?;
        for node in cluster.nodes.values() {
            ensure!(client.get_block(node, &pinned.cid).await? == pinned_payload);
        }
        context.run.events.record("invariant", json!({"invariant_id":"LIV-GC-001","invariant_result":"pass","details":{"collected_root":unpinned.cid,"protected_root":pinned.cid}}))?;
        Ok(())
    }
}

fn encode_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}
