// SPDX-License-Identifier: Apache-2.0

use super::{bootstrap_cluster, bootstrap_three_nodes};
use crate::{
    harness::{
        backend::{Fault, RestartPolicy},
        cluster::ClusterSpec,
        context::ScenarioContext,
        scenario::{Scenario, ScenarioRequirements},
        wait::eventually,
    },
    oracles::{block_inventory, canonical_cid, deterministic_bytes},
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use pepper_types::{
    CODEC_DIR_MANIFEST, CODEC_OBJECT_MANIFEST, CODEC_RAW, DirEntry, DirManifest, DurabilityReceipt,
    ObjectManifest,
};
use serde_json::json;
use std::{collections::BTreeSet, time::Duration};

pub struct RawBlockScenario;
pub struct DeduplicationScenario;
pub struct ObjectScenario;
pub struct DirectoryScenario;
pub struct DagRegistryScenario;

fn requirements() -> ScenarioRequirements {
    ScenarioRequirements {
        minimum_nodes: 3,
        ..ScenarioRequirements::default()
    }
}

#[async_trait]
impl Scenario for RawBlockScenario {
    fn id(&self) -> &'static str {
        "BLOCK-001"
    }
    fn name(&self) -> &'static str {
        "raw-block-lifecycle"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let payload = deterministic_bytes(b"block-001", context.run.seed, 257 * 1024 + 13);
        let receipt = client.put_block(&ingress, &payload).await?;
        ensure!(receipt.cid.to_string() == canonical_cid(CODEC_RAW.0, &payload));
        for node in cluster.nodes.values() {
            let head = client
                .request(
                    node,
                    "HEAD",
                    &format!("/v1/blocks/{}", encode_segment(&receipt.cid.to_string())),
                    None,
                    Vec::new(),
                    10,
                )
                .await?;
            ensure!(
                head.status == 204,
                "HEAD failed on {} with HTTP {}",
                node.id,
                head.status
            );
            ensure!(client.get_block(node, &receipt.cid).await? == payload);
        }

        let oversized = deterministic_bytes(b"block-limit", context.run.seed, 5 * 1024 * 1024 + 1);
        let rejected = client
            .request(
                &ingress,
                "POST",
                "/v1/blocks",
                Some("application/octet-stream"),
                oversized,
                30,
            )
            .await?;
        ensure!(
            matches!(rejected.status, 400 | 413),
            "oversized block was not rejected: {}",
            rejected.status
        );
        ensure!(
            client.get_block(&ingress, &receipt.cid).await? == payload,
            "limit rejection changed existing bytes"
        );

        cluster
            .backend
            .restart(&ingress.id, RestartPolicy::PreserveAll)
            .await?;
        eventually(
            "restarted block node",
            Duration::from_secs(20),
            Duration::from_millis(100),
            || async { Ok(client.health(&ingress).await?.then_some(())) },
        )
        .await?;
        ensure!(client.get_block(&ingress, &receipt.cid).await? == payload);

        let lost = cluster.spec.nodes[0].id.clone();
        let survivor = cluster.node(&cluster.spec.nodes[1].id)?.clone();
        let fault = cluster
            .backend
            .clone()
            .apply_fault(Fault::Kill { node: lost })
            .await?;
        ensure!(client.get_block(&survivor, &receipt.cid).await? == payload);
        fault.heal().await?;

        context.run.events.record("invariant", json!({
            "invariant_id":"SAF-CID-001","invariant_result":"pass",
            "details":{"cid":receipt.cid,"limit_rejected":true,"restart_verified":true,"node_loss_verified":true}
        }))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for DeduplicationScenario {
    fn id(&self) -> &'static str {
        "BLOCK-002"
    }
    fn name(&self) -> &'static str {
        "block-deduplication"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let payload = deterministic_bytes(b"block-002", context.run.seed, 333_333);
        let mut receipts = Vec::new();
        for _ in 0..5 {
            receipts.push(client.put_block(&ingress, &payload).await?);
        }
        ensure!(
            receipts
                .iter()
                .all(|receipt| receipt.cid == receipts[0].cid)
        );
        for node in cluster.nodes.values() {
            let inventory =
                block_inventory(&cluster.backend, &node.id, &node.node_identity).await?;
            ensure!(
                inventory
                    .iter()
                    .filter(|entry| entry.cid == receipts[0].cid)
                    .count()
                    == 1
            );
            ensure!(client.get_block(node, &receipts[0].cid).await? == payload);
        }
        context.run.events.record("invariant", json!({
            "invariant_id":"SAF-IMM-001","invariant_result":"pass",
            "details":{"cid":receipts[0].cid,"repeated_puts":receipts.len(),"physical_entries_per_node":1}
        }))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for ObjectScenario {
    fn id(&self) -> &'static str {
        "OBJECT-001"
    }
    fn name(&self) -> &'static str {
        "object-boundaries-and-recovery"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let mut retained = None;
        for (index, size) in [0usize, 1, 4 * 1024 * 1024, 4 * 1024 * 1024 + 257]
            .into_iter()
            .enumerate()
        {
            let payload = deterministic_bytes(b"object-001", context.run.seed + index as u64, size);
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
            ensure!(
                (200..300).contains(&response.status),
                "object put failed: {}",
                response.status
            );
            let receipt: DurabilityReceipt = serde_json::from_slice(&response.body)?;
            ensure!(receipt.codec == CODEC_OBJECT_MANIFEST);
            let manifest_bytes = client.get_block(&ingress, &receipt.cid).await?;
            ensure!(
                receipt.cid.to_string() == canonical_cid(CODEC_OBJECT_MANIFEST.0, &manifest_bytes)
            );
            let manifest: ObjectManifest = serde_json::from_slice(&manifest_bytes)?;
            manifest.validate()?;
            ensure!(manifest.size == size as u64);
            let mut rebuilt = Vec::new();
            for chunk in &manifest.chunks {
                let bytes = client.get_block(&ingress, &chunk.cid).await?;
                ensure!(chunk.cid.to_string() == canonical_cid(CODEC_RAW.0, &bytes));
                ensure!(chunk.offset == rebuilt.len() as u64 && chunk.size == bytes.len() as u64);
                rebuilt.extend_from_slice(&bytes);
            }
            ensure!(rebuilt == payload);
            ensure!(
                client
                    .get_object(cluster.nodes.values().last().unwrap(), &receipt.cid)
                    .await?
                    == payload
            );
            retained = Some((receipt.cid, payload));
        }
        let rejected = client
            .request(
                &ingress,
                "POST",
                "/v1/objects",
                Some("application/octet-stream"),
                deterministic_bytes(b"object-limit", context.run.seed, 6 * 1024 * 1024 + 1),
                60,
            )
            .await?;
        ensure!(
            matches!(rejected.status, 400 | 413),
            "oversized object was accepted"
        );

        let (cid, payload) = retained.context("object cases empty")?;
        cluster
            .backend
            .restart(&ingress.id, RestartPolicy::PreserveAll)
            .await?;
        eventually(
            "object node restart",
            Duration::from_secs(20),
            Duration::from_millis(100),
            || async { Ok(client.health(&ingress).await?.then_some(())) },
        )
        .await?;
        ensure!(client.get_object(&ingress, &cid).await? == payload);
        let survivor = cluster.node(&cluster.spec.nodes[1].id)?.clone();
        let fault = cluster
            .backend
            .clone()
            .apply_fault(Fault::Kill {
                node: ingress.id.clone(),
            })
            .await?;
        ensure!(client.get_object(&survivor, &cid).await? == payload);
        fault.heal().await?;
        context.run.events.record("invariant", json!({"invariant_id":"SAF-OBJECT-001","invariant_result":"pass","details":{"boundary_cases":4,"multi_chunk":true,"restart":true,"node_loss":true}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for DirectoryScenario {
    fn id(&self) -> &'static str {
        "DIR-001"
    }
    fn name(&self) -> &'static str {
        "generated-directory-manifest"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let mut entries = Vec::new();
        let mut expected = Vec::new();
        for directory in 0..3 {
            entries.push(DirEntry {
                path: format!("dir-{directory:02}"),
                kind: "directory".into(),
                mode: 0o755,
                size: None,
                cid: None,
            });
            for file in 0..2 {
                let bytes = deterministic_bytes(
                    b"dir-001",
                    context.run.seed ^ ((directory * 17 + file) as u64),
                    100 + directory * 31 + file * 7,
                );
                let response = client
                    .request(
                        &ingress,
                        "POST",
                        "/v1/objects",
                        Some("application/octet-stream"),
                        bytes.clone(),
                        30,
                    )
                    .await?;
                ensure!((200..300).contains(&response.status));
                let receipt: DurabilityReceipt = serde_json::from_slice(&response.body)?;
                let path = format!("dir-{directory:02}/file-{file:02}.bin");
                entries.push(DirEntry {
                    path: path.clone(),
                    kind: "file".into(),
                    mode: 0o640,
                    size: Some(bytes.len() as u64),
                    cid: Some(receipt.cid.clone()),
                });
                expected.push((path, receipt.cid, bytes));
            }
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = DirManifest::new(entries);
        manifest.validate()?;
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let response = client
            .request(
                &ingress,
                "POST",
                "/v1/dirs",
                Some("application/json"),
                manifest_bytes.clone(),
                30,
            )
            .await?;
        ensure!((200..300).contains(&response.status));
        let receipt: DurabilityReceipt = serde_json::from_slice(&response.body)?;
        ensure!(receipt.codec == CODEC_DIR_MANIFEST);
        ensure!(receipt.cid.to_string() == canonical_cid(CODEC_DIR_MANIFEST.0, &manifest_bytes));
        for node in cluster.nodes.values() {
            let response = client
                .request(
                    node,
                    "GET",
                    &format!("/v1/dirs/{}", encode_segment(&receipt.cid.to_string())),
                    None,
                    Vec::new(),
                    30,
                )
                .await?;
            ensure!(response.status == 200);
            ensure!(serde_json::from_slice::<DirManifest>(&response.body)? == manifest);
        }
        for (_, cid, bytes) in &expected {
            ensure!(client.get_object(&ingress, cid).await? == *bytes);
        }

        let unsafe_manifest = DirManifest::new(vec![DirEntry {
            path: "../escape".into(),
            kind: "file".into(),
            mode: 0o600,
            size: Some(1),
            cid: Some(expected[0].1.clone()),
        }]);
        let rejected = client
            .request(
                &ingress,
                "POST",
                "/v1/dirs",
                Some("application/json"),
                serde_json::to_vec(&unsafe_manifest)?,
                10,
            )
            .await?;
        ensure!(rejected.status == 400, "unsafe directory path was accepted");
        ensure!(client.get_block(&ingress, &receipt.cid).await? == manifest_bytes);

        cluster
            .backend
            .restart(&ingress.id, RestartPolicy::PreserveAll)
            .await?;
        eventually(
            "directory node restart",
            Duration::from_secs(20),
            Duration::from_millis(100),
            || async { Ok(client.health(&ingress).await?.then_some(())) },
        )
        .await?;
        let survivor = cluster.node(&cluster.spec.nodes[1].id)?.clone();
        let fault = cluster
            .backend
            .clone()
            .apply_fault(Fault::Kill {
                node: ingress.id.clone(),
            })
            .await?;
        let response = client
            .request(
                &survivor,
                "GET",
                &format!("/v1/dirs/{}", encode_segment(&receipt.cid.to_string())),
                None,
                Vec::new(),
                30,
            )
            .await?;
        ensure!(response.status == 200);
        fault.heal().await?;
        context.run.events.record("invariant", json!({"invariant_id":"SAF-DIR-001","invariant_result":"pass","details":{"files":expected.len(),"unsafe_path_rejected":true,"restart":true,"node_loss":true}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for DagRegistryScenario {
    fn id(&self) -> &'static str {
        "DAG-001"
    }
    fn name(&self) -> &'static str {
        "storage-dag-registry"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_cluster(context, ClusterSpec::three_node(context.run.seed)).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let bytes = deterministic_bytes(b"dag-object", context.run.seed, 4 * 1024 * 1024 + 99);
        let object_response = client
            .request(
                &ingress,
                "POST",
                "/v1/objects",
                Some("application/octet-stream"),
                bytes,
                60,
            )
            .await?;
        let object: DurabilityReceipt = serde_json::from_slice(&object_response.body)?;
        let directory = DirManifest::new(vec![DirEntry {
            path: "payload.bin".into(),
            kind: "file".into(),
            mode: 0o644,
            size: Some(4 * 1024 * 1024 + 99),
            cid: Some(object.cid.clone()),
        }]);
        let directory_response = client
            .request(
                &ingress,
                "POST",
                "/v1/dirs",
                Some("application/json"),
                serde_json::to_vec(&directory)?,
                30,
            )
            .await?;
        let root: DurabilityReceipt = serde_json::from_slice(&directory_response.body)?;
        let object_manifest: ObjectManifest =
            serde_json::from_slice(&client.get_block(&ingress, &object.cid).await?)?;
        let expected = std::iter::once(root.cid.to_string())
            .chain(std::iter::once(object.cid.to_string()))
            .chain(
                object_manifest
                    .chunks
                    .iter()
                    .map(|chunk| chunk.cid.to_string()),
            )
            .collect::<BTreeSet<_>>();
        let response = client
            .request(
                &ingress,
                "GET",
                &format!("/v1/admin/dag/{}", encode_segment(&root.cid.to_string())),
                None,
                Vec::new(),
                30,
            )
            .await?;
        ensure!(response.status == 200);
        let observation: serde_json::Value = serde_json::from_slice(&response.body)?;
        let actual = observation["cids"]
            .as_array()
            .context("DAG CID inventory missing")?
            .iter()
            .map(|value| value.as_str().unwrap_or_default().to_string())
            .collect::<BTreeSet<_>>();
        ensure!(
            actual == expected,
            "DAG registry reachability differs from independent model"
        );
        ensure!(observation["truncated"] == false);
        context.run.events.record("invariant", json!({"invariant_id":"SAF-CID-001","invariant_result":"pass","details":{"dag_root":root.cid,"reachable":actual.len(),"codecs":["raw","object","directory"]}}))?;
        Ok(())
    }
}

fn encode_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}
