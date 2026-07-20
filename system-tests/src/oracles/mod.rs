// SPDX-License-Identifier: Apache-2.0

//! Independent system-test models. These implementations intentionally do not
//! call Pepper placement or CID constructors.

pub mod continuous;
pub mod linearizability;

use crate::harness::{
    backend::{ClusterBackend, HttpRequest},
    cluster::{Cluster, NodeId},
};
use anyhow::{Context, Result, bail, ensure};
use pepper_types::{Cid, Codec, DurabilityReceipt};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

#[derive(Debug, Clone)]
pub struct OracleNode {
    pub node_id: String,
    pub failure_domain: String,
}

#[derive(Debug, Clone, Default)]
pub struct NamespaceReferenceModel {
    pub revision: u64,
    pub root_cid: Option<String>,
    pub values: BTreeMap<String, ModelValue>,
    request_results: BTreeMap<String, (u64, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelValue {
    pub cid: String,
    pub generation: u64,
}

impl NamespaceReferenceModel {
    pub fn apply_put(
        &mut self,
        request_id: &str,
        key_hex: &str,
        cid: &str,
        revision: u64,
        root_cid: &str,
    ) -> Result<bool> {
        if let Some((existing_revision, existing_root)) = self.request_results.get(request_id) {
            ensure!(
                *existing_revision == revision && existing_root == root_cid,
                "idempotent replay changed result"
            );
            return Ok(true);
        }
        ensure!(
            revision == self.revision + 1,
            "namespace revision skipped or regressed"
        );
        let generation = self
            .values
            .get(key_hex)
            .map_or(1, |value| value.generation + 1);
        self.values.insert(
            key_hex.to_string(),
            ModelValue {
                cid: cid.to_string(),
                generation,
            },
        );
        self.revision = revision;
        self.root_cid = Some(root_cid.to_string());
        self.request_results
            .insert(request_id.to_string(), (revision, root_cid.to_string()));
        Ok(false)
    }

    pub fn apply_transaction(
        &mut self,
        request_id: &str,
        puts: &[(String, String)],
        revision: u64,
        root_cid: &str,
    ) -> Result<()> {
        ensure!(
            revision == self.revision + 1,
            "transaction revision differs from model"
        );
        for (key, cid) in puts {
            let generation = self.values.get(key).map_or(1, |value| value.generation + 1);
            self.values.insert(
                key.clone(),
                ModelValue {
                    cid: cid.clone(),
                    generation,
                },
            );
        }
        self.revision = revision;
        self.root_cid = Some(root_cid.to_string());
        self.request_results
            .insert(request_id.to_string(), (revision, root_cid.to_string()));
        Ok(())
    }
}

pub fn canonical_cid(codec: u64, payload: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[1]);
    hasher.update(&encode_varint(codec));
    hasher.update(&(payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    format!(
        "cid://pepper-v1:0x{codec:x}:b3:{}",
        hex::encode(hasher.finalize().as_bytes())
    )
}

pub fn storage_relative_path(cid: &Cid) -> PathBuf {
    let digest = hex::encode(cid.digest);
    PathBuf::from("blocks")
        .join(cid.hash_alg.code())
        .join(&digest[0..2])
        .join(&digest[2..4])
        .join(format!(
            "pepper-v{}_{}_{}_{}.blk",
            cid.version,
            cid.codec.canonical_display(),
            cid.hash_alg.code(),
            digest
        ))
}

pub fn deterministic_bytes(domain: &[u8], seed: u64, bytes: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes);
    let mut counter = 0u64;
    while output.len() < bytes {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&seed.to_be_bytes());
        hasher.update(&counter.to_be_bytes());
        output.extend_from_slice(hasher.finalize().as_bytes());
        counter = counter.saturating_add(1);
    }
    output.truncate(bytes);
    output
}

pub fn expected_replicas(cid: &Cid, nodes: &[OracleNode], factor: usize) -> Vec<String> {
    let mut scored = nodes
        .iter()
        .map(|node| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"pepper-placement-v1");
            hasher.update(cid.to_string().as_bytes());
            hasher.update(node.node_id.as_bytes());
            (*hasher.finalize().as_bytes(), node.node_id.clone())
        })
        .collect::<Vec<_>>();
    scored.sort_by(|(left_score, left_node), (right_score, right_node)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_node.cmp(right_node))
    });
    scored
        .into_iter()
        .take(factor)
        .map(|(_, node)| node)
        .collect()
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    diagnostic_version: u8,
    node_id: String,
    consistency: String,
    data: T,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InventoryEntry {
    pub cid: Cid,
    pub codec: Codec,
    pub logical_size_bytes: u64,
    pub stored_size_bytes: Option<u64>,
    pub storage_location_id: String,
    pub integrity_state: String,
    pub retention_class: String,
    pub pin_state: String,
    pub replica_state: String,
}

#[derive(Debug, Deserialize)]
struct InventoryPage {
    entries: Vec<InventoryEntry>,
    next_cursor: Option<String>,
}

pub async fn block_inventory(
    backend: &Arc<dyn ClusterBackend>,
    node: &NodeId,
    expected_node_identity: &str,
) -> Result<Vec<InventoryEntry>> {
    let mut entries = Vec::new();
    let mut cursor = None;
    for _ in 0..1024 {
        let path = cursor.as_ref().map_or_else(
            || "/v1/admin/diagnostics/blocks?limit=256".to_string(),
            |cursor: &String| {
                format!(
                    "/v1/admin/diagnostics/blocks?limit=256&after={}",
                    encode_segment(cursor)
                )
            },
        );
        let response = backend
            .http(
                node,
                HttpRequest {
                    method: "GET".to_string(),
                    path,
                    content_type: None,
                    body: Vec::new(),
                    timeout_seconds: 10,
                },
            )
            .await?;
        ensure!(
            response.status == 200,
            "inventory returned HTTP {}",
            response.status
        );
        let envelope: Envelope<InventoryPage> = serde_json::from_slice(&response.body)?;
        ensure!(
            envelope.diagnostic_version == 1,
            "unsupported diagnostic version"
        );
        ensure!(
            envelope.node_id == expected_node_identity,
            "inventory node identity mismatch"
        );
        ensure!(
            envelope.consistency == "local",
            "inventory consistency is not local"
        );
        entries.extend(envelope.data.entries);
        cursor = envelope.data.next_cursor;
        if cursor.is_none() {
            return Ok(entries);
        }
    }
    bail!("inventory pagination exceeded 1024 pages")
}

pub async fn verify_receipt_inventory(
    cluster: &Cluster,
    receipt: &DurabilityReceipt,
    payload: &[u8],
) -> Result<()> {
    let independent = canonical_cid(receipt.codec.0, payload);
    ensure!(
        receipt.cid.to_string() == independent,
        "receipt CID differs from independent oracle"
    );
    let by_identity = cluster
        .nodes
        .values()
        .map(|node| (node.node_identity.clone(), node.id.clone()))
        .collect::<BTreeMap<_, _>>();
    let receipt_nodes = receipt
        .replica_nodes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        receipt_nodes.len() == receipt.replicas_accepted,
        "receipt replica identities are not distinct"
    );
    for identity in &receipt_nodes {
        let node = by_identity
            .get(identity)
            .with_context(|| format!("receipt names unknown node {identity}"))?;
        let inventory = block_inventory(&cluster.backend, node, identity).await?;
        let entry = inventory
            .iter()
            .find(|entry| entry.cid == receipt.cid)
            .with_context(|| format!("receipt CID absent from local inventory on {node}"))?;
        ensure!(
            entry.integrity_state == "verified",
            "inventory is not verified on {node}"
        );
        ensure!(
            entry.logical_size_bytes == payload.len() as u64,
            "logical size differs on {node}"
        );
        ensure!(
            entry.stored_size_bytes.is_some_and(|size| size > 0),
            "stored representation is absent or empty on {node}"
        );
    }
    Ok(())
}

pub fn verify_provider_inventory(providers: &[serde_json::Value], now: i64) -> Result<()> {
    let mut nodes = BTreeSet::new();
    for provider in providers {
        let node = provider["node_id"]
            .as_str()
            .context("provider node_id missing")?;
        ensure!(nodes.insert(node), "duplicate provider {node}");
        let expected_not_expired = provider["expires_at_unix_seconds"]
            .as_i64()
            .unwrap_or_default()
            > now;
        ensure!(
            provider["not_expired"].as_bool() == Some(expected_not_expired),
            "provider expiry classification differs from controller clock"
        );
        ensure!(
            provider.get("signature_hex").is_none(),
            "provider signature was not redacted"
        );
    }
    Ok(())
}

pub fn verify_pin_inventory(
    response: &serde_json::Value,
    expected_root: &str,
    expected_owner: &str,
    expected_replication_factor: u64,
) -> Result<()> {
    ensure!(
        response["root_cid"].as_str() == Some(expected_root),
        "pin status root differs from expected root"
    );
    ensure!(
        response["reachable_count"].as_u64().unwrap_or_default() > 0,
        "active pin has an empty reachable inventory"
    );
    let pins = response["pins"]
        .as_array()
        .context("pin inventory missing")?;
    ensure!(!pins.is_empty(), "pin inventory is empty");
    ensure!(
        pins.iter().any(|pin| {
            pin["root_cid"].as_str() == Some(expected_root)
                && pin["owner"].as_str() == Some(expected_owner)
                && pin["replication_factor"].as_u64() == Some(expected_replication_factor)
                && pin["expires_at_unix_seconds"].is_null()
                && pin["status"].as_str() == Some("active")
        }),
        "expected permanent active pin is absent"
    );
    Ok(())
}

pub fn verify_gc_reasons(reasons: &[serde_json::Value]) -> Result<()> {
    for reason in reasons {
        let class = reason["class"]
            .as_str()
            .context("GC reason class missing")?;
        ensure!(
            matches!(
                class,
                "pin" | "staging_lease" | "read_lease" | "namespace_publication"
            ),
            "unknown GC protection class {class}"
        );
        ensure!(reason.get("root_cid").is_some(), "GC reason root missing");
    }
    Ok(())
}

pub fn verify_erasure_inventory(
    shards: &[serde_json::Value],
    expected: &[(usize, u16, Cid, u64)],
) -> Result<()> {
    ensure!(
        shards.len() == expected.len(),
        "erasure shard count differs"
    );
    for (stripe_index, index, cid, size) in expected {
        let shard = shards
            .iter()
            .find(|shard| {
                shard["stripe_index"].as_u64() == Some(*stripe_index as u64)
                    && shard["index"].as_u64() == Some(u64::from(*index))
            })
            .with_context(|| format!("erasure stripe {stripe_index} shard {index} missing"))?;
        ensure!(
            shard["cid"] == serde_json::to_value(cid)?,
            "stripe {stripe_index} shard {index} CID differs"
        );
        ensure!(
            shard["expected_size_bytes"].as_u64() == Some(*size),
            "stripe {stripe_index} shard {index} size differs"
        );
    }
    Ok(())
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return output;
        }
    }
}

fn encode_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_types::{CODEC_RAW, Cid};
    use std::str::FromStr;

    #[test]
    fn cid_oracle_matches_known_protocol_without_using_constructor_in_implementation() {
        let production = Cid::new(CODEC_RAW, b"independent");
        assert_eq!(
            canonical_cid(CODEC_RAW.0, b"independent"),
            production.to_string()
        );
        assert_eq!(
            Cid::from_str(&canonical_cid(1, b"independent")).unwrap(),
            production
        );
    }

    #[test]
    fn placement_oracle_is_order_independent() {
        let cid = Cid::new(CODEC_RAW, b"placement");
        let nodes = (0..5)
            .map(|index| OracleNode {
                node_id: format!("node-{index}"),
                failure_domain: format!("rack-{index}"),
            })
            .collect::<Vec<_>>();
        let mut reversed = nodes.clone();
        reversed.reverse();
        assert_eq!(
            expected_replicas(&cid, &nodes, 3),
            expected_replicas(&cid, &reversed, 3)
        );
    }

    #[test]
    fn provider_checker_rejects_expired_and_duplicate_records() {
        let valid = vec![
            serde_json::json!({"node_id":"a","expires_at_unix_seconds":20,"not_expired":true}),
        ];
        assert!(verify_provider_inventory(&valid, 10).is_ok());
        let expired = vec![
            serde_json::json!({"node_id":"a","expires_at_unix_seconds":9,"not_expired":false}),
        ];
        assert!(verify_provider_inventory(&expired, 10).is_ok());
        let misclassified =
            vec![serde_json::json!({"node_id":"a","expires_at_unix_seconds":9,"not_expired":true})];
        assert!(verify_provider_inventory(&misclassified, 10).is_err());
    }
}
