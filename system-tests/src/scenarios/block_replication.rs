// SPDX-License-Identifier: Apache-2.0

use super::bootstrap_three_nodes;
use crate::{
    harness::{
        backend::HttpRequest,
        context::ScenarioContext,
        scenario::{Scenario, ScenarioRequirements},
    },
    oracles::{
        OracleNode, deterministic_bytes, expected_replicas, verify_pin_inventory,
        verify_receipt_inventory,
    },
};
use anyhow::{Result, ensure};
use async_trait::async_trait;
use pepper_types::{CODEC_RAW, DurabilityReceipt};
use serde_json::json;
use std::collections::BTreeSet;

pub struct BlockReplicationScenario;

#[async_trait]
impl Scenario for BlockReplicationScenario {
    fn id(&self) -> &'static str {
        "REPL-001"
    }
    fn name(&self) -> &'static str {
        "block-replication-factors"
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
        let oracle_nodes = cluster
            .spec
            .nodes
            .iter()
            .map(|node| OracleNode {
                node_id: cluster.nodes[&node.id].node_identity.clone(),
                failure_domain: node.failure_domain.clone(),
            })
            .collect::<Vec<_>>();

        for factor in 1..=3usize {
            let payload = deterministic_bytes(
                b"repl-001",
                context.run.seed ^ factor as u64,
                256 * 1024 + factor * 113,
            );
            let response = client
                .request(
                    &ingress,
                    "POST",
                    &format!("/v1/blocks?replication_factor={factor}"),
                    Some("application/octet-stream"),
                    payload.clone(),
                    30,
                )
                .await?;
            ensure!(
                (200..300).contains(&response.status),
                "factor-{factor} put failed"
            );
            let receipt: DurabilityReceipt = serde_json::from_slice(&response.body)?;
            ensure!(receipt.codec == CODEC_RAW);
            ensure!(receipt.size == payload.len() as u64);
            ensure!(
                receipt.replicas_accepted == factor,
                "factor-{factor} receipt credited {}",
                receipt.replicas_accepted
            );
            ensure!(receipt.replica_nodes.iter().collect::<BTreeSet<_>>().len() == factor);
            let expected = expected_replicas(&receipt.cid, &oracle_nodes, factor)
                .into_iter()
                .collect::<BTreeSet<_>>();
            let actual = receipt
                .replica_nodes
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            ensure!(
                actual == expected,
                "factor-{factor} receipt differs from placement oracle"
            );
            verify_receipt_inventory(cluster, &receipt, &payload).await?;
            for node in cluster.nodes.values() {
                let fetched = client.get_block(node, &receipt.cid).await?;
                ensure!(
                    fetched == payload,
                    "factor-{factor} exact read failed on {}",
                    node.id
                );
                let pin = cluster
                    .backend
                    .http(
                        &node.id,
                        HttpRequest {
                            method: "GET".into(),
                            path: format!("/v1/pins/{}", encode_segment(&receipt.cid.to_string())),
                            content_type: None,
                            body: Vec::new(),
                            timeout_seconds: 5,
                        },
                    )
                    .await?;
                ensure!(pin.status == 200);
                verify_pin_inventory(
                    &serde_json::from_slice(&pin.body)?,
                    &receipt.cid.to_string(),
                    &ingress.node_identity,
                    factor as u64,
                )?;
            }
            context.run.events.record("invariant", json!({
                "invariant_id":"SAF-RECEIPT-001","invariant_result":"pass",
                "details":{"cid":receipt.cid,"factor":factor,"receipt_nodes":receipt.replica_nodes,"diagnostic_replicas_verified":factor}
            }))?;
        }

        let invalid = client
            .request(
                &ingress,
                "POST",
                "/v1/blocks?replication_factor=33",
                Some("application/octet-stream"),
                b"unchanged".to_vec(),
                10,
            )
            .await?;
        ensure!(
            invalid.status == 400,
            "unbounded replication factor was accepted"
        );
        let rpc_diagnostic = cluster
            .backend
            .http(
                &ingress.id,
                HttpRequest {
                    method: "GET".into(),
                    path: "/v1/admin/diagnostics/network-rpc".into(),
                    content_type: None,
                    body: Vec::new(),
                    timeout_seconds: 5,
                },
            )
            .await?;
        ensure!(rpc_diagnostic.status == 200);
        let rpc: serde_json::Value = serde_json::from_slice(&rpc_diagnostic.body)?;
        ensure!(
            rpc["data"]["metrics"]
                .as_array()
                .is_some_and(|metrics| !metrics.is_empty())
        );
        Ok(())
    }
}

fn encode_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}
