// SPDX-License-Identifier: Apache-2.0

use crate::harness::{
    backend::{ClusterBackend, HttpRequest},
    cluster::{NodeId, NodeRuntime},
    events::EventRecorder,
};
use anyhow::{Context, Result, bail};
use pepper_types::{Cid, DurabilityReceipt, ErasureManifest};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

pub struct PepperClient {
    backend: Arc<dyn ClusterBackend>,
    events: Arc<EventRecorder>,
    operation_counter: AtomicU64,
}

impl PepperClient {
    pub fn new(events: Arc<EventRecorder>, backend: Arc<dyn ClusterBackend>) -> Self {
        Self {
            backend,
            events,
            operation_counter: AtomicU64::new(0),
        }
    }

    pub async fn health(&self, node: &NodeRuntime) -> Result<bool> {
        Ok(self
            .request(node, "GET", "/healthz", None, Vec::new(), 2)
            .await
            .is_ok_and(|response| (200..300).contains(&response.status)))
    }

    pub async fn ready(&self, node: &NodeRuntime) -> Result<bool> {
        Ok(self
            .request(node, "GET", "/readyz", None, Vec::new(), 2)
            .await
            .is_ok_and(|response| (200..300).contains(&response.status)))
    }

    pub async fn peer_count(&self, node: &NodeRuntime) -> Result<usize> {
        let response = self
            .request(node, "GET", "/v1/node/peers", None, Vec::new(), 2)
            .await?;
        if !(200..300).contains(&response.status) {
            bail!("peer query returned HTTP {}", response.status);
        }
        Ok(serde_json::from_slice::<Vec<serde_json::Value>>(&response.body)?.len())
    }

    pub async fn put_block(&self, node: &NodeRuntime, bytes: &[u8]) -> Result<DurabilityReceipt> {
        let operation_id = self.begin(&node.id, "block_put", json!({"bytes":bytes.len()}))?;
        let result = self
            .request(
                node,
                "POST",
                "/v1/blocks",
                Some("application/octet-stream"),
                bytes.to_vec(),
                30,
            )
            .await;
        match result {
            Ok(response) if (200..300).contains(&response.status) => {
                let receipt = serde_json::from_slice::<DurabilityReceipt>(&response.body)?;
                self.complete(
                    &node.id,
                    &operation_id,
                    "block_put",
                    "ok",
                    json!({
                        "cid":receipt.cid,"replicas_accepted":receipt.replicas_accepted,"status":receipt.status
                    }),
                )?;
                Ok(receipt)
            }
            Ok(response) => {
                let body = String::from_utf8_lossy(&response.body);
                self.complete(
                    &node.id,
                    &operation_id,
                    "block_put",
                    "error",
                    json!({"http_status":response.status,"error":body}),
                )?;
                bail!("block put failed with HTTP {}: {body}", response.status)
            }
            Err(error) => {
                self.complete(
                    &node.id,
                    &operation_id,
                    "block_put",
                    "ambiguous",
                    json!({"error":error.to_string()}),
                )?;
                Err(error)
            }
        }
    }

    pub async fn put_erasure_object(
        &self,
        node: &NodeRuntime,
        bytes: &[u8],
        data_shards: u16,
        parity_shards: u16,
    ) -> Result<DurabilityReceipt> {
        let response = self
            .request(
                node,
                "POST",
                &format!(
                    "/v1/objects?erasure_data_shards={data_shards}&erasure_parity_shards={parity_shards}"
                ),
                Some("application/octet-stream"),
                bytes.to_vec(),
                60,
            )
            .await?;
        if !(200..300).contains(&response.status) {
            bail!(
                "erasure object put returned HTTP {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            );
        }
        Ok(serde_json::from_slice(&response.body)?)
    }

    pub async fn erasure_manifest(&self, node: &NodeRuntime, cid: &Cid) -> Result<ErasureManifest> {
        Ok(serde_json::from_slice(&self.get_block(node, cid).await?)?)
    }

    pub async fn get_object(&self, node: &NodeRuntime, cid: &Cid) -> Result<Vec<u8>> {
        let response = self
            .request(
                node,
                "GET",
                &format!("/v1/objects/{}", encode_path_segment(&cid.to_string())),
                None,
                Vec::new(),
                60,
            )
            .await?;
        if response.status != 200 {
            bail!(
                "object get returned HTTP {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            );
        }
        Ok(response.body)
    }

    pub async fn get_block(&self, node: &NodeRuntime, cid: &Cid) -> Result<Vec<u8>> {
        let operation_id = self.begin(&node.id, "block_get", json!({"cid":cid}))?;
        let encoded_cid = encode_path_segment(&cid.to_string());
        let response = self
            .request(
                node,
                "GET",
                &format!("/v1/blocks/{encoded_cid}"),
                None,
                Vec::new(),
                30,
            )
            .await
            .with_context(|| format!("block get from {} failed", node.id))?;
        if response.status != 200 {
            let body = String::from_utf8_lossy(&response.body);
            self.complete(
                &node.id,
                &operation_id,
                "block_get",
                "error",
                json!({"http_status":response.status,"error":body}),
            )?;
            bail!(
                "block get from {} returned HTTP {}: {body}",
                node.id,
                response.status
            );
        }
        self.complete(
            &node.id,
            &operation_id,
            "block_get",
            "ok",
            json!({"bytes":response.body.len()}),
        )?;
        Ok(response.body)
    }

    pub async fn request(
        &self,
        node: &NodeRuntime,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: Vec<u8>,
        timeout_seconds: u64,
    ) -> Result<crate::harness::backend::HttpResponse> {
        self.backend
            .http(
                &node.id,
                HttpRequest {
                    method: method.to_string(),
                    path: path.to_string(),
                    content_type: content_type.map(ToString::to_string),
                    body,
                    timeout_seconds,
                },
            )
            .await
    }

    fn begin(&self, node: &NodeId, operation: &str, details: serde_json::Value) -> Result<String> {
        let sequence = self.operation_counter.fetch_add(1, Ordering::AcqRel);
        let operation_id = format!("op-{sequence:08}");
        self.events.record("invoke", json!({
            "node_id":node,"operation_id":operation_id,"attempt":1,"operation":operation,"details":details
        }))?;
        Ok(operation_id)
    }

    fn complete(
        &self,
        node: &NodeId,
        operation_id: &str,
        operation: &str,
        result: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        self.events.record("complete", json!({
            "node_id":node,"operation_id":operation_id,"attempt":1,"operation":operation,"result":result,"details":details
        }))?;
        Ok(())
    }
}

fn encode_path_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}
