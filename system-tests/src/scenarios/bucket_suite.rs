// SPDX-License-Identifier: Apache-2.0

use super::{
    bootstrap_three_nodes, json_request, json_success_eventually,
    namespace_suite::wait_namespace_converged,
};
use crate::{
    harness::{
        backend::Fault,
        context::ScenarioContext,
        scenario::{Scenario, ScenarioRequirements},
    },
    oracles::deterministic_bytes,
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub struct BucketModelScenario;
pub struct BucketPaginationScenario;
pub struct BucketDurabilityScenario;

fn requirements() -> ScenarioRequirements {
    ScenarioRequirements {
        minimum_nodes: 3,
        ..ScenarioRequirements::default()
    }
}

async fn create_bucket(
    client: &crate::harness::client::PepperClient,
    node: &crate::harness::cluster::NodeRuntime,
    alias: &str,
) -> Result<Value> {
    json_success_eventually(client, node, "POST", "/v1/buckets", json!({"alias":alias})).await
}

struct BucketPut<'a> {
    bucket: &'a str,
    key: &'a str,
    cid: &'a str,
    size: usize,
    request: &'a str,
    generation: Option<u64>,
}

async fn put(
    client: &crate::harness::client::PepperClient,
    node: &crate::harness::cluster::NodeRuntime,
    request: BucketPut<'_>,
) -> Result<Value> {
    let mut body = json!({"bucket":request.bucket,"key_hex":hex::encode(request.key),"content_cid":request.cid,"logical_size":request.size,"request_id":request.request});
    if let Some(generation) = request.generation {
        body["if_generation"] = json!(generation);
    }
    json_success_eventually(client, node, "POST", "/v1/bucket/put", body).await
}

#[async_trait]
impl Scenario for BucketModelScenario {
    fn id(&self) -> &'static str {
        "BUCKET-001"
    }
    fn name(&self) -> &'static str {
        "bucket-version-model"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_bucket(&client, &nodes[0], "bucket-001").await?;
        let bucket = created["namespace_id"].as_str().unwrap();
        wait_namespace_converged(&client, cluster, bucket, 0, created["root_cid"].as_str()).await?;
        let mut model = BTreeMap::<String, (String, u64)>::new();
        for index in 0..4usize {
            let bytes =
                deterministic_bytes(b"bucket-001", context.run.seed ^ index as u64, 1000 + index);
            let content = client.put_block(&nodes[index % 3], &bytes).await?;
            let key = format!("key-{index}");
            let committed = put(
                &client,
                &nodes[index % 3],
                BucketPut {
                    bucket,
                    key: &key,
                    cid: &content.cid.to_string(),
                    size: bytes.len(),
                    request: &format!("bucket-put-{index}"),
                    generation: None,
                },
            )
            .await?;
            model.insert(key.clone(), (content.cid.to_string(), 0));
            ensure!(committed["namespace_revision"].as_u64() == Some((index + 1) as u64));
            let (status, got) = json_request(
                &client,
                &nodes[(index + 1) % 3],
                "POST",
                "/v1/bucket/get",
                json!({"bucket":bucket,"key_hex":hex::encode(&key)}),
            )
            .await?;
            ensure!(
                status == 200
                    && got["object"]["content_cid"] == content.cid.to_string()
                    && got["key_generation"] == 1
            );
        }
        let first_key = "key-0";
        let (status, current) = json_request(
            &client,
            &nodes[0],
            "POST",
            "/v1/bucket/head",
            json!({"bucket":bucket,"key_hex":hex::encode(first_key)}),
        )
        .await?;
        ensure!(status == 200);
        let generation = current["key_generation"].as_u64().unwrap();
        let bytes = b"bucket-new-version";
        let content = client.put_block(&nodes[1], bytes).await?;
        put(
            &client,
            &nodes[2],
            BucketPut {
                bucket,
                key: first_key,
                cid: &content.cid.to_string(),
                size: bytes.len(),
                request: "bucket-update",
                generation: Some(generation),
            },
        )
        .await?;
        let (conflict, _) = json_request(&client, &nodes[1], "POST", "/v1/bucket/put", json!({"bucket":bucket,"key_hex":hex::encode(first_key),"content_cid":content.cid,"logical_size":bytes.len(),"if_generation":generation,"request_id":"bucket-stale"})).await?;
        ensure!(conflict == 409);
        let deleted = json_success_eventually(
            &client,
            &nodes[0],
            "POST",
            "/v1/bucket/delete",
            json!({"bucket":bucket,"key_hex":hex::encode(first_key),"request_id":"bucket-delete"}),
        )
        .await?;
        ensure!(deleted["tombstone"] == true);
        let (status, versions) = json_request(
            &client,
            &nodes[2],
            "POST",
            "/v1/bucket/versions",
            json!({"bucket":bucket,"key_hex":hex::encode(first_key)}),
        )
        .await?;
        ensure!(
            status == 200
                && versions["versions"]
                    .as_array()
                    .is_some_and(|items| items.len() == 3)
        );
        wait_namespace_converged(&client, cluster, bucket, 6, deleted["root_cid"].as_str()).await?;
        context.run.events.record("invariant", json!({"invariant_id":"SAF-BUCKET-001","invariant_result":"pass","details":{"bucket":bucket,"modeled_keys":model.len(),"revision":6,"version_chain":3,"conflict_rejected":true}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for BucketPaginationScenario {
    fn id(&self) -> &'static str {
        "BUCKET-002"
    }
    fn name(&self) -> &'static str {
        "bucket-root-bound-pagination"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_bucket(&client, &nodes[0], "bucket-002").await?;
        let bucket = created["namespace_id"].as_str().unwrap();
        wait_namespace_converged(&client, cluster, bucket, 0, created["root_cid"].as_str()).await?;
        let content = client.put_block(&nodes[0], b"page-content").await?;
        for key in ["aa", "ab", "ac", "ba", "bb"] {
            put(
                &client,
                &nodes[0],
                BucketPut {
                    bucket,
                    key,
                    cid: &content.cid.to_string(),
                    size: 12,
                    request: &format!("put-{key}"),
                    generation: None,
                },
            )
            .await?;
        }
        let (status, first) = json_request(
            &client,
            &nodes[1],
            "POST",
            "/v1/bucket/list",
            json!({"bucket":bucket,"prefix_hex":hex::encode("a"),"limit":2}),
        )
        .await?;
        ensure!(status == 200);
        let keys = first["objects"]
            .as_array()
            .context("entries missing")?
            .iter()
            .map(|entry| entry["key_hex"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        ensure!(keys == vec![hex::encode("aa"), hex::encode("ab")]);
        let cursor = first["next_cursor"]
            .as_str()
            .context("cursor missing")?
            .to_string();
        put(
            &client,
            &nodes[2],
            BucketPut {
                bucket,
                key: "ad",
                cid: &content.cid.to_string(),
                size: 12,
                request: "put-ad",
                generation: None,
            },
        )
        .await?;
        let (mixed, error) = json_request(
            &client,
            &nodes[0],
            "POST",
            "/v1/bucket/list",
            json!({"bucket":bucket,"prefix_hex":hex::encode("a"),"limit":2,"cursor":cursor}),
        )
        .await?;
        ensure!(mixed == 400 && error["code"] == "invalid_cursor");
        let (status, page) = json_request(
            &client,
            &nodes[2],
            "POST",
            "/v1/bucket/list",
            json!({"bucket":bucket,"prefix_hex":hex::encode("a"),"limit":10}),
        )
        .await?;
        ensure!(
            status == 200
                && page["objects"]
                    .as_array()
                    .is_some_and(|entries| entries.len() == 4)
        );
        context.run.events.record("invariant", json!({"invariant_id":"SAF-CURSOR-001","invariant_result":"pass","details":{"bucket":bucket,"lexical":true,"prefix_bound":true,"cross_root_rejected":true}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for BucketDurabilityScenario {
    fn id(&self) -> &'static str {
        "BUCKET-003"
    }
    fn name(&self) -> &'static str {
        "bucket-node-loss-durability"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_bucket(&client, &nodes[0], "bucket-003").await?;
        let bucket = created["namespace_id"].as_str().unwrap().to_string();
        wait_namespace_converged(&client, cluster, &bucket, 0, created["root_cid"].as_str())
            .await?;
        let bytes = deterministic_bytes(b"bucket-003", context.run.seed, 512 * 1024);
        let content = client.put_block(&nodes[0], &bytes).await?;
        let commit = put(
            &client,
            &nodes[1],
            BucketPut {
                bucket: &bucket,
                key: "durable",
                cid: &content.cid.to_string(),
                size: bytes.len(),
                request: "durable-put",
                generation: None,
            },
        )
        .await?;
        wait_namespace_converged(&client, cluster, &bucket, 1, commit["root_cid"].as_str()).await?;
        let fault = cluster
            .backend
            .clone()
            .apply_fault(Fault::Kill {
                node: nodes[0].id.clone(),
            })
            .await?;
        for node in &nodes[1..] {
            let (status, got) = json_request(
                &client,
                node,
                "POST",
                "/v1/bucket/get",
                json!({"bucket":bucket,"key_hex":hex::encode("durable")}),
            )
            .await?;
            ensure!(status == 200 && got["object"]["content_cid"] == content.cid.to_string());
            ensure!(client.get_block(node, &content.cid).await? == bytes);
        }
        fault.heal().await?;
        context.run.events.record("invariant", json!({"invariant_id":"CONV-APP-001","invariant_result":"pass","details":{"bucket":bucket,"revision":1,"failed_node":nodes[0].node_identity,"surviving_reads":2}}))?;
        Ok(())
    }
}
