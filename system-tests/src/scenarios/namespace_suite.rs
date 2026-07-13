// SPDX-License-Identifier: Apache-2.0

use super::{bootstrap_cluster, bootstrap_three_nodes, json_request, json_success_eventually};
use crate::{
    harness::{
        backend::Fault,
        cluster::ClusterSpec,
        context::ScenarioContext,
        scenario::{Scenario, ScenarioRequirements},
        wait::eventually,
    },
    oracles::{NamespaceReferenceModel, deterministic_bytes},
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::{collections::BTreeSet, time::Duration};

pub struct NamespaceCreationScenario;
pub struct NamespaceRoutingScenario;
pub struct NamespaceTransactionScenario;
pub struct NamespaceIdempotencyScenario;
pub struct NamespaceFailoverScenario;
pub struct NamespaceRestartScenario;

fn requirements() -> ScenarioRequirements {
    ScenarioRequirements {
        minimum_nodes: 3,
        ..ScenarioRequirements::default()
    }
}

pub(super) async fn create_namespace(
    client: &crate::harness::client::PepperClient,
    node: &crate::harness::cluster::NodeRuntime,
    alias: &str,
) -> Result<Value> {
    let (status, response) = json_request(
        client,
        node,
        "POST",
        "/v1/namespaces",
        json!({"kind":"kv","alias":alias,"request_id":format!("create-{alias}")}),
    )
    .await?;
    ensure!(
        (200..300).contains(&status),
        "namespace create returned HTTP {status}: {response}"
    );
    Ok(response)
}

pub(super) async fn namespace_groups(
    client: &crate::harness::client::PepperClient,
    node: &crate::harness::cluster::NodeRuntime,
) -> Result<Vec<Value>> {
    let (status, response) = json_request(
        client,
        node,
        "GET",
        "/v1/admin/diagnostics/namespaces?limit=256",
        Value::Null,
    )
    .await?;
    ensure!(status == 200);
    Ok(response["data"]["groups"]
        .as_array()
        .context("namespace groups missing")?
        .clone())
}

pub(super) async fn wait_namespace_converged(
    client: &crate::harness::client::PepperClient,
    cluster: &crate::harness::cluster::Cluster,
    namespace: &str,
    revision: u64,
    root: Option<&str>,
) -> Result<()> {
    eventually(
        &format!("namespace {namespace} revision {revision} on all voters"),
        Duration::from_secs(45),
        Duration::from_millis(250),
        || async {
            let mut converged = 0usize;
            for node in cluster.nodes.values() {
                let groups = namespace_groups(client, node).await?;
                if groups.into_iter().any(|group| {
                    group["namespace_id"].as_str() == Some(namespace)
                        && group["current_revision"].as_u64() == Some(revision)
                        && root.is_none_or(|expected| {
                            group["current_root_cid"].as_str() == Some(expected)
                        })
                        && group["voter_count"].as_u64() == Some(3)
                        && group["local_voting"].as_bool() == Some(true)
                }) {
                    converged += 1;
                }
            }
            Ok((converged == 3).then_some(()))
        },
    )
    .await
}

pub(super) async fn put_value(
    client: &crate::harness::client::PepperClient,
    node: &crate::harness::cluster::NodeRuntime,
    namespace: &str,
    key: &str,
    cid: &str,
    request_id: &str,
) -> Result<Value> {
    json_success_eventually(
        client,
        node,
        "POST",
        "/v1/kv/put",
        json!({
            "namespace":namespace,"key_hex":hex::encode(key),"value_cid":cid,"request_id":request_id
        }),
    )
    .await
}

#[async_trait]
impl Scenario for NamespaceCreationScenario {
    fn id(&self) -> &'static str {
        "NS-001"
    }
    fn name(&self) -> &'static str {
        "namespace-three-replica-creation"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let created = create_namespace(&client, &ingress, "ns-001").await?;
        let namespace = created["namespace_id"]
            .as_str()
            .context("namespace ID missing")?;
        ensure!(created["descriptor_cid"].as_str() == Some(namespace));
        let replicas = created["replica_nodes"]
            .as_array()
            .context("replicas missing")?;
        let distinct = replicas
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        ensure!(replicas.len() == 3 && distinct.len() == 3);
        wait_namespace_converged(&client, cluster, namespace, 0, created["root_cid"].as_str())
            .await?;
        context.run.events.record("invariant", json!({"invariant_id":"SAF-GROUP-001","invariant_result":"pass","details":{"namespace":namespace,"replicas":replicas,"quorum_status":created["quorum_status"]}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for NamespaceRoutingScenario {
    fn id(&self) -> &'static str {
        "NS-002"
    }
    fn name(&self) -> &'static str {
        "namespace-any-ingress-routing"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_namespace(&client, &nodes[2], "ns-002").await?;
        let namespace = created["namespace_id"].as_str().unwrap().to_string();
        wait_namespace_converged(
            &client,
            cluster,
            &namespace,
            0,
            created["root_cid"].as_str(),
        )
        .await?;
        let mut last = created;
        for index in 0..3usize {
            let content = client
                .put_block(&nodes[index], format!("route-{index}").as_bytes())
                .await?;
            last = put_value(
                &client,
                &nodes[index],
                &namespace,
                &format!("route-{index}"),
                &content.cid.to_string(),
                &format!("route-request-{index}"),
            )
            .await?;
            let reader = &nodes[(index + 1) % 3];
            let (status, got) = json_request(&client, reader, "POST", "/v1/kv/get", json!({"namespace":namespace,"key_hex":hex::encode(format!("route-{index}")),"consistency":"linearizable"})).await?;
            ensure!(
                status == 200
                    && got["value"]["cid"] == content.cid.to_string()
                    && got["stale"] == false
            );
        }
        wait_namespace_converged(&client, cluster, &namespace, 3, last["root_cid"].as_str())
            .await?;
        context.run.events.record("invariant", json!({"invariant_id":"SAF-READ-001","invariant_result":"pass","details":{"namespace":namespace,"ingresses":3,"revision":3,"linearizable_reads":3}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for NamespaceTransactionScenario {
    fn id(&self) -> &'static str {
        "NS-003"
    }
    fn name(&self) -> &'static str {
        "namespace-transaction-model"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_namespace(&client, &nodes[0], "ns-003").await?;
        let namespace = created["namespace_id"].as_str().unwrap().to_string();
        wait_namespace_converged(
            &client,
            cluster,
            &namespace,
            0,
            created["root_cid"].as_str(),
        )
        .await?;
        let mut model = NamespaceReferenceModel::default();
        model.root_cid = created["root_cid"].as_str().map(ToString::to_string);
        let mut cids = Vec::new();
        for index in 0..3 {
            let bytes =
                deterministic_bytes(b"ns-003", context.run.seed ^ index, 1024 + index as usize);
            let receipt = client.put_block(&nodes[index as usize], &bytes).await?;
            cids.push(receipt.cid.to_string());
        }
        for index in 0..3 {
            let key = format!("key-{index}");
            let request = format!("ns003-put-{index}");
            let response = put_value(
                &client,
                &nodes[index as usize],
                &namespace,
                &key,
                &cids[index as usize],
                &request,
            )
            .await?;
            model.apply_put(
                &request,
                &hex::encode(&key),
                &cids[index as usize],
                response["namespace_revision"].as_u64().unwrap(),
                response["root_cid"].as_str().unwrap(),
            )?;
        }
        let base_revision = model.revision;
        let base_root = model.root_cid.clone().unwrap();
        let transaction = json!({
            "version":1,"namespace":namespace,"request_id":"ns003-txn","writer_identity":"http-client","signature_hex":"00",
            "base_revision":base_revision,"base_root_cid":base_root,
            "mutations":[
                {"op":"put","key_hex":hex::encode("txn-a"),"value_cid":cids[0],"value_kind":"raw","metadata":{},"precondition":"absent"},
                {"op":"put","key_hex":hex::encode("txn-b"),"value_cid":cids[1],"value_kind":"raw","metadata":{},"precondition":"absent"}
            ]
        });
        let committed = json_success_eventually(
            &client,
            &nodes[2],
            "POST",
            "/v1/kv/transactions",
            transaction,
        )
        .await?;
        model.apply_transaction(
            "ns003-txn",
            &[
                (hex::encode("txn-a"), cids[0].clone()),
                (hex::encode("txn-b"), cids[1].clone()),
            ],
            committed["namespace_revision"].as_u64().unwrap(),
            committed["root_cid"].as_str().unwrap(),
        )?;
        for (key, expected) in &model.values {
            let (status, got) = json_request(
                &client,
                &nodes[0],
                "POST",
                "/v1/kv/get",
                json!({"namespace":namespace,"key_hex":key,"consistency":"linearizable"}),
            )
            .await?;
            ensure!(
                status == 200
                    && got["value"]["cid"].as_str() == Some(expected.cid.as_str())
                    && got["value"]["generation"].as_u64() == Some(expected.generation)
            );
        }
        wait_namespace_converged(
            &client,
            cluster,
            &namespace,
            model.revision,
            model.root_cid.as_deref(),
        )
        .await?;
        let (status, history) = json_request(
            &client,
            &nodes[1],
            "GET",
            &format!("/v1/namespaces/{}/history", encode_segment(&namespace)),
            Value::Null,
        )
        .await?;
        ensure!(
            status == 200
                && history["history"]
                    .as_object()
                    .is_some_and(|entries| entries.len() == model.revision as usize + 1)
        );
        context.run.events.record("invariant", json!({"invariant_id":"CONV-TXN-001","invariant_result":"pass","details":{"namespace":namespace,"revision":model.revision,"root":model.root_cid,"keys":model.values.len(),"voters_verified":3}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for NamespaceIdempotencyScenario {
    fn id(&self) -> &'static str {
        "NS-004"
    }
    fn name(&self) -> &'static str {
        "namespace-idempotent-retry"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_namespace(&client, &nodes[0], "ns-004").await?;
        let namespace = created["namespace_id"].as_str().unwrap();
        wait_namespace_converged(&client, cluster, namespace, 0, created["root_cid"].as_str())
            .await?;
        let value = client.put_block(&nodes[0], b"idempotent-value").await?;
        let first = put_value(
            &client,
            &nodes[0],
            namespace,
            "key",
            &value.cid.to_string(),
            "same-request",
        )
        .await?;
        let replay = put_value(
            &client,
            &nodes[2],
            namespace,
            "key",
            &value.cid.to_string(),
            "same-request",
        )
        .await?;
        ensure!(replay["replayed"] == true);
        ensure!(
            first["namespace_revision"] == replay["namespace_revision"]
                && first["root_cid"] == replay["root_cid"]
        );
        let (reuse_status, reuse_error) = json_request(&client, &nodes[1], "POST", "/v1/kv/put", json!({"namespace":namespace,"key_hex":hex::encode("other"),"value_cid":value.cid,"request_id":"same-request"})).await?;
        ensure!(
            (400..500).contains(&reuse_status) && reuse_error["code"] != "",
            "request ID reuse with different command was accepted: HTTP {reuse_status} {reuse_error}"
        );
        wait_namespace_converged(&client, cluster, namespace, 1, first["root_cid"].as_str())
            .await?;
        context.run.events.record("invariant", json!({"invariant_id":"SAF-TXN-003","invariant_result":"pass","details":{"namespace":namespace,"request_id":"same-request","revision":1,"replayed":true}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for NamespaceFailoverScenario {
    fn id(&self) -> &'static str {
        "RAFT-001"
    }
    fn name(&self) -> &'static str {
        "namespace-leader-failover"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let spec = ClusterSpec::storage_cluster(context.run.seed, 4, 3, 128 * 1024 * 1024);
        let client = bootstrap_cluster(context, spec).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_namespace(&client, &nodes[0], "raft-001").await?;
        let namespace = created["namespace_id"].as_str().unwrap().to_string();
        wait_namespace_converged(
            &client,
            cluster,
            &namespace,
            0,
            created["root_cid"].as_str(),
        )
        .await?;
        let first_value = client.put_block(&nodes[0], b"before-failover").await?;
        let first = put_value(
            &client,
            &nodes[1],
            &namespace,
            "before",
            &first_value.cid.to_string(),
            "before-failover",
        )
        .await?;
        wait_namespace_converged(&client, cluster, &namespace, 1, first["root_cid"].as_str())
            .await?;
        let second_response = client
            .request(
                &nodes[2],
                "POST",
                "/v1/blocks?replication_factor=3",
                Some("application/octet-stream"),
                b"after-failover".to_vec(),
                30,
            )
            .await?;
        ensure!((200..300).contains(&second_response.status));
        let second_value: pepper_types::DurabilityReceipt =
            serde_json::from_slice(&second_response.body)?;
        let leader = find_leader(&client, cluster, &namespace).await?;
        let fault = cluster
            .backend
            .clone()
            .apply_fault(Fault::Kill {
                node: leader.clone(),
            })
            .await?;
        let new_leader_id = find_leader(&client, cluster, &namespace).await?;
        let new_leader = cluster.node(&new_leader_id)?.clone();
        ensure!(new_leader.id != leader, "failed leader remained elected");
        let (second_status, second) = json_request(&client, &new_leader, "POST", "/v1/kv/put", json!({"namespace":namespace,"key_hex":hex::encode("after"),"value_cid":second_value.cid,"request_id":"after-failover"})).await?;
        ensure!(
            (200..300).contains(&second_status),
            "post-failover write failed with HTTP {second_status}: {second}"
        );
        ensure!(second["namespace_revision"].as_u64() == Some(2));
        fault.heal().await?;
        for node in &nodes {
            eventually(
                &format!("{} returns after failover", node.id),
                Duration::from_secs(30),
                Duration::from_millis(200),
                || async { Ok(client.health(node).await?.then_some(())) },
            )
            .await?;
        }
        wait_namespace_converged(&client, cluster, &namespace, 2, second["root_cid"].as_str())
            .await?;
        context.run.events.record("invariant", json!({"invariant_id":"LIV-RAFT-001","invariant_result":"pass","details":{"namespace":namespace,"failed_leader":leader,"acknowledged_revision":2,"voters_converged":3}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for NamespaceRestartScenario {
    fn id(&self) -> &'static str {
        "RAFT-003"
    }
    fn name(&self) -> &'static str {
        "namespace-sequential-restart"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_namespace(&client, &nodes[0], "raft-003").await?;
        let namespace = created["namespace_id"].as_str().unwrap().to_string();
        wait_namespace_converged(
            &client,
            cluster,
            &namespace,
            0,
            created["root_cid"].as_str(),
        )
        .await?;
        let value = client.put_block(&nodes[0], b"restart-value").await?;
        let commit = put_value(
            &client,
            &nodes[0],
            &namespace,
            "persistent",
            &value.cid.to_string(),
            "restart-put",
        )
        .await?;
        let checkpoint = json_success_eventually(
            &client,
            &nodes[0],
            "POST",
            &format!(
                "/v1/admin/namespaces/{}/checkpoint",
                encode_segment(&namespace)
            ),
            json!({}),
        )
        .await?;
        ensure!(checkpoint["checkpoint_requested"] == true);
        let checkpoint_cid = eventually(
            "namespace checkpoint CID",
            Duration::from_secs(30),
            Duration::from_millis(200),
            || async {
                let groups = namespace_groups(&client, &nodes[0]).await?;
                Ok(groups
                    .into_iter()
                    .find(|group| {
                        group["namespace_id"].as_str() == Some(namespace.as_str())
                            && group["checkpoint_verified"] == true
                    })
                    .and_then(|group| group["checkpoint_cid"].as_str().map(ToString::to_string)))
            },
        )
        .await?;
        for node in &nodes {
            cluster
                .backend
                .restart(
                    &node.id,
                    crate::harness::backend::RestartPolicy::PreserveAll,
                )
                .await?;
            eventually(
                &format!("{} restart health", node.id),
                Duration::from_secs(30),
                Duration::from_millis(200),
                || async {
                    Ok((client.health(node).await? && client.ready(node).await?).then_some(()))
                },
            )
            .await?;
        }
        wait_namespace_converged(&client, cluster, &namespace, 1, commit["root_cid"].as_str())
            .await?;
        let (status, got) = json_request(&client, &nodes[2], "POST", "/v1/kv/get", json!({"namespace":namespace,"key_hex":hex::encode("persistent"),"consistency":"linearizable"})).await?;
        ensure!(status == 200 && got["value"]["cid"] == value.cid.to_string());
        context.run.events.record("invariant", json!({"invariant_id":"SAF-RAFT-003","invariant_result":"pass","details":{"namespace":namespace,"revision":1,"checkpoint":checkpoint_cid,"sequential_restarts":3}}))?;
        Ok(())
    }
}

pub(super) async fn find_leader(
    client: &crate::harness::client::PepperClient,
    cluster: &crate::harness::cluster::Cluster,
    namespace: &str,
) -> Result<crate::harness::cluster::NodeId> {
    eventually(
        "namespace leader",
        Duration::from_secs(30),
        Duration::from_millis(200),
        || async {
            for node in cluster.nodes.values() {
                if let Ok(groups) = namespace_groups(client, node).await
                    && groups.into_iter().any(|group| {
                        group["namespace_id"].as_str() == Some(namespace)
                            && group["role"] == "leader"
                    })
                {
                    return Ok(Some(node.id.clone()));
                }
            }
            Ok(None)
        },
    )
    .await
}

fn encode_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}
