// SPDX-License-Identifier: Apache-2.0

use super::{
    bootstrap_cluster, json_request,
    namespace_suite::{
        create_namespace, find_leader, namespace_groups, put_value, wait_namespace_converged,
    },
};
use crate::harness::{
    backend::Fault,
    client::PepperClient,
    cluster::ClusterSpec,
    context::ScenarioContext,
    scenario::{Scenario, ScenarioRequirements},
    wait::eventually,
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

pub struct LearnerReplacementScenario;

#[async_trait]
impl Scenario for LearnerReplacementScenario {
    fn id(&self) -> &'static str {
        "RAFT-004"
    }
    fn name(&self) -> &'static str {
        "learner-replacement-during-writes"
    }
    fn requirements(&self) -> ScenarioRequirements {
        ScenarioRequirements {
            minimum_nodes: 4,
            ..ScenarioRequirements::default()
        }
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let spec = ClusterSpec::storage_cluster(context.run.seed, 4, 3, 128 * 1024 * 1024);
        let client = Arc::new(bootstrap_cluster(context, spec).await?);
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_namespace(&client, &nodes[0], "raft-004").await?;
        let namespace = created["namespace_id"]
            .as_str()
            .context("namespace ID missing")?
            .to_string();
        wait_namespace_converged(
            &client,
            cluster,
            &namespace,
            0,
            created["root_cid"].as_str(),
        )
        .await?;

        let mut values = Vec::new();
        for index in 0..5 {
            values.push(
                client
                    .put_block(
                        &nodes[index % nodes.len()],
                        format!("replacement-value-{index}").as_bytes(),
                    )
                    .await?
                    .cid
                    .to_string(),
            );
        }
        let baseline = put_value(
            &client,
            &nodes[0],
            &namespace,
            "baseline",
            &values[0],
            "replacement-baseline",
        )
        .await?;
        wait_namespace_converged(
            &client,
            cluster,
            &namespace,
            1,
            baseline["root_cid"].as_str(),
        )
        .await?;

        let leader = find_leader(&client, cluster, &namespace).await?;
        let voter_identities = created["replica_nodes"]
            .as_array()
            .context("replica nodes missing")?
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        ensure!(voter_identities.len() == 3);
        let failed = nodes
            .iter()
            .find(|node| voter_identities.contains(&node.node_identity) && node.id != leader)
            .context("failed follower missing")?
            .clone();
        let replacement = nodes
            .iter()
            .find(|node| !voter_identities.contains(&node.node_identity))
            .context("replacement node missing")?
            .clone();
        let fault = cluster
            .backend
            .clone()
            .apply_fault(Fault::Stop {
                node: failed.id.clone(),
            })
            .await?;

        let replace_client = client.clone();
        let replace_node = cluster.node(&leader)?.clone();
        let replace_namespace = namespace.clone();
        let failed_identity = failed.node_identity.clone();
        let replacement_identity = replacement.node_identity.clone();
        let replace = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(750)).await;
            replace_client.request(
                &replace_node,
                "POST",
                &format!("/v1/admin/namespaces/{}/replace-replica", encode_segment(&replace_namespace)),
                Some("application/json"),
                serde_json::to_vec(&json!({"failed_node":failed_identity,"replacement_node":replacement_identity}))?,
                90,
            ).await
        });

        let writer_client = client.clone();
        let writer_node = cluster.node(&leader)?.clone();
        let writer_namespace = namespace.clone();
        let writer = tokio::spawn(async move {
            let mut committed = Vec::new();
            for index in 0..4 {
                let request_id = format!("replacement-write-{index}");
                let path = format!(
                    "/v1/namespaces/{}/snapshots",
                    encode_segment(&writer_namespace)
                );
                let response = eventually("write during learner replacement", Duration::from_secs(60), Duration::from_millis(200), || async {
                    let response = writer_client.request(&writer_node, "POST", &path, Some("application/json"), serde_json::to_vec(&json!({"action":"create","name":format!("during-{index}"),"revision":1,"request_id":request_id}))?, 20).await;
                    match response {
                        Ok(response) if (200..300).contains(&response.status) => Ok(Some(serde_json::from_slice::<Value>(&response.body)?)),
                        Ok(_) | Err(_) => Ok(None),
                    }
                }).await?;
                committed.push(response);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Result::<Vec<Value>>::Ok(committed)
        });

        let mut saw_learner = false;
        let mut saw_caught_up_learner = false;
        let monitor_deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        while !replace.is_finished() && tokio::time::Instant::now() < monitor_deadline {
            if let Ok(groups) = namespace_groups(&client, &replacement).await
                && let Some(group) = groups
                    .into_iter()
                    .find(|group| group["namespace_id"].as_str() == Some(namespace.as_str()))
            {
                let local_id = group["local_raft_id"].as_u64();
                let local_voting = group["local_voting"].as_bool().unwrap_or(false);
                if !local_voting {
                    saw_learner = true;
                    let leader_commit = group["commit_index"].as_u64().unwrap_or_default();
                    let applied = group["applied_index"].as_u64().unwrap_or_default();
                    if applied >= leader_commit && local_id.is_some() {
                        saw_caught_up_learner = true;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let replace_response = replace.await??;
        ensure!(
            (200..300).contains(&replace_response.status),
            "replacement failed: HTTP {} {}",
            replace_response.status,
            String::from_utf8_lossy(&replace_response.body)
        );
        let replaced: Value = serde_json::from_slice(&replace_response.body)?;
        ensure!(replaced["replacement"].as_str() == Some(replacement.node_identity.as_str()));
        let committed = writer.await??;
        ensure!(committed.len() == 4);
        let final_revision = committed
            .iter()
            .filter_map(|value| value["namespace_revision"].as_u64())
            .max()
            .context("writer revision missing")?;
        let final_root = committed
            .iter()
            .find(|value| value["namespace_revision"].as_u64() == Some(final_revision))
            .and_then(|value| value["root_cid"].as_str())
            .context("writer root missing")?;
        wait_replacement_converged(&client, cluster, &namespace, final_revision, final_root)
            .await?;

        let replacement_group = namespace_groups(&client, &replacement)
            .await?
            .into_iter()
            .find(|group| group["namespace_id"].as_str() == Some(namespace.as_str()))
            .context("replacement group missing")?;
        ensure!(replacement_group["local_voting"] == true);
        ensure!(replacement_group["voter_count"].as_u64() == Some(3));
        ensure!(
            replacement_group["applied_index"]
                .as_u64()
                .unwrap_or_default()
                <= replacement_group["commit_index"]
                    .as_u64()
                    .unwrap_or_default()
        );
        ensure!(
            saw_learner,
            "replacement was never observed as a learner before promotion"
        );
        ensure!(
            saw_caught_up_learner,
            "learner was not observed caught up before promotion"
        );

        // Heal the process fault, then retire the removed replica so it cannot
        // run as a fourth voter after committed membership has changed.
        fault.heal().await?;
        cluster.backend.stop(&failed.id).await?;
        let removed_outcome = "retired-after-fault-heal";
        let (status, snapshots) = json_request(
            &client,
            &replacement,
            "GET",
            &format!("/v1/namespaces/{}/snapshots", encode_segment(&namespace)),
            Value::Null,
        )
        .await?;
        ensure!(status == 200);
        for index in 0..4 {
            ensure!(
                snapshots["snapshots"]
                    .get(format!("during-{index}"))
                    .is_some()
            );
        }
        let (status, got) = json_request(&client, &replacement, "POST", "/v1/kv/get", json!({"namespace":namespace,"key_hex":hex::encode("baseline"),"consistency":"linearizable"})).await?;
        ensure!(status == 200 && got["value"]["cid"].as_str() == Some(values[0].as_str()));
        context.run.events.record("invariant", json!({"invariant_id":"SAF-RAFT-004","invariant_result":"pass","details":{"namespace":namespace,"removed":failed.node_identity,"replacement":replacement.node_identity,"learner_observed":saw_learner,"caught_up_before_vote":saw_caught_up_learner,"concurrent_writes":committed.len(),"final_revision":final_revision,"removed_outcome":removed_outcome}}))?;
        Ok(())
    }
}

async fn wait_replacement_converged(
    client: &PepperClient,
    cluster: &crate::harness::cluster::Cluster,
    namespace: &str,
    revision: u64,
    root: &str,
) -> Result<()> {
    eventually(
        "replacement voters converge",
        Duration::from_secs(45),
        Duration::from_millis(200),
        || async {
            let mut matched = 0;
            for node in cluster.nodes.values() {
                let Ok(groups) = namespace_groups(client, node).await else {
                    continue;
                };
                if groups.into_iter().any(|group| {
                    group["namespace_id"].as_str() == Some(namespace)
                        && group["current_revision"].as_u64() == Some(revision)
                        && group["current_root_cid"].as_str() == Some(root)
                        && group["local_voting"] == true
                        && group["voter_count"].as_u64() == Some(3)
                }) {
                    matched += 1;
                }
            }
            Ok((matched == 3).then_some(()))
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
