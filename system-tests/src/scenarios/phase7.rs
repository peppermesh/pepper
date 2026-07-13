// SPDX-License-Identifier: Apache-2.0

use super::{bootstrap_cluster, bootstrap_three_nodes, json_request};
use crate::{
    harness::{
        backend::Fault,
        client::PepperClient,
        cluster::{Cluster, ClusterSpec, NodeId, NodeRuntime},
        context::ScenarioContext,
        history::OperationHistory,
        scenario::{Scenario, ScenarioRequirements},
        wait::eventually,
    },
    oracles::{
        continuous::{
            ContinuousChecker, ContinuousSnapshot, DurabilityObservation, GcProtectionObservation,
            IntentObservation, ReplicaObservation,
        },
        linearizability::{
            CheckerLimits, KvOperation, KvResult, ModelValue, Mutation, Precondition,
            check_linearizable,
        },
        storage_relative_path,
    },
};
use anyhow::{Context, Result, anyhow, ensure};
use async_trait::async_trait;
use pepper_types::DurabilityReceipt;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

pub struct LinearizabilityScenario;
pub struct ContinuousPartitionScenario;

#[async_trait]
impl Scenario for LinearizabilityScenario {
    fn id(&self) -> &'static str {
        "LIN-001"
    }
    fn name(&self) -> &'static str {
        "concurrent-kv-linearizability"
    }
    fn requirements(&self) -> ScenarioRequirements {
        ScenarioRequirements {
            minimum_nodes: 3,
            ..ScenarioRequirements::default()
        }
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = Arc::new(bootstrap_three_nodes(context).await?);
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_namespace(&client, &nodes[0], "lin-001").await?;
        let namespace = created["namespace_id"]
            .as_str()
            .context("namespace missing")?
            .to_string();
        let initial_root = created["root_cid"]
            .as_str()
            .context("root missing")?
            .to_string();
        let cids = futures_util::future::try_join_all((0..6).map(|index| {
            let client = client.clone();
            let node = nodes[index % nodes.len()].clone();
            async move {
                Ok::<_, anyhow::Error>(
                    client
                        .put_block(&node, format!("linearizable-{index}").as_bytes())
                        .await?
                        .cid
                        .to_string(),
                )
            }
        }))
        .await?;
        let history = Arc::new(OperationHistory::new(context.run.events.clone()));

        // Two absent-only writes overlap. Exactly one can commit revision one.
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for (index, node) in nodes.iter().take(2).cloned().enumerate() {
            let client = client.clone();
            let history = history.clone();
            let barrier = barrier.clone();
            let namespace = namespace.clone();
            let root = initial_root.clone();
            let cid = cids[index].clone();
            tasks.push(tokio::spawn(async move {
                let mutations = vec![Mutation::Put { key: hex::encode("winner"), cid: cid.clone(), precondition: Precondition::Absent }];
                let invocation = history.invoke(format!("writer-{index}"), KvOperation::Mutate { request_id: format!("winner-{index}"), mutations: mutations.clone() })?;
                barrier.wait().await;
                let response = client.request(&node, "POST", "/v1/kv/transactions", Some("application/json"), serde_json::to_vec(&json!({
                    "version":1,"namespace":namespace,"request_id":format!("winner-{index}"),"writer_identity":"http-client","signature_hex":"00",
                    "base_revision":0,"base_root_cid":root,
                    "mutations":[{"op":"put","key_hex":hex::encode("winner"),"value_cid":cid,"value_kind":"raw","metadata":{},"precondition":"absent"}]
                }))?, 20).await;
                let result = mutation_result(response)?;
                history.complete(invocation, result.clone())?;
                Result::<KvResult>::Ok(result)
            }));
        }
        barrier.wait().await;
        let winner_results = futures_util::future::try_join_all(tasks)
            .await?
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            winner_results
                .iter()
                .filter(|result| matches!(
                    result,
                    KvResult::Committed {
                        revision: 1,
                        replayed: false
                    }
                ))
                .count()
                == 1,
            "absent-only race did not produce one winner"
        );

        record_get(&client, &history, &nodes[2], &namespace, "winner", false).await?;

        // One atomic two-key transaction.
        let transaction_mutations = vec![
            Mutation::Put {
                key: hex::encode("txn-a"),
                cid: cids[2].clone(),
                precondition: Precondition::Absent,
            },
            Mutation::Put {
                key: hex::encode("txn-b"),
                cid: cids[3].clone(),
                precondition: Precondition::Absent,
            },
        ];
        let invocation = history.invoke(
            "transaction",
            KvOperation::Mutate {
                request_id: "atomic-two-key".into(),
                mutations: transaction_mutations.clone(),
            },
        )?;
        let current = namespace_status(&client, &nodes[0], &namespace).await?;
        let response = client.request(&nodes[1], "POST", "/v1/kv/transactions", Some("application/json"), serde_json::to_vec(&json!({
            "version":1,"namespace":namespace,"request_id":"atomic-two-key","writer_identity":"http-client","signature_hex":"00",
            "base_revision":current["current_revision"],"base_root_cid":current["current_root_cid"],
            "mutations":[
                {"op":"put","key_hex":hex::encode("txn-a"),"value_cid":cids[2],"value_kind":"raw","metadata":{},"precondition":"absent"},
                {"op":"put","key_hex":hex::encode("txn-b"),"value_cid":cids[3],"value_kind":"raw","metadata":{},"precondition":"absent"}
            ]
        }))?, 20).await;
        history.complete(invocation, mutation_result(response)?)?;
        record_get(&client, &history, &nodes[0], &namespace, "txn-a", false).await?;
        record_get(&client, &history, &nodes[2], &namespace, "txn-b", false).await?;

        // A same-intent retry must replay the first logical commit.
        let mutations = vec![Mutation::Put {
            key: hex::encode("retry"),
            cid: cids[4].clone(),
            precondition: Precondition::Any,
        }];
        let mut retries = Vec::new();
        for (index, node) in nodes.iter().take(2).enumerate() {
            let invocation = history.invoke(
                format!("retry-{index}"),
                KvOperation::Mutate {
                    request_id: "same-retry".into(),
                    mutations: mutations.clone(),
                },
            )?;
            let response = client.request(node, "POST", "/v1/kv/put", Some("application/json"), serde_json::to_vec(&json!({"namespace":namespace,"key_hex":hex::encode("retry"),"value_cid":cids[4],"request_id":"same-retry"}))?, 20).await;
            let result = mutation_result(response)?;
            history.complete(invocation, result.clone())?;
            retries.push(result);
        }
        ensure!(
            matches!(
                retries[0],
                KvResult::Committed {
                    replayed: false,
                    ..
                }
            ),
            "initial idempotency request did not commit: {:?}",
            retries[0]
        );
        // A healthy but CPU-constrained debug cluster can transiently fail the
        // leader's linearizable-read confirmation. That is an unavailable
        // attempt, not an idempotency violation. Retry the identical intent
        // through other ingress nodes and require the committed replay within
        // a bounded convergence window.
        for attempt in 2..8 {
            if matches!(
                retries.last(),
                Some(KvResult::Committed { replayed: true, .. })
            ) {
                break;
            }
            ensure!(
                matches!(retries.last(), Some(KvResult::Failed)),
                "same-intent retry returned a non-replay terminal result: {:?}",
                retries.last()
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
            let node = &nodes[attempt % nodes.len()];
            let invocation = history.invoke(
                format!("retry-{attempt}"),
                KvOperation::Mutate {
                    request_id: "same-retry".into(),
                    mutations: mutations.clone(),
                },
            )?;
            let response = client.request(node, "POST", "/v1/kv/put", Some("application/json"), serde_json::to_vec(&json!({"namespace":namespace,"key_hex":hex::encode("retry"),"value_cid":cids[4],"request_id":"same-retry"}))?, 20).await;
            let result = mutation_result(response)?;
            history.complete(invocation, result.clone())?;
            retries.push(result);
        }
        ensure!(
            matches!(
                retries.last(),
                Some(KvResult::Committed { replayed: true, .. })
            ),
            "same-intent retry did not converge to a replay: {retries:?}"
        );

        // Conditional delete and an explicitly historical read complete the model surface.
        let invocation = history.invoke(
            "delete",
            KvOperation::Mutate {
                request_id: "delete-winner".into(),
                mutations: vec![Mutation::Delete {
                    key: hex::encode("winner"),
                    precondition: Precondition::Generation(1),
                }],
            },
        )?;
        let response = client.request(&nodes[1], "POST", "/v1/kv/delete", Some("application/json"), serde_json::to_vec(&json!({"namespace":namespace,"key_hex":hex::encode("winner"),"if_generation":1,"request_id":"delete-winner"}))?, 20).await;
        history.complete(invocation, mutation_result(response)?)?;
        record_get(&client, &history, &nodes[0], &namespace, "winner", false).await?;
        record_get(&client, &history, &nodes[2], &namespace, "winner", true).await?;

        let operations = history.write_artifact(
            &context.run.artifacts,
            "observations/linearizability-history.json",
        )?;
        let limits = CheckerLimits::default();
        match check_linearizable(&operations, &limits) {
            Ok(report) => {
                context
                    .run
                    .artifacts
                    .write_json("observations/linearizability-report.json", &report)?;
                context.run.events.record("invariant", json!({"invariant_id":"SAF-LIN-001","invariant_result":"pass","details":{"operations":report.checked_operations,"excluded_stale":report.excluded_stale_operations,"explored_states":report.explored_states,"history_bound":limits.max_history,"search_bound":limits.max_search_states,"deadline_ms":limits.deadline.as_millis()}}))?;
            }
            Err(failure) => {
                context
                    .run
                    .artifacts
                    .write_json("observations/linearizability-counterexample.json", &failure)?;
                return Err(anyhow!(
                    "linearizability failure: {} ({} minimized operations)",
                    failure.reason,
                    failure.counterexample.len()
                ));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Scenario for ContinuousPartitionScenario {
    fn id(&self) -> &'static str {
        "RAFT-002"
    }
    fn name(&self) -> &'static str {
        "namespace-minority-partition-continuous"
    }
    fn requirements(&self) -> ScenarioRequirements {
        ScenarioRequirements {
            minimum_nodes: 4,
            requires_docker: true,
            requires_net_admin: true,
            ..ScenarioRequirements::default()
        }
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let mut spec = ClusterSpec::storage_cluster(context.run.seed, 4, 3, 128 * 1024 * 1024);
        spec.net_admin = true;
        let client = bootstrap_cluster(context, spec).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_namespace(&client, &nodes[0], "raft-002").await?;
        let namespace = created["namespace_id"].as_str().unwrap().to_string();
        wait_revision(&client, cluster, &namespace, 0).await?;
        let durable_bytes = b"continuous-durability".to_vec();
        let receipt = client.put_block(&nodes[0], &durable_bytes).await?;
        let committed = successful_put(
            &client,
            &nodes[0],
            &namespace,
            "before",
            &receipt.cid.to_string(),
            "before-partition",
        )
        .await?;
        ensure!(committed["root_cid"].as_str().is_some());
        wait_revision(&client, cluster, &namespace, 1).await?;
        wait_local_roots_protected(&client, cluster, &namespace).await?;
        let checker = ContinuousChecker::new(context.run.events.clone(), 60);
        let mut sequence = 0;
        observe_continuous(
            &checker,
            &client,
            cluster,
            &namespace,
            ContinuousInputs {
                receipt: &receipt,
                bytes: &durable_bytes,
            },
            sequence,
        )
        .await?;
        sequence += 1;

        let leader = find_leader(&client, cluster, &namespace).await?;
        let mut voters = Vec::new();
        for node in &nodes {
            if namespace_status(&client, node, &namespace)
                .await
                .ok()
                .is_some_and(|group| group["local_voting"] == true)
            {
                voters.push(node.clone());
            }
        }
        ensure!(
            voters.len() == 3,
            "namespace does not have exactly three voter nodes"
        );
        let majority = voters
            .into_iter()
            .filter(|node| node.id != leader)
            .collect::<Vec<_>>();
        ensure!(majority.len() == 2);
        let mut guards = Vec::new();
        for peer in &majority {
            guards.push(
                cluster
                    .backend
                    .clone()
                    .apply_fault(Fault::NetworkPartition {
                        source: leader.clone(),
                        target: peer.id.clone(),
                    })
                    .await?,
            );
            guards.push(
                cluster
                    .backend
                    .clone()
                    .apply_fault(Fault::NetworkPartition {
                        source: peer.id.clone(),
                        target: leader.clone(),
                    })
                    .await?,
            );
        }
        let isolated = cluster.node(&leader)?.clone();
        let isolated_attempt = client.request(&isolated, "POST", "/v1/kv/put", Some("application/json"), serde_json::to_vec(&json!({"namespace":namespace,"key_hex":hex::encode("minority"),"value_cid":receipt.cid,"request_id":"minority-must-not-commit"}))?, 3).await;
        ensure!(
            !isolated_attempt
                .as_ref()
                .is_ok_and(|response| response.status < 400),
            "minority write unexpectedly succeeded"
        );
        let majority_leader = eventually(
            "majority leader after partition",
            Duration::from_secs(30),
            Duration::from_millis(200),
            || async { find_leader_except(&client, cluster, &namespace, &isolated.id).await },
        )
        .await?;
        // Monitor invariants concurrently with the write. The response may be
        // ambiguous while protection gossip retries the isolated peer.
        let request = client.request(cluster.node(&majority_leader)?, "POST", "/v1/kv/put", Some("application/json"), serde_json::to_vec(&json!({"namespace":namespace,"key_hex":hex::encode("majority"),"value_cid":receipt.cid,"request_id":"majority-commit"}))?, 60);
        let monitor = async {
            for _ in 0..8 {
                observe_continuous(
                    &checker,
                    &client,
                    cluster,
                    &namespace,
                    ContinuousInputs {
                        receipt: &receipt,
                        bytes: &durable_bytes,
                    },
                    sequence,
                )
                .await?;
                sequence += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Result::<()>::Ok(())
        };
        let (_ambiguous, monitor_result) = tokio::join!(request, monitor);
        monitor_result?;
        let majority_commit = eventually(
            "majority commit under partition",
            Duration::from_secs(30),
            Duration::from_millis(200),
            || async {
                for node in &majority {
                    if let Ok(group) = namespace_status(&client, node, &namespace).await
                        && group["current_revision"].as_u64() == Some(2)
                    {
                        return Ok(Some(group));
                    }
                }
                Ok(None)
            },
        )
        .await?;
        ensure!(majority_commit["current_root_cid"].as_str().is_some());
        for node in &nodes {
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
            ensure!(
                (200..300).contains(&gc.status),
                "continuous-check GC failed on {}",
                node.id
            );
        }
        for _ in 0..5 {
            observe_continuous(
                &checker,
                &client,
                cluster,
                &namespace,
                ContinuousInputs {
                    receipt: &receipt,
                    bytes: &durable_bytes,
                },
                sequence,
            )
            .await?;
            sequence += 1;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        let isolated_status = namespace_status(&client, &isolated, &namespace).await?;
        ensure!(
            isolated_status["current_revision"].as_u64().unwrap_or(0) <= 1,
            "minority advanced committed revision"
        );
        for guard in guards {
            guard.heal().await?;
        }
        wait_revision(&client, cluster, &namespace, 2).await?;
        wait_publication_quiescent(&client, cluster).await?;
        for _ in 0..3 {
            observe_continuous(
                &checker,
                &client,
                cluster,
                &namespace,
                ContinuousInputs {
                    receipt: &receipt,
                    bytes: &durable_bytes,
                },
                sequence,
            )
            .await?;
            sequence += 1;
        }
        checker.write_artifact(&context.run.artifacts)?;
        context.run.events.record("invariant", json!({"invariant_id":"CONV-RAFT-001","invariant_result":"pass","details":{"namespace":namespace,"minority":leader,"majority_revision":2,"samples":sequence,"healed":true}}))?;
        Ok(())
    }
}

async fn create_namespace(client: &PepperClient, node: &NodeRuntime, alias: &str) -> Result<Value> {
    let (status, value) = json_request(
        client,
        node,
        "POST",
        "/v1/namespaces",
        json!({"kind":"kv","alias":alias,"request_id":format!("create-{alias}")}),
    )
    .await?;
    ensure!(
        (200..300).contains(&status),
        "namespace creation failed: HTTP {status} {value}"
    );
    Ok(value)
}

async fn successful_put(
    client: &PepperClient,
    node: &NodeRuntime,
    namespace: &str,
    key: &str,
    cid: &str,
    request_id: &str,
) -> Result<Value> {
    eventually("namespace put", Duration::from_secs(30), Duration::from_millis(200), || async {
        let response = client.request(node, "POST", "/v1/kv/put", Some("application/json"), serde_json::to_vec(&json!({"namespace":namespace,"key_hex":hex::encode(key),"value_cid":cid,"request_id":request_id}))?, 10).await;
        match response {
            Ok(response) if (200..300).contains(&response.status) => Ok(Some(serde_json::from_slice(&response.body)?)),
            Ok(_) | Err(_) => Ok(None),
        }
    }).await
}

async fn record_get(
    client: &PepperClient,
    history: &OperationHistory,
    node: &NodeRuntime,
    namespace: &str,
    key: &str,
    stale: bool,
) -> Result<()> {
    let operation = KvOperation::Get {
        key: hex::encode(key),
    };
    let invocation = if stale {
        history.invoke_stale(node.id.to_string(), operation)?
    } else {
        history.invoke(node.id.to_string(), operation)?
    };
    let body = if stale {
        json!({"namespace":namespace,"key_hex":hex::encode(key),"revision":0})
    } else {
        json!({"namespace":namespace,"key_hex":hex::encode(key),"consistency":"linearizable"})
    };
    let response = client
        .request(
            node,
            "POST",
            "/v1/kv/get",
            Some("application/json"),
            serde_json::to_vec(&body)?,
            20,
        )
        .await;
    let result = match response {
        Ok(response) if response.status == 200 => {
            let value: Value = serde_json::from_slice(&response.body)?;
            ensure!(
                value["stale"].as_bool() == Some(stale),
                "read stale label does not match requested consistency"
            );
            let model_value = value["value"].as_object().map(|value| ModelValue {
                cid: value
                    .get("cid")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                generation: value
                    .get("generation")
                    .and_then(Value::as_u64)
                    .unwrap_or_default(),
            });
            KvResult::Read { value: model_value }
        }
        _ => KvResult::Failed,
    };
    history.complete(invocation, result)
}

fn mutation_result(response: Result<crate::harness::backend::HttpResponse>) -> Result<KvResult> {
    match response {
        Ok(response) if (200..300).contains(&response.status) => {
            let value: Value = serde_json::from_slice(&response.body)?;
            Ok(KvResult::Committed {
                revision: value["namespace_revision"]
                    .as_u64()
                    .context("commit revision missing")?,
                replayed: value["replayed"].as_bool().unwrap_or(false),
            })
        }
        Ok(response) if (400..500).contains(&response.status) => Ok(KvResult::Conflict),
        Ok(_) | Err(_) => Ok(KvResult::Failed),
    }
}

async fn namespace_status(
    client: &PepperClient,
    node: &NodeRuntime,
    namespace: &str,
) -> Result<Value> {
    let (status, response) = json_request(
        client,
        node,
        "GET",
        "/v1/admin/diagnostics/namespaces?limit=256",
        Value::Null,
    )
    .await?;
    ensure!(status == 200);
    response["data"]["groups"]
        .as_array()
        .and_then(|groups| {
            groups
                .iter()
                .find(|group| group["namespace_id"].as_str() == Some(namespace))
        })
        .cloned()
        .context("namespace status missing")
}

async fn wait_revision(
    client: &PepperClient,
    cluster: &Cluster,
    namespace: &str,
    revision: u64,
) -> Result<()> {
    eventually(
        &format!("namespace revision {revision}"),
        Duration::from_secs(45),
        Duration::from_millis(200),
        || async {
            let mut matched = 0;
            for node in cluster.nodes.values() {
                if namespace_status(client, node, namespace)
                    .await
                    .ok()
                    .and_then(|group| group["current_revision"].as_u64())
                    == Some(revision)
                {
                    matched += 1;
                }
            }
            Ok((matched == 3).then_some(()))
        },
    )
    .await
}

async fn wait_publication_quiescent(client: &PepperClient, cluster: &Cluster) -> Result<()> {
    eventually(
        "publication intents quiescent",
        Duration::from_secs(30),
        Duration::from_millis(200),
        || async {
            for node in cluster.nodes.values() {
                let (status, response) = json_request(
                    client,
                    node,
                    "GET",
                    "/v1/admin/diagnostics/publication-intents?status=pending&limit=1",
                    Value::Null,
                )
                .await?;
                if status != 200
                    || response["data"]["status_counts"]["pending"]
                        .as_u64()
                        .unwrap_or(0)
                        != 0
                {
                    return Ok(None);
                }
            }
            Ok(Some(()))
        },
    )
    .await
}

async fn wait_local_roots_protected(
    client: &PepperClient,
    cluster: &Cluster,
    namespace: &str,
) -> Result<()> {
    eventually(
        "local namespace roots protected",
        Duration::from_secs(30),
        Duration::from_millis(200),
        || async {
            let mut voters = 0;
            for node in cluster.nodes.values() {
                let Ok(group) = namespace_status(client, node, namespace).await else {
                    continue;
                };
                voters += 1;
                let root = group["current_root_cid"]
                    .as_str()
                    .context("current root missing")?;
                let (status, gc) = json_request(
                    client,
                    node,
                    "GET",
                    &format!("/v1/admin/diagnostics/gc/{}", encode_segment(root)),
                    Value::Null,
                )
                .await?;
                if status != 200 || gc["data"]["determination"] != "protected" {
                    return Ok(None);
                }
            }
            Ok((voters == 3).then_some(()))
        },
    )
    .await
}

async fn find_leader(client: &PepperClient, cluster: &Cluster, namespace: &str) -> Result<NodeId> {
    eventually(
        "namespace leader",
        Duration::from_secs(30),
        Duration::from_millis(200),
        || async { find_leader_once(client, cluster, namespace).await },
    )
    .await
}

async fn find_leader_except(
    client: &PepperClient,
    cluster: &Cluster,
    namespace: &str,
    excluded: &NodeId,
) -> Result<Option<NodeId>> {
    for node in cluster.nodes.values().filter(|node| &node.id != excluded) {
        if namespace_status(client, node, namespace)
            .await
            .ok()
            .is_some_and(|group| group["role"] == "leader")
        {
            return Ok(Some(node.id.clone()));
        }
    }
    Ok(None)
}

async fn find_leader_once(
    client: &PepperClient,
    cluster: &Cluster,
    namespace: &str,
) -> Result<Option<NodeId>> {
    for node in cluster.nodes.values() {
        if namespace_status(client, node, namespace)
            .await
            .ok()
            .is_some_and(|group| group["role"] == "leader")
        {
            return Ok(Some(node.id.clone()));
        }
    }
    Ok(None)
}

struct ContinuousInputs<'a> {
    receipt: &'a DurabilityReceipt,
    bytes: &'a [u8],
}

async fn observe_continuous(
    checker: &ContinuousChecker,
    client: &PepperClient,
    cluster: &Cluster,
    namespace: &str,
    inputs: ContinuousInputs<'_>,
    sequence: u64,
) -> Result<()> {
    let ContinuousInputs { receipt, bytes } = inputs;
    let mut snapshot = ContinuousSnapshot {
        sequence,
        ..Default::default()
    };
    for node in cluster.nodes.values() {
        let Ok(group) = namespace_status(client, node, namespace).await else {
            continue;
        };
        snapshot.replicas.push(ReplicaObservation {
            node: node.id.to_string(),
            namespace: namespace.to_string(),
            epoch: group["membership_epoch"].as_u64().unwrap_or_default(),
            revision: group["current_revision"].as_u64().unwrap_or_default(),
            root: group["current_root_cid"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            last_log_index: group["last_log_index"].as_u64(),
            commit_index: group["commit_index"].as_u64(),
            applied_index: group["applied_index"].as_u64(),
            local_raft_id: group["local_raft_id"].as_u64().unwrap_or_default(),
            local_voting: group["local_voting"].as_bool().unwrap_or(false),
            voter_ids: json_u64_set(&group["voter_raft_ids"]),
            learner_ids: json_u64_set(&group["learner_raft_ids"]),
            replication_match: json_match_map(&group["replication_match_indexes"]),
        });
        let local_root = group["current_root_cid"].as_str().unwrap_or_default();
        let (status, gc) = json_request(
            client,
            node,
            "GET",
            &format!("/v1/admin/diagnostics/gc/{}", encode_segment(local_root)),
            Value::Null,
        )
        .await?;
        let protected = status == 200 && gc["data"]["determination"] == "protected";
        snapshot.gc_protection.push(GcProtectionObservation {
            node: node.id.to_string(),
            root: local_root.to_string(),
            protected,
        });
        let (status, intents) = json_request(
            client,
            node,
            "GET",
            "/v1/admin/diagnostics/publication-intents?limit=256",
            Value::Null,
        )
        .await?;
        if status == 200 {
            let observed = intents["observed_at_unix_seconds"]
                .as_i64()
                .unwrap_or_default();
            for intent in intents["data"]["entries"].as_array().into_iter().flatten() {
                snapshot.intents.push(IntentObservation {
                    intent_id: intent["intent_id"].as_str().unwrap_or_default().to_string(),
                    status: intent["status"].as_str().unwrap_or("unknown").to_string(),
                    age_seconds: observed.saturating_sub(
                        intent["created_at_unix_seconds"]
                            .as_i64()
                            .unwrap_or(observed),
                    ) as u64,
                    actionable: intent["status"] == "pending",
                });
            }
        }
    }
    let relative = storage_relative_path(&receipt.cid);
    let mut verified = 0;
    for identity in &receipt.replica_nodes {
        if let Some(node) = cluster
            .nodes
            .values()
            .find(|node| &node.node_identity == identity)
            && cluster
                .backend
                .read_storage_file(&node.id, &relative, bytes.len() + 1)
                .await
                .is_ok_and(|stored| stored == bytes)
        {
            verified += 1;
        }
    }
    snapshot.durability.push(DurabilityObservation {
        cid: receipt.cid.to_string(),
        required: receipt.replicas_accepted,
        verified_replicas: verified,
    });
    checker.observe(snapshot)
}

fn json_u64_set(value: &Value) -> BTreeSet<u64> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect()
}
fn json_match_map(value: &Value) -> BTreeMap<u64, Option<u64>> {
    value
        .as_object()
        .into_iter()
        .flat_map(|map| map.iter())
        .filter_map(|(key, value)| key.parse().ok().map(|key| (key, value.as_u64())))
        .collect()
}
fn encode_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}
