// SPDX-License-Identifier: Apache-2.0

use super::{bootstrap_cluster, bootstrap_three_nodes};
use crate::{
    harness::{
        backend::{ExecRequest, Fault, HttpRequest},
        client::PepperClient,
        cluster::ClusterSpec,
        context::ScenarioContext,
        faults::{FaultScheduleEntry, NemesisScheduler, deterministic_fault},
        scenario::{Scenario, ScenarioRequirements},
        wait::eventually,
    },
    oracles::{deterministic_bytes, storage_relative_path},
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use pepper_types::DurabilityReceipt;
use serde_json::json;
use std::time::Duration;

pub struct ProcessFaultScenario;
pub struct NetworkFaultScenario;
pub struct StorageFaultScenario;
pub struct NemesisScenario;

fn requirements(nodes: usize) -> ScenarioRequirements {
    ScenarioRequirements {
        minimum_nodes: nodes,
        ..ScenarioRequirements::default()
    }
}

#[async_trait]
impl Scenario for ProcessFaultScenario {
    fn id(&self) -> &'static str {
        "FAULT-001"
    }
    fn name(&self) -> &'static str {
        "process-fault-primitives"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements(3)
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let node = cluster.node(&cluster.spec.nodes[1].id)?.clone();
        for fault in [
            Fault::Pause {
                node: node.id.clone(),
            },
            Fault::Stop {
                node: node.id.clone(),
            },
            Fault::Kill {
                node: node.id.clone(),
            },
        ] {
            let fault_id = fault.stable_id();
            context.run.events.record(
                "fault",
                json!({"fault_id":fault_id,"fault_action":"schedule"}),
            )?;
            let guard = cluster.backend.clone().apply_fault(fault).await?;
            eventually(
                "process fault activation",
                Duration::from_secs(5),
                Duration::from_millis(100),
                || async { Ok((!cluster.backend.observe(&node.id).await?.live).then_some(())) },
            )
            .await?;
            ensure!(
                client
                    .health(cluster.node(&cluster.spec.nodes[0].id)?)
                    .await?,
                "unrelated node was affected"
            );
            guard.heal().await?;
            eventually(
                "process fault healing",
                Duration::from_secs(20),
                Duration::from_millis(100),
                || async { Ok(client.health(&node).await?.then_some(())) },
            )
            .await?;
        }
        context.run.events.record("invariant", json!({"invariant_id":"LIV-NODE-001","invariant_result":"pass","details":{"stop":true,"kill":true,"pause":true,"healed":true,"isolation":true}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for NetworkFaultScenario {
    fn id(&self) -> &'static str {
        "FAULT-002"
    }
    fn name(&self) -> &'static str {
        "udp-partition-netem-primitives"
    }
    fn requirements(&self) -> ScenarioRequirements {
        ScenarioRequirements {
            minimum_nodes: 3,
            requires_docker: true,
            requires_net_admin: true,
            ..ScenarioRequirements::default()
        }
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let mut spec = ClusterSpec::three_node(context.run.seed);
        spec.net_admin = true;
        let client = bootstrap_cluster(context, spec).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let source = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let target = cluster.node(&cluster.spec.nodes[1].id)?.clone();
        let unrelated = cluster.node(&cluster.spec.nodes[2].id)?.clone();
        let partition = Fault::NetworkPartition {
            source: source.id.clone(),
            target: target.id.clone(),
        };
        let table_marker = format!("pepper_{}", short_hash(&partition.stable_id()));
        let guard = cluster.backend.clone().apply_fault(partition).await?;
        let source_rules = exec_text(cluster, &source.id, vec!["nft", "list", "ruleset"]).await?;
        let unrelated_rules =
            exec_text(cluster, &unrelated.id, vec!["nft", "list", "ruleset"]).await?;
        ensure!(
            source_rules.contains(&table_marker) && source_rules.contains(&target.address),
            "partition rule not active"
        );
        ensure!(
            !unrelated_rules.contains(&table_marker),
            "partition leaked to unrelated node"
        );
        guard.heal().await?;
        let healed_rules = exec_text(cluster, &source.id, vec!["nft", "list", "ruleset"]).await?;
        ensure!(
            !healed_rules.contains(&table_marker),
            "partition rule survived healing"
        );

        let netem = Fault::NetworkNetem {
            node: source.id.clone(),
            latency_ms: 80,
            jitter_ms: 10,
            loss_percent: 5,
            duplicate_percent: 1,
            reorder_percent: 1,
            rate_kbit: Some(10_000),
        };
        let guard = cluster.backend.clone().apply_fault(netem).await?;
        let active = exec_text(
            cluster,
            &source.id,
            vec!["tc", "qdisc", "show", "dev", "eth0"],
        )
        .await?;
        let isolated = exec_text(
            cluster,
            &unrelated.id,
            vec!["tc", "qdisc", "show", "dev", "eth0"],
        )
        .await?;
        ensure!(
            active.contains("netem") && !isolated.contains("netem"),
            "netem activation or isolation failed"
        );
        ensure!(
            client.health(&source).await? && client.health(&unrelated).await?,
            "loopback API was affected by P2P netem"
        );
        guard.heal().await?;
        let healed = exec_text(
            cluster,
            &source.id,
            vec!["tc", "qdisc", "show", "dev", "eth0"],
        )
        .await?;
        ensure!(!healed.contains("netem"), "netem survived healing");

        // Prove the RAII fallback heals even when a caller returns without an explicit heal.
        let drop_fault = Fault::NetworkPartition {
            source: source.id.clone(),
            target: unrelated.id.clone(),
        };
        let drop_marker = format!("pepper_{}", short_hash(&drop_fault.stable_id()));
        {
            let _guard = cluster.backend.clone().apply_fault(drop_fault).await?;
            ensure!(
                exec_text(cluster, &source.id, vec!["nft", "list", "ruleset"])
                    .await?
                    .contains(&drop_marker)
            );
        }
        eventually(
            "fault guard drop healing",
            Duration::from_secs(10),
            Duration::from_millis(100),
            || async {
                Ok(
                    (!exec_text(cluster, &source.id, vec!["nft", "list", "ruleset"])
                        .await?
                        .contains(&drop_marker))
                    .then_some(()),
                )
            },
        )
        .await?;
        context.run.events.record("invariant", json!({"invariant_id":"SEC-RPC-001","invariant_result":"pass","details":{"directional_partition":true,"netem":true,"unrelated_node_isolated":true,"explicit_heal":true,"drop_heal":true}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for StorageFaultScenario {
    fn id(&self) -> &'static str {
        "FAULT-003"
    }
    fn name(&self) -> &'static str {
        "storage-fault-primitives"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements(3)
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let ingress = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let payload = deterministic_bytes(b"fault-storage", context.run.seed, 128 * 1024);
        let receipt = client.put_block(&ingress, &payload).await?;
        let victim_identity = receipt
            .replica_nodes
            .first()
            .context("receipt has no replica")?;
        let victim = cluster
            .nodes
            .values()
            .find(|node| &node.node_identity == victim_identity)
            .context("victim missing")?
            .clone();
        let relative = storage_relative_path(&receipt.cid).display().to_string();
        let original = cluster
            .backend
            .read_storage_file(&victim.id, relative.as_ref(), payload.len() + 1)
            .await?;

        let delete = cluster
            .backend
            .clone()
            .apply_fault(Fault::StorageDelete {
                node: victim.id.clone(),
                relative_path: relative.clone(),
            })
            .await?;
        ensure!(
            cluster
                .backend
                .read_storage_file(&victim.id, relative.as_ref(), payload.len() + 1)
                .await
                .is_err(),
            "delete fault did not activate"
        );
        delete.heal().await?;
        ensure!(
            cluster
                .backend
                .read_storage_file(&victim.id, relative.as_ref(), payload.len() + 1)
                .await?
                == original
        );

        let corrupt = cluster
            .backend
            .clone()
            .apply_fault(Fault::StorageCorrupt {
                node: victim.id.clone(),
                relative_path: relative.clone(),
            })
            .await?;
        ensure!(
            cluster
                .backend
                .read_storage_file(&victim.id, relative.as_ref(), payload.len() + 1)
                .await?
                != original,
            "corruption fault did not activate"
        );
        corrupt.heal().await?;
        ensure!(
            cluster
                .backend
                .read_storage_file(&victim.id, relative.as_ref(), payload.len() + 1)
                .await?
                == original
        );

        let pressure_path = std::path::Path::new("pressure/fill.bin");
        let pressure = cluster
            .backend
            .clone()
            .apply_fault(Fault::StoragePressure {
                node: victim.id.clone(),
                bytes: 2 * 1024 * 1024,
            })
            .await?;
        ensure!(
            cluster
                .backend
                .read_storage_file(&victim.id, pressure_path, 2 * 1024 * 1024 + 1)
                .await?
                .len()
                == 2 * 1024 * 1024,
            "pressure file has wrong size"
        );
        pressure.heal().await?;
        ensure!(
            cluster
                .backend
                .read_storage_file(&victim.id, pressure_path, 1)
                .await
                .is_err(),
            "pressure file survived healing"
        );

        let readonly = cluster
            .backend
            .clone()
            .apply_fault(Fault::StorageReadOnly {
                node: victim.id.clone(),
            })
            .await?;
        let response = cluster
            .backend
            .http(
                &victim.id,
                HttpRequest {
                    method: "POST".into(),
                    path: "/v1/blocks?replication_factor=1".into(),
                    content_type: Some("application/octet-stream".into()),
                    body: b"read-only-write".to_vec(),
                    timeout_seconds: 10,
                },
            )
            .await;
        ensure!(
            !response
                .as_ref()
                .is_ok_and(|response| response.status < 400),
            "read-only storage accepted a write"
        );
        readonly.heal().await?;
        eventually(
            "storage writable after healing",
            Duration::from_secs(20),
            Duration::from_millis(100),
            || async {
                let response = client
                    .request(
                        &victim,
                        "POST",
                        "/v1/blocks?replication_factor=1",
                        Some("application/octet-stream"),
                        b"healed-write".to_vec(),
                        10,
                    )
                    .await;
                Ok(response
                    .ok()
                    .filter(|response| (200..300).contains(&response.status))
                    .map(|_| ()))
            },
        )
        .await?;
        context.run.events.record("invariant", json!({"invariant_id":"SAF-IMM-001","invariant_result":"pass","details":{"delete_restored":true,"corrupt_restored":true,"pressure_cleaned":true,"readonly_healed":true,"original_hash":blake3::hash(&original).to_hex().to_string()}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for NemesisScenario {
    fn id(&self) -> &'static str {
        "NEMESIS-001"
    }
    fn name(&self) -> &'static str {
        "concurrent-seeded-nemesis"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements(4)
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let spec = ClusterSpec::storage_cluster(context.run.seed, 4, 2, 128 * 1024 * 1024);
        let _client = bootstrap_cluster(context, spec).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let choices = vec![
            Fault::Pause {
                node: nodes[1].id.clone(),
            },
            Fault::Kill {
                node: nodes[2].id.clone(),
            },
            Fault::Stop {
                node: nodes[3].id.clone(),
            },
        ];
        let schedule = (0..3u64)
            .map(|step| {
                Ok(FaultScheduleEntry {
                    offset_ms: 200 + step * 900,
                    duration_ms: 350,
                    fault: deterministic_fault(context.run.seed, step, &choices)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let scheduler = NemesisScheduler::new(
            cluster.backend.clone(),
            context.run.events.clone(),
            schedule,
        )?;
        let workload_client =
            PepperClient::new(context.run.events.clone(), cluster.backend.clone());
        let ingress = nodes[0].clone();
        let workload = async {
            let mut acknowledged = Vec::<(pepper_types::Cid, Vec<u8>)>::new();
            for index in 0..12u64 {
                let payload = deterministic_bytes(
                    b"nemesis-workload",
                    context.run.seed ^ index,
                    32 * 1024 + index as usize,
                );
                let response = workload_client
                    .request(
                        &ingress,
                        "POST",
                        "/v1/blocks?replication_factor=2",
                        Some("application/octet-stream"),
                        payload.clone(),
                        20,
                    )
                    .await?;
                if (200..300).contains(&response.status) {
                    let receipt: DurabilityReceipt = serde_json::from_slice(&response.body)?;
                    if receipt.replicas_accepted >= 2 {
                        acknowledged.push((receipt.cid, payload));
                    }
                }
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
            Result::<_>::Ok(acknowledged)
        };
        let (fault_result, workload_result) = tokio::join!(scheduler.run(), workload);
        fault_result?;
        let acknowledged = workload_result?;
        ensure!(
            !acknowledged.is_empty(),
            "nemesis workload acknowledged no operations"
        );
        for node in &nodes {
            eventually(
                &format!("{} post-nemesis health", node.id),
                Duration::from_secs(30),
                Duration::from_millis(100),
                || async { Ok(workload_client.health(node).await?.then_some(())) },
            )
            .await?;
        }
        for (cid, payload) in &acknowledged {
            ensure!(workload_client.get_block(&ingress, cid).await? == *payload);
        }
        context.run.events.record("invariant", json!({"invariant_id":"SAF-RECEIPT-001","invariant_result":"pass","details":{"seed":context.run.seed,"faults":3,"acknowledged":acknowledged.len(),"post_heal_exact_reads":acknowledged.len()}}))?;
        Ok(())
    }
}

async fn exec_text(
    cluster: &crate::harness::cluster::Cluster,
    node: &crate::harness::cluster::NodeId,
    command: Vec<&str>,
) -> Result<String> {
    let result = cluster
        .backend
        .network_exec(
            node,
            ExecRequest {
                command: command.into_iter().map(ToString::to_string).collect(),
                stdin: Vec::new(),
                timeout_seconds: 10,
                max_output_bytes: 64 * 1024,
            },
        )
        .await?;
    ensure!(
        result.exit_code == 0,
        "fault inspection command failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}

fn short_hash(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex()[..12].to_string()
}
