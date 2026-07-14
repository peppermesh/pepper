// SPDX-License-Identifier: Apache-2.0

use super::bootstrap_three_nodes;
use crate::harness::{
    backend::RestartPolicy,
    context::ScenarioContext,
    scenario::{Scenario, ScenarioRequirements},
    wait::eventually,
};
use anyhow::{Result, ensure};
use async_trait::async_trait;
use serde_json::json;
use std::time::Duration;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub struct ThreeNodeBootstrapScenario;

#[async_trait]
impl Scenario for ThreeNodeBootstrapScenario {
    fn id(&self) -> &'static str {
        "BOOT-002"
    }

    fn name(&self) -> &'static str {
        "bootstrap-three-node"
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
        for node in cluster.node_ids() {
            let observation = cluster.backend.observe(node).await?;
            context.run.artifacts.write_json(
                &format!("observations/{node}/bootstrap.json"),
                &json!({
                    "schema_version":1,
                    "run_id":context.run.run_id,
                    "observation_id":format!("bootstrap-{node}"),
                    "node_id":node,
                    "captured_at":OffsetDateTime::now_utc().format(&Rfc3339)?,
                    "consistency":"local",
                    "source":"process-backend:/v1/admin/status",
                    "health":{"live":observation.live,"ready":observation.ready,"error":observation.error},
                    "diagnostics":observation.status
                }),
            )?;
            context.run.events.record(
                "observation",
                json!({
                    "node_id":node,"details":{"live":observation.live,"ready":observation.ready}
                }),
            )?;
        }

        let restart_id = cluster.spec.nodes[2].id.clone();
        let restart_node = cluster.node_handle(&restart_id)?;
        let identity_before = restart_node.runtime().node_identity.clone();
        restart_node.restart(RestartPolicy::PreserveAll).await?;
        eventually(
            "restarted node health and peer convergence",
            Duration::from_secs(30),
            Duration::from_millis(200),
            || async {
                if !client.health(restart_node.runtime()).await?
                    || !client.ready(restart_node.runtime()).await?
                {
                    return Ok(None);
                }
                Ok((client.peer_count(restart_node.runtime()).await? >= 2).then_some(()))
            },
        )
        .await?;
        ensure!(
            restart_node.runtime().node_identity == identity_before,
            "node identity changed across restart"
        );
        context.run.events.record(
            "invariant",
            json!({
                "invariant_id":"LIV-NODE-001","invariant_result":"pass",
                "details":{"restarted_node":restart_id,"identity_preserved":true,"minimum_peers":2}
            }),
        )?;
        Ok(())
    }
}
