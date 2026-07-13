// SPDX-License-Identifier: Apache-2.0

use super::bootstrap_three_nodes;
use crate::harness::{
    backend::ExecRequest,
    context::ScenarioContext,
    scenario::{Scenario, ScenarioRequirements},
};
use anyhow::{Result, ensure};
use async_trait::async_trait;
use serde_json::json;

pub struct IdentityFencingScenario;

#[async_trait]
impl Scenario for IdentityFencingScenario {
    fn id(&self) -> &'static str {
        "BOOT-003"
    }
    fn name(&self) -> &'static str {
        "identity-live-process-fencing"
    }
    fn requirements(&self) -> ScenarioRequirements {
        ScenarioRequirements {
            minimum_nodes: 1,
            ..ScenarioRequirements::default()
        }
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let node = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let config = if cluster.backend.metadata().name == "docker" {
            "/etc/pepper/config.toml".to_string()
        } else {
            node.config_path.display().to_string()
        };
        let duplicate = cluster
            .backend
            .exec(
                &node.id,
                ExecRequest {
                    command: vec!["pepper-agent".into(), "--config".into(), config],
                    stdin: Vec::new(),
                    timeout_seconds: 8,
                    max_output_bytes: 16 * 1024,
                },
            )
            .await?;
        ensure!(
            duplicate.exit_code != 0,
            "second agent unexpectedly acquired live identity"
        );
        let error = format!(
            "{}{}",
            String::from_utf8_lossy(&duplicate.stdout),
            String::from_utf8_lossy(&duplicate.stderr)
        );
        ensure!(
            error.to_ascii_lowercase().contains("lock")
                || error.to_ascii_lowercase().contains("already"),
            "identity rejection lacked a stable explanation: {error}"
        );
        ensure!(
            client.health(&node).await?,
            "original identity holder was harmed"
        );
        context.run.events.record("invariant", json!({"invariant_id":"SEC-IDENTITY-001","invariant_result":"pass","details":{"node":node.node_identity,"duplicate_exit_code":duplicate.exit_code,"original_live":true}}))?;
        Ok(())
    }
}
