// SPDX-License-Identifier: Apache-2.0

use crate::harness::context::ScenarioContext;
use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone, Default)]
pub struct ScenarioRequirements {
    pub minimum_nodes: usize,
    pub requires_docker: bool,
    pub requires_net_admin: bool,
    pub requires_kvm: bool,
    pub requires_wan: bool,
    pub requires_fixed_kernel: bool,
}

#[async_trait]
pub trait Scenario: Send + Sync {
    /// Stable traceability identifier from the requirements catalog.
    fn id(&self) -> &'static str;
    /// Human-readable, stable CLI alias.
    fn name(&self) -> &'static str;
    fn requirements(&self) -> ScenarioRequirements;
    async fn run(&self, context: &mut ScenarioContext) -> Result<()>;
}
