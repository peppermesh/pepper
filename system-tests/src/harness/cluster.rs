// SPDX-License-Identifier: Apache-2.0

use crate::harness::backend::{ClusterBackend, NodeObservation, RestartPolicy};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '-' || character == '_'
            })
        {
            bail!("invalid system-test node name {value:?}");
        }
        Ok(Self(value))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSpec {
    pub capacity_bytes: u64,
    pub repair_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSpec {
    pub cpu_limit: f64,
    pub memory_bytes: u64,
    pub tokio_workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSpec {
    pub id: NodeId,
    pub failure_domain: String,
    pub bootstrap_nodes: Vec<NodeId>,
    pub storage: StorageSpec,
    pub resources: ResourceSpec,
    pub consensus_enabled: bool,
    pub compute_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSpec {
    pub profile: String,
    pub nodes: Vec<NodeSpec>,
    pub replication_factor: usize,
    pub namespace_voter_count: Option<usize>,
    pub net_admin: bool,
}

impl ClusterSpec {
    pub fn storage_cluster(
        seed: u64,
        node_count: usize,
        replication_factor: usize,
        capacity_bytes: u64,
    ) -> Self {
        let suffix = format!("{:08x}", seed as u32);
        let ids = (1..=node_count)
            .map(|number| NodeId(format!("node-{number}-{suffix}")))
            .collect::<Vec<_>>();
        let nodes = ids
            .iter()
            .enumerate()
            .map(|(index, id)| NodeSpec {
                id: id.clone(),
                failure_domain: format!("rack-{}", index + 1),
                bootstrap_nodes: ids[..index.min(2)].to_vec(),
                storage: StorageSpec {
                    capacity_bytes,
                    repair_interval_seconds: 300,
                },
                resources: ResourceSpec {
                    cpu_limit: 1.0,
                    memory_bytes: 512 * 1024 * 1024,
                    tokio_workers: 2,
                },
                consensus_enabled: node_count >= 3,
                compute_enabled: false,
            })
            .collect();
        Self {
            profile: format!("storage-{node_count}-node-rf{replication_factor}"),
            nodes,
            replication_factor,
            namespace_voter_count: (node_count >= 3).then_some(3),
            net_admin: false,
        }
    }

    pub fn three_node(seed: u64) -> Self {
        Self::storage_cluster(seed, 3, 3, 128 * 1024 * 1024)
    }

    pub fn validate(&self) -> Result<()> {
        if self.nodes.is_empty() || self.nodes.len() > 256 {
            bail!("cluster node count must be 1 to 256");
        }
        if self.replication_factor == 0 || self.replication_factor > self.nodes.len() {
            bail!("replication factor must fit the cluster");
        }
        let mut names = std::collections::BTreeSet::new();
        for node in &self.nodes {
            if !names.insert(&node.id) {
                bail!("duplicate node {}", node.id);
            }
            if node.storage.capacity_bytes == 0
                || node.storage.repair_interval_seconds == 0
                || node.resources.tokio_workers == 0
            {
                bail!("node {} has invalid resources", node.id);
            }
        }
        for node in &self.nodes {
            for bootstrap in &node.bootstrap_nodes {
                if !names.contains(bootstrap) || bootstrap == &node.id {
                    bail!("node {} has invalid bootstrap node {bootstrap}", node.id);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRuntime {
    pub id: NodeId,
    pub node_identity: String,
    pub address: String,
    pub p2p_port: u16,
    pub api_port: u16,
    pub config_path: PathBuf,
    pub data_path: PathBuf,
    pub log_path: PathBuf,
}

#[derive(Clone)]
pub struct NodeHandle {
    runtime: NodeRuntime,
    backend: Arc<dyn ClusterBackend>,
}

impl NodeHandle {
    pub fn id(&self) -> &NodeId {
        &self.runtime.id
    }

    pub fn runtime(&self) -> &NodeRuntime {
        &self.runtime
    }

    pub fn api_base_url(&self) -> String {
        format!("http://{}:{}", self.runtime.address, self.runtime.api_port)
    }

    pub async fn start(&self) -> Result<()> {
        self.backend.start(&self.runtime.id).await
    }

    pub async fn stop(&self) -> Result<()> {
        self.backend.stop(&self.runtime.id).await
    }

    pub async fn restart(&self, policy: RestartPolicy) -> Result<()> {
        self.backend.restart(&self.runtime.id, policy).await
    }

    pub async fn observe(&self) -> Result<NodeObservation> {
        self.backend.observe(&self.runtime.id).await
    }
}

pub struct Cluster {
    pub spec: ClusterSpec,
    pub root: PathBuf,
    pub nodes: BTreeMap<NodeId, NodeRuntime>,
    pub(crate) backend: Arc<dyn ClusterBackend>,
}

impl Cluster {
    pub fn node(&self, id: &NodeId) -> Result<&NodeRuntime> {
        self.nodes
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("unknown node {id}"))
    }

    pub fn node_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.nodes.keys()
    }

    pub fn node_handle(&self, id: &NodeId) -> Result<NodeHandle> {
        Ok(NodeHandle {
            runtime: self.node(id)?.clone(),
            backend: self.backend.clone(),
        })
    }

    pub async fn start_all(&self) -> Result<()> {
        for node in self.node_ids() {
            self.backend.start(node).await?;
        }
        Ok(())
    }

    pub async fn destroy(&self) -> Result<()> {
        self.backend.destroy().await
    }
}
