// SPDX-License-Identifier: Apache-2.0

use crate::harness::{
    cluster::{Cluster, ClusterSpec, NodeId},
    context::RunContext,
};
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    PreserveAll,
    ProcessOnly,
    PreserveIdentityDropMetadata,
    PreserveMetadataDropBlocks,
    FreshNode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fault {
    Stop {
        node: NodeId,
    },
    Kill {
        node: NodeId,
    },
    Pause {
        node: NodeId,
    },
    /// Drop P2P UDP traffic from `source` to `target`; directional by design.
    NetworkPartition {
        source: NodeId,
        target: NodeId,
    },
    /// Apply a bounded root netem qdisc to one node's non-loopback interface.
    NetworkNetem {
        node: NodeId,
        latency_ms: u32,
        jitter_ms: u32,
        loss_percent: u8,
        duplicate_percent: u8,
        reorder_percent: u8,
        rate_kbit: Option<u32>,
    },
    StorageDelete {
        node: NodeId,
        relative_path: String,
    },
    StorageCorrupt {
        node: NodeId,
        relative_path: String,
    },
    StoragePressure {
        node: NodeId,
        bytes: u64,
    },
    StorageReadOnly {
        node: NodeId,
    },
}

impl Fault {
    pub fn stable_id(&self) -> String {
        match self {
            Self::Stop { node } => format!("stop-{node}"),
            Self::Kill { node } => format!("kill-{node}"),
            Self::Pause { node } => format!("pause-{node}"),
            Self::NetworkPartition { source, target } => format!("partition-{source}-{target}"),
            Self::NetworkNetem { node, .. } => format!("netem-{node}"),
            Self::StorageDelete {
                node,
                relative_path,
            } => format!("delete-{node}-{}", short_hash(relative_path.as_bytes())),
            Self::StorageCorrupt {
                node,
                relative_path,
            } => format!("corrupt-{node}-{}", short_hash(relative_path.as_bytes())),
            Self::StoragePressure { node, .. } => format!("pressure-{node}"),
            Self::StorageReadOnly { node } => format!("readonly-{node}"),
        }
    }
}

fn short_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex()[..12].to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: Vec<String>,
    pub stdin: Vec<u8>,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub exit_code: i64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendMetadata {
    pub name: String,
    pub capabilities: Vec<String>,
    pub image_reference: Option<String>,
    pub image_digest: Option<String>,
    pub docker_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeObservation {
    pub node: NodeId,
    pub live: bool,
    pub ready: bool,
    pub status: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[async_trait]
pub trait ClusterBackend: Send + Sync {
    async fn provision(self: Arc<Self>, spec: ClusterSpec, run: &RunContext) -> Result<Cluster>;
    async fn start(&self, node: &NodeId) -> Result<()>;
    async fn stop(&self, node: &NodeId) -> Result<()>;
    async fn kill(&self, node: &NodeId) -> Result<()>;
    async fn pause(&self, node: &NodeId) -> Result<()>;
    async fn resume(&self, node: &NodeId) -> Result<()>;
    async fn restart(&self, node: &NodeId, policy: RestartPolicy) -> Result<()>;
    async fn exec(&self, node: &NodeId, request: ExecRequest) -> Result<ExecResult>;
    /// Execute maintenance tooling with the node process stopped while retaining its volumes.
    async fn offline_exec(&self, node: &NodeId, request: ExecRequest) -> Result<ExecResult>;
    /// Execute bounded network-namespace tooling with NET_ADMIN when supported.
    async fn network_exec(&self, node: &NodeId, request: ExecRequest) -> Result<ExecResult>;
    async fn http(&self, node: &NodeId, request: HttpRequest) -> Result<HttpResponse>;
    async fn read_storage_file(
        &self,
        node: &NodeId,
        relative_path: &Path,
        max_bytes: usize,
    ) -> Result<Vec<u8>>;
    /// Overwrite one known storage-relative regular file for corruption tests.
    async fn overwrite_storage_file(
        &self,
        node: &NodeId,
        relative_path: &Path,
        bytes: &[u8],
    ) -> Result<()>;
    /// Remove one known storage-relative regular file for loss/repair tests.
    async fn remove_storage_file(&self, node: &NodeId, relative_path: &Path) -> Result<()>;
    async fn apply_fault(self: Arc<Self>, fault: Fault) -> Result<FaultGuard>;
    async fn heal_fault(&self, fault: &Fault) -> Result<()>;
    async fn observe(&self, node: &NodeId) -> Result<NodeObservation>;
    async fn collect_artifacts(&self, destination: &Path) -> Result<()>;
    async fn destroy(&self) -> Result<()>;
    fn metadata(&self) -> BackendMetadata;
    fn reproduction_arguments(&self) -> Vec<String>;
    fn artifact_root_hint(&self) -> Option<PathBuf> {
        None
    }
    fn record_fault_cleanup_failure(&self, fault: &Fault, error: &anyhow::Error) {
        let message = error.to_string();
        let bounded = message.chars().take(1024).collect::<String>();
        eprintln!("failed to heal fault {}: {bounded}", fault.stable_id());
        if let Some(root) = self.artifact_root_hint() {
            let path = root.join("fault-cleanup-failures.jsonl");
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(
                    file,
                    "{}",
                    serde_json::json!({"fault_id":fault.stable_id(),"error":bounded})
                );
            }
        }
    }
}

/// Explicitly healed in normal execution; Drop schedules best-effort healing
/// when a scenario returns early while a Tokio runtime is still available.
pub struct FaultGuard {
    backend: Arc<dyn ClusterBackend>,
    fault: Fault,
    healed: Arc<AtomicBool>,
}

impl FaultGuard {
    pub fn new(backend: Arc<dyn ClusterBackend>, fault: Fault) -> Self {
        Self {
            backend,
            fault,
            healed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn heal(self) -> Result<()> {
        self.backend.heal_fault(&self.fault).await?;
        self.healed.store(true, Ordering::Release);
        Ok(())
    }
}

impl Drop for FaultGuard {
    fn drop(&mut self) {
        if self.healed.swap(true, Ordering::AcqRel) {
            return;
        }
        let backend = self.backend.clone();
        let fault = self.fault.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = backend.heal_fault(&fault).await {
                    backend.record_fault_cleanup_failure(&fault, &error);
                }
            });
        }
    }
}
